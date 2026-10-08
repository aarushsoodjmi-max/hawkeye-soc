"""Regression tests for the hardened HawkEye AI subsystem.

Covers the shared response contract + safety invariant, evidence validation,
Local provider JSON hardening, Gemini provider failure mapping, the prompt
hard ceiling, and provider parity. All transports are faked — no network.
"""

from __future__ import annotations

import json

import pytest

from app.modules.ai import errors
from app.modules.ai.contracts.evidence import EntityRef, EvidencePackage
from app.modules.ai.contracts.requests import AiRequest
from app.modules.ai.contracts.responses import AiResponse
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.gemini import (
    GeminiConfigurationError,
    GeminiProvider,
    GeminiProviderError,
    GeminiQuotaError,
    GeminiTimeoutError,
)
from app.modules.ai.validation import build_evidence_index, validate_response

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
GOOD_MODEL_JSON = json.dumps(
    {
        "summary": "Compromised service account.",
        "confidence": 0.8,
        "evidence_references": [{"evidence_id": "EVT-1", "kind": "event", "summary": "Observed t on HOST-1"}],
    }
)


def gemini_envelope(content):
    return {
        "candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": content}]}}],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 20},
    }


def make_local_provider(content, settings=None):
    from tests.test_ai_local_foundation import (  # reuse existing fakes
        FakeTransport,
        InferenceClient,
        InferenceSettings,
        LocalProvider,
        ModelManager,
    )

    base = {
        "MODEL": "test-model",
        "SERVER_URL": "http://127.0.0.1:9999",
        "REQUEST_FORMAT": "chat",
        "CONTEXT_LENGTH": "4096",
        "MAX_TOKENS": "512",
        "RETRY_MAX_ATTEMPTS": "1",
        "RETRY_BACKOFF": "0",
    }
    base.update(settings or {})
    s = InferenceSettings(overrides=base)

    class Handler:
        def post_json(self, url, payload, timeout):
            return {"choices": [{"message": {"content": content}}]}

        def get_json(self, url, timeout):
            return {"status": "ok"}

    client = InferenceClient(s, transport=Handler(), sleep=lambda _: None)
    return LocalProvider(settings=s, client=client, model_manager=ModelManager(s, client=client))


def populated_evidence(incident_id="INC-1"):
    from app.schemas import AffectedAsset, TimelineEvent

    return EvidencePackage(
        incident_id=incident_id,
        normalized_events=[
            TimelineEvent(
                id="EVT-1", timestamp="2026-09-01T00:00:00Z", tactic="Initial Access",
                technique="Valid Accounts", techniqueId="T1078", title="t", description="d",
                source="EDR", target="HOST-1", severity="HIGH",
            )
        ],
        affected_assets=[
            AffectedAsset(id="A1", name="HOST-1", ip="10.0.0.1", os="Linux", role="server")
        ],
        users=[EntityRef(name="alice")],
        analyst_notes="analyst says hi",
    )


# ---------------------------------------------------------------------------
# 1. common response contract
# ---------------------------------------------------------------------------
def test_common_response_contract_fields():
    resp = AiResponse(incident_id="INC-1", summary="s")
    assert resp.requires_user_approval is True
    assert resp.auto_execute is False
    assert resp.evidence_status in ("sufficient", "insufficient")
    assert resp.validation_warnings == []
    assert hasattr(resp, "reasoning")
    assert resp.evidence_references == []


# ---------------------------------------------------------------------------
# 2/3. malicious model cannot set auto_execute / disable approval
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("injection", [True, False, "yes", None])
def test_malicious_model_cannot_authorize_execution(injection):
    payload = {
        "incident_id": "INC-1",
        "summary": "s",
        "auto_execute": injection,
        "requires_user_approval": injection,
    }
    resp = AiResponse.model_validate(payload)
    assert resp.auto_execute is False
    assert resp.requires_user_approval is True


def test_gemini_and_local_responses_always_safe():
    gem = GeminiProvider(api_key="k", transport=lambda *a: gemini_envelope(
        json.dumps({"summary": "s", "auto_execute": True, "requires_user_approval": False})
    ))
    resp_g = gem.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))
    assert resp_g.auto_execute is False and resp_g.requires_user_approval is True

    loc = make_local_provider(json.dumps({"summary": "s", "auto_execute": True, "requires_user_approval": False}))
    resp_l = loc.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))
    assert resp_l.auto_execute is False and resp_l.requires_user_approval is True


# ---------------------------------------------------------------------------
# 4. invalid evidence reference
# ---------------------------------------------------------------------------
def test_invalid_evidence_reference_detected():
    evidence = populated_evidence()
    resp = AiResponse(
        incident_id="INC-1", summary="s",
        evidence_references=[{"evidence_id": "EVT-DOES-NOT-EXIST", "kind": "event"}],
    )
    with pytest.raises(Exception, match="does not exist"):
        validate_response(resp, evidence)


def test_valid_evidence_reference_resolves():
    evidence = populated_evidence()
    resp = AiResponse(
        incident_id="INC-1", summary="s", confidence=0.9,
        evidence_references=[{"evidence_id": "EVT-1", "kind": "event", "basis": "inference", "summary": "Observed t on HOST-1"}],
    )
    validated = validate_response(resp, evidence)
    assert validated.evidence_status == "sufficient"
    assert validated.validation_warnings == []
    assert validated.evidence_references[0].basis == "observed"


# ---------------------------------------------------------------------------
# 5. invalid confidence rejected by schema
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [1.5, -0.1, "high"])
def test_invalid_confidence_rejected(bad):
    with pytest.raises(Exception):
        AiResponse.model_validate({"summary": "s", "confidence": bad})


# ---------------------------------------------------------------------------
# 6. insufficient evidence explicit
# ---------------------------------------------------------------------------
def test_insufficient_evidence_empty_package_caps_confidence():
    evidence = EvidencePackage(incident_id="INC-1")
    resp = AiResponse(incident_id="INC-1", summary="s", confidence=0.95)
    validated = validate_response(resp, evidence)
    assert validated.evidence_status == "insufficient"
    assert validated.confidence <= 0.3
    assert validated.validation_warnings


def test_model_declared_insufficient_flag():
    from app.modules.ai.validation import model_declared_insufficient_evidence

    assert model_declared_insufficient_evidence({"status": "insufficient_evidence"}) is True
    assert model_declared_insufficient_evidence({"summary": "ok"}) is False


# ---------------------------------------------------------------------------
# 7. Local fenced JSON
# ---------------------------------------------------------------------------
def test_local_fenced_json_parses():
    provider = make_local_provider(f"```json\n{GOOD_MODEL_JSON}\n```")
    resp = provider.analyze(AiRequest(incident_id="INC-1"), populated_evidence())
    assert resp.summary == "Compromised service account."


def test_local_prose_wrapped_json_parses():
    provider = make_local_provider(f"Here is the analysis:\n{GOOD_MODEL_JSON}\nHope this helps!")
    resp = provider.analyze(AiRequest(incident_id="INC-1"), populated_evidence())
    assert resp.summary == "Compromised service account."


# ---------------------------------------------------------------------------
# 8. Local malformed / empty JSON
# ---------------------------------------------------------------------------
def test_local_malformed_json_typed_error():
    provider = make_local_provider("definitely { not json")
    with pytest.raises(errors.InvalidModelOutputError):
        provider.analyze(AiRequest(incident_id="INC-1"), populated_evidence())


def test_local_empty_output_typed_error():
    from app.modules.ai.providers.local import _extract_json

    for empty in ("", "   ", "```", None):
        with pytest.raises(errors.InvalidModelOutputError):
            _extract_json(empty)


# ---------------------------------------------------------------------------
# 9-12. Gemini failure mapping
# ---------------------------------------------------------------------------
def test_gemini_missing_key_fails_before_transport():
    calls = []
    p = GeminiProvider(api_key="", transport=lambda *a: calls.append(a))
    with pytest.raises(GeminiConfigurationError):
        p.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))
    assert not calls


def test_gemini_timeout_typed():
    p = GeminiProvider(api_key="k", transport=lambda *a: (_ for _ in ()).throw(TimeoutError()))
    with pytest.raises(GeminiTimeoutError):
        p.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))


def test_gemini_http_error_typed_and_quota():
    import urllib.error

    def http(code):
        def t(*a):
            raise urllib.error.HTTPError(a[0], code, "err", {}, None)
        return t

    with pytest.raises(GeminiQuotaError):
        GeminiProvider(api_key="k", transport=http(429)).analyze(
            AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))
    with pytest.raises(GeminiProviderError):
        GeminiProvider(api_key="k", transport=http(500)).analyze(
            AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))


def test_gemini_malformed_output_typed():
    for bad in ("not json", '{"summary": }'):
        p = GeminiProvider(api_key="k", transport=lambda *a, b=bad: gemini_envelope(b))
        with pytest.raises((errors.InvalidModelOutputError, errors.ProviderOutputValidationError)):
            p.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))


def test_gemini_blocked_response_typed():
    p = GeminiProvider(
        api_key="k",
        transport=lambda *a: {"candidates": [], "promptFeedback": {"blockReason": "SAFETY"}},
    )
    with pytest.raises(GeminiProviderError):
        p.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))


def test_gemini_api_key_never_leaks_in_errors(caplog):
    import urllib.error

    secret = "SUPER-SECRET-KEY-123"

    def t(url, payload, timeout):
        # sanity: the key goes in the payload metadata (header transport), and
        # must never appear in any raised error message.
        raise urllib.error.HTTPError(url, 500, "boom", {}, None)

    p = GeminiProvider(api_key=secret, transport=t)
    with pytest.raises(GeminiProviderError) as exc_info:
        p.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))
    assert secret not in str(exc_info.value)
    assert secret not in json.dumps(exc_info.value.details)


# ---------------------------------------------------------------------------
# 13. prompt hard ceiling
# ---------------------------------------------------------------------------
def test_prompt_hard_ceiling_deterministic():
    big = EvidencePackage(incident_id="INC-1", analyst_notes="X" * 500_000)
    prompt = GeminiProvider._build_prompt(AiRequest(incident_id="INC-1"), big)
    assert len(prompt) <= 160_000
    assert "Return ONLY JSON matching this contract" in prompt
    assert '"_truncation"' in prompt

    from app.modules.ai.providers.gemini import MAX_PROMPT_CHARS

    marker = '{"_truncation":{"truncated":true,"reason":"evidence exceeded prompt ceiling"}}'
    exact = EvidencePackage(incident_id="INC-1", analyst_notes="Y" * (MAX_PROMPT_CHARS))
    prompt2 = GeminiProvider._build_prompt(AiRequest(incident_id="INC-1"), exact)
    assert len(prompt2) <= MAX_PROMPT_CHARS


# ---------------------------------------------------------------------------
# 14. provider parity
# ---------------------------------------------------------------------------
def test_provider_parity_same_contract():
    evidence = populated_evidence()
    gem = GeminiProvider(api_key="k", transport=lambda *a: gemini_envelope(GOOD_MODEL_JSON))
    loc = make_local_provider(GOOD_MODEL_JSON)
    resp_g = gem.analyze(AiRequest(incident_id="INC-1"), evidence)
    resp_l = loc.analyze(AiRequest(incident_id="INC-1"), evidence)
    assert set(resp_g.model_dump().keys()) == set(resp_l.model_dump().keys())
    assert isinstance(resp_g, AiResponse) and isinstance(resp_l, AiResponse)
    for attr in ("summary", "incident_id", "task", "confidence", "evidence_references",
                 "requires_user_approval", "auto_execute", "evidence_status"):
        assert getattr(resp_g, attr) == getattr(resp_l, attr)


def test_health_layered_not_config_only():
    h_unconf = GeminiProvider(api_key="").health()
    assert h_unconf["status"] == "unconfigured" and h_unconf["configured"] is False

    h_conf = GeminiProvider(api_key="k").health()
    assert h_conf["configured"] is True
    # configuration alone must not claim reachable/healthy
    assert h_conf["reachable"] is None
    assert h_conf["status"] != "ok"


def test_evidence_index_deterministic():
    e1 = populated_evidence()
    e2 = populated_evidence()
    assert build_evidence_index(e1) == build_evidence_index(e2)
    assert "EVT-1" in build_evidence_index(e1)
    assert "HOST-1" in build_evidence_index(e1)


def test_evidence_memory_is_present_and_tenant_bound():
    evidence = populated_evidence()
    evidence.workspace_id = "tenant-a"
    evidence.memory = {"workspace_id": "tenant-a", "notes": [{"workspace_id": "tenant-a", "text": "HOST-1"}]}
    evidence.assert_workspace("tenant-a")
    assert "incident_memory" in evidence.context_sections()
    evidence.memory["workspace_id"] = "tenant-b"
    with pytest.raises(ValueError, match="memory workspace"):
        evidence.assert_workspace("tenant-a")


def test_ai_affected_asset_must_be_grounded_in_evidence():
    evidence = populated_evidence()
    resp = AiResponse(
        incident_id="INC-1", summary="s",
        affected_assets=[{"id": "NOT-IN-EVIDENCE", "name": "OTHER", "ip": "1.2.3.4", "os": "Linux", "role": "server"}],
    )
    with pytest.raises(Exception, match="affected asset"):
        validate_response(resp, evidence)
