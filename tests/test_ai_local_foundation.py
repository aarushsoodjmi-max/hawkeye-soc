"""Focused tests for the HawkEye Local AI provider & inference foundation.

All inference tests run against a faked transport — no real model or server
is required.
"""

from __future__ import annotations

import json

import pytest
from fastapi import HTTPException

import app.modules.ai.router as ai_router
from app.modules.ai import errors
from app.modules.ai.contracts.evidence import EvidencePackage
from app.modules.ai.contracts.requests import AiAnalyzeRequest, AiRequest
from app.modules.ai.contracts.responses import AiResponse
from app.modules.ai.evaluation.benchmarks import BenchmarkCase, run_provider_benchmark
from app.modules.ai.evaluation.evaluator import evaluate_response
from app.modules.ai.inference.client import InferenceClient
from app.modules.ai.inference.config import InferenceSettings
from app.modules.ai.inference.model_manager import ModelManager
from app.modules.ai.orchestration.context_builder import ContextBuilder
from app.modules.ai.orchestration.orchestrator import AiOrchestrator
from app.modules.ai.providers.base import AIProvider, ProviderRegistry
from app.modules.ai.providers.local import LocalProvider, parse_model_response
from app.modules.ai.training.dataset import FeedbackRecord, TrainingDataset
from app.modules.ai.training.registry import ModelRegistry, ModelVersion
from app.modules.ai.training.trainer import UnavailableFineTuningTrainer


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def make_settings(**overrides):
    base = {
        "MODEL": "test-model",
        "MODEL_PATH": "/models/test-model.gguf",
        "SERVER_URL": "http://127.0.0.1:9999",
        "REQUEST_FORMAT": "chat",
        "CONTEXT_LENGTH": "2048",
        "MAX_TOKENS": "512",
        "TEMPERATURE": "0.2",
        "DEVICE": "cpu",
        "RETRY_MAX_ATTEMPTS": "3",
        "RETRY_BACKOFF": "0.01",
        "RETRY_BACKOFF_FACTOR": "1.0",
        "RETRY_MAX_BACKOFF": "0.05",
    }
    base.update(overrides)
    return InferenceSettings(overrides=base)


def chat_response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}], "usage": {"total_tokens": 10}}


VALID_MODEL_JSON = json.dumps(
    {
        "summary": "Contained and eradicated.",
        "severity_assessment": {"severity": "HIGH", "justification": "DC exposure", "confidence": 0.8},
        "root_cause": {
            "vector": "v", "entryPoint": "e", "compromisedAccount": "svc_backup",
            "c2Server": "c2.example", "c2Location": "loc", "vulnerabilityDetails": "vd",
            "detectionMechanism": "dm", "initialPayload": "ip", "firstObserved": "t",
            "primary": "compromised_account", "confidence": 0.84,
        },
        "affected_assets": [
            {"id": "A1", "name": "HOST-1", "ip": "10.0.0.1", "os": "Linux", "role": "server"}
        ],
        "predicted_next_steps": [
            {"step": "rotate krbtgt", "rationale": "ticket forging", "confidence": 0.7}
        ],
        "recommendations": [
            {"id": "RA-1", "title": "Isolate", "description": "Quarantine host",
             "target": "HOST-1", "type": "CONTAINMENT"}
        ],
        "confidence": 0.84,
        "confidence_breakdown": {"model": 0.84},
        "proposed_playbook": {
            "name": "Containment", "based_on": ["PB-CONTAIN-001"],
            "steps": [{"action_type": "isolate_device", "target": "HOST-1", "description": "q"}],
        },
        "mitre_techniques": ["T1190"],
    }
)


class FakeTransport:
    def __init__(self, post_handler=None, get_result=None):
        self.post_handler = post_handler
        self.get_result = get_result if get_result is not None else {"status": "ok"}
        self.post_calls = 0
        self.get_calls = 0
        self.last_payload = None

    def post_json(self, url, payload, timeout):
        self.post_calls += 1
        self.last_payload = payload
        if self.post_handler is None:
            return chat_response('{"summary": "ok"}')
        return self.post_handler(url, payload, timeout)

    def get_json(self, url, timeout):
        self.get_calls += 1
        if isinstance(self.get_result, BaseException):
            raise self.get_result
        return self.get_result


def incident_dict():
    return {
        "id": "INC-X", "title": "Test incident", "severity": "HIGH", "status": "ACTIVE",
        "threatActor": "APT-TEST", "impactSummary": "impact",
        "timelineEvents": [{
            "id": "EVT-1", "timestamp": "2026-09-01T00:00:00Z", "tactic": "Initial Access",
            "technique": "Exploit Public-Facing App", "techniqueId": "T1190",
            "title": "t", "description": "d", "source": "EDR", "target": "HOST-1",
            "severity": "HIGH", "evidenceConfidence": 90.0,
        }],
        "affectedAssets": [{
            "id": "A1", "name": "HOST-1", "ip": "10.0.0.1", "os": "Linux",
            "role": "server", "status": "COMPROMISED", "criticality": "TIER 1",
        }],
        "alerts": [{"user": "alice"}],
        "rootCause": {
            "cveId": "CVE-2024-0001", "c2Server": "1.2.3.4:443",
            "compromisedAccount": "svc_backup", "confidence": 0.9, "primary": "x",
        },
        "riskScore": 88, "riskLevel": "HIGH", "riskBreakdown": {"escalation": True},
    }


def build_local_provider(post_handler=None, get_result=None, settings=None):
    settings = settings or make_settings()
    transport = FakeTransport(post_handler=post_handler, get_result=get_result)
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    manager = ModelManager(settings, client=client)
    return (
        LocalProvider(settings=settings, client=client, model_manager=manager),
        transport,
    )


# ---------------------------------------------------------------------------
# configuration validation
# ---------------------------------------------------------------------------
def test_config_valid_defaults():
    s = make_settings()
    assert s.model_name == "test-model"
    assert s.model_path == "/models/test-model.gguf"
    assert s.context_length == 2048
    assert s.retry_max_attempts == 3
    assert s.device == "cpu"


def test_config_rejects_invalid_server_url():
    with pytest.raises(ValueError, match="SERVER_URL"):
        make_settings(SERVER_URL="not-a-url")


def test_config_rejects_invalid_request_format():
    with pytest.raises(ValueError, match="REQUEST_FORMAT"):
        make_settings(REQUEST_FORMAT="grpc")


def test_config_rejects_temperature_out_of_range():
    with pytest.raises(ValueError, match="TEMPERATURE"):
        make_settings(TEMPERATURE="3.0")


def test_config_rejects_max_tokens_exceeding_context():
    with pytest.raises(ValueError, match="MAX_TOKENS"):
        make_settings(CONTEXT_LENGTH="512", MAX_TOKENS="1024")


def test_config_rejects_unknown_device():
    with pytest.raises(ValueError, match="DEVICE"):
        make_settings(DEVICE="tpu")


def test_config_rejects_zero_retry_attempts():
    with pytest.raises(ValueError, match="RETRY_MAX_ATTEMPTS"):
        make_settings(RETRY_MAX_ATTEMPTS="0")


def test_config_env_driven():
    s = InferenceSettings(overrides={}, env={"HAWKEYE_AI_MODEL": "env-model"})
    assert s.model_name == "env-model"
    assert s.server_url == "http://127.0.0.1:8001"  # safe default


def test_config_metadata_never_exposes_api_key():
    s = make_settings(API_KEY="supersecret")
    assert s.api_key == "supersecret"
    md = s.metadata()
    assert "api_key" not in md
    assert "supersecret" not in json.dumps(md)


# ---------------------------------------------------------------------------
# inference client
# ---------------------------------------------------------------------------
def test_client_parses_chat_completion():
    settings = make_settings()
    transport = FakeTransport(post_handler=lambda u, p, t: chat_response("hello"))
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    result = client.generate("prompt")
    assert result.content == "hello"
    assert result.usage["total_tokens"] == 10
    assert transport.last_payload["model"] == "test-model"
    assert transport.last_payload["messages"][0]["content"] == "prompt"


def test_client_generic_format():
    settings = make_settings(REQUEST_FORMAT="generic")
    transport = FakeTransport(post_handler=lambda u, p, t: {"content": "hi"})
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    assert client.generate("p").content == "hi"
    assert "prompt" in transport.last_payload


def test_client_completion_format():
    settings = make_settings(REQUEST_FORMAT="completion")
    transport = FakeTransport(post_handler=lambda u, p, t: {"choices": [{"text": "x"}]})
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    assert client.generate("p").content == "x"


def test_client_rejects_malformed_responses():
    settings = make_settings()
    # missing choices
    client = InferenceClient(
        settings,
        transport=FakeTransport(post_handler=lambda u, p, t: {"choices": []}),
        sleep=lambda _: None,
    )
    with pytest.raises(errors.MalformedServerResponseError):
        client.generate("p")
    # empty content
    client2 = InferenceClient(
        settings,
        transport=FakeTransport(
            post_handler=lambda u, p, t: {"choices": [{"message": {"content": "  "}}]}
        ),
        sleep=lambda _: None,
    )
    with pytest.raises(errors.MalformedServerResponseError):
        client2.generate("p")
    # response is not an object
    client3 = InferenceClient(
        settings,
        transport=FakeTransport(post_handler=lambda u, p, t: [1, 2]),
        sleep=lambda _: None,
    )
    with pytest.raises(errors.MalformedServerResponseError):
        client3.generate("p")


def test_client_timeout_retries_then_raises():
    settings = make_settings()

    def h(u, p, t):
        raise errors.InferenceTimeoutError(details={"url": u})

    transport = FakeTransport(post_handler=h)
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    with pytest.raises(errors.InferenceTimeoutError):
        client.generate("p")
    assert transport.post_calls == settings.retry_max_attempts


def test_client_server_unavailable_stops_after_retries():
    settings = make_settings()

    def h(u, p, t):
        raise errors.InferenceConnectionError(details={"url": u})

    transport = FakeTransport(post_handler=h)
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    with pytest.raises(errors.InferenceConnectionError):
        client.generate("p")
    assert transport.post_calls == settings.retry_max_attempts


def test_client_retries_transient_server_error_then_succeeds():
    settings = make_settings()
    state = {"n": 0}

    def h(u, p, t):
        state["n"] += 1
        if state["n"] < 3:
            raise errors.InferenceServerError("boom", status_code=500, details={"url": u})
        return chat_response("recovered")

    transport = FakeTransport(post_handler=h)
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    assert client.generate("p").content == "recovered"
    assert state["n"] == 3


def test_client_non_retryable_server_error_raises_immediately():
    settings = make_settings()

    def h(u, p, t):
        raise errors.InferenceServerError("bad request", status_code=400, details={"url": u})

    transport = FakeTransport(post_handler=h)
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    with pytest.raises(errors.InferenceServerError):
        client.generate("p")
    assert transport.post_calls == 1


def test_client_context_exceeded_not_retried():
    settings = make_settings()

    def h(u, p, t):
        raise errors.ContextExceededError(details={"url": u})

    transport = FakeTransport(post_handler=h)
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    with pytest.raises(errors.ContextExceededError):
        client.generate("p")
    assert transport.post_calls == 1


def test_client_health_probe():
    settings = make_settings()
    ok = InferenceClient(settings, transport=FakeTransport(), sleep=lambda _: None)
    assert ok.health() == {"ok": True, "status": "ok"}
    down = InferenceClient(
        settings,
        transport=FakeTransport(get_result=errors.InferenceConnectionError("down")),
        sleep=lambda _: None,
    )
    probe = down.health()
    assert probe["ok"] is False and probe["error"] == "inference_connection_error"


def test_client_rejects_empty_prompt():
    client = InferenceClient(make_settings(), transport=FakeTransport(), sleep=lambda _: None)
    with pytest.raises(ValueError):
        client.generate("   ")


# ---------------------------------------------------------------------------
# model manager
# ---------------------------------------------------------------------------
def test_model_manager_health_and_availability():
    settings = make_settings()
    transport = FakeTransport()
    manager = ModelManager(settings, client=InferenceClient(settings, transport=transport, sleep=lambda _: None))
    assert manager.is_available() is True
    assert manager.get_model_info().available is True
    health = manager.health()
    assert health["provider"] == "local"
    assert health["status"] == "ok"
    assert health["model"]["model_name"] == "test-model"
    assert health["server"] == {"ok": True, "status": "ok"}


def test_model_manager_reports_server_down():
    settings = make_settings()
    transport = FakeTransport(get_result=errors.InferenceConnectionError("down"))
    manager = ModelManager(settings, client=InferenceClient(settings, transport=transport, sleep=lambda _: None))
    assert manager.is_available() is False
    health = manager.health()
    assert health["status"] == "unavailable"
    assert health["server"]["ok"] is False


def test_model_manager_metadata_safe():
    settings = make_settings(API_KEY="secret")
    transport = FakeTransport()
    manager = ModelManager(settings, client=InferenceClient(settings, transport=transport, sleep=lambda _: None))
    md = manager.get_metadata()
    assert md["model_name"] == "test-model"
    assert "api_key" not in md and "secret" not in json.dumps(md)


def test_model_manager_context_gate():
    settings = make_settings(CONTEXT_LENGTH="512", MAX_TOKENS="256")
    transport = FakeTransport()
    manager = ModelManager(settings, client=InferenceClient(settings, transport=transport, sleep=lambda _: None))
    with pytest.raises(errors.ContextExceededError):
        manager.validate_context("x" * 2000)


def test_inference_client_retries_connection_failure():
    settings = make_settings(RETRY_MAX_ATTEMPTS="2", RETRY_BACKOFF="0")

    class FailingTransport:
        def __init__(self):
            self.calls = 0

        def post_json(self, url, payload, timeout):
            self.calls += 1
            raise errors.InferenceConnectionError(details={"url": url})

        def get_json(self, url, timeout):
            return {"status": "ok"}

    transport = FailingTransport()
    client = InferenceClient(settings, transport=transport, sleep=lambda _: None)
    with pytest.raises(errors.InferenceConnectionError):
        client.generate("hello")
    assert transport.calls == 2


def test_model_manager_model_selection():
    settings = make_settings()
    manager = ModelManager(settings, client=InferenceClient(settings, transport=FakeTransport(), sleep=lambda _: None))
    assert manager.select_model(None) == "test-model"
    assert manager.select_model("") == "test-model"
    assert manager.select_model("override-model") == "override-model"


# ---------------------------------------------------------------------------
# LocalProvider
# ---------------------------------------------------------------------------
def test_local_provider_satisfies_common_interface():
    provider, _ = build_local_provider()
    assert isinstance(provider, AIProvider)
    assert provider.name == "local"
    health = provider.health()
    assert health["provider"] == "local" and health["status"] == "ok"
    models = provider.models()
    assert models and models[0]["model_name"] == "test-model"


def test_provider_analyze_valid_local_response():
    provider, transport = build_local_provider(
        post_handler=lambda u, p, t: chat_response(VALID_MODEL_JSON)
    )
    request = AiRequest(incident_id="INC-X", task="analysis", analyst_instructions="be thorough")
    evidence = EvidencePackage(incident_id="INC-X", affected_assets=[{"id":"A1","name":"HOST-1","ip":"10.0.0.1","os":"Linux","role":"server"}])
    response = provider.analyze(request, evidence)
    assert isinstance(response, AiResponse)
    assert response.incident_id == "INC-X"
    assert response.task == "analysis"
    assert response.generated_at
    assert response.summary == "Contained and eradicated."
    assert response.root_cause is not None
    assert response.root_cause.primary == "compromised_account"
    assert response.root_cause.confidence == 0.84
    assert len(response.recommendations) == 1
    assert response.proposed_playbook is not None
    assert response.severity_assessment.severity == "HIGH"
    # prompt carried the compact evidence sections
    assert "OUTPUT_SCHEMA" in transport.last_payload["messages"][0]["content"]


def test_provider_rejects_non_json_output():
    provider, _ = build_local_provider(post_handler=lambda u, p, t: chat_response("not json at all"))
    with pytest.raises(errors.InvalidModelOutputError):
        provider.analyze(AiRequest(incident_id="INC-X"), EvidencePackage(incident_id="INC-X"))


def test_provider_rejects_schema_violations():
    # missing summary + unknown top-level field
    provider, _ = build_local_provider(
        post_handler=lambda u, p, t: chat_response('{"summary": "", "intruder": 1}')
    )
    with pytest.raises(errors.ProviderOutputValidationError):
        provider.analyze(AiRequest(incident_id="INC-X"), EvidencePackage(incident_id="INC-X"))


def test_provider_requires_evidence_match():
    provider, _ = build_local_provider()
    with pytest.raises(ValueError):
        provider.analyze(AiRequest(incident_id="INC-X"), EvidencePackage(incident_id="OTHER"))


def test_provider_context_oversize_short_circuits_before_transport():
    settings = make_settings(CONTEXT_LENGTH="256", MAX_TOKENS="128")
    provider, transport = build_local_provider(settings=settings)
    with pytest.raises(errors.ContextExceededError):
        provider.analyze(AiRequest(incident_id="INC-X"), EvidencePackage(incident_id="INC-X"))
    assert transport.post_calls == 0


def test_parse_model_response_binds_identity_and_stamps_time():
    req = AiRequest(incident_id="INC-1", task="recommendations")
    resp = parse_model_response('{"summary": "s", "confidence": 0.5}', req)
    assert resp.incident_id == "INC-1"
    assert resp.task == "recommendations"
    assert resp.generated_at


def test_parse_model_response_rejects_unknown_fields():
    with pytest.raises(errors.ProviderOutputValidationError):
        parse_model_response('{"summary": "s", "intruder": 1}', AiRequest(incident_id="I"))


# ---------------------------------------------------------------------------
# provider registry / interface compatibility
# ---------------------------------------------------------------------------
def test_provider_registry_selection():
    registry = ProviderRegistry()
    provider, _ = build_local_provider()
    registry.register(provider)
    assert registry.has("local")
    assert registry.get("local") is provider
    assert "local" in registry.names()
    with pytest.raises(errors.ProviderNotFoundError):
        registry.get("gemini-not-implemented")


# ---------------------------------------------------------------------------
# context builder / evidence
# ---------------------------------------------------------------------------
def test_context_builder_from_incident():
    pkg = ContextBuilder().build_from_incident(incident_dict())
    assert pkg.incident_id == "INC-X"
    assert len(pkg.normalized_events) == 1
    assert pkg.normalized_events[0].techniqueId == "T1190"
    assert len(pkg.affected_assets) == 1
    users = {u.name: u for u in pkg.users}
    assert "alice" in users and "svc_backup" in users
    assert users["svc_backup"].risk == "compromised"
    assert len(pkg.knowledge_graph) == 1
    assert pkg.knowledge_graph[0].source == "EDR"
    assert pkg.threat_intelligence[0].indicators == ["CVE-2024-0001", "1.2.3.4:443"]
    assert pkg.risk.risk_score == 88
    assert pkg.risk.risk_level == "HIGH"
    assert pkg.business_impact.affected_critical_assets == 1


def test_context_builder_includes_similar_incidents():
    class FakeMemory:
        def similar(self, incident, workspace_id, limit=10):
            return [{
                "incident_id": "INC-PREV", "workspace_id": workspace_id, "similarity_score": 0.93, "root_cause": "x",
                "playbooks_used": ["PB-1"], "playbook_successful": True,
            }]

    pkg = ContextBuilder(memory_service=FakeMemory()).build_from_incident(incident_dict(), workspace_id="default")
    assert pkg.similar_incidents[0].incident_id == "INC-PREV"
    assert pkg.similar_incidents[0].similarity_score == 0.93
    assert pkg.similar_incidents[0].playbook_successful is True


def test_evidence_package_compact_prunes_large_collections():
    from app.modules.ai.contracts.evidence import EntityRef

    pkg = EvidencePackage(
        incident_id="I",
        entities=[EntityRef(name=f"e{i}") for i in range(120)],
        users=[EntityRef(name=f"u{i}") for i in range(120)],
    )
    compact = pkg.compact(max_assets=10)
    assert len(compact.entities) == 10
    assert len(compact.users) == 10
    assert len(pkg.entities) == 120  # original untouched


def test_context_sections_tolerate_dict_incident():
    pkg = ContextBuilder().build_from_incident(incident_dict())
    sections = pkg.context_sections()
    assert sections["incident"]["id"] == "INC-X"
    assert sections["incident"]["severity"] == "HIGH"
    assert len(sections["normalized_events"]) == 1


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
class RecordingProvider(AIProvider):
    name = "fake"

    def __init__(self):
        self.seen = None

    def analyze(self, request, evidence):
        self.seen = (request, evidence)
        return AiResponse(incident_id=request.incident_id, task=request.task, summary="ok")


def test_orchestrator_dispatches_through_registry():
    provider = RecordingProvider()
    orch = AiOrchestrator(
        registry=ProviderRegistry([provider]),
        context_builder=ContextBuilder(),
        default_provider="fake",
    )
    evidence = EvidencePackage(incident_id="INC-1")
    out = orch.analyze(AiRequest(incident_id="INC-1"), evidence=evidence)
    assert out.summary == "ok"
    seen_request, seen_evidence = provider.seen
    assert seen_evidence is evidence
    assert seen_request.incident_id == "INC-1"


def test_orchestrator_unknown_provider():
    orch = AiOrchestrator(registry=ProviderRegistry([]), context_builder=ContextBuilder())
    with pytest.raises(errors.ProviderNotFoundError):
        orch.analyze(
            AiRequest(incident_id="INC-1"),
            evidence=EvidencePackage(incident_id="INC-1", affected_assets=[{"id":"A1","name":"HOST-1","ip":"10.0.0.1","os":"Linux","role":"server"}]),
            provider="nope",
        )


def test_orchestrator_health_delegates():
    provider = RecordingProvider()
    orch = AiOrchestrator(
        registry=ProviderRegistry([provider]),
        context_builder=ContextBuilder(),
        default_provider="fake",
    )
    assert orch.health()["provider"] == "fake"
    assert orch.provider_names() == ["fake"]


# ---------------------------------------------------------------------------
# router mapping
# ---------------------------------------------------------------------------
def test_router_provider_not_found_maps_404(monkeypatch):
    class Orch:
        def analyze(self, request, provider="local"):
            raise errors.ProviderNotFoundError(details={"provider": provider})

    monkeypatch.setattr(ai_router, "orchestrator", Orch())
    with pytest.raises(HTTPException) as exc_info:
        ai_router.analyze_incident(AiAnalyzeRequest(incident_id="INC-1"))
    assert exc_info.value.status_code == 404


def test_router_returns_validated_response(monkeypatch):
    class Orch:
        def analyze(self, request, provider="local"):
            return AiResponse(incident_id=request.incident_id, task=request.task, summary="ok")

    monkeypatch.setattr(ai_router, "orchestrator", Orch())
    out = ai_router.analyze_incident(AiAnalyzeRequest(incident_id="INC-1", task="recommendations"))
    assert out.summary == "ok"
    assert out.task == "recommendations"
    assert out.incident_id == "INC-1"


# ---------------------------------------------------------------------------
# evaluation + benchmark
# ---------------------------------------------------------------------------
def test_evaluator_scores_full_response():
    response = AiResponse(
        incident_id="INC-1", task="analysis", summary="ok", confidence=0.84,
        severity_assessment={"severity": "HIGH", "confidence": 0.8},
        root_cause={
            "vector": "v", "entryPoint": "e", "compromisedAccount": "a", "c2Server": "c",
            "c2Location": "l", "vulnerabilityDetails": "vd", "detectionMechanism": "dm",
            "initialPayload": "ip", "firstObserved": "t", "primary": "x", "confidence": 0.8,
        },
        recommendations=[{"id": "RA-1", "title": "t", "description": "d", "target": "x"}],
        predicted_next_steps=[{"step": "s", "confidence": 0.5}],
        evidence_references=[{"evidence_id": "evt-1", "kind": "summary", "summary": "s"}],
    )
    report = evaluate_response(response, EvidencePackage(incident_id="INC-1"))
    assert report.valid is True
    assert report.score == 1.0
    assert not report.issues


def test_evaluator_flags_incomplete_response():
    response = AiResponse(incident_id="INC-1", task="analysis", summary="ok")
    report = evaluate_response(response, EvidencePackage(incident_id="INC-1"))
    assert report.valid is True  # minimal validity is preserved
    assert report.score < 0.6
    assert report.issues


def test_benchmark_pass_rate_with_faked_inference():
    provider, _ = build_local_provider(
        post_handler=lambda u, p, t: chat_response(VALID_MODEL_JSON)
    )
    case = BenchmarkCase(
        name="minimal", request=AiRequest(incident_id="INC-1"),
        evidence=EvidencePackage(incident_id="INC-1", affected_assets=[{"id":"A1","name":"HOST-1","ip":"10.0.0.1","os":"Linux","role":"server"}]),
    )
    result = run_provider_benchmark(provider, [case])
    assert result.total == 1
    assert result.passed == 1
    assert result.pass_rate == 1.0


# ---------------------------------------------------------------------------
# training readiness (extension points only)
# ---------------------------------------------------------------------------
def test_training_dataset_records_and_export():
    ds = TrainingDataset()
    ds.add(FeedbackRecord(incident_id="INC-1", verdict="accepted"))
    ds.add(FeedbackRecord(incident_id="INC-1", verdict="corrected", corrections={"summary": "x"}))
    assert len(ds) == 2
    assert '"verdict": "accepted"' in ds.to_jsonl()
    with pytest.raises(ValueError):
        ds.add(FeedbackRecord(incident_id="I", verdict="bogus"))


def test_model_registry_explicit_validation_gate():
    reg = ModelRegistry()
    reg.register(ModelVersion(version_id="v1", model_name="m", evaluated_score=0.9))
    assert reg.select() is None            # unvalidated versions are never selected
    assert reg.select("v1") is None
    reg.mark_validated("v1", score=0.91)
    selected = reg.select("v1")
    assert selected is not None and selected.validated
    assert reg.get_validated()[0].version_id == "v1"


def test_fine_tuning_not_implemented_yet():
    with pytest.raises(NotImplementedError):
        UnavailableFineTuningTrainer().train(TrainingDataset())
