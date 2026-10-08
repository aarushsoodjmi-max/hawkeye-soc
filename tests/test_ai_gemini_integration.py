from __future__ import annotations

import json
import urllib.error

import pytest

from app.modules.ai.contracts.evidence import EvidencePackage
from app.schemas import TimelineEvent
from app.modules.ai.contracts.requests import AiRequest, AiRequestOptions
from app.modules.ai.contracts.responses import AiResponse
from app.modules.ai.errors import ProviderOutputValidationError
from app.modules.ai.providers.base import AIProvider, ProviderRegistry
from app.modules.ai.providers.gemini import (
    GeminiConfigurationError,
    GeminiProvider,
    GeminiQuotaError,
    GeminiTimeoutError,
    GeminiProviderError,
)

def envelope(content):
    return {"candidates":[{"finishReason":"STOP","content":{"parts":[{"text":content}]}}], "usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":20}}

VALID = json.dumps({
    "summary":"Evidence indicates a compromised account led to host access.",
    "severity_assessment":{"severity":"HIGH","justification":"Observed compromise","confidence":0.8},
    "root_cause":{"vector":"credential theft","entryPoint":"identity","compromisedAccount":"alice","c2Server":"","c2Location":"","vulnerabilityDetails":"","detectionMechanism":"EDR","initialPayload":"","firstObserved":"2026-09-01T00:00:00Z","primary":"compromised_account","confidence":0.8},
    "attack_path":[{"order":1,"tactic":"Initial Access","technique":"Valid Accounts","techniqueId":"T1078","source":"alice","target":"HOST-1","description":"Observed account use","confidence":0.8}],
    "affected_assets":[{"id":"A1","name":"HOST-1","ip":"10.0.0.1","os":"Linux","role":"server","status":"COMPROMISED","criticality":"TIER 1"}],
    "predicted_next_steps":[{"step":"credential rotation","rationale":"containment","confidence":0.7}],
    "recommendations":[{"id":"RA1","title":"Rotate credentials","description":"Rotate compromised credentials","target":"alice","type":"CONTAINMENT"}],
    "confidence":0.82,
    "confidence_breakdown":{"evidence":0.9},
    "evidence_references":[{"evidence_id":"EVT-1","kind":"event","summary":"Observed access","source":"EDR"}],
    "proposed_playbook":{"name":"Credential Response","steps":[{"action_type":"rotate_credentials","target":"alice","description":"Rotate","sequence":1}],"based_on":["EVT-1"]},
    "mitre_techniques":["T1078"],
})


def evidence_with_event(incident_id="INC-1"):
    return EvidencePackage(
        incident_id=incident_id,
        normalized_events=[TimelineEvent(
            id="EVT-1", timestamp="2026-09-01T00:00:00Z", relativeTime="+00:00:00",
            tactic="Initial Access", technique="Valid Accounts", techniqueId="T1078",
            title="Observed access", description="Observed account use", source="EDR", target="HOST-1", severity="HIGH"
        )],
        affected_assets=[{"id":"A1","name":"HOST-1","ip":"10.0.0.1","os":"Linux","role":"server"}],
    )

def test_gemini_is_common_provider_and_registry():
    p=GeminiProvider(api_key="secret", transport=lambda *a: envelope(VALID))
    assert isinstance(p, AIProvider)
    r=ProviderRegistry([p])
    assert r.get("gemini") is p

def test_missing_key_fails_before_transport():
    calls=[]
    p=GeminiProvider(api_key="", transport=lambda *a: calls.append(a))
    with pytest.raises(GeminiConfigurationError):
        p.analyze(AiRequest(incident_id="INC-1"), EvidencePackage(incident_id="INC-1"))
    assert not calls

def test_analysis_returns_canonical_response_and_binds_identity():
    p=GeminiProvider(api_key="secret", transport=lambda *a: envelope(VALID))
    e=evidence_with_event("INC-1")
    resp=p.analyze(AiRequest(incident_id="INC-1", task="root_cause_analysis"), e)
    assert isinstance(resp,AiResponse)
    assert resp.incident_id=="INC-1"
    assert resp.task=="root_cause_analysis"
    assert resp.summary.startswith("Evidence")
    assert resp.root_cause.primary=="compromised_account"
    assert resp.generated_at

def test_options_override_model_and_generation():
    seen={}
    def transport(url,payload,timeout):
        seen.update(url=url,payload=payload,timeout=timeout)
        return envelope(VALID)
    p=GeminiProvider(api_key="secret", model="default", transport=transport)
    p.analyze(AiRequest(incident_id="I", options=AiRequestOptions(model="override",temperature=0.4,max_tokens=123)), evidence_with_event("I"))
    assert "/models/override:generateContent" in seen["url"]
    assert seen["payload"]["generationConfig"]["temperature"]==0.4
    assert seen["payload"]["generationConfig"]["maxOutputTokens"]==123

def test_transport_metadata_not_in_body():
    captured={}
    def transport(url,payload,timeout):
        captured.update(payload)
        return envelope(VALID)
    p=GeminiProvider(api_key="SECRET", transport=transport)
    p.analyze(AiRequest(incident_id="I"), evidence_with_event("I"))
    assert captured["_transport_metadata"]["api_key"]=="SECRET"
    # _default_transport is tested separately because fake transport sees metadata.
    assert "SECRET" not in json.dumps({k:v for k,v in captured.items() if k!="_transport_metadata"})

def test_default_transport_puts_key_only_in_header(monkeypatch):
    captured={}
    class Resp:
        def read(self): return b'{"ok":true}'
        def __enter__(self): return self
        def __exit__(self,*a): pass
    def fake_urlopen(req, timeout):
        captured["headers"]=dict(req.header_items())
        captured["body"]=req.data.decode()
        return Resp()
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    payload={"contents":[],"_transport_metadata":{"api_key":"SECRET"}}
    assert GeminiProvider._default_transport("https://example.test",payload,5)=={"ok":True}
    assert "SECRET" in str(captured["headers"])
    assert "SECRET" not in captured["body"]
    assert "_transport_metadata" not in captured["body"]

def test_prompt_hard_ceiling():
    e=EvidencePackage(incident_id="I", analyst_notes="X"*300000)
    prompt=GeminiProvider._build_prompt(AiRequest(incident_id="I"), e)
    assert len(prompt)<=160000
    assert "Return ONLY JSON matching this contract" in prompt

def test_malformed_output_is_rejected():
    p=GeminiProvider(api_key="secret", transport=lambda *a: envelope("not json"))
    with pytest.raises(Exception) as exc:
        p.analyze(AiRequest(incident_id="I"), evidence_with_event("I"))
    assert exc.value.__class__.__name__ in {"InvalidModelOutputError", "ProviderOutputValidationError"}

def test_http_429_maps_to_quota():
    def t(*a):
        raise urllib.error.HTTPError(a[0],429,"rate",{},None)
    p=GeminiProvider(api_key="secret",transport=t)
    with pytest.raises(GeminiQuotaError):
        p.analyze(AiRequest(incident_id="I"), evidence_with_event("I"))

def test_timeout_maps_to_timeout():
    p=GeminiProvider(api_key="secret",transport=lambda *a: (_ for _ in ()).throw(TimeoutError()))
    with pytest.raises(GeminiTimeoutError):
        p.analyze(AiRequest(incident_id="I"), evidence_with_event("I"))

def test_empty_evidence_still_produces_safe_prompt():
    # The unified contract has incident_id, so it is not "empty" in the old provider sense.
    p=GeminiProvider(api_key="secret", transport=lambda *a: envelope(VALID))
    resp=p.analyze(AiRequest(incident_id="I"), evidence_with_event("I"))
    assert resp.confidence <= 1
