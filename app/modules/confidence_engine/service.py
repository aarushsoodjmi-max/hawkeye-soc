"""Explainable unified confidence composition for Hawkeye Decision Intelligence."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional

DEFAULT_WEIGHTS = {"correlation": 0.25, "ml": 0.25, "threat_intel": 0.20, "data_quality": 0.20, "evidence_completeness": 0.10}

def _get(o,k,d=None): return o.get(k,d) if isinstance(o,dict) else getattr(o,k,d)
def _clamp(v): return max(0.0, min(1.0, float(v or 0.0)))

def compute_confidence(incident: Any, inputs: Optional[Dict[str, float]] = None, weights: Optional[Dict[str,float]] = None) -> Dict[str, Any]:
    timeline = _get(incident, "timelineEvents", []) or []
    root = _get(incident, "rootCause", None)
    events = len(timeline)
    required = 0; present = 0
    for e in timeline:
        for field in ("timestamp", "technique", "source", "target", "severity"):
            required += 1; present += bool(_get(e, field, None))
    evidence = 0.0 if required == 0 else present / required
    avg_evidence = sum(float(_get(e, "evidenceConfidence", 0) or 0) for e in timeline) / max(1, events) / 100.0
    evidence = round((evidence + avg_evidence) / 2, 4)
    dq = 0.9 if events else 0.35
    # Data quality can be supplied by a future Data Quality module without changing this contract.
    source_counts = len({str(_get(e, "source", "")).lower() for e in timeline if _get(e, "source")})
    dq = min(1.0, dq + 0.03 * max(0, source_counts - 1))
    correlation = min(1.0, max(0.0, avg_evidence * 0.7 + (0.2 if len(_get(incident, "affectedAssets", []) or []) > 1 else 0.0)))
    ml = _clamp(_get(root, "confidence", 0.0) if root else 0.0)
    ti = 0.0
    if root and (_get(root, "cveId") or _get(root, "c2Server")): ti = 0.75
    values = {"correlation": correlation, "ml": ml, "threat_intel": ti, "data_quality": dq, "evidence_completeness": evidence}
    if inputs: values.update({k: _clamp(v) for k,v in inputs.items() if k in DEFAULT_WEIGHTS})
    w = dict(DEFAULT_WEIGHTS); w.update(weights or {})
    total_weight = sum(w.values()) or 1.0
    unified = sum(values[k] * w[k] for k in w) / total_weight
    partial = any(k not in (inputs or {}) and values[k] == 0.0 for k in ("ml", "threat_intel"))
    return {"subject_type": "incident", "subject_id": str(_get(incident,"id",_get(incident,"incident_id",""))), "correlation_confidence": round(values["correlation"],4), "ml_confidence": round(values["ml"],4), "threat_intel_confidence": round(values["threat_intel"],4), "data_quality_score": round(values["data_quality"],4), "evidence_completeness_score": round(values["evidence_completeness"],4), "unified_confidence": round(unified,4), "unified_confidence_percent": round(unified*100,2), "confidence_partial": partial, "weights": w, "breakdown": {k:{"value":round(values[k],4),"weight":w[k],"contribution":round(values[k]*w[k],4)} for k in w}, "computed_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
