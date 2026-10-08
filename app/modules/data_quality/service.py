from __future__ import annotations

from typing import Any, Dict, Iterable, List

REQUIRED_FIELDS = (
    "id",
    "title",
    "severity",
    "host",
    "user",
    "timestamp",
    "source",
    "sourceIp",
)


def _score_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    missing = [field for field in REQUIRED_FIELDS if not alert.get(field)]
    present_ratio = 1.0 - (len(missing) / len(REQUIRED_FIELDS))
    confidence = float(alert.get("confidenceScore") or 0.0) / 100.0
    score = max(0.0, min(1.0, round((present_ratio * 0.7) + (min(confidence, 1.0) * 0.3), 4)))
    quality = {
        "score": score,
        "status": "PASS" if score >= 0.75 else "REVIEW",
        "missing_fields": missing,
    }
    metadata = dict(alert.get("metadata") or {})
    metadata["data_quality"] = quality
    enriched = dict(alert)
    enriched["metadata"] = metadata
    return enriched


def assess_normalized_alerts(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_score_alert(dict(alert)) for alert in (alerts or [])]
