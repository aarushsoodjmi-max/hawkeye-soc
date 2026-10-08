from __future__ import annotations

from typing import Any, Dict, Iterable, List
import json

from app.config import settings

from app.modules.normalization.service import normalize_alert_batch
from app.modules.data_quality.service import assess_normalized_alerts


def validate_ingestion_limits(raw_alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items = list(raw_alerts or [])
    if len(items) > settings.MAX_BATCH_SIZE:
        raise ValueError(f"batch size exceeds MAX_BATCH_SIZE={settings.MAX_BATCH_SIZE}")
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"alert at index {idx} must be an object")
        title = item.get("title") or item.get("event_type") or item.get("alert_type") or "Security Alert"
        raw_log = item.get("rawLog", item.get("raw_log"))
        effective_raw_log = raw_log if raw_log is not None else f"Telemetry: {title}"
        if len(str(effective_raw_log)) > settings.MAX_RAW_LOG_CHARS:
            raise ValueError(f"alert {idx} rawLog exceeds MAX_RAW_LOG_CHARS={settings.MAX_RAW_LOG_CHARS}")
        description = item.get("description")
        effective_description = description if description is not None else title
        if len(str(effective_description)) > settings.MAX_DESCRIPTION_CHARS:
            raise ValueError(f"alert {idx} description exceeds MAX_DESCRIPTION_CHARS={settings.MAX_DESCRIPTION_CHARS}")
        metadata = item.get("metadata")
        if metadata is not None:
            try:
                size = len(json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"alert {idx} metadata is not serializable") from exc
            if size > settings.MAX_METADATA_BYTES:
                raise ValueError(f"alert {idx} metadata exceeds MAX_METADATA_BYTES={settings.MAX_METADATA_BYTES}")
    return items


def prepare_ingestion_batch(raw_alerts: Iterable[Dict[str, Any]], event_metadata: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    items = validate_ingestion_limits(raw_alerts)
    normalized = normalize_alert_batch(items, event_metadata=event_metadata)
    return assess_normalized_alerts(normalized)
