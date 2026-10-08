"""
Model registry — validated-version tracking (extension point only).

Registration and promotion are explicit operations; there is no automatic
production model replacement. A new backend model can be added without
changing the provider interface.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ModelVersion:
    version_id: str
    model_name: str
    path: Optional[str] = None
    evaluated_score: float = 0.0
    validated: bool = False
    created_at: str = field(default_factory=_now_iso)


class ModelRegistry:
    """Tracks candidate vs validated model versions. Promotion is explicit."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: Dict[str, ModelVersion] = {}

    def register(self, version: ModelVersion) -> None:
        with self._lock:
            self._versions[version.version_id] = version

    def mark_validated(self, version_id: str, score: float) -> Optional[ModelVersion]:
        with self._lock:
            existing = self._versions.get(version_id)
            if existing is None:
                return None
            updated = ModelVersion(
                version_id=existing.version_id,
                model_name=existing.model_name,
                path=existing.path,
                evaluated_score=round(score, 4),
                validated=True,
                created_at=existing.created_at,
            )
            self._versions[version_id] = updated
            return updated

    def get_validated(self) -> List[ModelVersion]:
        with self._lock:
            return [
                v
                for v in sorted(
                    self._versions.values(), key=lambda v: v.evaluated_score, reverse=True
                )
                if v.validated
            ]

    def select(self, version_id: Optional[str] = None) -> Optional[ModelVersion]:
        """Explicit selection only — never automatic replacement."""
        with self._lock:
            if version_id is not None:
                v = self._versions.get(version_id)
                return v if v is not None and v.validated else None
            validated = self.get_validated()
            return validated[0] if validated else None
