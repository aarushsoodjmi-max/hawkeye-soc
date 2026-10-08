"""
Training dataset capture — extension point only.

Pipeline (NOT built in this session):

    Incident/Analyst Feedback
        ↓
    Training Dataset   <- this module
        ↓
    Fine-tuning        <- training.trainer (interface stub)
        ↓
    Evaluation         <- evaluation.evaluator / benchmarks
        ↓
    Model Registry     <- training.registry (gate)
        ↓
    Validated Model Version

Runtime inference never imports this module: training code is deliberately
decoupled from the serving path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class FeedbackRecord:
    """One analyst verdict on a produced AI response."""

    incident_id: str
    verdict: str  # accepted | corrected | rejected
    corrections: Dict[str, Any] = field(default_factory=dict)
    accepted_response: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    recorded_at: str = field(default_factory=_now_iso)


class TrainingDataset:
    """In-memory collector of analyst feedback; can export JSONL."""

    def __init__(self) -> None:
        self._records: List[FeedbackRecord] = []

    def add(self, record: FeedbackRecord) -> None:
        if record.verdict not in ("accepted", "corrected", "rejected"):
            raise ValueError(f"unknown verdict {record.verdict!r}")
        self._records.append(record)

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[FeedbackRecord]:
        return iter(self._records)

    def to_jsonl(self) -> str:
        return "\n".join(
            json.dumps(r.__dict__, ensure_ascii=False, default=str)
            for r in self._records
        )
