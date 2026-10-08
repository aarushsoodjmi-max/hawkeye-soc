"""
Fine-tuning pipeline interface — awareness stub, NOT implemented.

This session deliberately does not build the training pipeline. The
interface below is the extension point a future session wires to a real
fine-tuning backend. Runtime inference never imports this module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .dataset import TrainingDataset
from .registry import ModelVersion


class FineTuningTrainer(ABC):
    """Contract for future fine-tuning implementations."""

    @abstractmethod
    def train(self, dataset: TrainingDataset) -> ModelVersion:
        """Produce a candidate ModelVersion from a TrainingDataset.

        Training must be routed through evaluation (evaluation.evaluator /
        evaluation.benchmarks) before a version may be marked validated in
        the ModelRegistry. Runtime inference must not be coupled to this path.
        """
        raise NotImplementedError(
            "Fine-tuning is not implemented in the Local AI foundation session. "
            "Implement FineTuningTrainer.train to enable future training readiness."
        )


class UnavailableFineTuningTrainer(FineTuningTrainer):
    """Placeholder that fails loudly until a real trainer is wired."""

    def train(self, dataset: TrainingDataset) -> ModelVersion:
        raise NotImplementedError(
            "No fine-tuning trainer is configured; training is not available in "
            "the Local AI foundation."
        )
