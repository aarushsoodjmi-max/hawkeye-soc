"""
Synthetic benchmark harness for AI providers.

Runs canned evidence cases through any AIProvider and reports schema
validation pass/fail. Unit-runnable with a faked inference backend; no real
model is required. Benchmark results can later gate promoted model versions
in ``training.registry``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..contracts.evidence import EvidencePackage
from ..contracts.requests import AiRequest
from ..providers.base import AIProvider
from .evaluator import EvaluationReport, evaluate_response


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    request: AiRequest
    evidence: EvidencePackage


@dataclass
class BenchmarkResult:
    provider: str
    total: int = 0
    passed: int = 0
    failures: List[dict] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return round(self.passed / max(1, self.total), 4)


def run_provider_benchmark(
    provider: AIProvider,
    cases: List[BenchmarkCase],
) -> BenchmarkResult:
    result = BenchmarkResult(provider=provider.name)
    for case in cases:
        result.total += 1
        try:
            response = provider.analyze(case.request, case.evidence)
            report: EvaluationReport = evaluate_response(response, case.evidence)
            if report.valid and report.score >= 0.6:
                result.passed += 1
            else:
                result.failures.append(
                    {"case": case.name, "score": report.score, "issues": report.issues}
                )
        except Exception as exc:  # noqa: BLE001 - benchmark captures any failure
            result.failures.append(
                {"case": case.name, "error": f"{type(exc).__name__}: {exc}"}
            )
    return result
