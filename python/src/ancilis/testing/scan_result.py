"""ScanResult — wrapper around evaluation results for assertion helpers."""

from __future__ import annotations

from ancilis.engine.result import ControlResult, EvaluationResult

_SCORED_RESULTS = {"PASS", "FAIL", "FLAG", "ERROR"}


class ScanResult:
    """Wraps one or more EvaluationResult objects with computed posture score.

    Returned by the ``ancilis_scan`` pytest fixture and by
    ``ComplianceScenarios`` factory methods. Can be passed directly to
    compliance assertion helpers.

    Attributes:
        evaluations: The underlying EvaluationResult list.
        score: Pass rate in [0.0, 1.0] across all scored controls.
    """

    def __init__(self, evaluations: list[EvaluationResult]) -> None:
        if not evaluations:
            raise ValueError("ScanResult requires at least one EvaluationResult")
        self.evaluations = evaluations

    @classmethod
    def from_single(cls, evaluation: EvaluationResult) -> ScanResult:
        return cls([evaluation])

    @property
    def score(self) -> float:
        """Pass rate across all scored controls in all evaluations.

        SKIP results are excluded from the denominator.
        """
        pass_count = 0
        total = 0
        for ev in self.evaluations:
            for cr in ev.control_results:
                if cr.result in _SCORED_RESULTS:
                    total += 1
                    if cr.result == "PASS":
                        pass_count += 1
        return pass_count / total if total > 0 else 1.0

    def get_control_result(self, control_id: str) -> ControlResult | None:
        """Return the ControlResult for the given control_id (latest evaluation)."""
        for ev in reversed(self.evaluations):
            for cr in ev.control_results:
                if cr.control_id == control_id:
                    return cr
        return None

    def decision(self) -> str:
        """Decision from the most recent evaluation."""
        return self.evaluations[-1].decision

    def __repr__(self) -> str:
        return (
            f"ScanResult(evaluations={len(self.evaluations)}, "
            f"score={self.score:.2f}, decision={self.decision()!r})"
        )
