"""Compliance assertion helpers for use in pytest tests."""

from __future__ import annotations

from ancilis.engine.result import EvaluationResult
from ancilis.testing.scan_result import ScanResult


def _to_scan_result(target: ScanResult | EvaluationResult) -> ScanResult:
    if isinstance(target, EvaluationResult):
        return ScanResult.from_single(target)
    return target


def assert_control_passes(
    scan: ScanResult | EvaluationResult,
    control_id: str,
) -> None:
    """Assert that the given control passed.

    Raises AssertionError with detailed context if the control did not pass.

    Usage::

        assert_control_passes(ancilis_scan, "PR-01")
    """
    result = _to_scan_result(scan)
    cr = result.get_control_result(control_id)
    if cr is None:
        raise AssertionError(
            f"Control '{control_id}' was not evaluated. "
            f"Available controls: {_available_controls(result)}"
        )
    if cr.result != "PASS":
        raise AssertionError(
            f"Expected control '{control_id}' to PASS but got '{cr.result}'.\n"
            f"  Detail: {cr.detail}\n"
            f"  Evidence: {cr.evidence_data}"
        )


def assert_control_fails(
    scan: ScanResult | EvaluationResult,
    control_id: str,
) -> None:
    """Assert that the given control failed (result is FAIL or ERROR).

    Raises AssertionError with detailed context if the control did not fail.

    Usage::

        assert_control_fails(ancilis_scan, "PR-01")
    """
    result = _to_scan_result(scan)
    cr = result.get_control_result(control_id)
    if cr is None:
        raise AssertionError(
            f"Control '{control_id}' was not evaluated. "
            f"Available controls: {_available_controls(result)}"
        )
    if cr.result not in ("FAIL", "ERROR"):
        raise AssertionError(
            f"Expected control '{control_id}' to FAIL but got '{cr.result}'.\n"
            f"  Detail: {cr.detail}\n"
            f"  Evidence: {cr.evidence_data}"
        )


def assert_control_flags(
    scan: ScanResult | EvaluationResult,
    control_id: str,
) -> None:
    """Assert that the given control raised a FLAG.

    Usage::

        assert_control_flags(ancilis_scan, "DE-01")
    """
    result = _to_scan_result(scan)
    cr = result.get_control_result(control_id)
    if cr is None:
        raise AssertionError(
            f"Control '{control_id}' was not evaluated. "
            f"Available controls: {_available_controls(result)}"
        )
    if cr.result != "FLAG":
        raise AssertionError(
            f"Expected control '{control_id}' to FLAG but got '{cr.result}'.\n"
            f"  Detail: {cr.detail}\n"
            f"  Evidence: {cr.evidence_data}"
        )


def assert_posture_above(
    scan: ScanResult | EvaluationResult,
    threshold: float,
) -> None:
    """Assert that the overall posture score is above a threshold.

    Score is the pass rate across all scored controls (SKIP excluded).

    Args:
        scan: ScanResult or EvaluationResult to evaluate.
        threshold: Float in [0.0, 1.0]. For example, 0.80 means 80% pass rate.

    Usage::

        assert_posture_above(ancilis_scan, 0.80)
    """
    result = _to_scan_result(scan)
    score = result.score
    if score < threshold:
        raise AssertionError(
            f"Posture score {score:.2%} is below required threshold {threshold:.2%}.\n"
            f"  Failing controls: {_failing_controls(result)}"
        )


def assert_decision_allows(scan: ScanResult | EvaluationResult) -> None:
    """Assert that the most recent evaluation decision is ALLOW."""
    result = _to_scan_result(scan)
    decision = result.decision()
    if decision != "ALLOW":
        raise AssertionError(
            f"Expected decision ALLOW but got '{decision}'.\n"
            f"  Failing controls: {_failing_controls(result)}"
        )


def assert_decision_blocks(scan: ScanResult | EvaluationResult) -> None:
    """Assert that the most recent evaluation decision is BLOCK."""
    result = _to_scan_result(scan)
    decision = result.decision()
    if decision != "BLOCK":
        raise AssertionError(
            f"Expected decision BLOCK but got '{decision}'."
        )


# --- Internal helpers ---

def _available_controls(result: ScanResult) -> list[str]:
    if not result.evaluations:
        return []
    return [cr.control_id for cr in result.evaluations[-1].control_results]


def _failing_controls(result: ScanResult) -> list[str]:
    failing = []
    for ev in result.evaluations:
        for cr in ev.control_results:
            if cr.result in ("FAIL", "ERROR", "FLAG"):
                failing.append(f"{cr.control_id}={cr.result}: {cr.detail}")
    return failing
