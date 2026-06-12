"""ComplianceScenarios — pre-built test datasets for common compliance states."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.testing.scan_result import ScanResult


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_evaluation(
    control_results: list[ControlResult],
    agent_id: str = "test-agent",
    mode: str = "audit",
    tool_name: str = "test_tool",
    active_overlays: list[str] | None = None,
    data_classifications: list[str] | None = None,
) -> EvaluationResult:
    has_failure = any(cr.result in ("FAIL", "ERROR") for cr in control_results)
    decision = "ALLOW"
    if mode == "enforce" and has_failure:
        decision = "BLOCK"

    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        action_id=str(uuid.uuid4()),
        timestamp=_now(),
        agent_id=agent_id,
        mode=mode,
        control_results=control_results,
        decision=decision,
        decision_reason="Pre-built test scenario",
        active_overlays=active_overlays or [],
        data_classifications=data_classifications or [],
        total_duration_ms=0.0,
    )


class ComplianceScenarios:
    """Factory for pre-built compliance test scenarios.

    All scenarios work fully offline — no platform API, no DuckDB file.

    Usage::

        from ancilis.testing import ComplianceScenarios

        scenario = ComplianceScenarios.financial_compliant()
        assert scenario.score == 1.0

        scenario = ComplianceScenarios.missing_identity()
        assert scenario.score < 1.0
    """

    @staticmethod
    def financial_compliant() -> ScanResult:
        """All controls passing for a financial services overlay context.

        Simulates a well-configured agent with identity, scope, provenance,
        and exposure controls all PASS. Active overlays: financial.
        """
        results = [
            ControlResult(
                control_id="PR-01",
                control_name="Action Authorization",
                result="PASS",
                detail="Action authorized for the configured agent.",
                evidence_data={"agent_id": "test-agent", "verification_result": "verified"},
            ),
            ControlResult(
                control_id="PR-02",
                control_name="Scope & Boundary Enforcement",
                result="PASS",
                detail="Tool is allowed. Rate limit: 0/60 actions per minute.",
                evidence_data={"tool_name": "test_tool", "rate_limit_ok": True},
            ),
            ControlResult(
                control_id="PR-03",
                control_name="Tool Provenance Verification",
                result="PASS",
                detail="Tool registered and approved.",
                evidence_data={"tool_name": "test_tool", "approved": True},
            ),
            ControlResult(
                control_id="PR-04",
                control_name="Data Exposure Prevention",
                result="PASS",
                detail="No sensitive data patterns detected.",
                evidence_data={"patterns_detected": []},
            ),
            ControlResult(
                control_id="PR-05",
                control_name="Audit Trail Completeness",
                result="PASS",
                detail="Audit trail complete.",
                evidence_data={},
            ),
            ControlResult(
                control_id="DE-01",
                control_name="Baseline Behavior Detection",
                result="PASS",
                detail="No anomalous baseline drift detected.",
                evidence_data={},
            ),
        ]
        ev = _make_evaluation(
            results,
            active_overlays=["financial"],
            data_classifications=["DC-03", "DC-07"],
        )
        return ScanResult([ev])

    @staticmethod
    def missing_identity() -> ScanResult:
        """PR-01 fails — agent identity is missing.

        Simulates an agent that forgot to configure its name, or is calling
        from an unrecognized agent_id. All other controls pass.
        """
        results = [
            ControlResult(
                control_id="PR-01",
                control_name="Action Authorization",
                result="FAIL",
                detail="Agent identity missing.",
                evidence_data={
                    "agent_id": None,
                    "verification_result": "failed",
                    "failure_reason": "agent_id is empty or missing",
                },
            ),
            ControlResult(
                control_id="PR-02",
                control_name="Scope & Boundary Enforcement",
                result="PASS",
                detail="Tool is allowed.",
                evidence_data={"tool_name": "test_tool"},
            ),
            ControlResult(
                control_id="PR-03",
                control_name="Tool Provenance Verification",
                result="PASS",
                detail="Tool registered.",
                evidence_data={"tool_name": "test_tool"},
            ),
            ControlResult(
                control_id="PR-04",
                control_name="Data Exposure Prevention",
                result="PASS",
                detail="No sensitive data patterns detected.",
                evidence_data={"patterns_detected": []},
            ),
            ControlResult(
                control_id="PR-05",
                control_name="Audit Trail Completeness",
                result="PASS",
                detail="Audit trail complete.",
                evidence_data={},
            ),
            ControlResult(
                control_id="DE-01",
                control_name="Baseline Behavior Detection",
                result="PASS",
                detail="No anomalous baseline drift detected.",
                evidence_data={},
            ),
        ]
        ev = _make_evaluation(results)
        return ScanResult([ev])

    @staticmethod
    def minimal_viable() -> ScanResult:
        """Bare minimum passing scenario — only PR-01 scored, rest skipped.

        Useful for testing that your agent at least provides identity
        before adding other controls.
        """
        results = [
            ControlResult(
                control_id="PR-01",
                control_name="Action Authorization",
                result="PASS",
                detail="Action authorized for the configured agent.",
                evidence_data={"agent_id": "test-agent", "verification_result": "verified"},
            ),
            ControlResult(
                control_id="PR-02",
                control_name="Scope & Boundary Enforcement",
                result="SKIP",
                detail="Control is disabled.",
                evidence_data={},
            ),
            ControlResult(
                control_id="PR-03",
                control_name="Tool Provenance Verification",
                result="SKIP",
                detail="Control is disabled.",
                evidence_data={},
            ),
            ControlResult(
                control_id="PR-04",
                control_name="Data Exposure Prevention",
                result="SKIP",
                detail="Control is disabled.",
                evidence_data={},
            ),
            ControlResult(
                control_id="PR-05",
                control_name="Audit Trail Completeness",
                result="SKIP",
                detail="Control is disabled.",
                evidence_data={},
            ),
            ControlResult(
                control_id="DE-01",
                control_name="Baseline Behavior Detection",
                result="SKIP",
                detail="Control is disabled.",
                evidence_data={},
            ),
        ]
        ev = _make_evaluation(results)
        return ScanResult([ev])

    @staticmethod
    def all_failing() -> ScanResult:
        """All controls failing — useful for testing assertion error messages."""
        results = [
            ControlResult(
                control_id="PR-01",
                control_name="Action Authorization",
                result="FAIL",
                detail="Agent identity missing.",
                evidence_data={"failure_reason": "agent_id is empty or missing"},
            ),
            ControlResult(
                control_id="PR-02",
                control_name="Scope & Boundary Enforcement",
                result="FAIL",
                detail="Tool is blocked.",
                evidence_data={"tool_name": "blocked_tool"},
            ),
            ControlResult(
                control_id="PR-03",
                control_name="Tool Provenance Verification",
                result="FAIL",
                detail="Tool not registered.",
                evidence_data={"tool_name": "unknown_tool"},
            ),
            ControlResult(
                control_id="PR-04",
                control_name="Data Exposure Prevention",
                result="FLAG",
                detail="Sensitive data patterns detected.",
                evidence_data={"patterns_detected": [{"type": "pii", "count": 2}]},
            ),
            ControlResult(
                control_id="PR-05",
                control_name="Audit Trail Completeness",
                result="FAIL",
                detail="Missing required audit fields.",
                evidence_data={},
            ),
            ControlResult(
                control_id="DE-01",
                control_name="Baseline Behavior Detection",
                result="FLAG",
                detail="Anomalous behavior detected.",
                evidence_data={},
            ),
        ]
        ev = _make_evaluation(results)
        return ScanResult([ev])
