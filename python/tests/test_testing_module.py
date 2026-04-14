"""Tests for ancilis.testing module — ScanResult, ComplianceScenarios, assertions, FakeProducer."""
from __future__ import annotations

import pytest

from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.testing import (
    ComplianceScenarios,
    FakeProducer,
)
from ancilis.testing.mock_store import MockEvidenceStore
from ancilis.testing.assertions import (
    assert_control_fails,
    assert_control_flags,
    assert_control_passes,
    assert_decision_allows,
    assert_decision_blocks,
    assert_posture_above,
)
from ancilis.testing.scan_result import ScanResult


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


def _make_cr(control_id: str, result: str) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        control_name=f"Control {control_id}",
        result=result,
        detail=f"Detail for {control_id}",
        evidence_data={},
    )


def _make_eval(crs: list[ControlResult], mode: str = "audit", decision: str = "ALLOW") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id="eval-1",
        action_id="action-1",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="test-agent",
        mode=mode,
        control_results=crs,
        decision=decision,
        decision_reason="test",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=0.0,
    )


def test_scan_result_requires_at_least_one_evaluation() -> None:
    with pytest.raises(ValueError, match="at least one"):
        ScanResult([])


def test_scan_result_from_single() -> None:
    ev = _make_eval([_make_cr("PR-01", "PASS")])
    sr = ScanResult.from_single(ev)
    assert len(sr.evaluations) == 1


def test_scan_result_score_all_pass() -> None:
    crs = [_make_cr(f"PR-0{i}", "PASS") for i in range(1, 4)]
    sr = ScanResult([_make_eval(crs)])
    assert sr.score == 1.0


def test_scan_result_score_with_failures() -> None:
    crs = [_make_cr("PR-01", "PASS"), _make_cr("PR-02", "FAIL"), _make_cr("PR-03", "PASS")]
    sr = ScanResult([_make_eval(crs)])
    assert sr.score == pytest.approx(2 / 3)


def test_scan_result_score_skips_excluded() -> None:
    crs = [_make_cr("PR-01", "PASS"), _make_cr("PR-02", "SKIP")]
    sr = ScanResult([_make_eval(crs)])
    assert sr.score == 1.0  # SKIP not in denominator


def test_scan_result_score_all_skip_returns_one() -> None:
    sr = ScanResult([_make_eval([_make_cr("PR-01", "SKIP")])])
    assert sr.score == 1.0


def test_scan_result_get_control_result_found() -> None:
    crs = [_make_cr("PR-01", "PASS"), _make_cr("PR-02", "FAIL")]
    sr = ScanResult([_make_eval(crs)])
    cr = sr.get_control_result("PR-02")
    assert cr is not None
    assert cr.result == "FAIL"


def test_scan_result_get_control_result_not_found() -> None:
    sr = ScanResult([_make_eval([_make_cr("PR-01", "PASS")])])
    assert sr.get_control_result("PR-99") is None


def test_scan_result_get_control_result_latest_wins() -> None:
    ev1 = _make_eval([_make_cr("PR-01", "FAIL")])
    ev2 = _make_eval([_make_cr("PR-01", "PASS")])
    sr = ScanResult([ev1, ev2])
    cr = sr.get_control_result("PR-01")
    assert cr is not None
    assert cr.result == "PASS"


def test_scan_result_decision() -> None:
    sr = ScanResult([_make_eval([_make_cr("PR-01", "PASS")], decision="BLOCK")])
    assert sr.decision() == "BLOCK"


def test_scan_result_repr() -> None:
    sr = ScanResult([_make_eval([_make_cr("PR-01", "PASS")])])
    r = repr(sr)
    assert "ScanResult" in r
    assert "score=" in r


# ---------------------------------------------------------------------------
# ComplianceScenarios
# ---------------------------------------------------------------------------


def test_compliance_scenarios_financial_compliant() -> None:
    sr = ComplianceScenarios.financial_compliant()
    assert sr.score == 1.0
    assert "financial" in sr.evaluations[0].active_overlays
    assert sr.decision() == "ALLOW"


def test_compliance_scenarios_missing_identity() -> None:
    sr = ComplianceScenarios.missing_identity()
    pr01 = sr.get_control_result("PR-01")
    assert pr01 is not None
    assert pr01.result == "FAIL"
    assert sr.score < 1.0


def test_compliance_scenarios_minimal_viable() -> None:
    sr = ComplianceScenarios.minimal_viable()
    pr01 = sr.get_control_result("PR-01")
    assert pr01 is not None
    assert pr01.result == "PASS"
    pr02 = sr.get_control_result("PR-02")
    assert pr02 is not None
    assert pr02.result == "SKIP"
    assert sr.score == 1.0  # Only PR-01 scored, it PASSes


def test_compliance_scenarios_all_failing() -> None:
    sr = ComplianceScenarios.all_failing()
    assert sr.score == 0.0


# ---------------------------------------------------------------------------
# Assertion helpers — happy paths
# ---------------------------------------------------------------------------


def test_assert_control_passes_happy() -> None:
    sr = ComplianceScenarios.financial_compliant()
    assert_control_passes(sr, "PR-01")  # should not raise


def test_assert_control_fails_happy() -> None:
    sr = ComplianceScenarios.missing_identity()
    assert_control_fails(sr, "PR-01")  # should not raise


def test_assert_control_flags_happy() -> None:
    sr = ComplianceScenarios.all_failing()
    assert_control_flags(sr, "PR-04")  # DE-01 is FLAG in all_failing scenario


def test_assert_posture_above_happy() -> None:
    sr = ComplianceScenarios.financial_compliant()
    assert_posture_above(sr, 0.80)  # should not raise


def test_assert_decision_allows_happy() -> None:
    sr = ComplianceScenarios.financial_compliant()
    assert_decision_allows(sr)  # should not raise


def test_assert_decision_blocks_happy() -> None:
    crs = [_make_cr("PR-01", "FAIL")]
    sr = ScanResult([_make_eval(crs, decision="BLOCK")])
    assert_decision_blocks(sr)  # should not raise


# ---------------------------------------------------------------------------
# Assertion helpers — accept EvaluationResult directly
# ---------------------------------------------------------------------------


def test_assert_control_passes_accepts_evaluation_result() -> None:
    ev = _make_eval([_make_cr("PR-01", "PASS")])
    assert_control_passes(ev, "PR-01")  # should not raise (converted via _to_scan_result)


# ---------------------------------------------------------------------------
# Assertion helpers — error paths
# ---------------------------------------------------------------------------


def test_assert_control_passes_raises_when_not_found() -> None:
    sr = ComplianceScenarios.financial_compliant()
    with pytest.raises(AssertionError, match="not evaluated"):
        assert_control_passes(sr, "PR-99")


def test_assert_control_passes_raises_when_fail() -> None:
    sr = ComplianceScenarios.missing_identity()
    with pytest.raises(AssertionError, match="PASS"):
        assert_control_passes(sr, "PR-01")


def test_assert_control_fails_raises_when_not_found() -> None:
    sr = ComplianceScenarios.financial_compliant()
    with pytest.raises(AssertionError, match="not evaluated"):
        assert_control_fails(sr, "PR-99")


def test_assert_control_fails_raises_when_passes() -> None:
    sr = ComplianceScenarios.financial_compliant()
    with pytest.raises(AssertionError, match="FAIL"):
        assert_control_fails(sr, "PR-01")


def test_assert_control_flags_raises_when_not_found() -> None:
    sr = ComplianceScenarios.financial_compliant()
    with pytest.raises(AssertionError, match="not evaluated"):
        assert_control_flags(sr, "PR-99")


def test_assert_control_flags_raises_when_not_flagged() -> None:
    sr = ComplianceScenarios.financial_compliant()
    with pytest.raises(AssertionError, match="FLAG"):
        assert_control_flags(sr, "PR-01")


def test_assert_posture_above_raises_when_below() -> None:
    sr = ComplianceScenarios.all_failing()
    with pytest.raises(AssertionError, match="below required threshold"):
        assert_posture_above(sr, 0.80)


def test_assert_decision_allows_raises_when_blocked() -> None:
    crs = [_make_cr("PR-01", "FAIL")]
    sr = ScanResult([_make_eval(crs, decision="BLOCK")])
    with pytest.raises(AssertionError, match="ALLOW"):
        assert_decision_allows(sr)


def test_assert_decision_blocks_raises_when_allowed() -> None:
    sr = ComplianceScenarios.financial_compliant()
    with pytest.raises(AssertionError, match="BLOCK"):
        assert_decision_blocks(sr)


# ---------------------------------------------------------------------------
# FakeProducer
# ---------------------------------------------------------------------------


def test_fake_producer_producer_type() -> None:
    from ancilis.producers.protocol import ProducerType
    fp = FakeProducer()
    assert fp.producer_type == ProducerType.MANUAL


def test_fake_producer_producer_version() -> None:
    fp = FakeProducer()
    assert fp.producer_version == "0.1.0-test"


def test_fake_producer_emit_and_emitted_data() -> None:
    fp = FakeProducer("test-producer", agent_id="agent-x")
    fp.emit("user.id", "alice")
    fp.emit("action", "read")
    assert fp.emitted_data == {"user.id": "alice", "action": "read"}


def test_fake_producer_clear() -> None:
    fp = FakeProducer()
    fp.emit("key", "val")
    fp.clear()
    assert fp.emitted_data == {}


def test_fake_producer_make_action_merges_emitted() -> None:
    fp = FakeProducer("my-tool", agent_id="agent-1")
    fp.emit("context", "important")
    action = fp.make_action(parameters={"extra": "param"})
    assert action.parameters.raw["context"] == "important"
    assert action.parameters.raw["extra"] == "param"


def test_fake_producer_make_action_uses_producer_name_as_tool() -> None:
    fp = FakeProducer("my-tool")
    action = fp.make_action()
    assert action.tool.name == "my-tool"


def test_fake_producer_translate_dict_invocation() -> None:
    fp = FakeProducer("base-tool")
    action = fp.translate({"tool": "override-tool", "parameters": {"x": 1}})
    assert action.tool.name == "override-tool"
    assert action.parameters.raw["x"] == 1


def test_fake_producer_translate_non_dict_invocation() -> None:
    fp = FakeProducer("fallback")
    action = fp.translate("not-a-dict")
    assert action.tool.name == "fallback"


def test_fake_producer_compute_tool_hash() -> None:
    fp = FakeProducer()
    h = fp.compute_tool_hash("my-tool")
    assert len(h) == 64  # SHA-256 hex digest


def test_fake_producer_register_tools() -> None:
    from ancilis.engine.registry import ToolRegistry
    fp = FakeProducer("registered-tool")
    registry = ToolRegistry()
    names = fp.register_tools(registry)
    assert names == ["registered-tool"]
    assert registry.is_registered("registered-tool")


# ---------------------------------------------------------------------------
# MockEvidenceStore — get_summary, verify_chain, reset, context manager
# ---------------------------------------------------------------------------


def _make_eval_for_store(decision: str = "ALLOW") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id="eval-mock",
        action_id="action-mock",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="mock-agent",
        mode="audit",
        control_results=[
            ControlResult("PR-01", "Agent Identity", "PASS", "ok", {}, 1.0)
        ],
        decision=decision,
        decision_reason="test",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
    )


def test_mock_store_get_summary() -> None:
    store = MockEvidenceStore()
    store.store(_make_eval_for_store("ALLOW"), tool_name="tool_a")
    store.store(_make_eval_for_store("ALLOW"), tool_name="tool_b")

    summary = store.get_summary()

    assert summary["total_evaluations"] == 2
    assert summary["decisions"]["ALLOW"] == 2
    store.close()


def test_mock_store_get_summary_with_since_filter() -> None:
    store = MockEvidenceStore()
    store.store(_make_eval_for_store("ALLOW"), tool_name="tool_a")

    summary = store.get_summary(since="2030-01-01T00:00:00Z")

    assert summary["total_evaluations"] == 0
    store.close()


def test_mock_store_verify_chain() -> None:
    store = MockEvidenceStore()
    store.store(_make_eval_for_store("ALLOW"), tool_name="tool_a")

    valid, errors = store.verify_chain()

    assert valid is True
    assert errors == []
    store.close()


def test_mock_store_reset() -> None:
    store = MockEvidenceStore()
    store.store(_make_eval_for_store("ALLOW"), tool_name="tool_a")
    store.store(_make_eval_for_store("BLOCK"), tool_name="tool_b")
    assert store.count() == 2

    deleted = store.reset()

    assert deleted == 2
    assert store.count() == 0
    store.close()


def test_mock_store_context_manager() -> None:
    with MockEvidenceStore() as store:
        store.store(_make_eval_for_store("ALLOW"), tool_name="tool_a")
        assert store.count() == 1
    # After __exit__, store is closed — no assertion needed, just no exception
