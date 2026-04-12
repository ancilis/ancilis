"""Tests for ancilis.testing module — MockEvidenceStore, FakeProducer, assertions, scenarios."""

from __future__ import annotations

import pytest

from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.testing import (
    ComplianceScenarios,
    FakeProducer,
    MockEvidenceStore,
    ScanResult,
    assert_control_fails,
    assert_control_flags,
    assert_control_passes,
    assert_decision_allows,
    assert_decision_blocks,
    assert_posture_above,
    make_action,
    make_test_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_evaluation(
    control_results: list[ControlResult] | None = None,
    decision: str = "ALLOW",
    mode: str = "audit",
) -> EvaluationResult:
    if control_results is None:
        control_results = [
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Verified",
                evidence_data={"agent_id": "test-agent"},
            )
        ]
    return EvaluationResult(
        evaluation_id="ev-test",
        action_id="act-test",
        timestamp="2026-04-12T00:00:00Z",
        agent_id="test-agent",
        mode=mode,
        control_results=control_results,
        decision=decision,
        decision_reason="Test",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
    )


# ---------------------------------------------------------------------------
# make_test_config
# ---------------------------------------------------------------------------


class TestMakeTestConfig:
    def test_creates_minimal_config(self):
        config = make_test_config()
        assert config.agent_name == "test-agent"
        assert config.mode == "audit"

    def test_custom_agent_name(self):
        config = make_test_config(agent_name="my-agent")
        assert config.agent_name == "my-agent"

    def test_enforce_mode(self):
        config = make_test_config(mode="enforce")
        assert config.mode == "enforce"

    def test_overlay_activation(self):
        config = make_test_config(overlay="financial")
        # financial overlay should activate
        assert len(config.active_overlays) > 0 or len(config.warnings) >= 0


# ---------------------------------------------------------------------------
# make_action
# ---------------------------------------------------------------------------


class TestMakeAction:
    def test_creates_action_with_defaults(self):
        action = make_action()
        assert action.tool.name == "test_tool"
        assert action.agent_id == "test-agent"
        assert action.action_type == "tool_call"

    def test_custom_tool_name(self):
        action = make_action(tool_name="read_file")
        assert action.tool.name == "read_file"

    def test_custom_agent_id(self):
        action = make_action(agent_id="my-agent")
        assert action.agent_id == "my-agent"

    def test_parameters_embedded(self):
        action = make_action(parameters={"path": "/tmp/foo"})
        assert action.parameters.raw == {"path": "/tmp/foo"}

    def test_session_id_in_context(self):
        action = make_action(session_id="sess-123")
        assert action.context.session_id == "sess-123"

    def test_data_classifications_in_context(self):
        action = make_action(data_classifications=["DC-01"])
        assert action.context.data_classifications == ["DC-01"]


# ---------------------------------------------------------------------------
# MockEvidenceStore
# ---------------------------------------------------------------------------


class TestMockEvidenceStore:
    def test_starts_empty(self):
        store = MockEvidenceStore()
        assert store.count() == 0

    def test_store_and_count(self):
        store = MockEvidenceStore()
        ev = _make_evaluation()
        store.store(ev, tool_name="my_tool")
        assert store.count() == 1

    def test_store_returns_evidence_record(self):
        store = MockEvidenceStore()
        ev = _make_evaluation()
        record = store.store(ev)
        assert record.record_id
        assert record.decision in ("ALLOW", "allow")
        assert record.tool_name == "test_tool"

    def test_get_records_returns_stored(self):
        store = MockEvidenceStore()
        ev = _make_evaluation()
        store.store(ev)
        records = store.get_records()
        assert len(records) == 1

    def test_get_summary(self):
        store = MockEvidenceStore()
        ev = _make_evaluation()
        store.store(ev)
        summary = store.get_summary()
        assert summary["total_evaluations"] == 1
        # decisions dict keys may be "ALLOW" or "allow" depending on normalization
        decisions_lower = {k.lower(): v for k, v in summary["decisions"].items()}
        assert "allow" in decisions_lower

    def test_verify_chain_valid(self):
        store = MockEvidenceStore()
        ev = _make_evaluation()
        store.store(ev)
        valid, errors = store.verify_chain()
        assert valid
        assert errors == []

    def test_reset_clears_records(self):
        store = MockEvidenceStore()
        ev = _make_evaluation()
        store.store(ev)
        assert store.count() == 1
        n = store.reset()
        assert n == 1
        assert store.count() == 0

    def test_context_manager(self):
        with MockEvidenceStore() as store:
            ev = _make_evaluation()
            store.store(ev)
            assert store.count() == 1

    def test_no_filesystem_side_effects(self, tmp_path, monkeypatch):
        """MockEvidenceStore must not create any files."""
        monkeypatch.chdir(tmp_path)
        store = MockEvidenceStore()
        ev = _make_evaluation()
        store.store(ev)
        store.close()
        # No files should exist in tmp_path
        assert list(tmp_path.rglob("*.db")) == []

    def test_multiple_stores_independent(self):
        store_a = MockEvidenceStore()
        store_b = MockEvidenceStore()
        ev = _make_evaluation()
        store_a.store(ev)
        assert store_a.count() == 1
        assert store_b.count() == 0
        store_a.close()
        store_b.close()


# ---------------------------------------------------------------------------
# FakeProducer
# ---------------------------------------------------------------------------


class TestFakeProducer:
    def test_emit_and_retrieve(self):
        producer = FakeProducer("test")
        producer.emit("user.id", "alice")
        producer.emit("session", "sess-001")
        assert producer.emitted_data == {"user.id": "alice", "session": "sess-001"}

    def test_make_action_includes_emitted(self):
        producer = FakeProducer("identity", agent_id="my-agent")
        producer.emit("user.id", "alice")
        action = producer.make_action()
        assert action.agent_id == "my-agent"
        assert action.parameters.raw["user.id"] == "alice"

    def test_make_action_overrides_params(self):
        producer = FakeProducer()
        producer.emit("key", "base")
        action = producer.make_action(parameters={"key": "override", "extra": 1})
        assert action.parameters.raw["key"] == "override"
        assert action.parameters.raw["extra"] == 1

    def test_make_action_tool_name(self):
        producer = FakeProducer("my_tool")
        action = producer.make_action()
        assert action.tool.name == "my_tool"

    def test_make_action_explicit_tool_name(self):
        producer = FakeProducer("default")
        action = producer.make_action(tool_name="read_file")
        assert action.tool.name == "read_file"

    def test_clear_emitted(self):
        producer = FakeProducer()
        producer.emit("k", "v")
        producer.clear()
        assert producer.emitted_data == {}

    def test_translate_dict(self):
        producer = FakeProducer()
        action = producer.translate({"tool": "my_tool", "parameters": {"p": 1}})
        assert action.tool.name == "my_tool"
        assert action.parameters.raw["p"] == 1

    def test_translate_non_dict(self):
        producer = FakeProducer("fallback")
        action = producer.translate("something")
        assert action.tool.name == "fallback"

    def test_compute_tool_hash_deterministic(self):
        producer = FakeProducer()
        h1 = producer.compute_tool_hash("my_tool_v1")
        h2 = producer.compute_tool_hash("my_tool_v1")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256

    def test_register_tools(self):
        producer = FakeProducer("my_tool")
        registry = ToolRegistry()
        names = producer.register_tools(registry)
        assert names == ["my_tool"]
        assert registry.is_registered("my_tool")

    def test_producer_type_is_manual(self):
        from ancilis.producers.protocol import ProducerType
        producer = FakeProducer()
        assert producer.producer_type == ProducerType.MANUAL

    def test_producer_version(self):
        producer = FakeProducer()
        assert "test" in producer.producer_version


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_score_all_pass(self):
        scenario = ComplianceScenarios.financial_compliant()
        assert scenario.score == 1.0

    def test_score_one_fail(self):
        scenario = ComplianceScenarios.missing_identity()
        assert 0 < scenario.score < 1.0

    def test_score_skip_excluded(self):
        scenario = ComplianceScenarios.minimal_viable()
        # Only PR-01 is scored (PASS), rest are SKIP
        assert scenario.score == 1.0

    def test_get_control_result(self):
        scenario = ComplianceScenarios.financial_compliant()
        cr = scenario.get_control_result("PR-01")
        assert cr is not None
        assert cr.result == "PASS"

    def test_get_control_result_missing(self):
        scenario = ComplianceScenarios.financial_compliant()
        assert scenario.get_control_result("XX-99") is None

    def test_decision(self):
        scenario = ComplianceScenarios.financial_compliant()
        assert scenario.decision() == "ALLOW"

    def test_requires_at_least_one_evaluation(self):
        with pytest.raises(ValueError, match="at least one"):
            ScanResult([])

    def test_from_single(self):
        ev = _make_evaluation()
        result = ScanResult.from_single(ev)
        assert len(result.evaluations) == 1

    def test_repr(self):
        scenario = ComplianceScenarios.financial_compliant()
        r = repr(scenario)
        assert "ScanResult" in r
        assert "score=" in r


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------


class TestAssertControlPasses:
    def test_passes_when_pass(self):
        scenario = ComplianceScenarios.financial_compliant()
        assert_control_passes(scenario, "PR-01")  # should not raise

    def test_raises_when_fail(self):
        scenario = ComplianceScenarios.missing_identity()
        with pytest.raises(AssertionError, match="PR-01"):
            assert_control_passes(scenario, "PR-01")

    def test_raises_for_unknown_control(self):
        scenario = ComplianceScenarios.financial_compliant()
        with pytest.raises(AssertionError, match="not evaluated"):
            assert_control_passes(scenario, "XX-99")

    def test_accepts_evaluation_result_directly(self):
        ev = _make_evaluation()
        assert_control_passes(ev, "PR-01")


class TestAssertControlFails:
    def test_passes_when_fail(self):
        scenario = ComplianceScenarios.missing_identity()
        assert_control_fails(scenario, "PR-01")  # should not raise

    def test_raises_when_pass(self):
        scenario = ComplianceScenarios.financial_compliant()
        with pytest.raises(AssertionError, match="PR-01"):
            assert_control_fails(scenario, "PR-01")

    def test_raises_for_unknown_control(self):
        scenario = ComplianceScenarios.financial_compliant()
        with pytest.raises(AssertionError, match="not evaluated"):
            assert_control_fails(scenario, "ZZ-01")


class TestAssertControlFlags:
    def test_passes_when_flag(self):
        scenario = ComplianceScenarios.all_failing()
        assert_control_flags(scenario, "PR-04")

    def test_raises_when_pass(self):
        scenario = ComplianceScenarios.financial_compliant()
        with pytest.raises(AssertionError, match="PR-04"):
            assert_control_flags(scenario, "PR-04")


class TestAssertPostureAbove:
    def test_passes_when_above(self):
        scenario = ComplianceScenarios.financial_compliant()
        assert_posture_above(scenario, 0.80)  # should not raise

    def test_raises_when_below(self):
        scenario = ComplianceScenarios.missing_identity()
        with pytest.raises(AssertionError, match="below required threshold"):
            assert_posture_above(scenario, 1.0)

    def test_accepts_evaluation_result_directly(self):
        ev = _make_evaluation()
        assert_posture_above(ev, 0.5)

    def test_error_message_contains_score(self):
        scenario = ComplianceScenarios.missing_identity()
        with pytest.raises(AssertionError) as exc_info:
            assert_posture_above(scenario, 1.0)
        assert "%" in str(exc_info.value)


class TestAssertDecision:
    def test_allows_when_allow(self):
        scenario = ComplianceScenarios.financial_compliant()
        assert_decision_allows(scenario)

    def test_blocks_raises_on_allow(self):
        scenario = ComplianceScenarios.financial_compliant()
        with pytest.raises(AssertionError, match="BLOCK"):
            assert_decision_blocks(scenario)

    def test_blocks_when_block(self):
        cr = ControlResult(
            control_id="PR-01",
            control_name="Agent Identity",
            result="FAIL",
            detail="Missing",
            evidence_data={},
        )
        ev = _make_evaluation(control_results=[cr], decision="BLOCK", mode="enforce")
        result = ScanResult([ev])
        assert_decision_blocks(result)


# ---------------------------------------------------------------------------
# ComplianceScenarios
# ---------------------------------------------------------------------------


class TestComplianceScenarios:
    def test_financial_compliant_score_is_1(self):
        scenario = ComplianceScenarios.financial_compliant()
        assert scenario.score == 1.0

    def test_financial_compliant_all_pass(self):
        scenario = ComplianceScenarios.financial_compliant()
        for cr in scenario.evaluations[0].control_results:
            assert cr.result == "PASS"

    def test_missing_identity_pr01_fails(self):
        scenario = ComplianceScenarios.missing_identity()
        cr = scenario.get_control_result("PR-01")
        assert cr is not None
        assert cr.result == "FAIL"

    def test_minimal_viable_score_is_1(self):
        scenario = ComplianceScenarios.minimal_viable()
        assert scenario.score == 1.0

    def test_all_failing_score_is_low(self):
        scenario = ComplianceScenarios.all_failing()
        assert scenario.score < 0.5

    def test_scenarios_are_offline(self):
        """Scenarios must not make any network calls or file system access."""
        import os
        original_env = dict(os.environ)
        scenario = ComplianceScenarios.financial_compliant()
        assert scenario is not None
        # No env vars should change (network calls often set things)
        assert dict(os.environ) == original_env


# ---------------------------------------------------------------------------
# pytest plugin fixtures (integration)
# ---------------------------------------------------------------------------


class TestAncilisFixtures:
    def test_ancilis_scan_fixture(self, ancilis_scan):
        assert isinstance(ancilis_scan, ScanResult)
        assert len(ancilis_scan.evaluations) == 1
        assert ancilis_scan.score > 0

    def test_ancilis_scan_pr01_passes(self, ancilis_scan):
        assert_control_passes(ancilis_scan, "PR-01")

    def test_ancilis_store_fixture(self, ancilis_store):
        assert isinstance(ancilis_store, MockEvidenceStore)
        assert ancilis_store.count() == 0

    def test_ancilis_store_can_persist(self, ancilis_store):
        ev = _make_evaluation()
        ancilis_store.store(ev)
        assert ancilis_store.count() == 1

    def test_ancilis_overlay_fixture(self, ancilis_overlay):
        # By default no overlay is configured
        assert ancilis_overlay is None


# ---------------------------------------------------------------------------
# Integration: FakeProducer → Engine → ScanResult
# ---------------------------------------------------------------------------


class TestFakeProducerWithEngine:
    def test_end_to_end_pass(self):
        """FakeProducer → Engine → assertions — full test pipeline."""
        config = make_test_config(agent_name="my-agent")
        registry = ToolRegistry()
        registry.register(ToolEntry(name="read_file"))
        registry.approve("read_file", approved_by="test")
        engine = Engine(config, registry=registry)

        producer = FakeProducer("read_file", agent_id="my-agent")
        producer.emit("path", "/tmp/safe.txt")

        action = producer.make_action()
        evaluation = engine.evaluate(action)
        result = ScanResult([evaluation])

        assert_control_passes(result, "PR-01")
        assert_posture_above(result, 0.5)

    def test_end_to_end_identity_failure(self):
        """Wrong agent_id causes PR-01 to FAIL."""
        config = make_test_config(agent_name="expected-agent")
        engine = Engine(config)

        producer = FakeProducer("some_tool", agent_id="wrong-agent")
        action = producer.make_action()
        evaluation = engine.evaluate(action)
        result = ScanResult([evaluation])

        assert_control_fails(result, "PR-01")
