"""Tests for ancilis.engine — Unit 2: Control Engine Core."""

import uuid

import pytest

from ancilis.config import load_config
from ancilis.engine import (
    Action,
    ActionContext,
    ActionParameters,
    ControlResult,
    Engine,
    ToolEntry,
    ToolInfo,
    ToolRegistry,
)
from ancilis.engine.evaluators.pr02_scope import RateTracker
from ancilis.engine.registry import ToolStatus


def _make_action(
    agent_id: str = "test-agent",
    agent_owner: str | None = None,
    tool_name: str = "test-tool",
    tool_version: str | None = None,
    description_hash: str | None = None,
    params: dict | None = None,
    action_type: str = "tool_call",
) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp="2026-03-10T12:00:00Z",
        agent_id=agent_id,
        agent_owner=agent_owner,
        action_type=action_type,
        tool=ToolInfo(
            name=tool_name,
            version=tool_version,
            description_hash=description_hash,
        ),
        parameters=ActionParameters(
            raw=params or {},
            parameter_hash="abc123",
        ),
        context=ActionContext(),
    )


def _make_config(**overrides):
    raw = {"agent": {"name": "test-agent"}}
    raw.update(overrides)
    return load_config(raw=raw)


def _make_registry(*tools: tuple) -> ToolRegistry:
    """Create a registry with approved tool entries: (name, version, hash)."""
    reg = ToolRegistry()
    for t in tools:
        name = t[0]
        version = t[1] if len(t) > 1 else None
        desc_hash = t[2] if len(t) > 2 else None
        reg.register(ToolEntry(
            name=name, version=version, description_hash=desc_hash,
            status=ToolStatus.APPROVED,
        ))
    return reg


# --- Action Object Tests ---


class TestAction:
    def test_valid_action_all_fields(self):
        a = _make_action(agent_id="x", tool_name="y")
        assert a.agent_id == "x"
        assert a.tool.name == "y"

    def test_minimal_action(self):
        a = Action(
            action_id="1",
            timestamp="2026-01-01T00:00:00Z",
            agent_id="a",
            action_type="tool_call",
            tool=ToolInfo(name="t"),
            parameters=ActionParameters(raw={}, parameter_hash="h"),
        )
        assert a.agent_owner is None
        assert a.context.session_id is None

    def test_action_missing_agent_id(self):
        a = _make_action(agent_id="")
        assert a.agent_id == ""


# --- PR-01 Identity Tests ---


class TestPR01Identity:
    def test_matching_agent_id_passes(self):
        config = _make_config()
        action = _make_action(agent_id="test-agent")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr01 = next(r for r in result.control_results if r.control_id == "PR-01")
        assert pr01.result == "PASS"

    def test_missing_agent_id_fails(self):
        config = _make_config()
        action = _make_action(agent_id="")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr01 = next(r for r in result.control_results if r.control_id == "PR-01")
        assert pr01.result == "FAIL"

    def test_mismatched_agent_id_fails(self):
        config = _make_config()
        action = _make_action(agent_id="wrong-agent")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr01 = next(r for r in result.control_results if r.control_id == "PR-01")
        assert pr01.result == "FAIL"

    def test_matching_owner_passes(self):
        config = _make_config(agent={"name": "test-agent", "owner": "alice"})
        action = _make_action(agent_id="test-agent", agent_owner="alice")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr01 = next(r for r in result.control_results if r.control_id == "PR-01")
        assert pr01.result == "PASS"

    def test_mismatched_owner_fails(self):
        config = _make_config(agent={"name": "test-agent", "owner": "alice"})
        action = _make_action(agent_id="test-agent", agent_owner="bob")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr01 = next(r for r in result.control_results if r.control_id == "PR-01")
        assert pr01.result == "FAIL"


# --- PR-02 Scope Tests ---


class TestPR02Scope:
    def test_tool_in_allowed_list_passes(self):
        config = _make_config(security={"tools": {"allowed": ["test-tool"]}})
        action = _make_action()
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr02 = next(r for r in result.control_results if r.control_id == "PR-02")
        assert pr02.result == "PASS"

    def test_tool_not_in_allowed_list_fails(self):
        config = _make_config(security={"tools": {"allowed": ["other-tool"]}})
        action = _make_action()
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr02 = next(r for r in result.control_results if r.control_id == "PR-02")
        assert pr02.result == "FAIL"

    def test_tool_in_blocked_list_fails(self):
        config = _make_config(
            security={"tools": {"allowed": ["test-tool"], "blocked": ["test-tool"]}}
        )
        action = _make_action()
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr02 = next(r for r in result.control_results if r.control_id == "PR-02")
        assert pr02.result == "FAIL"

    def test_empty_allowed_list_permits_all(self):
        config = _make_config()
        action = _make_action(tool_name="any-tool")
        engine = Engine(config, registry=_make_registry(("any-tool",)))
        result = engine.evaluate(action)
        pr02 = next(r for r in result.control_results if r.control_id == "PR-02")
        assert pr02.result == "PASS"

    def test_blocked_destination_fails(self):
        config = _make_config(
            security={"scope": {"blocked_destinations": ["evil.com"]}}
        )
        action = _make_action(params={"url": "evil.com"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr02 = next(r for r in result.control_results if r.control_id == "PR-02")
        assert pr02.result == "FAIL"


# --- PR-03 Provenance Tests ---


class TestPR03Provenance:
    def test_registered_tool_matching_hash_passes(self):
        reg = _make_registry(("test-tool", "1.0", "hash123"))
        config = _make_config()
        action = _make_action(tool_version="1.0", description_hash="hash123")
        engine = Engine(config, registry=reg)
        result = engine.evaluate(action)
        pr03 = next(r for r in result.control_results if r.control_id == "PR-03")
        assert pr03.result == "PASS"

    def test_unregistered_tool_fails(self):
        reg = ToolRegistry()
        config = _make_config()
        action = _make_action(tool_name="unknown-tool")
        engine = Engine(config, registry=reg)
        result = engine.evaluate(action)
        pr03 = next(r for r in result.control_results if r.control_id == "PR-03")
        assert pr03.result == "FAIL"

    def test_hash_mismatch_fails(self):
        reg = _make_registry(("test-tool", "1.0", "hash123"))
        config = _make_config()
        action = _make_action(tool_version="1.0", description_hash="hash999")
        engine = Engine(config, registry=reg)
        result = engine.evaluate(action)
        pr03 = next(r for r in result.control_results if r.control_id == "PR-03")
        assert pr03.result == "FAIL"
        assert "tampering" in pr03.detail.lower()

    def test_no_hash_baseline_flags(self):
        """Approved tool with no description hash baseline returns FLAG, not PASS."""
        reg = _make_registry(("test-tool", "1.0"))
        config = _make_config()
        action = _make_action(tool_version="1.0")
        engine = Engine(config, registry=reg)
        result = engine.evaluate(action)
        pr03 = next(r for r in result.control_results if r.control_id == "PR-03")
        assert pr03.result == "FLAG"
        assert pr03.evidence_data["hash_match"] == "no_baseline"
        assert "no description baseline" in pr03.detail

    def test_version_mismatch_fails(self):
        reg = _make_registry(("test-tool", "1.0", "hash123"))
        config = _make_config()
        action = _make_action(tool_version="2.0", description_hash="hash123")
        engine = Engine(config, registry=reg)
        result = engine.evaluate(action)
        pr03 = next(r for r in result.control_results if r.control_id == "PR-03")
        assert pr03.result == "FAIL"
        assert "version" in pr03.detail.lower()


# --- PR-04 Data Exposure Tests ---


class TestPR04Exposure:
    def test_clean_parameters_pass(self):
        config = _make_config()
        action = _make_action(params={"query": "SELECT * FROM users"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr04 = next(r for r in result.control_results if r.control_id == "PR-04")
        assert pr04.result == "PASS"
        assert pr04.evidence_data["scan_result"] == "clean"

    def test_ssn_pattern_detected(self):
        config = _make_config()
        action = _make_action(params={"data": "SSN: 123-45-6789"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr04 = next(r for r in result.control_results if r.control_id == "PR-04")
        assert pr04.evidence_data["scan_result"] == "patterns_found"
        patterns = pr04.evidence_data["patterns_detected"]
        assert any(p["type"] == "ssn" for p in patterns)
        # Verify redaction
        ssn_match = next(p for p in patterns if p["type"] == "ssn")
        assert "6789" in ssn_match["redacted_sample"]
        assert "123" not in ssn_match["redacted_sample"]

    def test_credit_card_detected(self):
        config = _make_config()
        # Luhn-valid test card number
        action = _make_action(params={"card": "4111 1111 1111 1111"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr04 = next(r for r in result.control_results if r.control_id == "PR-04")
        patterns = pr04.evidence_data["patterns_detected"]
        assert any(p["type"] == "credit_card" for p in patterns)

    def test_sensitive_data_to_blocked_destination_fails(self):
        config = _make_config(
            security={"scope": {"blocked_destinations": ["evil.com"]}}
        )
        action = _make_action(
            params={"data": "SSN: 123-45-6789", "url": "evil.com"}
        )
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr04 = next(r for r in result.control_results if r.control_id == "PR-04")
        assert pr04.result == "FAIL"

    def test_sensitive_data_to_allowed_destination_passes(self):
        config = _make_config(
            security={"scope": {"allowed_destinations": ["safe.com"]}}
        )
        action = _make_action(
            params={"data": "SSN: 123-45-6789", "url": "safe.com"}
        )
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr04 = next(r for r in result.control_results if r.control_id == "PR-04")
        assert pr04.result == "PASS"

    def test_no_data_classifications_passes_with_note(self):
        config = _make_config()
        action = _make_action(params={"query": "clean data"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr04 = next(r for r in result.control_results if r.control_id == "PR-04")
        assert pr04.result == "PASS"
        assert "no data classifications" in pr04.detail.lower()


# --- Decision Engine Tests ---


class TestDecisionEngine:
    def test_all_pass_audit_allows(self):
        config = _make_config()
        action = _make_action()
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert result.decision == "ALLOW"

    def test_all_pass_enforce_allows(self):
        config = _make_config(security={"mode": "enforce"})
        action = _make_action()
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert result.decision == "ALLOW"

    def test_failure_audit_still_allows(self):
        config = _make_config()
        action = _make_action(agent_id="wrong-agent")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert result.decision == "ALLOW"
        assert "audit" in result.decision_reason.lower()

    def test_failure_enforce_blocks(self):
        config = _make_config(security={"mode": "enforce"})
        action = _make_action(agent_id="wrong-agent")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert result.decision == "BLOCK"

    def test_multiple_failures_enforce_lists_all(self):
        config = _make_config(security={"mode": "enforce"})
        action = _make_action(agent_id="wrong-agent", tool_name="unknown-tool")
        engine = Engine(config, registry=ToolRegistry())
        result = engine.evaluate(action)
        assert result.decision == "BLOCK"
        assert "PR-01" in result.decision_reason
        assert "PR-03" in result.decision_reason

    def test_disabled_control_skipped(self):
        config = _make_config(
            security={"controls": {"PR-01": {"enabled": False}}}
        )
        action = _make_action(agent_id="wrong-agent")
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        pr01 = next(r for r in result.control_results if r.control_id == "PR-01")
        assert pr01.result == "SKIP"
        # PR-01 disabled, so its failure doesn't affect decision
        assert result.decision == "ALLOW"

    def test_evaluator_error_handled(self):
        config = _make_config(security={"mode": "enforce"})
        action = _make_action()
        engine = Engine(config, registry=_make_registry(("test-tool",)))

        # Monkey-patch an evaluator to raise
        original = engine._evaluators["PR-01"]

        class BrokenEvaluator:
            control_id = "PR-01"
            control_name = "Agent Identity & Authentication"

            def evaluate(self, action, config):
                raise RuntimeError("boom")

        engine._evaluators["PR-01"] = BrokenEvaluator()
        result = engine.evaluate(action)
        pr01 = next(r for r in result.control_results if r.control_id == "PR-01")
        assert pr01.result == "ERROR"
        assert result.decision == "BLOCK"  # ERROR treated as FAIL in enforce

        engine._evaluators["PR-01"] = original

    def test_result_has_metadata(self):
        config = _make_config(my_agent_handles=["credit_cards"])
        action = _make_action()
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert result.agent_id == "test-agent"
        assert result.mode == "audit"
        assert "pci-dss-v4" in result.active_overlays
        assert "DC-CHD" in result.data_classifications
        assert result.total_duration_ms >= 0


# --- detected_data_types (ANC-716) ---


class TestDetectedDataTypes:
    """Engine extraction of PR-04 patterns → DC codes."""

    def _make_action_with_pii(self) -> "Action":
        return _make_action(
            params={"text": "SSN: 123-45-6789, email: foo@bar.com"},
        )

    def test_no_patterns_yields_empty_list(self):
        config = _make_config()
        action = _make_action(params={"msg": "hello world"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert result.detected_data_types == []

    def test_ssn_maps_to_dc_pii(self):
        config = _make_config()
        action = _make_action(params={"data": "123-45-6789"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert "DC-PII" in result.detected_data_types

    def test_email_maps_to_dc_pii(self):
        config = _make_config()
        action = _make_action(params={"to": "user@example.com"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert "DC-PII" in result.detected_data_types

    def test_credit_card_maps_to_dc_chd(self):
        config = _make_config()
        action = _make_action(params={"card": "4111111111111111"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert "DC-CHD" in result.detected_data_types

    def test_api_key_maps_to_dc_ip(self):
        config = _make_config()
        action = _make_action(params={"key": "sk-" + "a" * 40})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert "DC-IP" in result.detected_data_types

    def test_multiple_pattern_types_deduped(self):
        """Multiple patterns mapping to same DC code should produce one entry."""
        config = _make_config()
        action = _make_action(params={"data": "123-45-6789 foo@bar.com 555-867-5309"})
        engine = Engine(config, registry=_make_registry(("test-tool",)))
        result = engine.evaluate(action)
        assert result.detected_data_types.count("DC-PII") == 1
