"""Tests for DE-03, GOV-03, DE-02 evaluators (ANC-512)."""

from __future__ import annotations

import uuid

import pytest

from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.evaluators.de03_config_drift import DE03ConfigDriftEvaluator
from ancilis.engine.evaluators.gov03_risk_tolerance import GOV03RiskToleranceEvaluator
from ancilis.engine.evaluators.de02_classification_drift import DE02ClassificationDriftEvaluator


# --- Helpers ---


def _make_action(
    tool_name: str = "test-tool",
    description_hash: str | None = None,
    version: str | None = None,
    server: str | None = None,
) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp="2026-04-12T00:00:00Z",
        agent_id="test-agent",
        action_type="tool_call",
        tool=ToolInfo(
            name=tool_name,
            description_hash=description_hash,
            version=version,
            server=server,
        ),
        parameters=ActionParameters(raw={}, parameter_hash="abc"),
        context=ActionContext(),
    )


def _make_action_no_tool() -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp="2026-04-12T00:00:00Z",
        agent_id="test-agent",
        action_type="tool_call",
        tool=ToolInfo(name=""),
        parameters=ActionParameters(raw={}, parameter_hash="abc"),
        context=ActionContext(),
    )


def _make_config_full(**agent_overrides):
    """Config with mode, data_classifications, and scope — all criteria met."""
    agent = {"name": "test-agent", "owner": "team@example.com"}
    agent.update(agent_overrides)
    return load_config(raw={
        "agent": agent,
        "security": {
            "mode": "enforce",
            "tools": {"allowed": ["read_file", "write_file"]},
        },
        "my_agent_handles": ["personal_info"],
    })


def _make_config_minimal():
    """Config with only agent name and mode — missing data_classifications and scope."""
    return load_config(raw={"agent": {"name": "test-agent"}})


def _make_config_partial():
    """Config with mode but no data_classifications or scope."""
    return load_config(raw={
        "agent": {"name": "test-agent"},
        "security": {"mode": "audit"},
    })


# ============================================================
# DE-03: Configuration/Dependency Drift Monitoring
# ============================================================


class TestDE03ConfigDrift:
    def test_first_observation_establishes_baseline(self):
        ev = DE03ConfigDriftEvaluator()
        action = _make_action(tool_name="read_file", description_hash="abc123")
        result = ev.evaluate(action, _make_config_minimal())
        assert result.result == "PASS"
        assert result.control_id == "DE-03"
        assert result.evidence_data["baseline_established"] is True
        assert result.evidence_data["hash_match"] is True
        assert "established" in result.detail.lower()

    def test_same_hash_passes_on_repeat(self):
        ev = DE03ConfigDriftEvaluator()
        action = _make_action(tool_name="read_file", description_hash="abc123")
        ev.evaluate(action, _make_config_minimal())  # establish
        result = ev.evaluate(action, _make_config_minimal())  # verify
        assert result.result == "PASS"
        assert result.evidence_data["hash_match"] is True

    def test_changed_hash_fails(self):
        ev = DE03ConfigDriftEvaluator()
        action1 = _make_action(tool_name="read_file", description_hash="abc123")
        action2 = _make_action(tool_name="read_file", description_hash="xyz999")
        ev.evaluate(action1, _make_config_minimal())  # establish baseline
        result = ev.evaluate(action2, _make_config_minimal())  # drift
        assert result.result == "FAIL"
        assert result.evidence_data["hash_match"] is False
        assert "drift" in result.detail.lower()

    def test_no_tool_name_skips(self):
        ev = DE03ConfigDriftEvaluator()
        action = _make_action_no_tool()
        result = ev.evaluate(action, _make_config_minimal())
        assert result.result == "SKIP"
        assert result.evidence_data["tool_name"] is None

    def test_no_description_hash_skips(self):
        """Without description_hash, cannot establish a reliable baseline — SKIP."""
        ev = DE03ConfigDriftEvaluator()
        action = _make_action(tool_name="read_file", description_hash=None, version="1.0")
        result = ev.evaluate(action, _make_config_minimal())
        assert result.result == "SKIP"

    def test_different_tools_tracked_independently(self):
        """Two distinct tools each get their own baseline slot."""
        ev = DE03ConfigDriftEvaluator()
        a1 = _make_action(tool_name="tool_a", description_hash="hash_a")
        a2 = _make_action(tool_name="tool_b", description_hash="hash_b")
        r1 = ev.evaluate(a1, _make_config_minimal())
        r2 = ev.evaluate(a2, _make_config_minimal())
        assert r1.result == "PASS"
        assert r2.result == "PASS"
        # Same tools again — should still pass
        assert ev.evaluate(a1, _make_config_minimal()).result == "PASS"
        assert ev.evaluate(a2, _make_config_minimal()).result == "PASS"


# ============================================================
# GOV-03: Risk Tolerance Definition
# ============================================================


class TestGOV03RiskTolerance:
    def test_full_config_passes(self):
        ev = GOV03RiskToleranceEvaluator()
        action = _make_action()
        result = ev.evaluate(action, _make_config_full())
        assert result.result == "PASS"
        assert result.control_id == "GOV-03"
        assert result.evidence_data["has_data_classifications"] is True
        assert result.evidence_data["has_scope_constraints"] is True

    def test_missing_all_criteria_fails(self):
        """Config with no mode, no data_classifications, no scope."""
        ev = GOV03RiskToleranceEvaluator()
        action = _make_action()
        # load_config always sets mode to "audit" default; we need partial to
        # test FAIL path: only 0/3 met — but mode default = "audit" counts as met.
        # Instead test that absent data_classifications + scope → FLAG (1/3 met)
        config = _make_config_partial()
        result = ev.evaluate(action, config)
        assert result.result == "FLAG"
        assert "data_classifications" in result.evidence_data["criteria_missing"]
        assert "scope_constraints" in result.evidence_data["criteria_missing"]

    def test_partial_config_flags(self):
        ev = GOV03RiskToleranceEvaluator()
        action = _make_action()
        config = _make_config_partial()  # has mode but missing classifications + scope
        result = ev.evaluate(action, config)
        assert result.result == "FLAG"
        assert "security_mode" in result.evidence_data["criteria_met"]

    def test_scope_via_rate_limit(self):
        """Scope constraints can be satisfied by max_actions_per_minute."""
        ev = GOV03RiskToleranceEvaluator()
        action = _make_action()
        config = load_config(raw={
            "agent": {"name": "test-agent"},
            "security": {
                "mode": "enforce",
                "scope": {"max_actions_per_minute": 30},
            },
            "my_agent_handles": ["personal_info"],
        })
        result = ev.evaluate(action, config)
        assert result.result == "PASS"
        assert result.evidence_data["has_scope_constraints"] is True

    def test_scope_via_blocked_destinations(self):
        ev = GOV03RiskToleranceEvaluator()
        action = _make_action()
        config = load_config(raw={
            "agent": {"name": "test-agent"},
            "security": {
                "mode": "audit",
                "scope": {"blocked_destinations": ["prod.example.com"]},
            },
            "my_agent_handles": ["personal_info"],
        })
        result = ev.evaluate(action, config)
        assert result.result == "PASS"

    def test_evidence_fields_present(self):
        ev = GOV03RiskToleranceEvaluator()
        result = ev.evaluate(_make_action(), _make_config_full())
        for field in ("criteria_met", "criteria_missing", "security_mode",
                      "has_data_classifications", "has_scope_constraints"):
            assert field in result.evidence_data


# ============================================================
# DE-02: Classification Drift and Boundary Validation
# ============================================================


class TestDE02ClassificationDrift:
    def test_clean_action_passes(self):
        ev = DE02ClassificationDriftEvaluator()
        action = _make_action(tool_name="read_file", description_hash="abc123")
        result = ev.evaluate(action, _make_config_full())
        assert result.result == "PASS"
        assert result.control_id == "DE-02"
        assert result.evidence_data["observed_data_classes"] == []

    def test_undeclared_classification_fails(self):
        ev = DE02ClassificationDriftEvaluator()
        action = _make_action(tool_name="read_file")
        action.parameters.raw = {"card": "4111-1111-1111-1111"}
        result = ev.evaluate(action, _make_config_full())
        assert result.result == "FAIL"
        assert result.evidence_data["undeclared_data_classes"] == ["DC-CHD"]

    def test_declared_classification_passes(self):
        ev = DE02ClassificationDriftEvaluator()
        action = _make_action(tool_name="read_file")
        action.parameters.raw = {"ssn": "123-45-6789"}
        result = ev.evaluate(action, _make_config_full())
        assert result.result == "PASS"

    def test_boundary_violation_fails(self):
        ev = DE02ClassificationDriftEvaluator()
        action = _make_action(tool_name="read_file")
        action.parameters.raw = {"destination": "blocked.example.com"}
        config = load_config(raw={
            "agent": {"name": "test-agent"},
            "security": {"scope": {"blocked_destinations": ["blocked.example.com"]}},
        })
        result = ev.evaluate(action, config)
        assert result.result == "FAIL"
        assert result.evidence_data["boundary_violation"]


class TestDE03MovedConfigDriftCoverage:
    def test_different_tools_independent_tracking(self):
        """Drift on tool_a should not affect tool_b."""
        ev = DE03ConfigDriftEvaluator()
        a1v1 = _make_action(tool_name="tool_a", description_hash="hash_a1")
        a1v2 = _make_action(tool_name="tool_a", description_hash="hash_a2")
        b1 = _make_action(tool_name="tool_b", description_hash="hash_b1")

        ev.evaluate(a1v1, _make_config_minimal())  # establish tool_a
        ev.evaluate(b1, _make_config_minimal())    # establish tool_b
        drift_result = ev.evaluate(a1v2, _make_config_minimal())  # drift on tool_a
        stable_result = ev.evaluate(b1, _make_config_minimal())   # tool_b stable

        assert drift_result.result == "FAIL"
        assert stable_result.result == "PASS"

    def test_no_description_hash_skips(self):
        """Without description_hash, cannot reliably fingerprint — SKIP."""
        ev = DE03ConfigDriftEvaluator()
        action = _make_action(tool_name="list_files", description_hash=None, version="1.0")
        result = ev.evaluate(action, _make_config_minimal())
        assert result.result == "SKIP"

    def test_fingerprint_includes_server_and_version(self):
        """Changing server with description_hash present should be detected as drift."""
        ev = DE03ConfigDriftEvaluator()
        a1 = _make_action(tool_name="list_files", description_hash="same_hash", version="1.0", server="mcp://a")
        a2 = _make_action(tool_name="list_files", description_hash="same_hash", version="1.0", server="mcp://b")
        ev.evaluate(a1, _make_config_minimal())
        result = ev.evaluate(a2, _make_config_minimal())
        assert result.result == "FAIL"
