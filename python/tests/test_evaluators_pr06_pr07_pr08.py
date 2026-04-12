"""Tests for PR-06, PR-07, and PR-08 evaluators."""

from __future__ import annotations

import pytest

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.evaluators.pr06_config_baseline import PR06ConfigBaselineEvaluator
from ancilis.engine.evaluators.pr07_transport import PR07TransportEvaluator
from ancilis.engine.evaluators.pr08_input import PR08InputEvaluator
from ancilis.testing._helpers import make_action, make_test_config


# ---------------------------------------------------------------------------
# PR-06: Configuration Integrity Baseline
# ---------------------------------------------------------------------------

class TestPR06ConfigBaselineEvaluator:
    def setup_method(self):
        self.evaluator = PR06ConfigBaselineEvaluator()
        self.config = make_test_config()

    def test_skip_no_tool(self):
        action = make_action(tool_name="t")
        action = Action(
            action_id=action.action_id,
            timestamp=action.timestamp,
            agent_id=action.agent_id,
            action_type=action.action_type,
            tool=None,
            parameters=action.parameters,
            agent_owner=action.agent_owner,
            context=action.context,
            source_type=action.source_type,
        )
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "SKIP"

    def test_skip_no_description_hash(self):
        action = make_action(tool_name="my_tool")
        # tool has no description_hash by default
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "SKIP"
        assert "cannot compute" in result.detail.lower() or "cannot establish" in result.detail.lower() or "cannot" in result.detail.lower()

    def test_pass_baseline_established(self):
        action = make_action(tool_name="my_tool")
        # Inject a description_hash
        action.tool.description_hash = "abc123hash"
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"
        assert result.evidence_data["baseline_established"] is True
        assert result.evidence_data["hash_match"] is True

    def test_pass_hash_matches_baseline(self):
        action = make_action(tool_name="my_tool")
        action.tool.description_hash = "abc123hash"
        # First call — establish
        self.evaluator.evaluate(action, self.config)
        # Second call — same hash
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"
        assert "matches baseline" in result.detail

    def test_fail_drift_detected(self):
        action1 = make_action(tool_name="drifted_tool")
        action1.tool.description_hash = "original_hash"
        self.evaluator.evaluate(action1, self.config)  # establish baseline

        action2 = make_action(tool_name="drifted_tool")
        action2.tool.description_hash = "changed_hash"
        result = self.evaluator.evaluate(action2, self.config)
        assert result.result == "FAIL"
        assert result.evidence_data["hash_match"] is False
        assert "drift detected" in result.detail.lower()

    def test_skip_empty_tool_name(self):
        action = make_action(tool_name="")
        action.tool.description_hash = "some_hash"
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "SKIP"


# ---------------------------------------------------------------------------
# PR-07: Transport Security
# ---------------------------------------------------------------------------

class TestPR07TransportEvaluator:
    def setup_method(self):
        self.evaluator = PR07TransportEvaluator()
        self.config = make_test_config()

    def test_pass_no_urls(self):
        action = make_action(tool_name="t", parameters={"text": "hello world"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"
        assert "nothing to validate" in result.detail

    def test_pass_https_url(self):
        action = make_action(tool_name="t", parameters={"url": "https://api.example.com/v1"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"
        assert "secure" in result.detail.lower()

    def test_fail_http_url(self):
        action = make_action(tool_name="t", parameters={"endpoint": "http://api.example.com/data"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"
        assert "insecure" in result.detail.lower()
        assert len(result.evidence_data["insecure_urls"]) > 0

    def test_fail_ws_url(self):
        action = make_action(tool_name="t", parameters={"ws_url": "ws://stream.example.com/feed"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"

    def test_localhost_exempt(self):
        action = make_action(tool_name="t", parameters={"url": "http://localhost:8080/api"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"
        assert "localhost" in str(result.evidence_data.get("localhost_exempt", []))

    def test_localhost_127_exempt(self):
        action = make_action(tool_name="t", parameters={"url": "http://127.0.0.1:3000/health"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"

    def test_wss_pass(self):
        action = make_action(tool_name="t", parameters={"ws": "wss://stream.secure.com"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"

    def test_control_id(self):
        assert self.evaluator.control_id == "PR-07"


# ---------------------------------------------------------------------------
# PR-08: Input Validation
# ---------------------------------------------------------------------------

class TestPR08InputEvaluator:
    def setup_method(self):
        self.evaluator = PR08InputEvaluator()
        self.config = make_test_config()

    def test_pass_clean_input(self):
        action = make_action(tool_name="t", parameters={"query": "get all users", "limit": "10"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"
        assert result.evidence_data["scan_result"] == "clean"

    def test_pass_empty_parameters(self):
        action = make_action(tool_name="t", parameters={})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "PASS"

    def test_fail_sql_or_injection(self):
        action = make_action(tool_name="t", parameters={"input": "' OR 1=1"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"
        assert "sql_or_injection" in result.evidence_data["patterns_found"]

    def test_fail_sql_drop_table(self):
        action = make_action(tool_name="t", parameters={"cmd": "; DROP TABLE users"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"
        assert "sql_drop_table" in result.evidence_data["patterns_found"]

    def test_fail_sql_union_select(self):
        action = make_action(tool_name="t", parameters={"q": "x UNION SELECT password FROM users"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"

    def test_fail_command_injection_rm(self):
        action = make_action(tool_name="t", parameters={"cmd": "; rm -rf /"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"

    def test_fail_path_traversal(self):
        action = make_action(tool_name="t", parameters={"path": "../../etc/passwd"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"

    def test_flag_sql_comment_suspicious(self):
        action = make_action(tool_name="t", parameters={"input": "admin'--"})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FLAG"
        assert result.evidence_data["scan_result"] == "suspicious"

    def test_fail_nested_params(self):
        action = make_action(tool_name="t", parameters={"outer": {"inner": "' OR 1=1"}})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"

    def test_fail_list_params(self):
        action = make_action(tool_name="t", parameters={"items": ["safe_value", "; DROP TABLE x"]})
        result = self.evaluator.evaluate(action, self.config)
        assert result.result == "FAIL"

    def test_control_id(self):
        assert self.evaluator.control_id == "PR-08"

    def test_evidence_parameter_keys(self):
        action = make_action(tool_name="t", parameters={"key1": "val", "key2": "val2"})
        result = self.evaluator.evaluate(action, self.config)
        assert "key1" in result.evidence_data["parameter_keys"]
        assert "key2" in result.evidence_data["parameter_keys"]
