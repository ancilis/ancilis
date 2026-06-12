"""Tests for PR-07, PR-08, and GOV-01 evaluators (ANC-506)."""

from __future__ import annotations

import uuid

import pytest

from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.evaluators.pr07_transport import PR07TransportEvaluator
from ancilis.engine.evaluators.pr08_input import PR08InputEvaluator
from ancilis.engine.evaluators.gov01_identity_auth import GOV01IdentityAuthEvaluator


# --- Helpers ---


def _make_action(params: dict | None = None) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp="2026-04-12T00:00:00Z",
        agent_id="test-agent",
        action_type="tool_call",
        tool=ToolInfo(name="test-tool"),
        parameters=ActionParameters(raw=params or {}, parameter_hash="abc"),
        context=ActionContext(),
    )


def _make_config(**overrides):
    raw = {"agent": {"name": "test-agent"}}
    raw.update(overrides)
    return load_config(raw=raw)


# --- PR-07 Transport Security ---


class TestPR07Transport:
    eval = PR07TransportEvaluator()

    def test_https_url_passes(self):
        action = _make_action({"url": "https://api.example.com/v1/data"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"
        assert result.control_id == "PR-07"

    def test_http_url_fails(self):
        action = _make_action({"url": "http://api.example.com/v1/data"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert "http://api.example.com" in result.evidence_data["insecure_urls"][0]

    def test_localhost_http_exempt(self):
        action = _make_action({"url": "http://localhost:8080/api"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"
        assert "http://localhost:8080/api" in result.evidence_data["localhost_exempt"]

    def test_localhost_127_exempt(self):
        action = _make_action({"endpoint": "http://127.0.0.1:3000/health"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"

    def test_mixed_urls_one_insecure_fails(self):
        action = _make_action({
            "url": "https://secure.example.com",
            "baseUrl": "http://insecure.example.com",
        })
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert len(result.evidence_data["insecure_urls"]) == 1

    def test_no_urls_passes(self):
        action = _make_action({"query": "SELECT * FROM users", "limit": 10})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"
        assert result.evidence_data["urls_checked"] == []

    def test_wss_url_passes(self):
        action = _make_action({"url": "wss://realtime.example.com/socket"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"

    def test_ws_url_fails(self):
        action = _make_action({"server": "ws://stream.example.com"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"

    def test_evidence_structure(self):
        action = _make_action({"url": "https://api.example.com"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert "urls_checked" in result.evidence_data
        assert "insecure_urls" in result.evidence_data
        assert "localhost_exempt" in result.evidence_data
        assert result.duration_ms >= 0


# --- PR-08 Input Validation ---


class TestPR08Input:
    eval = PR08InputEvaluator()

    def test_clean_params_passes(self):
        action = _make_action({"query": "SELECT name FROM users WHERE id = 1", "limit": 100})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"
        assert result.evidence_data["scan_result"] == "clean"
        assert result.evidence_data["patterns_found"] == []

    def test_sql_or_injection_fails(self):
        action = _make_action({"input": "admin' OR 1=1 --"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert "sql_or_injection" in result.evidence_data["patterns_found"]

    def test_sql_drop_table_fails(self):
        action = _make_action({"query": "users'; DROP TABLE users; --"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert "sql_drop_table" in result.evidence_data["patterns_found"]

    def test_sql_union_select_fails(self):
        action = _make_action({"filter": "1 UNION SELECT password FROM accounts"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert "sql_union_select" in result.evidence_data["patterns_found"]

    def test_command_injection_rm_fails(self):
        action = _make_action({"filename": "report.txt; rm -rf /"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert "cmd_rm" in result.evidence_data["patterns_found"]

    def test_command_injection_pipe_fails(self):
        action = _make_action({"arg": "foo | cat /etc/passwd"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"

    def test_command_subshell_fails(self):
        action = _make_action({"input": "$(whoami)"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"

    def test_path_traversal_fails(self):
        action = _make_action({"path": "../../etc/passwd"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"

    def test_nested_params_injection_detected(self):
        action = _make_action({
            "options": {"filter": "x' OR 1=1"},
        })
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"

    def test_double_dash_in_comment_is_suspicious(self):
        # SQL-style comment alone (e.g. in a regular SQL query comment context)
        # Our sql_comment_injection pattern requires a quote before --
        action = _make_action({"note": "-- this is just a comment"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        # No quote before -- so this should be PASS
        assert result.result == "PASS"

    def test_evidence_structure(self):
        action = _make_action({"key": "value"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert "scan_result" in result.evidence_data
        assert "patterns_found" in result.evidence_data
        assert "parameter_keys" in result.evidence_data
        assert result.duration_ms >= 0

    def test_encoded_path_traversal_fails(self):
        action = _make_action({"path": "%2e%2e/etc/shadow"})
        config = _make_config()
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"


# --- GOV-01 Agent Identity and Authentication ---


class TestGOV01IdentityAuth:
    eval = GOV01IdentityAuthEvaluator()

    def _full_config(self):
        return load_config(raw={
            "agent": {
                "name": "production-agent",
                "agent_id": "test-agent",
                "owner": "security-team",
            },
        })

    def test_matching_agent_id_passes(self):
        config = self._full_config()
        action = _make_action()
        action.agent_owner = "security-team"
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"
        # GOV-01 matches a declared identity; it does not authenticate a credential.
        assert result.evidence_data["verification_result"] == "matched"

    def test_missing_agent_id_fails(self):
        config = self._full_config()
        action = _make_action()
        action.agent_id = ""
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert result.evidence_data["failure_reason"] == "agent_id is empty or missing"

    def test_mismatched_agent_id_fails(self):
        config = self._full_config()
        action = _make_action()
        action.agent_id = "wrong-agent"
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert result.evidence_data["expected_agent_id"] == "test-agent"

    def test_mismatched_owner_fails(self):
        config = self._full_config()
        action = _make_action()
        action.agent_owner = "other-team"
        result = self.eval.evaluate(action, config)
        assert result.result == "FAIL"
        assert result.evidence_data["failure_reason"] == "agent_owner does not match configured owner"

    def test_falls_back_to_agent_name_when_agent_id_not_configured(self):
        config = load_config(raw={"agent": {"name": "test-agent"}})
        action = _make_action()
        result = self.eval.evaluate(action, config)
        assert result.result == "PASS"

    def test_evidence_structure(self):
        config = self._full_config()
        action = _make_action()
        action.agent_owner = "security-team"
        result = self.eval.evaluate(action, config)
        assert "agent_id" in result.evidence_data
        assert "expected_agent_id" in result.evidence_data
        assert "verification_result" in result.evidence_data
        assert result.control_id == "GOV-01"
        assert result.duration_ms >= 0
