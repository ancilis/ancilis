"""Tests for `ancilis scan` CLI command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


# --- Helpers ---


def _make_config_file(data: dict[str, Any], tmpdir: Path) -> Path:
    path = tmpdir / "ancilis.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return path


def _minimal_config() -> dict[str, Any]:
    return {"agent": {"name": "test-agent"}}


def _make_action(tool_name: str = "read_file", agent_id: str = "test-agent") -> Action:
    return Action(
        action_id="test-action-1",
        timestamp="2026-03-11T10:00:00Z",
        agent_id=agent_id,
        agent_owner="test-owner",
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw={}),
        context=ActionContext(session_id="sess-1"),
    )


def _make_fail_evaluation(decision: str = "BLOCK") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id="fail-eval",
        action_id="fail-action",
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id="test-agent",
        mode="enforce",
        control_results=[
            ControlResult(
                control_id="PR-02",
                control_name="Scope",
                result="FAIL",
                detail="Tool is not in the allowlist.",
                evidence_data={},
                duration_ms=1.0,
            )
        ],
        decision=decision,
        decision_reason="Blocked by scope",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
    )


def _populate_clean_evidence(config: Any, store: EvidenceStore, n: int = 3) -> None:
    """Store clean passing evaluations."""
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)
    for _ in range(n):
        action = _make_action(tool_name="read_file", agent_id=config.agent_name)
        evaluation = engine.evaluate(action)
        store.store(evaluation, tool_name="read_file")


# --- Tests ---


class TestScanCommand:
    def test_scan_clean_evidence_exit_0(self, tmp_path: Path) -> None:
        """Exit 0 when all controls pass."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_clean_evidence(config, store)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0
        assert "compliant" in result.output.lower()

    def test_scan_ci_clean_outputs_valid_json(self, tmp_path: Path) -> None:
        """--ci with passing evidence outputs valid JSON and exits 0."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_clean_evidence(config, store)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert data["version"] == "0.1.0"
        assert data["agent"] == "test-agent"
        assert data["posture"] == "compliant"
        assert data["exit_code"] == 0
        assert isinstance(data["controls"], list)
        assert "passing" in data["summary"]
        assert "total_controls" in data["summary"]
        assert "timestamp" in data

    def test_scan_violations_exit_1(self, tmp_path: Path) -> None:
        """Exit 1 when control failures detected."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        store.store(_make_fail_evaluation(decision="BLOCK"), tool_name="blocked-tool")
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 1
        assert "non_compliant" in result.output.lower()

    def test_scan_ci_violations_json_shows_failing(self, tmp_path: Path) -> None:
        """--ci with violations outputs JSON with failing controls and exit_code 1."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        store.store(_make_fail_evaluation(decision="BLOCK"), tool_name="blocked-tool")
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 1

        data = json.loads(result.output)
        assert data["posture"] == "non_compliant"
        assert data["exit_code"] == 1
        failing = [c for c in data["controls"] if c["status"] == "fail"]
        assert len(failing) > 0

    def test_scan_missing_config_exit_2(self, tmp_path: Path) -> None:
        """Exit 2 when config file is missing."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--config", str(tmp_path / "missing.yaml")])
        assert result.exit_code == 2

    def test_scan_human_readable_no_ci_flag(self, tmp_path: Path) -> None:
        """Without --ci, output is human-readable text (not JSON)."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_clean_evidence(config, store)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0
        # Human-readable has "Ancilis scan" header, not raw JSON keys
        assert "Ancilis scan" in result.output
        with pytest.raises((json.JSONDecodeError, ValueError)):
            json.loads(result.output)

    def test_scan_session_scoping(self, tmp_path: Path) -> None:
        """--session scopes evidence to a specific session."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        # Store a violation under session "sess-bad"
        store.store(_make_fail_evaluation(decision="BLOCK"), tool_name="blocked-tool")
        store.close()

        runner = CliRunner()
        # Scanning a different session should see no evaluations → compliant
        result = runner.invoke(
            cli,
            ["scan", "--ci", "--config", str(cfg_path), "--db", str(db), "--session", "sess-clean"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["posture"] == "compliant"
        assert data["summary"]["total_evaluations"] == 0

    def test_scan_no_evaluations_compliant(self, tmp_path: Path) -> None:
        """No evaluations in period → exit 0, posture compliant."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0
        assert "compliant" in result.output.lower()

    def test_scan_ci_schema_fields_present(self, tmp_path: Path) -> None:
        """--ci JSON output includes all required schema fields."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0

        data = json.loads(result.output)
        required_top = {"version", "agent", "mode", "timestamp", "controls", "summary", "posture", "exit_code"}
        assert required_top <= set(data.keys())
        required_summary = {"total_controls", "passing", "failing", "skipped", "total_evaluations"}
        assert required_summary <= set(data["summary"].keys())


class TestScanLatestSessionDefault:
    def test_scan_defaults_to_latest_session(self, tmp_path: Path) -> None:
        """Default scan shows only latest session — stale prior-run violations don't bleed in."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))

        # Old session: has a BLOCK violation (no session_id → stored with NULL)
        store.store(_make_fail_evaluation(decision="BLOCK"), tool_name="bad-tool")

        # Latest session: clean passes (session_id="sess-1")
        _populate_clean_evidence(config, store, n=3)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["posture"] == "compliant"

    def test_scan_all_shows_everything(self, tmp_path: Path) -> None:
        """--all flag shows all accumulated sessions including prior violations."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))

        # Old failure (no session_id)
        store.store(_make_fail_evaluation(decision="BLOCK"), tool_name="bad-tool")
        # Latest session: clean
        _populate_clean_evidence(config, store, n=3)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--ci", "--all", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["posture"] == "non_compliant"

    def test_scan_explicit_session_overrides_latest(self, tmp_path: Path) -> None:
        """--session <id> scopes to that session regardless of --latest default."""
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_clean_evidence(config, store, n=2)  # session_id="sess-1"
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "--ci", "--session", "sess-1", "--config", str(cfg_path), "--db", str(db)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["posture"] == "compliant"
        assert data["summary"]["total_evaluations"] == 2
