"""Tests for the read-only `ancilis shell` REPL."""

from __future__ import annotations

import io
from pathlib import Path

from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.cli.shell import AncilisShell
from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


def _config() -> ResolvedConfig:
    return load_config(
        raw={
            "agent": {"name": "shell-agent"},
            "security": {
                "mode": "audit",
                "tools": {
                    "allowed": ["read_file"],
                    "blocked": ["send_email"],
                },
            },
        }
    )


def _evaluation(
    *,
    evaluation_id: str = "eval-001",
    decision: str = "ALLOW",
    session_id: str | None = "session-a",
    control_result: str = "PASS",
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id="action-001",
        timestamp="2025-01-15T10:30:00Z",
        agent_id="shell-agent",
        mode="audit",
        session_id=session_id,
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result=control_result,
                detail="Agent identity verified",
                evidence_data={"agent_id": "shell-agent"},
                duration_ms=1.5,
            )
        ],
        decision=decision,
        decision_reason="All controls passed",
        active_overlays=["soc2"],
        data_classifications=[],
        total_duration_ms=5.0,
    )


def _shell(store: EvidenceStore, session_id: str | None = None) -> tuple[AncilisShell, io.StringIO]:
    output = io.StringIO()
    shell = AncilisShell(config=_config(), store=store, session_id=session_id, stdout=output)
    return shell, output


def test_shell_help_lists_available_commands() -> None:
    store = EvidenceStore(_config(), in_memory=True)
    shell, output = _shell(store)

    shell.onecmd("help")

    text = output.getvalue()
    assert "posture" in text
    assert "evidence list" in text
    assert "config show" in text
    store.close()


def test_shell_renders_config_and_overlay_summaries() -> None:
    store = EvidenceStore(_config(), in_memory=True)
    shell, output = _shell(store)

    shell.onecmd("config show")
    shell.onecmd("overlay list")

    text = output.getvalue()
    assert "Agent: shell-agent" in text
    assert "Mode: audit" in text
    assert "Allowed tools: read_file" in text
    assert "Blocked tools: send_email" in text
    assert "Enabled controls:" in text
    assert "No active overlays or certifications." in text
    store.close()


def test_shell_evidence_list_show_and_evaluate_records() -> None:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    stored = store.store(_evaluation(), tool_name="read_file")
    shell, output = _shell(store, session_id="session-a")

    shell.onecmd("evidence list --limit 5 --tool read_file --decision ALLOW")
    shell.onecmd(f"evidence show {stored.record_id}")
    shell.onecmd("evaluate PR-01")

    text = output.getvalue()
    assert stored.record_id in text
    assert "read_file" in text
    assert "ALLOW" in text
    assert '"evaluation_id": "eval-001"' in text
    assert "PR-01" in text
    assert "Agent Identity" in text
    assert "PASS" in text
    store.close()


def test_shell_evaluate_respects_session_scope() -> None:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    store.store(
        _evaluation(
            evaluation_id="eval-session-a",
            session_id="session-a",
            control_result="PASS",
        ),
        tool_name="read_file",
    )
    store.store(
        _evaluation(
            evaluation_id="eval-session-b",
            session_id="session-b",
            control_result="FAIL",
        ),
        tool_name="read_file",
    )
    shell, output = _shell(store, session_id="session-a")

    shell.onecmd("evaluate PR-01")

    text = output.getvalue()
    assert '"result": "PASS"' in text
    assert '"result": "FAIL"' not in text
    store.close()


def test_shell_evidence_list_empty_store_does_not_create_persistent_db(tmp_path: Path) -> None:
    config = _config()
    db_path = tmp_path / "missing.duckdb"
    store = EvidenceStore(config, db_path=db_path)
    shell, output = _shell(store)

    shell.onecmd("posture")
    shell.onecmd("evidence list")

    text = output.getvalue()
    assert "No evaluations recorded yet" in text
    assert "No evidence records found." in text
    assert not db_path.exists()
    store.close()


def test_shell_command_smoke_help_exit(tmp_path: Path) -> None:
    config_path = tmp_path / "ancilis.yaml"
    config_path.write_text("agent:\n  name: shell-agent\n")
    db_path = tmp_path / "evidence.duckdb"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["shell", "--config", str(config_path), "--db", str(db_path)],
        input="help\nexit\n",
    )

    assert result.exit_code == 0, result.output
    assert "ancilis> " in result.output
    assert "Available commands:" in result.output
    assert not db_path.exists()
