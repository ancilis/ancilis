"""CLI tests for evidence browsing commands."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


def _write_config(tmp_path: Path, raw: dict | None = None) -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(
        yaml.dump(raw or {"agent": {"name": "test-agent"}}, default_flow_style=False),
        encoding="utf-8",
    )
    return path


def _make_evaluation(
    *,
    evaluation_id: str,
    timestamp: str,
    agent_id: str = "test-agent",
    session_id: str = "session-1",
    source_type: str = "agent",
    decision: str = "ALLOW",
    control_id: str = "PR-01",
    control_name: str = "Test Control",
    result: str = "PASS",
    detail: str = "ok",
    evidence_data: dict | None = None,
    active_overlays: list[str] | None = None,
    active_certifications: list[str] | None = None,
    data_classifications: list[str] | None = None,
    detected_data_types: list[str] | None = None,
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id=f"{evaluation_id}-action",
        timestamp=timestamp,
        agent_id=agent_id,
        session_id=session_id,
        source_type=source_type,
        mode="audit",
        control_results=[
            ControlResult(
                control_id=control_id,
                control_name=control_name,
                result=result,
                detail=detail,
                evidence_data=evidence_data or {},
                duration_ms=1.0,
            )
        ],
        decision=decision,
        decision_reason="test",
        active_overlays=active_overlays or [],
        data_classifications=data_classifications or [],
        detected_data_types=detected_data_types or [],
        total_duration_ms=1.0,
    )


def _store_record(
    tmp_path: Path,
    evaluation: EvaluationResult,
    *,
    tool_name: str = "read_file",
) -> tuple[Path, Path, str]:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    record = store.store(evaluation, tool_name=tool_name)
    store.close()
    return cfg_path, db_path, record.record_id


def _rewrite_record_id(db_path: Path, cfg_path: Path, current_id: str, new_id: str) -> None:
    store = EvidenceStore(load_config(path=str(cfg_path)), db_path=str(db_path))
    store._connection.execute(
        "UPDATE evidence_records SET record_id = ? WHERE record_id = ?",
        [new_id, current_id],
    )
    store._connection.execute(
        "UPDATE evidence_sync_state SET record_id = ? WHERE record_id = ?",
        [new_id, current_id],
    )
    store.close()


def test_evidence_help_lists_browse_subcommands() -> None:
    result = CliRunner().invoke(cli, ["evidence", "--help"])

    assert result.exit_code == 0
    assert "list" in result.output
    assert "show" in result.output


def test_evidence_list_empty_store_is_graceful(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        ["evidence", "list", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 0
    assert "No evidence records found." in result.output


def test_evidence_list_filters_and_sorts_descending(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    newer = store.store(
        _make_evaluation(
            evaluation_id="eval-new",
            timestamp="2026-05-19T14:00:00+00:00",
            control_id="PR-05",
            control_name="Action Logging",
            result="FAIL",
            data_classifications=["DC-PII"],
        ),
        tool_name="send_email",
    )
    older = store.store(
        _make_evaluation(
            evaluation_id="eval-old",
            timestamp="2026-05-19T13:00:00+00:00",
            control_id="PR-05",
            control_name="Action Logging",
            result="PASS",
            data_classifications=["DC-GEN"],
        ),
        tool_name="read_file",
    )
    store.close()

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "list",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--classification",
            "DC-PII",
            "--control-id",
            "PR-05",
            "--format",
            "table",
        ],
    )

    assert result.exit_code == 0, result.output
    assert newer.record_id[:7] in result.output
    assert older.record_id[:7] not in result.output
    assert "PR-05" in result.output
    assert "FAIL" in result.output


def test_evidence_list_table_uses_requested_columns(tmp_path: Path) -> None:
    cfg_path, db_path, _ = _store_record(
        tmp_path,
        _make_evaluation(
            evaluation_id="eval-columns",
            timestamp="2026-05-19T14:00:00+00:00",
            control_id="PR-01",
            data_classifications=["DC-GEN"],
        ),
    )

    result = CliRunner().invoke(
        cli,
        ["evidence", "list", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    header = result.output.splitlines()[0]
    assert "timestamp" in header
    assert "evidence_id" in header
    assert "agent_id" in header
    assert "source_type" in header
    assert "classification" in header
    assert "control_id" in header
    assert "status" in header


def test_evidence_list_limit_since_and_agent_filters(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    old_agent_a = store.store(
        _make_evaluation(
            evaluation_id="eval-old-agent-a",
            timestamp="2026-05-19T13:00:00+00:00",
            agent_id="agent-a",
            data_classifications=["DC-GEN"],
        ),
        tool_name="read_file",
    )
    middle_agent_a = store.store(
        _make_evaluation(
            evaluation_id="eval-middle-agent-a",
            timestamp="2026-05-19T14:00:00+00:00",
            agent_id="agent-a",
            data_classifications=["DC-PII"],
        ),
        tool_name="write_file",
    )
    newest_agent_a = store.store(
        _make_evaluation(
            evaluation_id="eval-new-agent-a",
            timestamp="2026-05-19T15:00:00+00:00",
            agent_id="agent-a",
            data_classifications=["DC-PII"],
        ),
        tool_name="send_email",
    )
    other_agent = store.store(
        _make_evaluation(
            evaluation_id="eval-other-agent",
            timestamp="2026-05-19T16:00:00+00:00",
            agent_id="agent-b",
            data_classifications=["DC-PII"],
        ),
        tool_name="send_email",
    )
    store.close()

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "list",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--agent-id",
            "agent-a",
            "--since",
            "2026-05-19T14:00:00+00:00",
            "--limit",
            "1",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [item["record_id"] for item in payload] == [newest_agent_a.record_id]
    assert old_agent_a.record_id not in result.output
    assert middle_agent_a.record_id not in result.output
    assert other_agent.record_id not in result.output


def test_evidence_list_json_returns_full_records_sorted_desc(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    older = store.store(
        _make_evaluation(
            evaluation_id="eval-old",
            timestamp="2026-05-19T13:00:00+00:00",
            control_id="PR-01",
            data_classifications=["DC-GEN"],
        ),
        tool_name="read_file",
    )
    newer = store.store(
        _make_evaluation(
            evaluation_id="eval-new",
            timestamp="2026-05-19T14:00:00+00:00",
            control_id="PR-02",
            data_classifications=["DC-PII"],
        ),
        tool_name="write_file",
    )
    store.close()

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "list",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [item["record_id"] for item in payload] == [newer.record_id, older.record_id]
    assert payload[0]["control_results"][0]["control_id"] == "PR-02"


def test_evidence_show_pretty_supports_short_prefix_and_framework_context(tmp_path: Path) -> None:
    cfg_path = _write_config(
        tmp_path,
        {
            "agent": {"name": "test-agent"},
            "my_agent_handles": ["personal_info"],
            "certification_targets": ["aiuc-1"],
        },
    )
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    record = store.store(
        _make_evaluation(
            evaluation_id="eval-show",
            timestamp="2026-05-19T14:00:00+00:00",
            control_id="PR-01",
            control_name="Agent Identity",
            result="PASS",
            detail="identity verified",
            evidence_data={
                "source_provenance": {"source": "unit-test", "path": "fixtures/demo.json"},
            },
            active_overlays=["soc2"],
            active_certifications=["aiuc-1"],
            data_classifications=["DC-PII"],
            detected_data_types=["personal_info"],
        ),
        tool_name="read_file",
    )
    store.close()

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "show",
            record.record_id[:7],
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert record.record_id in result.output
    assert "Framework Mappings" in result.output
    assert "CC6.1" in result.output
    assert "B001" in result.output
    assert "source_provenance" in result.output


def test_evidence_show_rejects_prefixes_shorter_than_seven_chars(tmp_path: Path) -> None:
    cfg_path, db_path, record_id = _store_record(
        tmp_path,
        _make_evaluation(
            evaluation_id="eval-short",
            timestamp="2026-05-19T14:00:00+00:00",
        ),
    )

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "show",
            record_id[:6],
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 1
    assert "at least 7 characters" in result.output


def test_evidence_show_errors_when_record_not_found(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "show",
            "abcdef0",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 1
    assert "No evidence record found" in result.output


def test_evidence_show_errors_on_ambiguous_short_prefix(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    first = store.store(
        _make_evaluation(
            evaluation_id="eval-a",
            timestamp="2026-05-19T14:00:00+00:00",
        ),
        tool_name="read_file",
    )
    second = store.store(
        _make_evaluation(
            evaluation_id="eval-b",
            timestamp="2026-05-19T14:01:00+00:00",
        ),
        tool_name="write_file",
    )
    store.close()
    _rewrite_record_id(db_path, cfg_path, first.record_id, "abcdef0123456789")
    _rewrite_record_id(db_path, cfg_path, second.record_id, "abcdef0fedcba987")

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "show",
            "abcdef0",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 1
    assert "Ambiguous evidence ID prefix" in result.output
    assert "abcdef0123456789" in result.output
    assert "abcdef0fedcba987" in result.output


def test_evidence_show_pretty_includes_hash_and_runtime_fields(tmp_path: Path) -> None:
    cfg_path, db_path, record_id = _store_record(
        tmp_path,
        _make_evaluation(
            evaluation_id="eval-fields",
            timestamp="2026-05-19T14:00:00+00:00",
            control_id="PR-01",
            data_classifications=["DC-GEN"],
        ),
    )

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "show",
            record_id[:7],
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Record Hash:" in result.output
    assert "Previous Hash:" in result.output
    assert "Tenant ID:" in result.output
    assert "SDK Version:" in result.output


def test_evidence_list_integration_reads_engine_written_record(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)
    action = Action(
        action_id="action-1",
        timestamp="2026-05-19T14:00:00+00:00",
        agent_id=config.agent_name,
        agent_owner="test-owner",
        action_type="tool_call",
        tool=ToolInfo(name="read_file"),
        parameters=ActionParameters(raw={}),
        context=ActionContext(session_id="session-1"),
    )
    evaluation = engine.evaluate(action)
    store = EvidenceStore(config, db_path=str(db_path))
    record = store.store(evaluation, tool_name="read_file")
    store.close()

    result = CliRunner().invoke(
        cli,
        ["evidence", "list", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert record.record_id[:7] in result.output


def test_evidence_show_integration_reads_engine_written_record(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)
    action = Action(
        action_id="action-1",
        timestamp="2026-05-19T14:00:00+00:00",
        agent_id=config.agent_name,
        agent_owner="test-owner",
        action_type="tool_call",
        tool=ToolInfo(name="read_file"),
        parameters=ActionParameters(raw={}),
        context=ActionContext(session_id="session-1"),
    )
    evaluation = engine.evaluate(action)
    store = EvidenceStore(config, db_path=str(db_path))
    record = store.store(evaluation, tool_name="read_file")
    store.close()

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "show",
            record.record_id[:7],
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["record_id"] == record.record_id
    assert payload["control_results"]
