"""CLI tests for evidence chain verification."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


def _make_config_file(tmp_path: Path) -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(yaml.dump({"agent": {"name": "test-agent"}}), encoding="utf-8")
    return path


def _make_evaluation(evaluation_id: str = "eval-001") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id="action-001",
        timestamp="2026-04-14T00:00:00+00:00",
        agent_id="test-agent",
        source_type="agent",
        mode="audit",
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Agent identity verified",
                evidence_data={"agent_id": "test-agent"},
                duration_ms=1.0,
            )
        ],
        decision="ALLOW",
        decision_reason="All controls passed",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
        session_id="session-1",
    )


def _store_record(tmp_path: Path) -> tuple[Path, Path, str]:
    cfg_path = _make_config_file(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    record = store.store(_make_evaluation(), tool_name="read_file")
    store.close()
    return cfg_path, db_path, record.record_id


def test_evidence_verify_valid_chain_exits_zero(tmp_path: Path) -> None:
    cfg_path, db_path, _record_id = _store_record(tmp_path)

    result = CliRunner().invoke(
        cli,
        ["evidence", "verify", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 0
    # No chain key set in tests → records are legacy v1, reported as
    # legacy-unverified (never a silent "verified" pass).
    assert "Evidence chain intact" in result.output
    assert "legacy-unverified" in result.output


def test_evidence_verify_db_only_does_not_require_config_in_cwd(tmp_path: Path) -> None:
    _cfg_path, db_path, _record_id = _store_record(tmp_path)
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["evidence", "verify", "--db", str(db_path)])

    assert result.exit_code == 0
    assert "Evidence chain intact" in result.output
    assert "legacy-unverified" in result.output


def test_evidence_verify_tampered_chain_exits_nonzero(tmp_path: Path) -> None:
    cfg_path, db_path, record_id = _store_record(tmp_path)
    store = EvidenceStore(load_config(path=str(cfg_path)), db_path=str(db_path))
    store._connection.execute(
        "UPDATE evidence_records SET tool_name = ? WHERE record_id = ?",
        ["tampered-tool", record_id],
    )
    store.close()

    result = CliRunner().invoke(
        cli,
        ["evidence", "verify", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 1
    assert "Evidence chain broken" in result.output
    assert record_id in result.output


def test_evidence_verify_json_reports_session_scope(tmp_path: Path) -> None:
    cfg_path, db_path, _record_id = _store_record(tmp_path)

    result = CliRunner().invoke(
        cli,
        [
            "evidence",
            "verify",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--session-id",
            "session-1",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["record_count"] == 1
    assert payload["session_id"] == "session-1"
    assert payload["errors"] == []
    # Richer, honest fields: legacy (v1) records are surfaced explicitly.
    assert payload["status"] == "legacy-unverified"
    assert payload["verified"] == 0
    assert payload["legacy_unverified"] == 1
    assert payload["reset_events"] == 0
    assert payload["purge_events"] == 0
