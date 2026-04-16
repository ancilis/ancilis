"""Tests for local evidence export CLI alias."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


def _evaluation(evaluation_id: str, timestamp: str) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id=f"action-{evaluation_id}",
        timestamp=timestamp,
        agent_id="export-demo-agent",
        source_type="framework",
        mode="audit",
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="agent identified",
                evidence_data={},
                duration_ms=1.0,
            )
        ],
        decision="ALLOW",
        decision_reason="All controls passed.",
        active_overlays=["soc2"],
        data_classifications=["DC-GEN"],
        detected_data_types=["DC-GEN"],
        total_duration_ms=1.0,
        session_id="demo-export-session",
    )


def test_export_cli_filters_local_ndjson_by_since(tmp_path: Path) -> None:
    config_path = tmp_path / "ancilis.yaml"
    config_path.write_text("agent:\n  name: export-demo-agent\n", encoding="utf-8")
    config = load_config(path=config_path)
    db_path = tmp_path / "evidence.duckdb"
    store = EvidenceStore(config, db_path=db_path)
    try:
        store.store(_evaluation("old", "2026-04-15T10:00:00+00:00"), tool_name="read_old")
        store.store(_evaluation("new", "2026-04-15T13:00:00+00:00"), tool_name="read_new")
    finally:
        store.close()

    result = CliRunner().invoke(
        cli,
        [
            "export",
            "--format",
            "ndjson",
            "--since",
            "2026-04-15T12:00:00+00:00",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 0
    rows = [json.loads(line) for line in result.output.splitlines()]
    assert [row["evaluation_id"] for row in rows] == ["new"]
    assert rows[0]["tool_name"] == "read_new"


def test_export_cli_writes_csv_to_output_path(tmp_path: Path) -> None:
    config_path = tmp_path / "ancilis.yaml"
    config_path.write_text("agent:\n  name: export-demo-agent\n", encoding="utf-8")
    config = load_config(path=config_path)
    db_path = tmp_path / "evidence.duckdb"
    output_path = tmp_path / "export.csv"
    store = EvidenceStore(config, db_path=db_path)
    try:
        store.store(_evaluation("row-1", "2026-04-15T13:00:00+00:00"), tool_name="read_file")
    finally:
        store.close()

    result = CliRunner().invoke(
        cli,
        [
            "export",
            "--format",
            "csv",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert f"Export written to {output_path}" in result.output
    assert "row-1" in output_path.read_text(encoding="utf-8")


def test_export_cli_errors_when_db_path_is_missing(tmp_path: Path) -> None:
    missing_db = tmp_path / "missing.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "export",
            "--format",
            "ndjson",
            "--db",
            str(missing_db),
        ],
    )

    assert result.exit_code == 1
    assert "Evidence database not found" in result.output
    assert str(missing_db) in result.output
    assert not missing_db.exists()
