"""CLI tests for certification coverage reporting."""

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
    control_id: str,
    result: str,
    control_name: str = "Test Control",
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id=f"{evaluation_id}-action",
        timestamp=timestamp,
        agent_id="test-agent",
        source_type="agent",
        mode="audit",
        session_id="session-1",
        control_results=[
            ControlResult(
                control_id=control_id,
                control_name=control_name,
                result=result,
                detail="test",
                evidence_data={},
                duration_ms=1.0,
            )
        ],
        decision="ALLOW",
        decision_reason="test",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
    )


def _store_evaluations(tmp_path: Path, evaluations: list[EvaluationResult]) -> tuple[Path, Path]:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    for evaluation in evaluations:
        store.store(evaluation, tool_name="read_file")
    store.close()
    return cfg_path, db_path


def test_help_lists_certify_command() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "certify" in result.output


def test_certify_empty_store_lists_honest_statuses_for_target_controls(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "soc2",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "PR-01" in result.output
    assert "CC6.1" in result.output
    assert "attestation_required" in result.output
    assert "deferred_cross_action" in result.output
    assert "deferred_new_data" in result.output
    assert "No evaluator implemented" not in result.output


def test_certify_table_uses_requested_columns_and_dry_run_is_noop(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "soc2",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    header = result.output.splitlines()[0]
    assert "control_id" in header
    assert "framework_ref" in header
    assert "coverage_status" in header
    assert "action_required" in header
    assert "evidence_count" in header
    assert "last_evidence_at" in header


def test_certify_reports_covered_partial_and_latest_evidence(tmp_path: Path) -> None:
    cfg_path, db_path = _store_evaluations(
        tmp_path,
        [
            _make_evaluation(
                evaluation_id="eval-covered",
                timestamp="2026-05-19T14:00:00+00:00",
                control_id="PR-01",
                result="PASS",
                control_name="Agent Identity",
            ),
            _make_evaluation(
                evaluation_id="eval-partial-pass",
                timestamp="2026-05-19T14:01:00+00:00",
                control_id="PR-02",
                result="PASS",
                control_name="Scope",
            ),
            _make_evaluation(
                evaluation_id="eval-partial-fail",
                timestamp="2026-05-19T14:02:00+00:00",
                control_id="PR-02",
                result="FAIL",
                control_name="Scope",
            ),
        ],
    )

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "soc2",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "PR-01" in result.output
    assert "covered" in result.output.lower()
    assert "PR-02" in result.output
    assert "gap" in result.output.lower()
    assert "2026-05-19T14:02:00+00:00" in result.output


def test_certify_rejects_unknown_targets(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "nist",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code != 0
    assert "Invalid value for '--target'" in result.output


def test_certify_json_uses_friendly_target_mapping_for_aiuc1(tmp_path: Path) -> None:
    cfg_path, db_path = _store_evaluations(
        tmp_path,
        [
            _make_evaluation(
                evaluation_id="eval-aiuc",
                timestamp="2026-05-19T14:00:00+00:00",
                control_id="PR-01",
                result="PASS",
                control_name="Agent Identity",
            ),
        ],
    )

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "aiuc1",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--format",
            "json",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["target"] == "aiuc1"
    assert payload["target_id"] == "aiuc-1"
    assert payload["target_name"].startswith("AIUC-1")
    control_ids = [item["control_id"] for item in payload["controls"]]
    assert control_ids == ["DE-01", "PR-01", "PR-02", "PR-03", "PR-04", "PR-05"]
    pr01 = next(item for item in payload["controls"] if item["control_id"] == "PR-01")
    assert "B001" in pr01["framework_ref"]
    assert "action_required" in pr01


def test_certify_json_reports_dry_run_by_default(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "soc2",
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
    assert payload["dry_run"] is True


def test_certify_integration_reads_engine_written_evidence(tmp_path: Path) -> None:
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
    store.store(evaluation, tool_name="read_file")
    store.close()

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "soc2",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "PR-01" in result.output


def test_certify_empty_json_reports_attestation_deferred_and_policy_actions(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "certify",
            "--target",
            "soc2",
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
    by_id = {row["control_id"]: row for row in payload["controls"]}
    assert by_id["GOV-04"]["coverage_status"] == "attestation_required"
    assert by_id["GOV-04"]["action_required"] == "ancilis attest GOV-04"
    assert by_id["ID-03"]["coverage_status"] == "deferred_cross_action"
    assert by_id["ID-03"]["action_required"] == "v0.2 roadmap"
    assert by_id["ID-04"]["coverage_status"] == "deferred_new_data"
    assert by_id["GOV-02"]["coverage_status"] == "policy_gated"
    assert by_id["GOV-02"]["action_required"] == "enable in policy"
