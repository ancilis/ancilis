"""CLI tests for manual AKSI attestation evidence."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.evaluators.attestation import (
    ATTESTATION_CONTROL_SPECS,
    ManualAttestationEvaluator,
)
from ancilis.evidence.store import EvidenceStore


GOV04_FIELDS = [
    "oversight_policy_url=https://example.test/oversight",
    "approval_workflow_id=wf-human-review",
    "reviewer_role=risk-owner",
    "exception_log_location=https://example.test/exceptions",
    "responsible_party=Kevin",
    "last_review_date=2026-05-19",
]


def _write_config(tmp_path: Path, raw: dict | None = None) -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(
        yaml.dump(
            raw
            or {
                "agent": {
                    "name": "attest-agent",
                    "owner": "platform-team",
                }
            },
            default_flow_style=False,
        ),
        encoding="utf-8",
    )
    return path


def _record_args(cfg_path: Path, db_path: Path, control_id: str = "GOV-04") -> list[str]:
    args = [
        "attest",
        "record",
        control_id,
        "--config",
        str(cfg_path),
        "--db",
        str(db_path),
        "--by",
        "kevin@example.test",
    ]
    for field in GOV04_FIELDS:
        args.extend(["--field", field])
    return args


def test_attest_help_is_registered() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "attest" in result.output


def test_attest_list_shows_manual_controls(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        ["attest", "list", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert "GOV-04" in result.output
    assert "none" in result.output


def test_attest_show_reports_required_fields_without_record(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        ["attest", "show", "GOV-04", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert "No attestation recorded." in result.output
    assert "oversight_policy_url" in result.output


def test_attest_show_rejects_unknown_control(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        ["attest", "show", "NO-99", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code != 0
    assert "No attestation evaluator registered for NO-99" in result.output


def test_attest_record_requires_all_required_fields(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "attest",
            "record",
            "GOV-04",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--field",
            "oversight_policy_url=https://example.test/oversight",
        ],
    )

    assert result.exit_code != 0
    assert "Missing required attestation fields" in result.output


def test_attest_record_rejects_invalid_field_syntax(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        [
            "attest",
            "record",
            "GOV-04",
            "--config",
            str(cfg_path),
            "--db",
            str(db_path),
            "--field",
            "not-key-value",
        ],
    )

    assert result.exit_code != 0
    assert "Fields must use key=value syntax" in result.output


def test_attest_record_writes_fresh_attestation(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    record_result = CliRunner().invoke(cli, _record_args(cfg_path, db_path))
    list_result = CliRunner().invoke(
        cli,
        ["attest", "list", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert record_result.exit_code == 0, record_result.output
    assert "Attestation recorded" in record_result.output
    assert list_result.exit_code == 0, list_result.output
    assert "GOV-04" in list_result.output
    assert "fresh" in list_result.output
    assert "kevin@example.test" in list_result.output


def test_attest_show_displays_latest_attestation_fields(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    CliRunner().invoke(cli, _record_args(cfg_path, db_path))

    result = CliRunner().invoke(
        cli,
        ["attest", "show", "GOV-04", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert "Latest Attestation" in result.output
    assert "approval_workflow_id: wf-human-review" in result.output
    assert "Attested By: kevin@example.test" in result.output


def test_attest_revoke_marks_latest_attestation_inactive(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    runner = CliRunner()
    runner.invoke(cli, _record_args(cfg_path, db_path))

    revoke_result = runner.invoke(
        cli,
        ["attest", "revoke", "GOV-04", "--config", str(cfg_path), "--db", str(db_path)],
    )
    list_result = runner.invoke(
        cli,
        ["attest", "list", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert revoke_result.exit_code == 0, revoke_result.output
    assert "Attestation revoked" in revoke_result.output
    assert list_result.exit_code == 0, list_result.output
    gov04_line = next(line for line in list_result.output.splitlines() if line.startswith("GOV-04"))
    assert "none" in gov04_line


def test_attest_revoke_requires_existing_attestation(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"

    result = CliRunner().invoke(
        cli,
        ["attest", "revoke", "GOV-04", "--config", str(cfg_path), "--db", str(db_path)],
    )

    assert result.exit_code != 0
    assert "No active attestation found for GOV-04" in result.output


def test_manual_attestation_evaluator_skips_without_evidence() -> None:
    spec = ATTESTATION_CONTROL_SPECS["GOV-04"]
    result = ManualAttestationEvaluator(
        spec.control_id,
        required_evidence_fields=list(spec.required_evidence_fields),
        optional_evidence_fields=list(spec.optional_evidence_fields),
        staleness_days=spec.staleness_days,
    ).evaluate(
        Action(
            action_id="action-1",
            timestamp="2026-05-19T00:00:00+00:00",
            agent_id="attest-agent",
            action_type="tool_call",
            tool=ToolInfo(name="read_file"),
            parameters=ActionParameters(raw={}),
            context=ActionContext(),
        ),
        load_config(raw={"agent": {"name": "attest-agent"}}),
    )

    assert result.result == "SKIP"
    assert result.detail == "MANUAL: attestation required"
    assert result.evidence_data["command"] == "ancilis attest GOV-04"


def test_attest_cli_written_evidence_satisfies_engine_evaluator(tmp_path: Path) -> None:
    cfg_path = _write_config(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    CliRunner().invoke(cli, _record_args(cfg_path, db_path))

    config = load_config(path=str(cfg_path))
    store = EvidenceStore(config, db_path=str(db_path))
    engine = Engine(config, evidence_store=store)
    evaluation = engine.evaluate(
        Action(
            action_id="action-1",
            timestamp="2026-05-19T00:00:00+00:00",
            agent_id=config.agent_name,
            agent_owner=config.agent_owner,
            action_type="tool_call",
            tool=ToolInfo(name="read_file"),
            parameters=ActionParameters(raw={}),
            context=ActionContext(session_id="session-1"),
        )
    )
    store.close()

    gov04 = next(result for result in evaluation.control_results if result.control_id == "GOV-04")
    assert gov04.result == "PASS"
    assert "fresh manual attestation" in gov04.detail.lower()
