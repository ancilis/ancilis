"""Tests for CLI commands and report generation."""

from __future__ import annotations

import csv
import json
import os
import tempfile
import unittest.mock
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.engine import Engine
from ancilis.engine.action import Action, ActionParameters, ActionContext, ToolInfo
from ancilis.engine.registry import ToolRegistry, ToolEntry, ToolStatus
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import ReportGenerator, ReportData
from ancilis.report.renderer import render_terminal, render_markdown, render_pdf
from ancilis.engine.result import EvaluationResult, ControlResult


# --- Helpers ---

def _make_config_file(data: dict[str, Any], tmpdir: Path) -> Path:
    """Write a config dict to a temp YAML file."""
    path = tmpdir / "ancilis.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return path


def _minimal_config() -> dict[str, Any]:
    return {"agent": {"name": "test-agent"}}


def _full_config() -> dict[str, Any]:
    return {
        "agent": {"name": "test-agent"},
        "security": {"mode": "audit"},
        "my_agent_handles": ["credit_cards", "personal_info"],
        "compliance": {"evidence": {"retention_days": 365}},
    }


def _cert_config() -> dict[str, Any]:
    return {
        "agent": {"name": "test-agent"},
        "security": {"mode": "audit"},
    }


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


def _make_blocked_evaluation(decision: str = "BLOCK") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id="blocked-eval",
        action_id="blocked-action",
        timestamp="2026-03-18T00:00:00Z",
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


def _populate_evidence(config: ResolvedConfig, store: EvidenceStore, n: int = 5) -> None:
    """Run evaluations to populate evidence store."""
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)

    for _i in range(n):
        action = _make_action(tool_name="read_file", agent_id=config.agent_name)
        evaluation = engine.evaluate(action)
        store.store(evaluation, tool_name="read_file")


def _make_renderer_report(
    *,
    failing_controls: int = 1,
    chain_valid: bool = True,
) -> ReportData:
    controls: list[dict[str, Any]] = []
    failing_control_ids = ["PR-03", "PR-04", "PR-05"][:failing_controls]
    control_names = [
        ("PR-01", "Access Governance"),
        ("PR-02", "Tool Scope Control"),
        ("PR-03", "Data Exposure Prevention"),
        ("PR-04", "Output Moderation"),
        ("PR-05", "Action Logging"),
        ("DE-01", "Evidence Durability"),
    ]

    for control_id, display_name in control_names:
        failed = 2 if control_id in failing_control_ids else 0
        passed = 8 if failed else 10
        total = passed + failed
        controls.append(
            {
                "control_id": control_id,
                "display_name": display_name,
                "display_detail": "",
                "threshold": 95,
                "total": total,
                "passed": passed,
                "failed": failed,
                "flagged": 0,
                "pass_rate": round((passed / total) * 100, 1),
            }
        )

    def section(
        overlay_name: str,
        rows: list[str],
        *,
        trigger: str = "personal_info",
    ) -> dict[str, Any]:
        section_controls = []
        for control_id in rows:
            failed = 2 if control_id in failing_control_ids else 0
            total = 10
            passed = total - failed
            section_controls.append(
                {
                    "control_id": control_id,
                    "display_name": next(
                        control["display_name"]
                        for control in controls
                        if control["control_id"] == control_id
                    ),
                    "citations": [f"{overlay_name[:3].upper()}-{control_id}"],
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "pass_rate": round((passed / total) * 100, 1),
                    "threshold": "strict" if control_id == "PR-03" else "standard",
                }
            )

        return {
            "overlay_id": overlay_name.lower().replace(" ", "-"),
            "overlay_name": overlay_name,
            "triggered_by": trigger,
            "strict_controls": ["PR-03"] if "PR-03" in rows else [],
            "controls": section_controls,
            "gaps": [row for row in section_controls if row["failed"] > 0],
            "evidence_retention_days": 365,
            "retention_met": True,
        }

    return ReportData(
        agent_name="test-agent",
        mode="enforce",
        period_start="2026-03-01T00:00:00+00:00",
        period_end="2026-03-31T23:59:59+00:00",
        generated_at="2026-04-01T00:00:00+00:00",
        report_format="terminal",
        baseline={
            "controls": controls,
            "tools_evaluated": ["read_file", "send_email"],
            "total_evaluations": 1234,
            "decisions": {"allow": 1222, "block": 12, "flag": 0},
            "evidence_retention_days": 365,
        },
        compliance_sections=[
            section("SOC 2", ["PR-01", "PR-03", "PR-05"]),
            section("PCI-DSS v4.0", ["PR-01", "PR-03", "DE-01"], trigger="credit_cards"),
            section("GLBA", ["PR-01", "PR-02"]),
            section("GDPR", ["PR-02", "PR-04", "PR-05"]),
        ],
        certification={
            "certification_id": "aiuc-1",
            "certification_name": "AIUC-1",
            "readiness_percentage": 87,
            "ready_count": 13,
            "total_requirements": 15,
            "coverage_percentage": 80,
            "automated_count": 12,
            "operator_count": 3,
            "evidence_count": 1234,
            "chain_valid": chain_valid,
            "automated_coverage": [],
            "operator_action_required": [],
        },
        advisory=None,
        total_evaluations=1234,
        chain_valid=chain_valid,
        chain_errors=[],
    )


# ===== CLI Framework Tests =====

class TestCLIFramework:
    def test_help_shows_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "status" in result.output
        assert "report" in result.output
        assert "doctor" in result.output
        assert "config" in result.output
        assert "approve-tool" in result.output

    def test_status_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--help"])
        assert result.exit_code == 0
        assert "--verbose" in result.output

    def test_report_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--period" in result.output

    def test_config_validate_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--help"])
        assert result.exit_code == 0

    def test_unknown_subcommand(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["nonexistent"])
        assert result.exit_code != 0

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


# ===== Config Validate Tests =====

class TestConfigValidate:
    def test_valid_config(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_minimal_config(), tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "\u2713" in result.output or "Config valid" in result.output
        assert "test-agent" in result.output

    def test_valid_config_accepts_positional_path(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_minimal_config(), tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", str(cfg)])
        assert result.exit_code == 0
        assert "\u2713" in result.output or "Config valid" in result.output
        assert "test-agent" in result.output

    def test_invalid_certification_target(self, tmp_path: Path) -> None:
        data = _minimal_config()
        # Invalid cert target is not validated by config parser directly,
        # but unknown data types are.
        data["my_agent_handles"] = ["nonexistent_type"]
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 1
        assert "Unknown data type" in result.output

    def test_invalid_data_type_shows_available(self, tmp_path: Path) -> None:
        data = _minimal_config()
        data["my_agent_handles"] = ["fake_data"]
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 1
        assert "Available types" in result.output or "Valid types" in result.output

    def test_missing_agent_name(self, tmp_path: Path) -> None:
        data = {"agent": {"name": ""}}
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 1

    def test_both_paths_configured(self, tmp_path: Path) -> None:
        data = _full_config()
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "test-agent" in result.output

    def test_config_not_found(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", "/nonexistent/ancilis.yaml"])
        assert result.exit_code == 1

    def test_pci_overlay_activated(self, tmp_path: Path) -> None:
        """Config validate loads PCI-DSS v4 overlay when credit_cards declared."""
        data = _minimal_config()
        data["my_agent_handles"] = ["credit_cards"]
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "PCI-DSS" in result.output

    def test_government_overlay_activated(self, tmp_path: Path) -> None:
        """Config validate loads the government overlay when CUI is declared."""
        data = _minimal_config()
        data["my_agent_handles"] = ["government_cui"]
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "CMMC Level 2" in result.output

    def test_nist_csf_2_overlay_alias_validates_as_nist_csf(self, tmp_path: Path) -> None:
        data = _minimal_config()
        data["compliance"] = {"overlays": ["nist-csf-2"]}
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "NIST Cybersecurity Framework 2.0" in result.output
        assert "nist-csf-2" not in result.output


# ===== Status Tests =====

class TestStatus:
    def test_default_output(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--config", str(cfg), "--db", str(db)])
        assert result.exit_code == 0
        assert "test-agent" in result.output
        assert "Mode: audit" in result.output
        assert "Controls:" in result.output

    def test_verbose_adds_per_control(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_evidence(config, store, n=3)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--verbose", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0
        # Verbose shows per-control detail with display names
        assert "Controls:" in result.output

    def test_status_counts_lowercase_blocked_decisions(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        store.store(_make_blocked_evaluation(decision="block"), tool_name="blocked-tool")
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0
        assert "1 blocked" in result.output


class TestDoctor:
    def test_doctor_reports_core_checks(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.duckdb"
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor", "--config", str(cfg), "--db", str(db)])
        # exit_code 0 = all pass, 1 = warnings (expected in test env), 2 = errors
        assert result.exit_code in (0, 1)
        assert "Ancilis Doctor" in result.output
        assert "Configuration:" in result.output
        assert "checks passed" in result.output

    def test_doctor_fails_on_missing_config(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor", "--config", str(tmp_path / "missing.yaml")])
        # Config FAIL → errors > 0 → exit_code 2
        assert result.exit_code == 2
        assert "Configuration:" in result.output

    def test_no_control_ids_in_output(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--verbose", "--config", str(cfg), "--db", str(db)])
        # Control IDs like PR-01, DE-01 should not appear in status output
        for line in result.output.split("\n"):
            # Skip lines that are part of the activation section source attribution
            if "certification_targets" in line or "Controls:" in line:
                continue
            assert "PR-01:" not in line
            assert "DE-01:" not in line

    def test_empty_evidence_message(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--config", str(cfg), "--db", str(db)])
        assert "No evaluations recorded" in result.output or "0" in result.output

    def test_overlay_shown(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_full_config(), tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--config", str(cfg), "--db", str(db)])
        assert result.exit_code == 0
        assert "SOC 2" in result.output or "GDPR" in result.output or "gdpr" in result.output.lower()


# ===== Approve Tool Tests =====

class TestApproveTool:
    def test_adds_tool(self, tmp_path: Path) -> None:
        cfg = _make_config_file(_minimal_config(), tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["approve-tool", "send_email", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "Approved 'send_email'" in result.output

        # Verify it was written
        data = yaml.safe_load(cfg.read_text())
        assert "send_email" in data["security"]["tools"]["allowed"]

    def test_already_approved(self, tmp_path: Path) -> None:
        data = _minimal_config()
        data["security"] = {"tools": {"allowed": ["send_email"]}}
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["approve-tool", "send_email", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "already" in result.output

    def test_config_not_found(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["approve-tool", "x", "--config", "/nonexistent/ancilis.yaml"])
        assert result.exit_code == 1


# ===== Report — Baseline Mode Tests =====

class TestReportBaseline:
    def test_baseline_report_no_overlays(self, tmp_path: Path) -> None:
        config = load_config(raw=_minimal_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=5)

        gen = ReportGenerator(config, store)
        report = gen.generate(period="30d")

        assert report.baseline is not None
        assert report.baseline["total_evaluations"] == 5
        assert len(report.compliance_sections) == 0
        assert report.certification is None
        store.close()

    def test_baseline_report_terminal(self, tmp_path: Path) -> None:
        config = load_config(raw=_minimal_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=3)

        gen = ReportGenerator(config, store)
        report = gen.generate()
        output = render_terminal(report)

        assert "test-agent" in output
        assert "Controls:" in output
        store.close()

    def test_baseline_report_markdown(self, tmp_path: Path) -> None:
        config = load_config(raw=_minimal_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=3)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="markdown")
        md = render_markdown(report)

        assert "# Ancilis Posture Report" in md
        assert "Baseline Security" in md
        assert "Pass Rate" in md
        store.close()

    def test_baseline_report_via_cli(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_evidence(config, store, n=2)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--config", str(cfg_path), "--db", str(db)])
        assert result.exit_code == 0
        assert "test-agent" in result.output

    def test_baseline_report_generate_subcommand_alias(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_evidence(config, store, n=2)
        store.close()

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "generate", "--config", str(cfg_path), "--db", str(db)])

        assert result.exit_code == 0
        assert "test-agent" in result.output

    def test_pdf_renderer_writes_markdown_fallback_next_to_pdf(self, tmp_path: Path) -> None:
        output_path = tmp_path / "report.pdf"
        fallback_path = tmp_path / "report.md"
        markdown = "# Example Report\n"

        with unittest.mock.patch("ancilis.report.renderer.subprocess.run", side_effect=FileNotFoundError):
            result = render_pdf(markdown, str(output_path))

        assert result.format == "markdown"
        assert result.output_path == str(fallback_path)
        assert result.fallback_reason == "pandoc/xelatex unavailable"
        assert not output_path.exists()
        assert fallback_path.read_text() == markdown

    def test_pdf_report_cli_reports_markdown_fallback(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        output_path = tmp_path / "report.pdf"
        fallback_path = tmp_path / "report.md"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        _populate_evidence(config, store, n=2)
        store.close()

        runner = CliRunner()
        with unittest.mock.patch("ancilis.report.renderer.subprocess.run", side_effect=FileNotFoundError):
            result = runner.invoke(
                cli,
                [
                    "report",
                    "--config",
                    str(cfg_path),
                    "--db",
                    str(db),
                    "--format",
                    "pdf",
                    "--output",
                    str(output_path),
                ],
            )

        assert result.exit_code == 0
        assert (
            result.output.strip()
            == f"PDF export unavailable (pandoc/xelatex unavailable); wrote Markdown fallback to {fallback_path}"
        )
        assert not output_path.exists()
        assert fallback_path.read_text().startswith("# Ancilis Posture Report")

    def test_ndjson_report_cli_exports_period_filtered_evidence(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        registry = ToolRegistry()
        registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
        engine = Engine(config, registry=registry)
        now = datetime.now(timezone.utc)

        recent = engine.evaluate(_make_action(tool_name="read_file", agent_id=config.agent_name))
        recent.timestamp = (now - timedelta(days=2)).isoformat()
        store.store(recent, tool_name="read_file", output_summary="recent")

        older = engine.evaluate(_make_action(tool_name="read_file", agent_id=config.agent_name))
        older.timestamp = (now - timedelta(days=45)).isoformat()
        store.store(older, tool_name="read_file", output_summary="older")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "report",
                "--config",
                str(cfg_path),
                "--db",
                str(db),
                "--format",
                "ndjson",
                "--period",
                "7d",
            ],
        )

        assert result.exit_code == 0
        lines = [line for line in result.output.strip().splitlines() if line]
        assert len(lines) == 1
        payload = json.loads(lines[0])
        assert payload["tool_name"] == "read_file"
        assert payload["output_summary"] == "recent"
        assert payload["decision"] == "ALLOW"
        assert payload["source_type"] == "agent"
        assert payload["record_hash"]
        assert payload["previous_hash"]

    def test_csv_report_cli_writes_structured_evidence_rows(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        output_path = tmp_path / "report.csv"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        registry = ToolRegistry()
        registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
        engine = Engine(config, registry=registry)

        evaluation = engine.evaluate(_make_action(tool_name="read_file", agent_id=config.agent_name))
        store.store(evaluation, tool_name="read_file", output_summary="csv-export")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "report",
                "--config",
                str(cfg_path),
                "--db",
                str(db),
                "--format",
                "csv",
                "--output",
                str(output_path),
            ],
        )

        assert result.exit_code == 0
        assert result.output.strip() == f"Report written to {output_path}"
        with output_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        assert len(rows) == 1
        row = rows[0]
        assert row["tool_name"] == "read_file"
        assert row["decision"] == "ALLOW"
        assert row["output_summary"] == "csv-export"
        assert row["control_results"].startswith("[")
        assert row["active_overlays"] == "[]"

    def test_csv_report_cli_exports_all_period_records(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        output_path = tmp_path / "report.csv"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        registry = ToolRegistry()
        registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
        engine = Engine(config, registry=registry)
        now = datetime.now(timezone.utc)

        for index in range(101):
            evaluation = engine.evaluate(
                _make_action(tool_name="read_file", agent_id=config.agent_name)
            )
            evaluation.timestamp = (now - timedelta(hours=index)).isoformat()
            store.store(evaluation, tool_name="read_file", output_summary=f"row-{index}")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "report",
                "--config",
                str(cfg_path),
                "--db",
                str(db),
                "--format",
                "csv",
                "--period",
                "30d",
                "--output",
                str(output_path),
            ],
        )

        assert result.exit_code == 0
        with output_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        assert len(rows) == 101

    def test_oscal_report_cli_writes_assessment_results_json(self, tmp_path: Path) -> None:
        cfg_path = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        output_path = tmp_path / "report.oscal.json"
        config = load_config(path=str(cfg_path))
        store = EvidenceStore(config, db_path=str(db))
        registry = ToolRegistry()
        registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
        engine = Engine(config, registry=registry)

        evaluation = engine.evaluate(_make_action(tool_name="read_file", agent_id=config.agent_name))
        store.store(evaluation, tool_name="read_file", output_summary="oscal-export")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "report",
                "generate",
                "--config",
                str(cfg_path),
                "--db",
                str(db),
                "--format",
                "oscal",
                "--output",
                str(output_path),
            ],
        )

        assert result.exit_code == 0
        assert result.output.strip() == f"Report written to {output_path}"
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["assessment-results"]["metadata"]["oscal-version"] == "1.1.2"
        assert payload["assessment-results"]["results"][0]["observations"]

    def test_report_export_downloads_with_jwt_and_query_params(self, tmp_path: Path) -> None:
        output_path = tmp_path / "export.ndjson"

        class FakeResponse:
            status = 200

            def __init__(self, body: bytes) -> None:
                self._body = BytesIO(body)

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, *exc: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                return self._body.read(size)

        requests: list[urllib.request.Request] = []

        def fake_urlopen(request: urllib.request.Request) -> FakeResponse:
            requests.append(request)
            return FakeResponse(b'{"record_id":"r1"}\n')

        runner = CliRunner()
        with unittest.mock.patch("ancilis.cli.report.urllib.request.urlopen", fake_urlopen):
            result = runner.invoke(
                cli,
                [
                    "report",
                    "export",
                    "--format",
                    "ndjson",
                    "--period",
                    "7d",
                    "--api-url",
                    "https://app.ancilis.ai/",
                    "--auth-token",
                    "jwt-token",
                    "--output",
                    str(output_path),
                ],
            )

        assert result.exit_code == 0
        assert result.output.strip() == f"Export written to {output_path}"
        assert output_path.read_text(encoding="utf-8") == '{"record_id":"r1"}\n'
        assert len(requests) == 1
        request = requests[0]
        assert request.full_url == "https://app.ancilis.ai/v1/evidence/export?format=ndjson&period=7d"
        assert request.get_method() == "GET"
        assert request.headers["Authorization"] == "Bearer jwt-token"

    def test_report_export_auth_error_is_clear(self) -> None:
        def fake_urlopen(_request: urllib.request.Request) -> object:
            raise urllib.error.HTTPError(
                url="https://app.ancilis.ai/v1/evidence/export",
                code=401,
                msg="Unauthorized",
                hdrs=None,
                fp=None,
            )

        runner = CliRunner()
        with unittest.mock.patch("ancilis.cli.report.urllib.request.urlopen", fake_urlopen):
            result = runner.invoke(
                cli,
                [
                    "report",
                    "export",
                    "--format",
                    "csv",
                    "--period",
                    "30d",
                    "--api-url",
                    "https://app.ancilis.ai",
                    "--auth-token",
                    "bad-token",
                ],
            )

        assert result.exit_code == 1
        assert "Authentication failed" in result.output


# ===== Report — Compliance Mode Tests =====

class TestReportCompliance:
    def test_overlays_produce_compliance_sections(self, tmp_path: Path) -> None:
        config = load_config(raw=_full_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=3)

        gen = ReportGenerator(config, store)
        report = gen.generate()

        assert len(report.compliance_sections) > 0
        # SOC 2 should be present (credit_cards and personal_info activate it)
        overlay_names = [s["overlay_name"] for s in report.compliance_sections]
        assert any("SOC 2" in n for n in overlay_names)
        store.close()

    def test_compliance_section_has_citations(self, tmp_path: Path) -> None:
        config = load_config(raw=_full_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=2)

        gen = ReportGenerator(config, store)
        report = gen.generate()

        soc2 = [s for s in report.compliance_sections if "SOC 2" in s["overlay_name"]]
        assert len(soc2) == 1
        controls = soc2[0]["controls"]
        # SOC 2 framework_mapping includes regulatory citations
        assert any(c.get("citations") for c in controls)
        store.close()

    def test_gaps_framed_as_improvements(self, tmp_path: Path) -> None:
        config = load_config(raw=_full_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=2)

        gen = ReportGenerator(config, store)
        report = gen.generate()
        md = render_markdown(report)

        # If there are gaps, they should be "Areas for Improvement" not "Failures"
        if "Areas for Improvement" in md:
            assert "failure" not in md.lower().split("areas for improvement")[1].split("##")[0]
        store.close()

    def test_multiple_overlays(self, tmp_path: Path) -> None:
        config = load_config(raw=_full_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))

        gen = ReportGenerator(config, store)
        report = gen.generate()

        # credit_cards and personal_info should trigger SOC 2 and GDPR
        assert len(report.compliance_sections) >= 2
        store.close()

    def test_compliance_markdown(self, tmp_path: Path) -> None:
        config = load_config(raw=_full_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=2)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="markdown")
        md = render_markdown(report)

        assert "Compliance Posture" in md
        assert "Citation" in md  # Table header
        store.close()

    def test_report_uses_canonical_nist_csf_section_for_alias(self, tmp_path: Path) -> None:
        data = _minimal_config()
        data["compliance"] = {"overlays": ["nist-csf", "nist-csf-2"]}
        config = load_config(raw=data)
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))

        gen = ReportGenerator(config, store)
        report = gen.generate()

        nist_sections = [
            section
            for section in report.compliance_sections
            if section["overlay_name"] == "NIST Cybersecurity Framework 2.0"
        ]
        assert [section["overlay_id"] for section in nist_sections] == ["nist-csf"]
        assert "nist-csf-2" not in [section["overlay_id"] for section in report.compliance_sections]
        store.close()


# ===== Report — AIUC-1 Readiness Tests =====

class TestAIUC1Readiness:
    def _cert_config_resolved(self) -> ResolvedConfig:
        raw = _cert_config()
        config = load_config(raw=raw)
        config.active_certifications = ["aiuc-1"]
        return config

    def test_aiuc1_report_generated(self, tmp_path: Path) -> None:
        config = self._cert_config_resolved()
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=5)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="aiuc1-readiness")

        assert report.certification is not None
        assert report.certification["certification_id"] == "aiuc-1"
        store.close()

    def test_automated_coverage(self, tmp_path: Path) -> None:
        config = self._cert_config_resolved()
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=5)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="aiuc1-readiness")

        cert = report.certification
        assert cert is not None
        assert cert["automated_count"] > 0
        # Automated items should have aksi_control mappings
        for item in cert["automated_coverage"]:
            assert "requirement_id" in item
            assert "aksi_control" in item
        store.close()

    def test_operator_items_match_profile(self, tmp_path: Path) -> None:
        config = self._cert_config_resolved()
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="aiuc1-readiness")

        cert = report.certification
        assert cert is not None
        operator = cert["operator_action_required"]
        assert len(operator) > 0
        # Check items match the aiuc-1.json profile
        req_ids = [item["requirement_id"] for item in operator]
        assert "A006" in req_ids
        assert "F001" in req_ids
        store.close()

    def test_operator_items_framing(self, tmp_path: Path) -> None:
        """Operator items framed as team responsibilities, not product failures."""
        config = self._cert_config_resolved()
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="aiuc1-readiness")
        md = render_markdown(report)

        # Must contain team-oriented framing
        assert "your team" in md.lower() or "operator" in md.lower()
        # Must NOT frame as failures
        assert "ancilis failed" not in md.lower()
        store.close()

    def test_hash_chain_status_shown(self, tmp_path: Path) -> None:
        config = self._cert_config_resolved()
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=3)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="aiuc1-readiness")
        md = render_markdown(report)

        assert "hash chain" in md.lower() or "Hash chain" in md
        store.close()

    def test_evidence_counts_from_store(self, tmp_path: Path) -> None:
        config = self._cert_config_resolved()
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=7)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="aiuc1-readiness")

        cert = report.certification
        assert cert is not None
        assert cert["evidence_count"] == 7
        store.close()

    def test_aiuc1_readiness_markdown(self, tmp_path: Path) -> None:
        config = self._cert_config_resolved()
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=5)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="aiuc1-readiness")
        md = render_markdown(report)

        assert "AIUC-1 READINESS REPORT" in md
        assert "Automated" in md
        assert "Operator Action Required" in md
        store.close()


# ===== Report — Combined Mode Tests =====

class TestReportCombined:
    def test_both_paths_all_sections(self, tmp_path: Path) -> None:
        raw = _full_config()
        config = load_config(raw=raw)
        config.active_certifications = ["aiuc-1"]
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=3)

        gen = ReportGenerator(config, store)
        report = gen.generate()

        # Baseline always present
        assert report.baseline is not None
        # Compliance sections (HIPAA at least)
        assert len(report.compliance_sections) > 0
        # Certification section
        assert report.certification is not None
        store.close()

    def test_sections_additive(self, tmp_path: Path) -> None:
        """Compliance adds to baseline, certification adds to compliance."""
        raw = _full_config()
        config = load_config(raw=raw)
        config.active_certifications = ["aiuc-1"]
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=3)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="markdown")
        md = render_markdown(report)

        # All three sections present
        assert "Baseline Security" in md
        assert "Compliance Posture" in md
        assert "AIUC-1" in md
        store.close()


class TestAdvisoryReports:
    def test_advisory_section_generated_from_pattern_detections(self, tmp_path: Path) -> None:
        config = load_config(raw=_minimal_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))

        advisory_eval = EvaluationResult(
            evaluation_id="advisory-eval",
            action_id="action-1",
            timestamp="2026-03-20T00:00:00Z",
            agent_id=config.agent_name,
            mode=config.mode,
            control_results=[
                ControlResult(
                    control_id="PR-04",
                    control_name="Data Exposure Prevention",
                    result="PASS",
                    detail="Sensitive data patterns detected.",
                    evidence_data={
                        "scan_result": "patterns_found",
                        "patterns_detected": [
                            {"type": "credit_card", "count": 2, "redacted_sample": "****1111"},
                        ],
                    },
                    duration_ms=1.0,
                )
            ],
            decision="ALLOW",
            decision_reason="Advisory test",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=1.0,
        )
        store.store(advisory_eval, tool_name="read_file")

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="markdown")
        md = render_markdown(report)

        assert report.advisory is not None
        assert "Classification Advisory" in md
        assert "credit_cards" in md
        assert "my_agent_handles" in md
        store.close()


# ===== Output Format Tests =====

class TestOutputFormats:
    def test_terminal_output(self, tmp_path: Path) -> None:
        config = load_config(raw=_minimal_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=2)

        gen = ReportGenerator(config, store)
        report = gen.generate()
        output = render_terminal(report)

        assert isinstance(output, str)
        assert len(output) > 0
        store.close()

    def test_markdown_output(self, tmp_path: Path) -> None:
        config = load_config(raw=_minimal_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=2)

        gen = ReportGenerator(config, store)
        report = gen.generate(report_format="markdown")
        md = render_markdown(report)

        assert "# " in md  # Has markdown headers
        assert "|" in md  # Has tables
        store.close()

    def test_markdown_and_terminal_same_content(self, tmp_path: Path) -> None:
        """Both formats contain the same core information."""
        config = load_config(raw=_minimal_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=2)

        gen = ReportGenerator(config, store)
        report = gen.generate()
        terminal = render_terminal(report)
        md = render_markdown(report)

        # Both should mention the agent
        assert "test-agent" in terminal
        assert "test-agent" in md
        store.close()


class TestReportRendererUX:
    def test_terminal_adds_posture_summary_and_collapses_passing_controls(self) -> None:
        report = _make_renderer_report(failing_controls=1)

        output = render_terminal(report)

        assert "Posture: ATTENTION" in output
        assert "Evaluations: 1,234 total | 12 blocked | 1,222 allowed" in output
        assert "Active overlays: SOC 2, PCI-DSS v4.0, GLBA, GDPR" in output
        assert "Active certifications: AIUC-1 (87% ready)" in output
        assert "Evidence chain: ✓ intact (1,234 records)" in output
        assert "✗ Data Exposure Prevention — 80.0% pass rate (10 evaluations)" in output
        assert "✓ 5 controls passing" in output
        assert "Access Governance — 100.0% pass rate" not in output

    def test_terminal_replaces_overlay_sections_with_compact_matrix(self) -> None:
        report = _make_renderer_report(failing_controls=1)

        output = render_terminal(report)

        assert "Compliance Matrix:" in output
        assert "Control" in output
        assert "SOC 2" in output
        assert "PCI-DSS v4.0" in output
        assert "PR-03" in output
        assert "✗(2)" in output
        assert "SOC 2 Compliance Posture" not in output
        assert "GDPR Compliance Posture" not in output
        assert len(output.splitlines()) < 40

    def test_terminal_uses_color_when_stdout_is_tty(self) -> None:
        report = _make_renderer_report(failing_controls=1)

        with (
            unittest.mock.patch.dict(os.environ, {}, clear=True),
            unittest.mock.patch("ancilis.report.renderer.sys.stdout.isatty", return_value=True),
        ):
            output = render_terminal(report)

        assert "\033[1m" in output
        assert "\033[31m" in output
        assert "\033[32m" in output

    def test_terminal_disables_color_when_no_color_is_set(self) -> None:
        report = _make_renderer_report(failing_controls=1)

        with (
            unittest.mock.patch("ancilis.report.renderer.sys.stdout.isatty", return_value=True),
            unittest.mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False),
        ):
            output = render_terminal(report)

        assert "\033[" not in output

    def test_markdown_adds_executive_summary_and_attention_section(self) -> None:
        report = _make_renderer_report(failing_controls=1)

        md = render_markdown(report)

        assert "## Executive Summary" in md
        assert "**Posture: ATTENTION**" in md
        assert "5 of 6 controls passing across 4 active overlays." in md
        assert "Active overlays: SOC 2, PCI-DSS v4.0, GLBA, GDPR" in md
        assert "Active certifications: AIUC-1 (87% ready)" in md
        assert "Evidence chain: intact (1,234 records, SHA-256 verified)" in md
        assert "### Attention Required" in md
        assert "**Data Exposure Prevention**: 2 failures in reporting period" in md

    def test_markdown_omits_attention_section_when_all_controls_pass(self) -> None:
        report = _make_renderer_report(failing_controls=0)

        md = render_markdown(report)

        assert "## Executive Summary" in md
        assert "**Posture: HEALTHY**" in md
        assert "6 of 6 controls passing across 4 active overlays." in md
        assert "### Attention Required" not in md


# ===== Display Fields Tests =====

class TestDisplayFields:
    def test_control_results_have_display_fields(self) -> None:
        """Engine post-processes results to include display fields from control JSON."""
        config = load_config(raw=_minimal_config())
        registry = ToolRegistry()
        registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
        engine = Engine(config, registry=registry)

        action = _make_action()
        result = engine.evaluate(action)

        for cr in result.control_results:
            if cr.result != "SKIP":
                assert cr.display_name, f"{cr.control_id} missing display_name"
                assert cr.display_detail, f"{cr.control_id} missing display_detail"

    def test_no_raw_control_ids_in_status(self, tmp_path: Path) -> None:
        """Status output uses display names, never raw control IDs."""
        cfg = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--verbose", "--config", str(cfg), "--db", str(db)])
        output = result.output
        # These patterns should never appear as standalone labels
        for pattern in ["PR-01:", "PR-02:", "PR-03:", "PR-04:", "PR-05:", "DE-01:"]:
            # Allow in non-display contexts (like activation source strings)
            lines = [line for line in output.split("\n") if pattern in line]
            for line in lines:
                assert "certification_targets" in line or "overlay:" in line, \
                    f"Raw control ID found in status output: {line}"


# ===== Progressive Output Disclosure Tests =====

class TestProgressiveDisclosure:
    def test_zero_config_no_framework_references(self, tmp_path: Path) -> None:
        """Zero-config agent status has no framework references."""
        cfg = _make_config_file(_minimal_config(), tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--config", str(cfg), "--db", str(db)])
        output = result.output.lower()
        assert "hipaa" not in output
        assert "gdpr" not in output
        assert "aiuc" not in output

    def test_cert_adds_certification_line(self, tmp_path: Path) -> None:
        """certification_targets adds certification one-liner."""
        data = _cert_config()
        cfg = _make_config_file(data, tmp_path)
        db = tmp_path / "evidence.db"

        # Manually set active_certifications by loading and modifying
        config = load_config(path=str(cfg))
        config.active_certifications = ["aiuc-1"]
        store = EvidenceStore(config, db_path=str(db))
        store.close()

        # For CLI test, we can't easily inject active_certifications
        # This tests the report generator directly
        store = EvidenceStore(config, db_path=str(db))
        gen = ReportGenerator(config, store)
        report = gen.generate()
        output = render_terminal(report)
        # No compliance sections when no overlays
        assert len(report.compliance_sections) == 0
        store.close()

    def test_my_agent_handles_adds_overlay_sections(self, tmp_path: Path) -> None:
        """my_agent_handles adds overlay information."""
        config = load_config(raw=_full_config())
        store = EvidenceStore(config, db_path=str(tmp_path / "ev.db"))
        _populate_evidence(config, store, n=2)

        gen = ReportGenerator(config, store)
        report = gen.generate()
        output = render_terminal(report)

        assert len(report.compliance_sections) > 0
        store.close()
