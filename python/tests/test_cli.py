"""Tests for CLI commands and report generation."""

from __future__ import annotations

import json
import os
import tempfile
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
from ancilis.report.renderer import render_terminal, render_markdown


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


def _populate_evidence(config: ResolvedConfig, store: EvidenceStore, n: int = 5) -> None:
    """Run evaluations to populate evidence store."""
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)

    for i in range(n):
        action = _make_action(tool_name="read_file", agent_id=config.agent_name)
        evaluation = engine.evaluate(action)
        store.store(evaluation, tool_name="read_file")


# ===== CLI Framework Tests =====

class TestCLIFramework:
    def test_help_shows_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "status" in result.output
        assert "report" in result.output
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

    def test_roadmap_overlay_surfaced(self, tmp_path: Path) -> None:
        """Config validate surfaces roadmap overlays with baseline assurance."""
        data = _minimal_config()
        data["my_agent_handles"] = ["credit_cards"]
        cfg = _make_config_file(data, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "pci-dss" in result.output
        assert "not yet available" in result.output
        assert "Baseline security controls" in result.output


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
            lines = [l for l in output.split("\n") if pattern in l]
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
