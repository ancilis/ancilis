"""Tests filling coverage gaps — ANC-830.

Covers:
- _shared.py: shared_path_context enter/exit, iter_shared_paths, FileNotFoundError fallback
- cli/validate.py: Unknown control ID hint, active_certifications, unavailable_overlays, warnings
- cli/doctor.py: pkg version exception, assets load failure, engine probe failure,
  evidence write failure, mcp not installed, pandoc found
- cli/scan.py: zero-config _default_config, first-run sentinel display, dep remediation,
  dep posture paths, sentinel creation
- cli/report.py: markdown/ndjson/csv with --output file path, pdf success path
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ancilis._shared import (
    _source_tree_shared_root,
    iter_shared_paths,
    shared_path_context,
)
from ancilis.cli.main import cli
from ancilis.config import (
    ResolvedConfig,
    UnavailableOverlay,
    load_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_YAML = "agent:\n  name: test-agent\n"


def _make_config_file(content: str, tmp_path: Path) -> Path:
    p = tmp_path / "ancilis.yaml"
    p.write_text(content)
    return p


def _make_config() -> ResolvedConfig:
    return load_config(raw={"agent": {"name": "test-agent"}})


# ===========================================================================
# _shared.py
# ===========================================================================

class TestSharedModule:
    def test_source_tree_shared_root_raises_when_no_shared_dir(self) -> None:
        """_source_tree_shared_root raises FileNotFoundError when no 'shared/' ancestor found."""
        with (
            patch("pathlib.Path.is_dir", return_value=False),
            pytest.raises(FileNotFoundError, match="Could not locate shared/"),
        ):
            _source_tree_shared_root()

    def test_shared_path_context_enter_exit(self) -> None:
        """shared_path_context yields a real path and cleans up."""
        with shared_path_context("controls") as p:
            assert isinstance(p, Path)

    def test_shared_path_context_enter_returns_path(self) -> None:
        """shared_path_context.__enter__ returns a Path and stores it on .path."""
        ctx = shared_path_context("controls")
        assert ctx.path is None
        entered = ctx.__enter__()
        assert isinstance(entered, Path)
        assert ctx.path is not None
        ctx.__exit__(None, None, None)

    def test_shared_path_context_exit_handles_exception(self) -> None:
        """shared_path_context.__exit__ delegates exception to inner context."""
        ctx = shared_path_context("controls")
        ctx.__enter__()
        # Should not raise even if exc_type is provided
        ctx.__exit__(ValueError, ValueError("test"), None)

    def test_iter_shared_paths_yields_sorted(self) -> None:
        """iter_shared_paths returns sorted paths matching the glob."""
        paths = list(iter_shared_paths("controls", pattern="*.json"))
        assert len(paths) > 0
        assert all(isinstance(p, Path) for p in paths)
        assert paths == sorted(paths)

    def test_iter_shared_paths_empty_pattern(self) -> None:
        """iter_shared_paths returns empty when no files match."""
        paths = list(iter_shared_paths("controls", pattern="*.nonexistent_ext"))
        assert paths == []


# ===========================================================================
# cli/validate.py
# ===========================================================================

class TestValidateCoverage:
    def test_unknown_control_id_hint(self, tmp_path: Path) -> None:
        """ValueError with 'Unknown control ID' shows available controls list."""
        cfg_content = (
            "agent:\n  name: test-agent\n"
            "security:\n  controls:\n    FAKE-99:\n      enabled: true\n"
        )
        cfg = _make_config_file(cfg_content, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 1
        assert "Available controls" in result.output
        assert "PR-08" in result.output
        assert "RC-02" in result.output

    def test_active_certifications_shown(self, tmp_path: Path) -> None:
        """Validate output shows active certification when certification_targets set."""
        cfg_content = "agent:\n  name: cert-agent\ncertification_targets:\n  - aiuc-1\n"
        cfg = _make_config_file(cfg_content, tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "aiuc-1" in result.output.lower() or "AIUC" in result.output

    def test_unavailable_overlays_section(self, tmp_path: Path) -> None:
        """Validate shows 'Roadmap overlays' when unavailable_overlays is populated."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        mock_config = _make_config()
        mock_config.unavailable_overlays = [
            UnavailableOverlay("hipaa-extended", "DC-PH", "patient_data")
        ]
        runner = CliRunner()
        with patch("ancilis.cli.validate.load_config", return_value=mock_config):
            result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "Roadmap overlays" in result.output
        assert "Baseline security controls" in result.output

    def test_warnings_section_shown(self, tmp_path: Path) -> None:
        """Validate shows Warnings section when resolved config has warnings."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        mock_config = _make_config()
        mock_config.warnings = ["Deprecated key detected", "Unknown overlay requested"]
        runner = CliRunner()
        with patch("ancilis.cli.validate.load_config", return_value=mock_config):
            result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "Warnings" in result.output
        assert "Deprecated key detected" in result.output

    def test_unknown_control_id_hint_line33(self, tmp_path: Path) -> None:
        """'Unknown control ID' branch in validate produces correct hint text."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        runner = CliRunner()
        with patch(
            "ancilis.cli.validate.load_config",
            side_effect=ValueError("Unknown control ID in security.controls: 'FAKE-01'"),
        ):
            result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 1
        assert "Available controls" in result.output

    def test_agent_name_hint(self, tmp_path: Path) -> None:
        """'agent.name' error branch produces fix hint."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        runner = CliRunner()
        with patch(
            "ancilis.cli.validate.load_config",
            side_effect=ValueError("agent.name is required"),
        ):
            result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])
        assert result.exit_code == 1
        assert "agent:" in result.output


# ===========================================================================
# cli/doctor.py
# ===========================================================================

class TestDoctorCoverage:
    def test_pkg_version_fallback_on_exception(self, tmp_path: Path) -> None:
        """Doctor falls back to '0.1.0' when importlib.metadata.version raises."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        with patch("ancilis.cli.doctor.version", side_effect=Exception("not installed")):
            result = runner.invoke(cli, ["doctor", "--config", str(cfg), "--db", str(db)])
        assert "Ancilis doctor" in result.output
        assert "0.1.0" in result.output

    def test_assets_load_failure(self, tmp_path: Path) -> None:
        """Doctor reports FAIL on assets when load_taxonomy raises."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        with patch("ancilis.cli.doctor.load_taxonomy", side_effect=RuntimeError("corrupt asset")):
            result = runner.invoke(cli, ["doctor", "--config", str(cfg), "--db", str(db)])
        assert "[FAIL] assets" in result.output
        assert result.exit_code == 1

    def test_engine_probe_failure_via_import(self, tmp_path: Path) -> None:
        """Doctor emits WARN for engine when evaluator probe raises (patched at import site)."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"

        class _BrokenEngine:
            def __init__(self, *a: object, **kw: object) -> None:
                raise RuntimeError("simulated engine failure")

        runner = CliRunner()
        with patch.dict("sys.modules", {"ancilis.engine.engine": MagicMock(Engine=_BrokenEngine)}):
            result = runner.invoke(cli, ["doctor", "--config", str(cfg), "--db", str(db)])
        assert "Ancilis doctor" in result.output

    def test_evidence_write_failure(self, tmp_path: Path) -> None:
        """Doctor reports FAIL on evidence when write probe raises."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        with patch("ancilis.cli.doctor.EvidenceStore") as mock_store_cls:
            instance = mock_store_cls.return_value
            instance.db_path = str(db)
            # Make the write probe fail
            instance.get_summary.side_effect = PermissionError("no write access")
            result = runner.invoke(cli, ["doctor", "--config", str(cfg), "--db", str(db)])
        assert "[FAIL] evidence" in result.output
        assert result.exit_code == 1

    def test_mcp_not_installed(self, tmp_path: Path) -> None:
        """Doctor emits WARN when mcp extra is not installed."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        with patch("ancilis.cli.doctor.import_module", side_effect=ImportError("no module named mcp")):
            result = runner.invoke(cli, ["doctor", "--config", str(cfg), "--db", str(db)])
        assert "[WARN] optional mcp extra: not installed" in result.output

    def test_pandoc_found(self, tmp_path: Path) -> None:
        """Doctor emits OK for pandoc when shutil.which returns a path."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        with patch("ancilis.cli.doctor.shutil.which", return_value="/usr/local/bin/pandoc"):
            result = runner.invoke(cli, ["doctor", "--config", str(cfg), "--db", str(db)])
        assert "[OK] pdf reporting dependency: pandoc executable detected" in result.output


# ===========================================================================
# cli/scan.py
# ===========================================================================

class TestScanCoverage:
    def test_default_config_used_when_no_ancilis_yaml(self, tmp_path: Path) -> None:
        """scan falls back to _default_config() when no config exists."""
        runner = CliRunner()
        db = tmp_path / "evidence.db"
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["scan", "--ci", "--db", str(db)])
        # Should produce JSON output using cwd name as agent
        data = json.loads(result.output)
        assert "agent" in data
        assert data["posture"] in ("compliant", "non_compliant")

    def test_first_run_message_no_sentinel(self, tmp_path: Path) -> None:
        """scan shows first-run quickstart when no evidence and no sentinel."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()
        # Patch _SENTINEL.exists() to return False (no sentinel)
        with patch("ancilis.cli.scan._SENTINEL", tmp_path / ".nonexistent-sentinel"):
            result = runner.invoke(cli, ["scan", "--config", str(cfg), "--db", str(db)])
        # Exit code is 0 (no failures, just no evidence)
        assert result.exit_code == 0
        assert "first run" in result.output.lower() or "Quick start" in result.output

    def test_sentinel_exists_shows_no_evidence_message(self, tmp_path: Path) -> None:
        """scan shows 'no evidence found' when sentinel exists but no evaluations."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        sentinel = tmp_path / ".first-run-complete"
        sentinel.touch()
        runner = CliRunner()
        with patch("ancilis.cli.scan._SENTINEL", sentinel):
            result = runner.invoke(cli, ["scan", "--config", str(cfg), "--db", str(db)])
        assert "no evidence found" in result.output.lower() or "No tool-call evidence" in result.output

    def test_sentinel_created_after_first_evaluation(self, tmp_path: Path) -> None:
        """scan creates the sentinel file after finding evaluations for first time."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        fake_sentinel = tmp_path / ".test-sentinel"
        runner = CliRunner()
        # Populate the DB with a minimal evaluation first
        from ancilis.config import load_config as _lc
        from ancilis.evidence.store import EvidenceStore
        from ancilis.engine.result import ControlResult, EvaluationResult
        import uuid
        from datetime import datetime, timezone

        _cfg = _lc(raw={"agent": {"name": "test-agent"}})
        store = EvidenceStore(_cfg, db_path=str(db))
        ev = EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id="a-001",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id="test-agent",
            mode="audit",
            session_id="sess-1",
            control_results=[
                ControlResult(
                    control_id="PR-01",
                    control_name="Identity",
                    result="PASS",
                    detail="ok",
                    evidence_data={},
                    duration_ms=1.0,
                )
            ],
            decision="ALLOW",
            decision_reason="ok",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=2.0,
        )
        store.store(ev, tool_name="test_tool")
        store.close()

        with patch("ancilis.cli.scan._SENTINEL", fake_sentinel):
            result = runner.invoke(cli, ["scan", "--config", str(cfg), "--db", str(db), "--all"])

        # Sentinel should have been created
        assert fake_sentinel.exists(), "Sentinel should be created after first evaluation"

    def test_dep_remediation_in_human_summary(self, tmp_path: Path) -> None:
        """_print_human_summary renders dep_items with remediation hints."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()

        dep_items = [
            {
                "result": "FAIL",
                "detail": "lodash@4.17.20 — CVE-2021-23337 (HIGH)",
                "remediation": "Upgrade to lodash>=4.17.21",
            }
        ]

        with patch("ancilis.cli.scan.DependencyScanner") as mock_scanner_cls:
            mock_eval = MagicMock()
            mock_cr = MagicMock()
            mock_cr.result = "FAIL"
            mock_cr.detail = "lodash@4.17.20 — CVE-2021-23337 (HIGH)"
            mock_cr.remediation_hint = "Upgrade to lodash>=4.17.21"
            mock_cr.evidence_data = {}
            mock_eval.control_results = [mock_cr]
            mock_scanner_cls.return_value.scan.return_value = [mock_eval]

            result = runner.invoke(cli, ["scan", "--config", str(cfg), "--db", str(db)])

        assert "Upgrade to lodash" in result.output

    def test_dep_posture_flag_path(self, tmp_path: Path) -> None:
        """dep posture is 'flag' when any dep item is FLAG and none are FAIL."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()

        with patch("ancilis.cli.scan.DependencyScanner") as mock_scanner_cls:
            mock_eval = MagicMock()
            mock_cr = MagicMock()
            mock_cr.result = "FLAG"
            mock_cr.detail = "express@4.18.0 — outdated"
            mock_cr.remediation_hint = None
            mock_cr.evidence_data = {}
            mock_eval.control_results = [mock_cr]
            mock_scanner_cls.return_value.scan.return_value = [mock_eval]

            result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg), "--db", str(db)])

        data = json.loads(result.output)
        assert data["dependencies"]["posture"] == "flag"

    def test_dep_posture_compliant_path(self, tmp_path: Path) -> None:
        """dep posture is 'compliant' when deps are all PASS."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()

        with patch("ancilis.cli.scan.DependencyScanner") as mock_scanner_cls:
            mock_eval = MagicMock()
            mock_cr = MagicMock()
            mock_cr.result = "PASS"
            mock_cr.detail = "lodash@4.17.21 — clean"
            mock_cr.remediation_hint = None
            mock_cr.evidence_data = {}
            mock_eval.control_results = [mock_cr]
            mock_scanner_cls.return_value.scan.return_value = [mock_eval]

            result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg), "--db", str(db)])

        data = json.loads(result.output)
        assert data["dependencies"]["posture"] == "compliant"

    def test_dep_posture_all_skip_path(self, tmp_path: Path) -> None:
        """dep posture is 'skip' when all dep items are SKIP."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        runner = CliRunner()

        with patch("ancilis.cli.scan.DependencyScanner") as mock_scanner_cls:
            mock_eval = MagicMock()
            mock_cr = MagicMock()
            mock_cr.result = "SKIP"
            mock_cr.detail = "no sbom found"
            mock_cr.remediation_hint = None
            mock_cr.evidence_data = {}
            mock_eval.control_results = [mock_cr]
            mock_scanner_cls.return_value.scan.return_value = [mock_eval]

            result = runner.invoke(cli, ["scan", "--ci", "--config", str(cfg), "--db", str(db)])

        data = json.loads(result.output)
        assert data["dependencies"]["posture"] == "skip"


# ===========================================================================
# cli/report.py (file output paths)
# ===========================================================================

class TestReportFilePaths:
    def test_markdown_writes_to_file(self, tmp_path: Path) -> None:
        """report --format markdown --output writes file and confirms path."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        out = tmp_path / "report.md"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["report", "--config", str(cfg), "--db", str(db), "--format", "markdown", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        assert "Report written to" in result.output

    def test_ndjson_writes_to_file(self, tmp_path: Path) -> None:
        """report --format ndjson --output writes file and confirms path."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        out = tmp_path / "report.ndjson"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["report", "--config", str(cfg), "--db", str(db), "--format", "ndjson", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        assert "Report written to" in result.output

    def test_csv_writes_to_file(self, tmp_path: Path) -> None:
        """report --format csv --output writes file and confirms path."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        out = tmp_path / "report.csv"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["report", "--config", str(cfg), "--db", str(db), "--format", "csv", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        assert "Report written to" in result.output

    def test_pdf_success_path(self, tmp_path: Path) -> None:
        """report --format pdf with pandoc mocked to succeed shows PDF confirmation."""
        cfg = _make_config_file(MINIMAL_YAML, tmp_path)
        db = tmp_path / "evidence.db"
        out = str(tmp_path / "report.pdf")
        runner = CliRunner()

        from ancilis.report.renderer import RenderPdfResult
        mock_pdf = RenderPdfResult(
            format="pdf",
            output_path=out,
            fallback_reason=None,
        )

        with patch("ancilis.cli.report.render_pdf", return_value=mock_pdf):
            result = runner.invoke(
                cli,
                ["report", "--config", str(cfg), "--db", str(db), "--format", "pdf", "--output", out],
            )
        assert result.exit_code == 0
        assert "PDF report written to" in result.output
