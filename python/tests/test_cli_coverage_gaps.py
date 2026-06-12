"""Tests filling CLI coverage gaps — ANC-803.

Covers:
- cli/evidence.py: evidence_import (SARIF + CycloneDX + error paths),
  evidence_sessions error path, evidence_reset error path
- cli/baseline.py: baseline_create, baseline_list, baseline_drift via CLI
- cli/connect.py: connect command (connected / not-connected)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config, ResolvedConfig
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = "agent:\n  name: test-agent\n"


def make_config() -> ResolvedConfig:
    return load_config(raw={"agent": {"name": "test-agent"}})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_evaluation(
    decision: str = "ALLOW",
    session_id: str | None = None,
    control_id: str = "PR-01",
    result: str = "PASS",
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        action_id="action-001",
        timestamp=_now_iso(),
        agent_id="test-agent",
        mode="audit",
        session_id=session_id,
        control_results=[
            ControlResult(
                control_id=control_id,
                control_name="Test Control",
                result=result,
                detail="ok",
                evidence_data={},
                duration_ms=1.0,
            )
        ],
        decision=decision,
        decision_reason="test",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=2.0,
    )


# ---------------------------------------------------------------------------
# Minimal SARIF / CycloneDX inline fixtures (reused from test_evidence_import)
# ---------------------------------------------------------------------------

SARIF_ONE_FINDING = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "TestScanner",
                    "version": "1.0",
                    "rules": [
                        {"id": "js/sql-injection", "name": "SqlInjection",
                         "shortDescription": {"text": "SQL Injection"}}
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "js/sql-injection",
                    "level": "error",
                    "message": {"text": "Query built from user input"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db.js"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                }
            ],
        }
    ],
})

CDX_WITH_VULN = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "tools": [{"name": "syft", "version": "0.90.0"}],
        "component": {"name": "myapp", "version": "1.0.0"},
    },
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.15",
         "purl": "pkg:npm/lodash@4.17.15"},
    ],
    "vulnerabilities": [
        {
            "id": "CVE-2021-23337",
            "description": "Prototype pollution",
            "cwes": [1321],
            "ratings": [{"severity": "high", "score": 7.2}],
            "affects": [{"ref": "pkg:npm/lodash@4.17.15",
                         "versions": [{"version": "4.17.15"}]}],
        }
    ],
})


# ===========================================================================
# cli/evidence.py — error paths
# ===========================================================================

class TestEvidenceSessionsErrorPath:
    """evidence sessions with missing/invalid config."""

    def test_missing_config_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "sessions",
             "--config", str(tmp_path / "nonexistent.yaml")],
        )
        assert result.exit_code != 0

    def test_no_sessions_outputs_empty_message(self, tmp_path: Path) -> None:
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "sessions", "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0
        assert "No sessions" in result.output


class TestEvidenceResetErrorPath:
    """evidence reset with missing config."""

    def test_missing_config_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "reset",
             "--config", str(tmp_path / "nonexistent.yaml"), "-y"],
        )
        assert result.exit_code != 0


# ===========================================================================
# cli/evidence.py — evidence import command
# ===========================================================================

class TestEvidenceImportCommand:
    """CLI-level tests for `ancilis evidence import`."""

    def test_import_sarif_by_extension(self, tmp_path: Path) -> None:
        sarif_file = tmp_path / "findings.sarif"
        sarif_file.write_text(SARIF_ONE_FINDING)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(sarif_file),
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "Imported" in result.output
        assert "SARIF" in result.output

    def test_import_cyclonedx_explicit_format(self, tmp_path: Path) -> None:
        cdx_file = tmp_path / "sbom.json"
        cdx_file.write_text(CDX_WITH_VULN)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(cdx_file),
             "--format", "cyclonedx",
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "Imported" in result.output
        assert "CYCLONEDX" in result.output

    def test_import_cyclonedx_auto_detect_by_extension(self, tmp_path: Path) -> None:
        cdx_file = tmp_path / "bom.cdx.json"
        cdx_file.write_text(CDX_WITH_VULN)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(cdx_file),
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "Imported" in result.output

    def test_import_sarif_auto_detect_by_content(self, tmp_path: Path) -> None:
        """Unknown extension — should sniff from JSON content (has 'runs' key)."""
        unknown_file = tmp_path / "scan_output.dat"
        unknown_file.write_text(SARIF_ONE_FINDING)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(unknown_file),
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "Imported" in result.output

    def test_import_cyclonedx_auto_detect_by_content(self, tmp_path: Path) -> None:
        """Unknown extension — should sniff from JSON content (has 'bomFormat' key)."""
        unknown_file = tmp_path / "scan_output.dat"
        unknown_file.write_text(CDX_WITH_VULN)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(unknown_file),
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output

    def test_import_unknown_format_exits_nonzero(self, tmp_path: Path) -> None:
        """Non-JSON file with unknown extension — cannot detect format."""
        bad_file = tmp_path / "output.dat"
        bad_file.write_text("not json at all {{{")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(bad_file),
             "--config", config_path],
        )
        assert result.exit_code != 0

    def test_import_json_with_unknown_schema_exits_nonzero(self, tmp_path: Path) -> None:
        """Valid JSON but neither SARIF nor CycloneDX keys."""
        bad_file = tmp_path / "weird.json"
        bad_file.write_text(json.dumps({"hello": "world"}))
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(bad_file), "--config", config_path],
        )
        assert result.exit_code != 0

    def test_import_missing_config_exits_nonzero(self, tmp_path: Path) -> None:
        sarif_file = tmp_path / "findings.sarif"
        sarif_file.write_text(SARIF_ONE_FINDING)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(sarif_file),
             "--config", str(tmp_path / "nonexistent.yaml")],
        )
        assert result.exit_code != 0

    def test_import_explicit_sarif_format(self, tmp_path: Path) -> None:
        """--format sarif should work regardless of extension."""
        sarif_file = tmp_path / "results.json"
        sarif_file.write_text(SARIF_ONE_FINDING)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(sarif_file),
             "--format", "sarif",
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "Imported" in result.output

    def test_import_records_written_to_store(self, tmp_path: Path) -> None:
        """Verify imported records actually land in the evidence store."""
        sarif_file = tmp_path / "findings.sarif"
        sarif_file.write_text(SARIF_ONE_FINDING)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        runner.invoke(
            cli,
            ["evidence", "import", str(sarif_file),
             "--config", config_path, "--db", db],
        )

        config = make_config()
        store = EvidenceStore(config, db_path=db)
        try:
            assert store.count() >= 1
        finally:
            store.close()

    def test_import_custom_agent_id(self, tmp_path: Path) -> None:
        sarif_file = tmp_path / "findings.sarif"
        sarif_file.write_text(SARIF_ONE_FINDING)
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "import", str(sarif_file),
             "--agent-id", "my-scanner",
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output


# ===========================================================================
# cli/baseline.py — baseline create / list / drift via CLI
# ===========================================================================

class TestBaselineCLICreate:
    """ancilis baseline create via CLI runner."""

    def test_create_baseline_happy_path(self, tmp_path: Path) -> None:
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        # Seed a record so the baseline has something to snapshot
        config = make_config()
        store = EvidenceStore(config, db_path=db)
        store.store(make_evaluation(), tool_name="tool")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["baseline", "create", "--label", "v1-snap",
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "Baseline created" in result.output
        assert "v1-snap" in result.output

    def test_create_baseline_missing_config_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["baseline", "create", "--label", "x",
             "--config", str(tmp_path / "nonexistent.yaml")],
        )
        assert result.exit_code != 0

    def test_create_baseline_empty_store(self, tmp_path: Path) -> None:
        """Creating a baseline on an empty store should still succeed (0 snapshots)."""
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["baseline", "create", "--label", "empty-snap",
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "Baseline created" in result.output
        assert "0 snapshot" in result.output


class TestBaselineCLIList:
    """ancilis baseline list via CLI runner."""

    def test_list_no_baselines(self, tmp_path: Path) -> None:
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["baseline", "list", "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "No baselines" in result.output

    def test_list_shows_created_baseline(self, tmp_path: Path) -> None:
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        # Create first
        runner.invoke(
            cli,
            ["baseline", "create", "--label", "release-1",
             "--config", config_path, "--db", db],
        )
        # Then list
        result = runner.invoke(
            cli,
            ["baseline", "list", "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "release-1" in result.output

    def test_list_missing_config_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["baseline", "list",
             "--config", str(tmp_path / "nonexistent.yaml")],
        )
        assert result.exit_code != 0


class TestBaselineCLIDrift:
    """ancilis baseline drift via CLI runner."""

    def _create_baseline(self, runner: CliRunner, config_path: str, db: str, label: str = "snap") -> None:
        runner.invoke(
            cli,
            ["baseline", "create", "--label", label,
             "--config", config_path, "--db", db],
        )

    def test_drift_stable_terminal(self, tmp_path: Path) -> None:
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        self._create_baseline(runner, config_path, db)

        result = runner.invoke(
            cli,
            ["baseline", "drift", "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "STABLE" in result.output

    def test_drift_stable_json_output(self, tmp_path: Path) -> None:
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        self._create_baseline(runner, config_path, db)

        result = runner.invoke(
            cli,
            ["baseline", "drift", "--format", "json",
             "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "overall_status" in data
        assert data["overall_status"] == "STABLE"

    def test_drift_missing_baseline_id_exits_nonzero(self, tmp_path: Path) -> None:
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["baseline", "drift", "--id", "nonexistent-id-xyz",
             "--config", config_path, "--db", db],
        )
        assert result.exit_code != 0

    def test_drift_missing_config_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["baseline", "drift",
             "--config", str(tmp_path / "nonexistent.yaml")],
        )
        assert result.exit_code != 0

    def test_drift_drifted_exits_2(self, tmp_path: Path) -> None:
        """When drift is detected the command should exit with code 2 (CI-friendly)."""
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text(MINIMAL_CONFIG)

        # Seed passing evidence and create baseline
        config = make_config()
        store = EvidenceStore(config, db_path=db)
        for _ in range(10):
            store.store(make_evaluation(decision="ALLOW"), tool_name="tool")
        store.close()

        runner = CliRunner()
        self._create_baseline(runner, config_path, db, label="pre-regression")

        # Now add failing evidence to simulate regression
        store = EvidenceStore(config, db_path=db)
        for _ in range(10):
            store.store(
                make_evaluation(decision="BLOCK", result="FAIL"),
                tool_name="tool",
            )
        store.close()

        result = runner.invoke(
            cli,
            ["baseline", "drift", "--config", config_path, "--db", db],
        )
        # DRIFTED exits with code 2
        assert result.exit_code == 2, result.output


# ===========================================================================
# cli/connect.py — connect command
# ===========================================================================

class TestConnectCommand:
    """ancilis connect — connected and not-connected branches."""

    def test_not_connected_shows_instructions(self, tmp_path: Path) -> None:
        runner = CliRunner()
        # Patch Path.home() to a tmp dir that has no platform.json
        with patch("ancilis.cli.connect.Path") as mock_path_cls:
            fake_home = tmp_path
            platform_path = fake_home / ".ancilis" / "platform.json"
            # platform.json does NOT exist
            mock_path_cls.home.return_value = fake_home
            # /  operator needs to work on the real Path
            mock_path_cls.side_effect = lambda *a, **kw: Path(*a, **kw)

            # Simplest: patch just the platform_path existence check
            with patch("ancilis.cli.connect.Path.home", return_value=tmp_path):
                result = runner.invoke(cli, ["connect"])

        assert result.exit_code == 0
        assert "not connected" in result.output.lower()
        assert "ancilis.ai" in result.output

    def test_connected_shows_status(self, tmp_path: Path) -> None:
        runner = CliRunner()
        # Create the platform.json where connect will look
        ancilis_dir = tmp_path / ".ancilis"
        ancilis_dir.mkdir()
        platform_json = ancilis_dir / "platform.json"
        platform_json.write_text(json.dumps({"api_key": "test-key"}))

        with patch("ancilis.cli.connect.Path.home", return_value=tmp_path):
            result = runner.invoke(cli, ["connect"])

        assert result.exit_code == 0
        assert "connected" in result.output.lower()
