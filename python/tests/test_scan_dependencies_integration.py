"""Integration tests for dependency scan config (ANC-403).

Covers:
- scan.dependencies.enabled=false skips dependency scanning
- scan.dependencies.ignore excludes specific CVE IDs from exit code
- scan.dependencies.severity_threshold controls what causes non-zero exit
- Existing behavior unchanged when no manifests found
- Evidence records written to store after dep scan
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.deps.osv import Vuln


# --- Helpers ---


def _make_config_file(data: dict[str, Any], tmpdir: Path) -> Path:
    path = tmpdir / "ancilis.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return path


def _minimal_config() -> dict[str, Any]:
    return {"agent": {"name": "test-agent"}}


def _mock_vuln(
    vuln_id: str = "CVE-2024-1234",
    severity: str = "HIGH",
    fixed: str | None = "2.0.0",
    summary: str = "Test vulnerability",
) -> Vuln:
    return Vuln(
        id=vuln_id,
        severity=severity,
        summary=summary,
        fixed_version=fixed,
        aliases=[],
        affected_versions=[],
    )


# --- Config parsing tests ---


class TestScanDepsConfig:
    def test_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(raw=_minimal_config())
        assert cfg.scan_dependencies_enabled is True
        assert cfg.scan_dependencies_severity_threshold == "high"
        assert cfg.scan_dependencies_ignore == []

    def test_explicit_config(self, tmp_path: Path) -> None:
        raw = {
            **_minimal_config(),
            "scan": {
                "dependencies": {
                    "enabled": False,
                    "severity_threshold": "critical",
                    "ignore": ["CVE-2024-1111", "CVE-2024-2222"],
                }
            },
        }
        cfg = load_config(raw=raw)
        assert cfg.scan_dependencies_enabled is False
        assert cfg.scan_dependencies_severity_threshold == "critical"
        assert cfg.scan_dependencies_ignore == ["CVE-2024-1111", "CVE-2024-2222"]

    def test_invalid_severity_threshold_rejected(self, tmp_path: Path) -> None:
        raw = {
            **_minimal_config(),
            "scan": {"dependencies": {"severity_threshold": "catastrophic"}},
        }
        with pytest.raises((ValueError, Exception)):  # pydantic raises ValidationError
            load_config(raw=raw)


# --- CLI scan integration tests ---


class TestScanDepEnabled:
    def test_disabled_skips_dep_scan(self, tmp_path: Path) -> None:
        """scan.dependencies.enabled=false means DependencyScanner never called."""
        cfg_file = _make_config_file(
            {
                **_minimal_config(),
                "scan": {"dependencies": {"enabled": False}},
            },
            tmp_path,
        )
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            result = runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", str(tmp_path / "ev.db")],
                catch_exceptions=False,
            )
        mock_cls.return_value.scan.assert_not_called()
        # Should succeed (exit 0 — no evidence, shows first-run message)
        assert result.exit_code == 0

    def test_enabled_calls_dep_scan(self, tmp_path: Path) -> None:
        """scan.dependencies.enabled=true (default) calls DependencyScanner.scan()."""
        cfg_file = _make_config_file(_minimal_config(), tmp_path)
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = []
            result = runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", str(tmp_path / "ev.db")],
                catch_exceptions=False,
            )
        mock_cls.return_value.scan.assert_called_once()
        assert result.exit_code == 0


class TestScanDepIgnore:
    def _make_eval_result_with_cve(self, cve_id: str, severity: str = "HIGH") -> Any:
        """Build a minimal EvaluationResult with a single FAIL CVE finding."""
        from datetime import datetime, timezone
        from ancilis.engine.result import ControlResult, EvaluationResult

        return EvaluationResult(
            evaluation_id="dep-eval-1",
            action_id="dep-scan-abc",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id="cli-scan",
            source_type="dependency_scan",
            mode="audit",
            control_results=[
                ControlResult(
                    control_id="DE-01",
                    control_name="Dependency Evaluation",
                    result="FAIL",
                    detail=f"requests==2.28.0: {cve_id} ({severity}) — test vuln",
                    evidence_data={
                        "package": "requests",
                        "version": "2.28.0",
                        "vuln_id": cve_id,
                        "severity": severity,
                        "fixed_version": "2.31.0",
                        "source_file": "requirements.txt",
                        "aliases": [],
                        "affected_versions": [],
                    },
                    remediation_hint="Upgrade requests to >=2.31.0",
                )
            ],
            decision="BLOCK",
            decision_reason="Dependency vulnerability scan",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def test_ignored_cve_does_not_cause_exit_1(self, tmp_path: Path) -> None:
        cve_id = "CVE-2024-9999"
        cfg_file = _make_config_file(
            {
                **_minimal_config(),
                "scan": {"dependencies": {"ignore": [cve_id]}},
            },
            tmp_path,
        )
        eval_result = self._make_eval_result_with_cve(cve_id)
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = [eval_result]
            result = runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", str(tmp_path / "ev.db")],
                catch_exceptions=False,
            )
        # Even though there's a FAIL finding, it's in the ignore list → exit 0
        assert result.exit_code == 0

    def test_non_ignored_cve_causes_exit_1(self, tmp_path: Path) -> None:
        cve_id = "CVE-2024-9999"
        cfg_file = _make_config_file(
            {
                **_minimal_config(),
                "scan": {"dependencies": {"ignore": ["CVE-2024-0001"]}},  # different CVE ignored
            },
            tmp_path,
        )
        eval_result = self._make_eval_result_with_cve(cve_id)
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = [eval_result]
            result = runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", str(tmp_path / "ev.db")],
            )
        assert result.exit_code == 1


class TestScanDepSeverityThreshold:
    def _make_eval_with_severity(self, severity: str, cve_id: str = "CVE-2024-1234") -> Any:
        from datetime import datetime, timezone
        from ancilis.engine.result import ControlResult, EvaluationResult

        result_val = "FAIL" if severity.upper() in ("CRITICAL", "HIGH") else "FLAG"
        return EvaluationResult(
            evaluation_id="dep-eval-sev",
            action_id="dep-scan-xyz",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id="cli-scan",
            source_type="dependency_scan",
            mode="audit",
            control_results=[
                ControlResult(
                    control_id="DE-01",
                    control_name="Dependency Evaluation",
                    result=result_val,
                    detail=f"pkg==1.0.0: {cve_id} ({severity}) — test vuln",
                    evidence_data={
                        "package": "pkg",
                        "version": "1.0.0",
                        "vuln_id": cve_id,
                        "severity": severity.upper(),
                        "fixed_version": "2.0.0",
                        "source_file": "requirements.txt",
                        "aliases": [],
                        "affected_versions": [],
                    },
                    remediation_hint="Upgrade pkg to >=2.0.0",
                )
            ],
            decision="BLOCK" if result_val == "FAIL" else "FLAG",
            decision_reason="Dependency vulnerability scan",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def test_default_threshold_high_fails_on_high(self, tmp_path: Path) -> None:
        cfg_file = _make_config_file(_minimal_config(), tmp_path)
        eval_result = self._make_eval_with_severity("HIGH")
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = [eval_result]
            result = runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", str(tmp_path / "ev.db")],
            )
        assert result.exit_code == 1

    def test_critical_threshold_passes_on_high(self, tmp_path: Path) -> None:
        """With threshold=critical, HIGH severity should NOT cause exit 1."""
        cfg_file = _make_config_file(
            {
                **_minimal_config(),
                "scan": {"dependencies": {"severity_threshold": "critical"}},
            },
            tmp_path,
        )
        eval_result = self._make_eval_with_severity("HIGH")
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = [eval_result]
            result = runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", str(tmp_path / "ev.db")],
                catch_exceptions=False,
            )
        assert result.exit_code == 0


class TestScanDepNoManifests:
    def test_no_manifests_exits_zero(self, tmp_path: Path) -> None:
        """Existing behavior: no manifests found → no dep failures → exit 0."""
        from datetime import datetime, timezone
        from ancilis.engine.result import ControlResult, EvaluationResult

        skip_result = EvaluationResult(
            evaluation_id="dep-eval-skip",
            action_id="dep-scan-skip",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id="cli-scan",
            source_type="dependency_scan",
            mode="audit",
            control_results=[
                ControlResult(
                    control_id="DE-01",
                    control_name="Dependency Evaluation",
                    result="SKIP",
                    detail="No dependency manifests found",
                    evidence_data=None,
                )
            ],
            decision="ALLOW",
            decision_reason="Dependency vulnerability scan",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
        cfg_file = _make_config_file(_minimal_config(), tmp_path)
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = [skip_result]
            result = runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", str(tmp_path / "ev.db")],
                catch_exceptions=False,
            )
        assert result.exit_code == 0


class TestScanDepEvidenceWrite:
    def test_dep_scan_writes_to_evidence_store(self, tmp_path: Path) -> None:
        """DependencyScanner results are stored in the evidence store."""
        from datetime import datetime, timezone
        from ancilis.engine.result import ControlResult, EvaluationResult

        pass_result = EvaluationResult(
            evaluation_id="dep-eval-pass",
            action_id="dep-scan-pass",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id="cli-scan",
            source_type="dependency_scan",
            mode="audit",
            control_results=[
                ControlResult(
                    control_id="DE-01",
                    control_name="Dependency Evaluation",
                    result="PASS",
                    detail="No known vulnerabilities in 10 dependencies",
                    evidence_data={"dep_count": 10},
                )
            ],
            decision="ALLOW",
            decision_reason="Dependency vulnerability scan",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
        cfg_file = _make_config_file(_minimal_config(), tmp_path)
        db_path = str(tmp_path / "ev.db")
        runner = CliRunner()
        with patch("ancilis.cli.scan.DependencyScanner") as mock_cls:
            mock_cls.return_value.scan.return_value = [pass_result]
            runner.invoke(
                cli,
                ["scan", "--config", str(cfg_file), "--db", db_path],
                catch_exceptions=False,
            )

        # Verify the dep scan record was written to the evidence store
        from ancilis.config import load_config as lc
        from ancilis.evidence.store import EvidenceStore

        cfg = lc(raw=_minimal_config())
        store = EvidenceStore(cfg, db_path=db_path)
        try:
            records = store._connection.execute(
                "SELECT source_type FROM evidence_records WHERE source_type='dependency_scan'"
            ).fetchall()
            assert len(records) == 1
        finally:
            store.close()
