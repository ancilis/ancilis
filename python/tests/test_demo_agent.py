"""Tests for the financial demo agent example."""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import ancilis.evidence.store as evidence_store_module
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.demo_orchestration import (
    build_demo_integration_name,
    build_demo_integration_payload,
)
from ancilis.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
DEMO_PATH = ROOT / "examples" / "demo" / "run.py"
DEMO_CONFIG_PATH = ROOT / "examples" / "demo" / "ancilis.yaml"
DEMO_SETUP_PATH = ROOT / "examples" / "demo" / "setup.sh"
DEMO_RUN_ALL_PATH = ROOT / "examples" / "demo" / "run-all.sh"
DEMO_README_PATH = ROOT / "examples" / "demo" / "README.md"


def _load_demo_module():
    assert DEMO_PATH.exists(), f"Demo script missing: {DEMO_PATH}"
    spec = importlib.util.spec_from_file_location("examples.demo.run", DEMO_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_demo(tmp_path: Path):
    module = _load_demo_module()
    db_path = tmp_path / "demo-evidence.duckdb"
    stream = io.StringIO()

    result = module.main(db_path=db_path, stream=stream)

    return module, result, db_path, stream.getvalue()


def _extract_evidence_path(output: str) -> Path:
    for line in output.splitlines():
        if line.startswith("Evidence stored at: "):
            return Path(line.removeprefix("Evidence stored at: ").strip())

    raise AssertionError(f"Missing evidence path in output:\n{output}")


def test_demo_main_executes_without_error(tmp_path: Path) -> None:
    module, result, db_path, output = _run_demo(tmp_path)

    assert module is not None
    assert result.db_path == db_path
    assert "Ancilis Demo - Financial AI Agent with Runtime Controls" in output
    assert "ALLOW" in output
    assert "BLOCK" in output
    assert "Evidence stored at:" in output


def test_demo_output_points_to_split_repo_walkthrough(tmp_path: Path) -> None:
    _, _, _, output = _run_demo(tmp_path)

    assert "bash examples/demo/run-all.sh" in output
    assert "cd platform && ./start.sh" not in output


def test_demo_run_persists_expected_evidence(tmp_path: Path) -> None:
    _, _, db_path, _ = _run_demo(tmp_path)
    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=db_path)

    try:
        assert store.count() == 6
        summary = store.get_summary()
        assert summary["decisions"]["ALLOW"] == 4
        assert summary["decisions"]["BLOCK"] == 2
        assert summary["chain_valid"] is True
    finally:
        store.close()


def test_demo_evidence_records_expected_overlays_and_certifications(tmp_path: Path) -> None:
    _, _, db_path, _ = _run_demo(tmp_path)
    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=db_path)

    try:
        records = store.get_records(limit=10)
        assert len(records) == 6

        overlay_ids = {overlay for record in records for overlay in record.active_overlays}
        certification_ids = {cert for record in records for cert in record.active_certifications}

        assert "soc2" in overlay_ids
        assert "pci-dss-v4" in overlay_ids
        assert "glba" in overlay_ids
        assert "aiuc-1" in certification_ids
    finally:
        store.close()


def test_demo_status_and_markdown_report_surface_demo_evidence(tmp_path: Path) -> None:
    _, _, db_path, _ = _run_demo(tmp_path)
    runner = CliRunner()

    status_result = runner.invoke(
        cli,
        [
            "status",
            "--verbose",
            "--config",
            str(DEMO_CONFIG_PATH),
            "--db",
            str(db_path),
        ],
    )

    assert status_result.exit_code == 0
    assert "finance-demo-agent" in status_result.output
    assert "Tool calls: 6 evaluated, 2 blocked" in status_result.output
    assert "AIUC-1: active" in status_result.output
    assert "SOC 2 Type II: active" in status_result.output
    assert "PCI-DSS v4.0: active" in status_result.output

    report_result = runner.invoke(
        cli,
        [
            "report",
            "--format",
            "markdown",
            "--config",
            str(DEMO_CONFIG_PATH),
            "--db",
            str(db_path),
        ],
    )

    assert report_result.exit_code == 0
    assert "Ancilis Posture Report" in report_result.output
    assert "finance-demo-agent" in report_result.output
    assert "## AIUC-1 Certification Readiness" in report_result.output
    assert "Evidence records: 6" in report_result.output


def test_demo_setup_script_is_present_and_executable() -> None:
    assert DEMO_SETUP_PATH.exists(), f"Demo setup script missing: {DEMO_SETUP_PATH}"
    assert DEMO_SETUP_PATH.stat().st_mode & 0o111


def test_demo_main_resets_evidence_on_programmatic_rerun_by_default(tmp_path: Path, monkeypatch) -> None:
    module = _load_demo_module()
    monkeypatch.setattr(evidence_store_module, "DEFAULT_DB_DIR", tmp_path / ".ancilis")
    monkeypatch.chdir(tmp_path)
    stream = io.StringIO()

    first_result = module.main(stream=stream)
    second_result = module.main(stream=stream)

    assert first_result.db_path == second_result.db_path

    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=second_result.db_path)

    try:
        assert store.count() == 6
    finally:
        store.close()


def test_demo_main_can_preserve_evidence_when_requested(tmp_path: Path, monkeypatch) -> None:
    module = _load_demo_module()
    monkeypatch.setattr(evidence_store_module, "DEFAULT_DB_DIR", tmp_path / ".ancilis")
    monkeypatch.chdir(tmp_path)
    stream = io.StringIO()

    first_result = module.main(stream=stream, fresh=False)
    second_result = module.main(stream=stream, fresh=False)

    assert first_result.db_path == second_result.db_path

    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=second_result.db_path)

    try:
        assert store.count() == 12
    finally:
        store.close()


def test_demo_main_preserved_history_reports_latest_session_only(tmp_path: Path, monkeypatch) -> None:
    module = _load_demo_module()
    monkeypatch.setattr(evidence_store_module, "DEFAULT_DB_DIR", tmp_path / ".ancilis")
    monkeypatch.chdir(tmp_path)
    stream = io.StringIO()

    module.main(stream=stream, fresh=False)
    second_result = module.main(stream=stream, fresh=False)

    assert second_result.decisions == {"ALLOW": 4, "BLOCK": 2}
    assert "Tool calls: 6 evaluated, 2 blocked" in second_result.status_output
    assert "Evidence records: 6" in second_result.report_markdown

    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=second_result.db_path)

    try:
        assert store.count() == 12
    finally:
        store.close()


def test_demo_main_entry_resets_evidence_on_rerun(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["PYTHONPATH"] = str(ROOT / "python" / "src")

    first_run = subprocess.run(
        [sys.executable, str(DEMO_PATH)],
        capture_output=True,
        check=True,
        cwd=ROOT,
        env=env,
        text=True,
    )
    second_run = subprocess.run(
        [sys.executable, str(DEMO_PATH)],
        capture_output=True,
        check=True,
        cwd=ROOT,
        env=env,
        text=True,
    )

    assert "Tool calls: 6 evaluated, 2 blocked" in first_run.stdout
    assert "Tool calls: 6 evaluated, 2 blocked" in second_run.stdout

    db_path = _extract_evidence_path(second_run.stdout)
    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=db_path)

    try:
        assert store.count() == 6
    finally:
        store.close()


def test_demo_integration_name_is_workspace_scoped_and_stable() -> None:
    db_path = Path("/tmp/ancilis/demo-a/evidence.duckdb")

    name = build_demo_integration_name(db_path)

    expected_suffix = sha256(str(db_path).encode("utf-8")).hexdigest()[:8]
    assert name == f"Finance Demo SDK ({expected_suffix})"
    assert name == build_demo_integration_name(db_path)


def test_demo_integration_name_changes_when_db_path_changes() -> None:
    first_path = Path("/tmp/ancilis/demo-a/evidence.duckdb")
    second_path = Path("/tmp/ancilis/demo-b/evidence.duckdb")

    assert build_demo_integration_name(first_path) != build_demo_integration_name(second_path)


def test_demo_integration_payload_points_to_current_db_path() -> None:
    db_path = Path("/tmp/ancilis/demo-a/evidence.duckdb")

    payload = build_demo_integration_payload(db_path)

    assert payload["name"] == build_demo_integration_name(db_path)
    assert payload["source_type"] == "sdk_direct"
    assert payload["config"]["transport"]["paths"] == [str(db_path)]
    assert payload["config"]["transport"]["scan_home_dir"] is False
    assert payload["config"]["sync"]["mode"] == "incremental"


def test_demo_integration_helpers_canonicalize_equivalent_paths() -> None:
    canonical_path = Path("/tmp/ancilis/demo-a/evidence.duckdb")
    equivalent_path = Path("/tmp/ancilis/demo-a/../demo-a/evidence.duckdb")

    canonical_name = build_demo_integration_name(canonical_path)
    equivalent_name = build_demo_integration_name(equivalent_path)
    canonical_payload = build_demo_integration_payload(canonical_path)
    equivalent_payload = build_demo_integration_payload(equivalent_path)

    assert canonical_name == equivalent_name
    assert (
        canonical_payload["config"]["transport"]["paths"][0]
        == equivalent_payload["config"]["transport"]["paths"][0]
    )
    assert canonical_payload["config"]["transport"]["paths"][0] == str(canonical_path)


def test_run_all_uses_workspace_scoped_demo_name_helper() -> None:
    script = DEMO_RUN_ALL_PATH.read_text(encoding="utf-8")

    assert 'DEMO_NAME="Finance Demo SDK"' not in script
    assert "build_demo_integration_name" in script


def test_demo_readme_surfaces_end_to_end_walkthrough() -> None:
    readme = DEMO_README_PATH.read_text(encoding="utf-8")

    assert "bash examples/demo/run-all.sh" in readme
    assert "ANCILIS_PLATFORM_DIR" in readme
    assert "ANCILIS_DEMO_BACKEND_URL" in readme
    assert "ANCILIS_DEMO_DASHBOARD_URL" in readme
    assert "Docker" in readme
    assert "curl" in readme
    assert "admin@ancilis.demo" in readme
    assert "ancilis-one-shot" in readme
    assert "ALLOW/BLOCK counts" not in readme
    assert "middleware summary line" in readme
