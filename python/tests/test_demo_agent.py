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
DEMO_COMPAT_PATH = ROOT / "examples" / "demo" / "run-demo.py"
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


def test_demo_output_is_polished_and_redirect_safe(tmp_path: Path) -> None:
    _, _, _, output = _run_demo(tmp_path)

    assert "╔" in output
    assert "╚" in output
    assert "├─ Tool Registry" in output
    assert "├─ Tool Calls" in output
    assert "├─ Summary" in output
    assert "✓ check_balance" in output
    assert "✗ drop_audit_log" in output
    assert "Overlays:" in output
    assert "Cert:" in output
    assert "\x1b[" not in output


def test_demo_output_uses_ansi_when_stream_is_a_tty(tmp_path: Path, monkeypatch) -> None:
    module = _load_demo_module()
    stream = io.StringIO()
    stream.isatty = lambda: True  # type: ignore[attr-defined]
    monkeypatch.delenv("NO_COLOR", raising=False)

    module.main(db_path=tmp_path / "demo-evidence.duckdb", stream=stream)

    output = stream.getvalue()
    assert "\x1b[" in output
    assert "\x1b[1;32m✓" in output
    assert "\x1b[1;31m✗" in output


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


def test_demo_setup_script_reuses_demo_venv() -> None:
    script = DEMO_SETUP_PATH.read_text(encoding="utf-8")

    assert 'if [ ! -d ".demo-venv" ]; then' in script
    assert 'python3 -m venv .demo-venv' in script


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

    assert "Evaluated: 6 tool calls | Allowed: 4 | Blocked: 2" in first_run.stdout
    assert "Evaluated: 6 tool calls | Allowed: 4 | Blocked: 2" in second_run.stdout

    db_path = _extract_evidence_path(second_run.stdout)
    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=db_path)

    try:
        assert store.count() == 6
    finally:
        store.close()


def test_demo_compat_entrypoint_matches_run_demo_name(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["PYTHONPATH"] = str(ROOT / "python" / "src")

    run = subprocess.run(
        [sys.executable, str(DEMO_COMPAT_PATH)],
        capture_output=True,
        check=True,
        cwd=ROOT,
        env=env,
        text=True,
    )

    assert "Evaluated: 6 tool calls | Allowed: 4 | Blocked: 2" in run.stdout

    db_path = _extract_evidence_path(run.stdout)
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


def test_run_all_can_reuse_an_existing_platform_stack() -> None:
    script = DEMO_RUN_ALL_PATH.read_text(encoding="utf-8")

    assert "ANCILIS_DEMO_SKIP_STACK_START" in script
    assert 'if [ "${SKIP_STACK_START}" = "1" ]; then' in script
    assert "Reusing existing Platform stack" in script
    assert "Press Ctrl+C to exit without stopping the reused Platform stack." in script


def test_demo_readme_surfaces_end_to_end_walkthrough() -> None:
    readme = DEMO_README_PATH.read_text(encoding="utf-8")

    assert "30-Second Demo Path" in readme
    assert "5-Minute Demo Path" in readme
    assert "bash examples/demo/setup.sh" in readme
    assert "bash examples/demo/run-all.sh" in readme
    assert "ANCILIS_PLATFORM_DIR" in readme
    assert "ANCILIS_DEMO_BACKEND_URL" in readme
    assert "ANCILIS_DEMO_DASHBOARD_URL" in readme
    assert "ANCILIS_DEMO_SKIP_STACK_START" in readme
    assert "http://localhost:3000" in readme
    assert "http://localhost:8000" in readme
    assert "http://localhost:8000/docs" in readme
    assert "Docker" in readme
    assert "Node.js" in readme
    assert "curl" in readme
    assert "admin@ancilis.demo" in readme
    assert "ancilis-one-shot" in readme
    assert "when you want `run-all.sh` to start the Platform stack locally" in readme
    assert "ALLOW/BLOCK counts" not in readme
    assert "tool registry" in readme
    assert "summary block" in readme
    assert "ancilis report generate" in readme


# ---------------------------------------------------------------------------
# Local server session scoping (ANC-654)
# ---------------------------------------------------------------------------

def test_local_server_scopes_to_latest_session(tmp_path: Path) -> None:
    """local_server.py must scope summary+records to the latest session only."""
    import importlib.util
    import sys as _sys

    local_server_path = ROOT / "examples" / "demo" / "local_server.py"
    assert local_server_path.exists()

    spec = importlib.util.spec_from_file_location("examples.demo.local_server", local_server_path)
    assert spec is not None and spec.loader is not None
    ls_mod = importlib.util.module_from_spec(spec)
    _sys.modules[spec.name] = ls_mod
    spec.loader.exec_module(ls_mod)

    db = str(tmp_path / "evidence.duckdb")
    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=db)

    # Old session — stale data that should NOT appear on the dashboard
    from ancilis.engine.result import ControlResult, EvaluationResult
    import uuid as _uuid

    def _make_eval(decision: str, session_id: str, timestamp: str = "2025-01-15T10:00:00Z") -> EvaluationResult:
        return EvaluationResult(
            evaluation_id=str(_uuid.uuid4()),
            action_id="a1",
            timestamp=timestamp,
            agent_id="demo-agent",
            mode="audit",
            session_id=session_id,
            control_results=[
                ControlResult(
                    control_id="PR-01",
                    control_name="Agent Identity",
                    result="PASS",
                    detail="ok",
                    evidence_data={},
                    duration_ms=1.0,
                )
            ],
            decision=decision,
            decision_reason="test",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=1.0,
        )

    for _ in range(4):
        store.store(_make_eval("BLOCK", "old-session"), tool_name="bad-tool")

    # Latest session — 6 clean records matching what make demo-local would produce
    for _ in range(6):
        store.store(_make_eval("ALLOW", "new-session", "2025-01-15T12:00:00Z"), tool_name="good-tool")

    store.close()

    # Simulate what local_server.main() does when it picks up the latest session
    handler_store = ls_mod._load_store(db)
    session_id = handler_store.latest_session_id()
    assert session_id == "new-session", f"Expected latest session, got {session_id!r}"

    summary = handler_store.get_summary(session_id=session_id)
    assert summary["total_evaluations"] == 6
    assert summary["decisions"].get("ALLOW") == 6
    assert summary["decisions"].get("BLOCK", 0) == 0

    records = handler_store.get_records(session_id=session_id, limit=500)
    assert len(records) == 6
    assert all(r.tool_name == "good-tool" for r in records)

    handler_store.close()


def test_local_server_session_attribute_is_set_on_handler_class(tmp_path: Path) -> None:
    """EvidenceHandler.session_id must be set during server initialisation."""
    import importlib.util
    import sys as _sys

    local_server_path = ROOT / "examples" / "demo" / "local_server.py"
    spec = importlib.util.spec_from_file_location("examples.demo.local_server2", local_server_path)
    assert spec is not None and spec.loader is not None
    ls_mod = importlib.util.module_from_spec(spec)
    _sys.modules[spec.name] = ls_mod
    spec.loader.exec_module(ls_mod)

    db = str(tmp_path / "ev.duckdb")
    config = load_config(path=DEMO_CONFIG_PATH)
    store = EvidenceStore(config, db_path=db)

    from ancilis.engine.result import ControlResult, EvaluationResult
    import uuid as _uuid

    ev = EvaluationResult(
        evaluation_id=str(_uuid.uuid4()),
        action_id="a",
        timestamp="2025-01-15T10:00:00Z",
        agent_id="demo-agent",
        mode="audit",
        session_id="my-session",
        control_results=[
            ControlResult("PR-01", "Agent Identity", "PASS", "ok", {}, 1.0)
        ],
        decision="ALLOW",
        decision_reason="test",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
    )
    store.store(ev, tool_name="tool")
    store.close()

    handler_store = ls_mod._load_store(db)
    ls_mod.EvidenceHandler.store = handler_store
    ls_mod.EvidenceHandler.session_id = handler_store.latest_session_id()

    assert ls_mod.EvidenceHandler.session_id == "my-session"
    handler_store.close()
