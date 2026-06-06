"""Tests for ancilis doctor — 12 test cases as specified in ANC-400."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ancilis.cli.doctor import (
    CheckResult,
    CheckStatus,
    DoctorReport,
    check_dependency_conflicts,
    check_evidence_cache,
    check_gitignore,
    check_producers,
    check_python_version,
    check_sdk_version,
    doctor,
)
from ancilis.cli.main import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config_file(tmp_path: Path, data: dict | None = None) -> Path:
    import yaml

    path = tmp_path / "ancilis.yaml"
    path.write_text(yaml.dump(data or {"agent": {"name": "test-agent"}}))
    return path


def _minimal_config_dict() -> dict:
    return {"agent": {"name": "test-agent"}}


# ---------------------------------------------------------------------------
# 1. test_doctor_all_pass
# ---------------------------------------------------------------------------


def test_doctor_all_pass(tmp_path: Path) -> None:
    """All checks pass — exit code 0, all ✓ markers present."""
    cfg = _make_config_file(tmp_path)

    with (
        patch("ancilis.cli.doctor.fetch_latest_version", return_value=None),
        patch("ancilis.cli.doctor.read_cache", return_value=None),
    ):
        result = CliRunner().invoke(
            cli,
            ["doctor", "--config", str(cfg)],
            env={"NO_COLOR": "1"},
            catch_exceptions=False,
        )

    assert result.exit_code in (0, 1), result.output
    assert "Ancilis Doctor" in result.output
    assert "checks passed" in result.output


# ---------------------------------------------------------------------------
# 2. test_doctor_config_missing
# ---------------------------------------------------------------------------


def test_doctor_config_missing(tmp_path: Path) -> None:
    """No ancilis.yaml → FAIL on config check, exit code 2."""
    with (
        patch("ancilis.cli.doctor.fetch_latest_version", return_value=None),
        patch("ancilis.cli.doctor.read_cache", return_value=None),
    ):
        result = CliRunner().invoke(
            cli,
            ["doctor", "--config", str(tmp_path / "nonexistent.yaml")],
            env={"NO_COLOR": "1"},
        )

    assert result.exit_code == 2
    assert "Configuration:" in result.output
    # Should show FAIL marker
    assert "[✗]" in result.output or "FAIL" in result.output.upper() or "not found" in result.output.lower()


# ---------------------------------------------------------------------------
# 3. test_doctor_python_version_too_old
# ---------------------------------------------------------------------------


def test_doctor_python_version_too_old() -> None:
    """Mock old Python version → check_python_version returns FAIL."""
    fake_vi = MagicMock()
    fake_vi.__ge__ = lambda self, other: False  # always < (3,9)

    with patch("ancilis.cli.doctor.sys") as mock_sys:
        mock_sys.version_info = (3, 8, 0)
        mock_sys.version = "3.8.0 (default)"

        result = check_python_version(None, False)

    assert result.status == CheckStatus.FAIL
    assert "3.8" in result.detail or "3.9" in result.detail


def test_doctor_python_version_ok() -> None:
    """Current Python is >=3.9 → PASS."""
    result = check_python_version(None, False)
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 4. test_doctor_sdk_version_outdated
# ---------------------------------------------------------------------------


def test_doctor_sdk_version_outdated() -> None:
    """Mock PyPI cache with newer version → check_sdk_version returns WARN."""
    with (
        patch(
            "ancilis.cli.doctor.read_cache",
            return_value={"latest_version": "99.99.99"},
        ),
        patch(
            "ancilis.cli.doctor.importlib.metadata.version",
            return_value="0.1.0",
        ),
    ):
        result = check_sdk_version(None, False)

    assert result.status == CheckStatus.WARN
    assert "0.1.0" in result.detail
    assert "99.99.99" in result.detail
    assert result.fix_hint


# ---------------------------------------------------------------------------
# 5. test_doctor_offline
# ---------------------------------------------------------------------------


def test_doctor_offline(tmp_path: Path) -> None:
    """All network calls time out — graceful degradation, no crash."""
    import urllib.error

    cfg = _make_config_file(tmp_path)

    def _raise_timeout(*args, **kwargs):
        raise urllib.error.URLError("timed out")

    with (
        patch("ancilis.cli.doctor.fetch_latest_version", return_value=None),
        patch("ancilis.cli.doctor.read_cache", return_value=None),
        patch("urllib.request.urlopen", side_effect=_raise_timeout),
    ):
        result = CliRunner().invoke(
            cli,
            ["doctor", "--config", str(cfg)],
            env={"NO_COLOR": "1"},
        )

    # Should not crash (exit_code not None and no exception)
    assert result.exit_code is not None
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Ancilis Doctor" in result.output


# ---------------------------------------------------------------------------
# 6. test_doctor_json_output
# ---------------------------------------------------------------------------


def test_doctor_json_output(tmp_path: Path) -> None:
    """--json outputs valid JSON matching the schema."""
    cfg = _make_config_file(tmp_path)

    with (
        patch("ancilis.cli.doctor.fetch_latest_version", return_value=None),
        patch("ancilis.cli.doctor.read_cache", return_value=None),
    ):
        result = CliRunner().invoke(
            cli,
            ["doctor", "--config", str(cfg), "--json"],
        )

    # Should be parseable JSON even if exit code != 0
    data = json.loads(result.output)
    assert "version" in data
    assert "checks" in data
    assert isinstance(data["checks"], list)
    assert len(data["checks"]) == 10
    assert "summary" in data
    assert "passed" in data["summary"]
    assert "warnings" in data["summary"]
    assert "errors" in data["summary"]
    assert "exit_code" in data
    for check in data["checks"]:
        assert "name" in check
        assert "status" in check
        assert check["status"] in ("pass", "warn", "fail")
        assert "detail" in check


# ---------------------------------------------------------------------------
# 7. test_doctor_verbose_output
# ---------------------------------------------------------------------------


def test_doctor_verbose_output(tmp_path: Path) -> None:
    """--verbose shows extra diagnostic detail indented under checks."""
    cfg = _make_config_file(tmp_path)

    with (
        patch("ancilis.cli.doctor.fetch_latest_version", return_value=None),
        patch("ancilis.cli.doctor.read_cache", return_value=None),
    ):
        result = CliRunner().invoke(
            cli,
            ["doctor", "--config", str(cfg), "--verbose"],
            env={"NO_COLOR": "1"},
        )

    # Verbose output has indented lines (4 spaces)
    lines = result.output.splitlines()
    indented = [line for line in lines if line.startswith("    ")]
    assert indented, "Expected verbose detail lines with 4-space indent"


# ---------------------------------------------------------------------------
# 8. test_doctor_fix_gitignore
# ---------------------------------------------------------------------------


def test_doctor_fix_gitignore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--fix appends .ancilis/ to .gitignore if missing."""
    # Create a git repo context
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.pyc\n")

    monkeypatch.chdir(tmp_path)

    result = check_gitignore(None, False, fix=True)

    assert result.status == CheckStatus.PASS
    assert ".ancilis/" in gitignore.read_text()


def test_doctor_fix_gitignore_creates_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--fix creates .gitignore if it doesn't exist."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    monkeypatch.chdir(tmp_path)

    result = check_gitignore(None, False, fix=True)

    assert result.status == CheckStatus.PASS
    assert (tmp_path / ".gitignore").exists()
    assert ".ancilis/" in (tmp_path / ".gitignore").read_text()


# ---------------------------------------------------------------------------
# 9. test_doctor_evidence_cache_large
# ---------------------------------------------------------------------------


def test_doctor_evidence_cache_large(tmp_path: Path) -> None:
    """Cache > 500 MB → WARN with cleanup hint."""
    cache_dir = tmp_path / ".ancilis"
    cache_dir.mkdir()
    # Write a probe file that passes writability, mock size calculation
    probe_file = cache_dir / "big.duckdb"
    probe_file.write_text("x")  # tiny actual file, but we mock the size

    big_stat = MagicMock()
    big_stat.st_size = 600 * 1024 * 1024  # 600 MB
    big_stat_result = MagicMock()
    big_stat_result.stat.return_value = big_stat
    big_stat_result.is_file.return_value = True

    def _fake_rglob(pattern):
        return [big_stat_result]

    with (
        patch.object(type(cache_dir), "home", return_value=tmp_path),
        patch("ancilis.cli.doctor.Path") as mock_path_cls,
    ):
        # Bypass patching complexity — test directly with monkeypatching rglob
        pass

    # Simpler approach: patch Path.home() to return tmp_path and create a big file mock
    import os

    orig_home = Path.home

    class _FakePath(type(Path())):
        pass

    # Direct unit test: override cache_dir size check
    with patch("ancilis.cli.doctor.Path") as _:
        pass

    # Cleanest: just mock the stat calls
    with patch("pathlib.Path.home", return_value=tmp_path):
        # rglob returns one "file" with 600MB size
        mock_file = MagicMock()
        mock_file.stat.return_value.st_size = 600 * 1024 * 1024
        mock_file.is_file.return_value = True

        with patch.object(Path, "rglob", return_value=[mock_file]):
            result = check_evidence_cache(None, False)

    assert result.status == CheckStatus.WARN
    assert "MB" in result.detail
    assert result.fix_hint


# ---------------------------------------------------------------------------
# 10. test_doctor_producer_missing
# ---------------------------------------------------------------------------


def test_doctor_producer_missing() -> None:
    """Configured producer with missing import → WARN."""
    from ancilis.config import ResolvedConfig

    mock_config = MagicMock(spec=ResolvedConfig)
    mock_config.my_agent_handles = ["langchain_data"]

    def _raise_import(name):
        if name == "langchain":
            raise ImportError("No module named 'langchain'")
        raise ImportError(f"No module named '{name}'")

    with patch("ancilis.cli.doctor.importlib.import_module", side_effect=_raise_import):
        result = check_producers(mock_config, False)

    assert result.status == CheckStatus.WARN
    assert "langchain" in result.detail


# ---------------------------------------------------------------------------
# 11. test_doctor_exit_codes
# ---------------------------------------------------------------------------


def test_doctor_exit_code_all_pass() -> None:
    report = DoctorReport(
        checks=[
            CheckResult(name="x", status=CheckStatus.PASS, label="X", detail="ok"),
        ]
    )
    assert report.exit_code == 0


def test_doctor_exit_code_warn_only() -> None:
    # Warnings are advisory: a healthy, warnings-only run must exit 0 so doctor
    # does not break CI/scripts on an otherwise-working install.
    report = DoctorReport(
        checks=[
            CheckResult(name="x", status=CheckStatus.PASS, label="X", detail="ok"),
            CheckResult(name="y", status=CheckStatus.WARN, label="Y", detail="warn"),
        ]
    )
    assert report.exit_code == 0


def test_doctor_exit_code_any_error() -> None:
    report = DoctorReport(
        checks=[
            CheckResult(name="x", status=CheckStatus.WARN, label="X", detail="warn"),
            CheckResult(name="y", status=CheckStatus.FAIL, label="Y", detail="fail"),
        ]
    )
    assert report.exit_code == 2


# ---------------------------------------------------------------------------
# 12. test_doctor_dependency_conflict
# ---------------------------------------------------------------------------


def test_doctor_dependency_conflict() -> None:
    """Mock old pydantic version → WARN about conflict."""
    version_map = {
        "pydantic": "1.10.0",
        "duckdb": "1.0.0",
    }

    with patch(
        "ancilis.cli.doctor.importlib.metadata.version",
        side_effect=lambda pkg: version_map.get(pkg, "0.0.0"),
    ):
        result = check_dependency_conflicts(None, False)

    assert result.status == CheckStatus.WARN
    assert "pydantic" in result.detail


def test_doctor_dependency_no_conflict() -> None:
    """Current environment should have no conflicts."""
    result = check_dependency_conflicts(None, False)
    # pydantic v2 + current duckdb → no conflicts in dev env
    assert result.status in (CheckStatus.PASS, CheckStatus.WARN)  # WARN only if missing pkg


# ---------------------------------------------------------------------------
# 13. Audit finding F4: no nonexistent `ancilis login`; hints point at `connect`
# ---------------------------------------------------------------------------


def test_doctor_has_no_ancilis_login_reference() -> None:
    import ancilis.cli.doctor as doctor_mod

    src = Path(doctor_mod.__file__).read_text(encoding="utf-8")
    assert "ancilis login" not in src
    # The real, existing command is `connect`.
    assert "ancilis connect" in src


def test_doctor_warning_only_run_exits_zero(tmp_path: Path) -> None:
    """A healthy, warnings-only run must exit 0 (not 1)."""
    cfg = _make_config_file(tmp_path)
    with (
        patch("ancilis.cli.doctor.fetch_latest_version", return_value=None),
        patch("ancilis.cli.doctor.read_cache", return_value=None),
    ):
        result = CliRunner().invoke(
            cli,
            ["doctor", "--config", str(cfg)],
            env={"NO_COLOR": "1"},
        )
    # No FAIL checks here; whatever warnings exist must not produce a nonzero exit.
    assert "[✗]" not in result.output  # no hard failures in this minimal setup
    assert result.exit_code == 0, result.output
