"""Regression tests for error-handling hardening (PG-5c).

Malformed config / bad CLI input must surface a clean Ancilis error (or Click
usage error) and a nonzero exit — never a raw Python traceback.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config, validate_config
from ancilis.errors import ConfigError, StorageError
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import _parse_period


def _yaml(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "ancilis.yaml"
    p.write_text(text, encoding="utf-8")
    return p


# --- config loading ---------------------------------------------------------


def test_malformed_yaml_raises_config_error_not_traceback(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "agent:\n  name: x\nbad: [unclosed\n")
    with pytest.raises(ConfigError):
        load_config(path=str(p))


def test_non_mapping_yaml_root_raises_config_error(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "- a\n- b\n")
    with pytest.raises(ConfigError):
        load_config(path=str(p))


def test_scalar_yaml_root_raises_config_error(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "just a string\n")
    with pytest.raises(ConfigError):
        load_config(path=str(p))


def test_non_string_control_key_raises_config_error() -> None:
    with pytest.raises(ConfigError):
        validate_config({"agent": {"name": "x"}, "security": {"controls": {123: {"enabled": True}}}})


def test_unhashable_handle_raises_config_error() -> None:
    # A list element would crash a set-membership test with a raw TypeError.
    with pytest.raises(ConfigError):
        validate_config({"agent": {"name": "x"}, "my_agent_handles": [["nested"]]})


def test_non_string_toplevel_key_raises_config_error() -> None:
    with pytest.raises(ConfigError):
        validate_config({"agent": {"name": "x"}, 123: "y"})


def test_unhashable_certification_target_raises_config_error() -> None:
    with pytest.raises(ConfigError):
        validate_config({"agent": {"name": "x"}, "certification_targets": [["nested"]]})


def test_malformed_warnings_field_does_not_crash() -> None:
    # A user-supplied non-list `_warnings` must be ignored, not crash the later
    # warnings.append() on the cert-target warning path.
    _cfg, warns = validate_config(
        {"agent": {"name": "x"}, "_warnings": "nope", "certification_targets": ["bogus-target"]}
    )
    assert isinstance(warns, list)


def test_installed_cli_group_handles_config_error_cleanly(tmp_path: Path) -> None:
    """The console-script path invokes the Click group directly (not module
    main()); a malformed config must still produce a clean E002, no traceback."""
    (tmp_path / "ancilis.yaml").write_text("agent:\n  name: x\nbad: [unclosed\n")
    proc = subprocess.run(
        [sys.executable, "-c", "import sys; sys.argv=['ancilis','status']; "
         "from ancilis.cli.main import cli; cli()"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "Traceback" not in out
    assert "ANCILIS-E002" in out


# --- evidence store ---------------------------------------------------------


def test_non_duckdb_file_raises_storage_error(tmp_path: Path) -> None:
    bad = tmp_path / "notdb.txt"
    bad.write_text("this is not a duckdb database", encoding="utf-8")
    store = EvidenceStore(load_config(raw={"agent": {"name": "x"}}), db_path=str(bad))
    with pytest.raises(StorageError):
        store.count()  # triggers _ensure_initialized -> duckdb.connect


def test_bare_relative_db_filename_raises_storage_error(tmp_path, monkeypatch) -> None:
    # A bare relative --db (no directory component) must not crash on makedirs('').
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rel.duckdb").write_text("not a database", encoding="utf-8")
    store = EvidenceStore(load_config(raw={"agent": {"name": "x"}}), db_path="rel.duckdb")
    with pytest.raises(StorageError):
        store.count()


# --- period parsing ---------------------------------------------------------


@pytest.mark.parametrize("bad", ["7xd", "xyzh", "abcd", "7w", "0h", "-1d", "", "nonsense", "d", "h"])
def test_parse_period_invalid_raises_clean_valueerror(bad: str) -> None:
    with pytest.raises(ValueError, match="invalid period"):
        _parse_period(bad)


@pytest.mark.parametrize("good,seconds", [("30d", 30 * 86400), ("24h", 86400), ("1d", 86400)])
def test_parse_period_valid(good: str, seconds: int) -> None:
    assert _parse_period(good).total_seconds() == seconds


def test_report_bad_period_is_clean_usage_error(tmp_path: Path) -> None:
    _yaml(tmp_path, "agent:\n  name: x\n")
    result = CliRunner().invoke(cli, ["report", "--period", "7xd", "--config", str(tmp_path / "ancilis.yaml")])
    assert result.exit_code == 2  # Click BadParameter
    assert "Traceback" not in result.output


# --- approve-tool on a malformed / non-mapping security section -------------


def test_approve_tool_malformed_yaml_clean_exit(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "security: [oops\n")
    result = CliRunner().invoke(cli, ["approve-tool", "mytool", "--config", str(p)])
    assert result.exit_code == 1
    assert "Traceback" not in result.output


def test_approve_tool_non_dict_security_clean(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "agent:\n  name: x\nsecurity: audit\n")
    result = CliRunner().invoke(cli, ["approve-tool", "mytool", "--config", str(p)], catch_exceptions=False)
    # Non-dict security is replaced, not crashed on; the tool is allow-listed.
    assert result.exit_code == 0
    assert "Traceback" not in result.output
