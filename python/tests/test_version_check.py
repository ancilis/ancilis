"""Unit tests for ancilis.cli.version_check — 13 tests as specified in ANC-387."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import click
import pytest

from ancilis.cli.version_check import (
    CI_ENV_VARS,
    check_and_notify,
    fetch_latest_version,
    is_ci_environment,
    is_suppressed,
    read_cache,
    should_notify,
    write_cache,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx(no_update_check: bool = False) -> click.Context:
    """Create a minimal Click context with no_update_check param."""

    @click.command()
    @click.pass_context
    def _cmd(ctx: click.Context) -> None:
        pass

    ctx = click.Context(_cmd)
    ctx.params["no_update_check"] = no_update_check
    ctx.ensure_object(dict)
    ctx.obj["no_update_check"] = no_update_check
    return ctx


def _write_cache_file(path: Path, latest_version: str, age_seconds: float = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"latest_version": latest_version, "checked_at": time.time() - age_seconds})
    )


@pytest.fixture(autouse=True)
def _clear_ci_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_var in CI_ENV_VARS:
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.delenv("ANCILIS_NO_UPDATE_CHECK", raising=False)


# ---------------------------------------------------------------------------
# 1. test_notice_when_outdated
# ---------------------------------------------------------------------------


def test_notice_when_outdated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.2.0")

    monkeypatch.setattr(
        "ancilis.cli.version_check.get_installed_version", lambda: "0.1.0"
    )

    ctx = _make_ctx()
    output_lines: list[str] = []

    def _fake_echo(msg: Any = None, err: bool = False, **kwargs: Any) -> None:
        if err and msg:
            output_lines.append(str(msg))

    with patch("ancilis.cli.version_check.click.echo", side_effect=_fake_echo):
        monkeypatch.setattr(
            "ancilis.cli.version_check.get_installed_version", lambda: "0.1.0"
        )
        check_and_notify(ctx, cache_path=cache)

    assert any("0.2.0" in line for line in output_lines)
    assert any("pip install" in line for line in output_lines)


# ---------------------------------------------------------------------------
# 2. test_no_notice_when_current
# ---------------------------------------------------------------------------


def test_no_notice_when_current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.1.0")
    monkeypatch.setattr(
        "ancilis.cli.version_check.get_installed_version", lambda: "0.1.0"
    )

    output_lines: list[str] = []

    def _fake_echo(msg: Any = None, err: bool = False, **kwargs: Any) -> None:
        if err and msg:
            output_lines.append(str(msg))

    ctx = _make_ctx()
    with patch("ancilis.cli.version_check.click.echo", side_effect=_fake_echo):
        check_and_notify(ctx, cache_path=cache)

    assert output_lines == []


# ---------------------------------------------------------------------------
# 3. test_no_notice_when_newer
# ---------------------------------------------------------------------------


def test_no_notice_when_newer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.1.0")  # cache has older stable
    monkeypatch.setattr(
        "ancilis.cli.version_check.get_installed_version", lambda: "0.2.0"
    )

    output_lines: list[str] = []

    def _fake_echo(msg: Any = None, err: bool = False, **kwargs: Any) -> None:
        if err and msg:
            output_lines.append(str(msg))

    ctx = _make_ctx()
    with patch("ancilis.cli.version_check.click.echo", side_effect=_fake_echo):
        check_and_notify(ctx, cache_path=cache)

    assert output_lines == []


# ---------------------------------------------------------------------------
# 4. test_cache_miss_triggers_background_fetch
# ---------------------------------------------------------------------------


def test_cache_miss_triggers_background_fetch(tmp_path: Path) -> None:
    cache = tmp_path / "version-check.json"
    # No cache file

    threads_started: list[threading.Thread] = []
    original_start = threading.Thread.start

    def _capture_start(self: threading.Thread) -> None:
        threads_started.append(self)
        original_start(self)

    ctx = _make_ctx()
    with patch.object(threading.Thread, "start", _capture_start), patch("ancilis.cli.version_check.fetch_latest_version", return_value="0.2.0"):
        check_and_notify(ctx, cache_path=cache)

    assert len(threads_started) == 1


# ---------------------------------------------------------------------------
# 5. test_cache_expired_triggers_background_fetch
# ---------------------------------------------------------------------------


def test_cache_expired_triggers_background_fetch(tmp_path: Path) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.2.0", age_seconds=90000)  # well past 24h TTL

    threads_started: list[threading.Thread] = []
    original_start = threading.Thread.start

    def _capture_start(self: threading.Thread) -> None:
        threads_started.append(self)
        original_start(self)

    ctx = _make_ctx()
    with patch.object(threading.Thread, "start", _capture_start), patch("ancilis.cli.version_check.fetch_latest_version", return_value="0.2.0"):
        check_and_notify(ctx, cache_path=cache)

    assert len(threads_started) == 1


# ---------------------------------------------------------------------------
# 6. test_cache_valid_no_network
# ---------------------------------------------------------------------------


def test_cache_valid_no_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.1.0")  # same version, no notice expected
    monkeypatch.setattr(
        "ancilis.cli.version_check.get_installed_version", lambda: "0.1.0"
    )

    network_called = []

    def _no_network() -> None:
        network_called.append(True)

    ctx = _make_ctx()
    with patch("ancilis.cli.version_check.fetch_latest_version", side_effect=_no_network):
        check_and_notify(ctx, cache_path=cache)

    # fetch_latest_version should NOT have been called
    assert network_called == []


# ---------------------------------------------------------------------------
# 7. test_suppressed_by_flag
# ---------------------------------------------------------------------------


def test_suppressed_by_flag(tmp_path: Path) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.2.0")

    fetch_called = []
    ctx = _make_ctx(no_update_check=True)

    with patch("ancilis.cli.version_check.fetch_latest_version", side_effect=lambda: fetch_called.append(True)), patch("ancilis.cli.version_check.read_cache", side_effect=lambda **kw: fetch_called.append(True)):
        check_and_notify(ctx, cache_path=cache)

    assert fetch_called == []


# ---------------------------------------------------------------------------
# 8. test_suppressed_by_env
# ---------------------------------------------------------------------------


def test_suppressed_by_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.2.0")

    monkeypatch.setenv("ANCILIS_NO_UPDATE_CHECK", "1")

    output_lines: list[str] = []

    def _fake_echo(msg: Any = None, err: bool = False, **kwargs: Any) -> None:
        if err and msg:
            output_lines.append(str(msg))

    ctx = _make_ctx()
    with patch("ancilis.cli.version_check.click.echo", side_effect=_fake_echo):
        check_and_notify(ctx, cache_path=cache)

    assert output_lines == []


# ---------------------------------------------------------------------------
# 9. test_suppressed_in_ci
# ---------------------------------------------------------------------------


def test_suppressed_in_ci(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.2.0")

    monkeypatch.setenv("CI", "true")
    # Make sure ANCILIS_NO_UPDATE_CHECK is not set
    monkeypatch.delenv("ANCILIS_NO_UPDATE_CHECK", raising=False)

    output_lines: list[str] = []

    def _fake_echo(msg: Any = None, err: bool = False, **kwargs: Any) -> None:
        if err and msg:
            output_lines.append(str(msg))

    ctx = _make_ctx()
    with patch("ancilis.cli.version_check.click.echo", side_effect=_fake_echo):
        check_and_notify(ctx, cache_path=cache)

    assert output_lines == []


# ---------------------------------------------------------------------------
# 10. test_network_error_graceful
# ---------------------------------------------------------------------------


def test_network_error_graceful(tmp_path: Path) -> None:
    cache = tmp_path / "version-check.json"
    # No cache — triggers background fetch

    ctx = _make_ctx()

    def _raise() -> None:
        raise OSError("Network unreachable")

    # Should not raise, should not produce output
    with patch("ancilis.cli.version_check.fetch_latest_version", side_effect=_raise):
        try:
            check_and_notify(ctx, cache_path=cache)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"check_and_notify raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# 11. test_invalid_cache_json
# ---------------------------------------------------------------------------


def test_invalid_cache_json(tmp_path: Path) -> None:
    cache = tmp_path / "version-check.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("{not valid json!!!")

    threads_started: list[threading.Thread] = []
    original_start = threading.Thread.start

    def _capture_start(self: threading.Thread) -> None:
        threads_started.append(self)
        original_start(self)

    ctx = _make_ctx()
    # Corrupt cache → treated as miss → background thread spawned
    with patch.object(threading.Thread, "start", _capture_start), patch("ancilis.cli.version_check.fetch_latest_version", return_value="0.2.0"):
        check_and_notify(ctx, cache_path=cache)

    assert len(threads_started) == 1


# ---------------------------------------------------------------------------
# 12. test_stderr_not_stdout
# ---------------------------------------------------------------------------


def test_stderr_not_stdout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.2.0")
    monkeypatch.setattr(
        "ancilis.cli.version_check.get_installed_version", lambda: "0.1.0"
    )

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    def _fake_echo(msg: Any = None, err: bool = False, **kwargs: Any) -> None:
        if err:
            stderr_lines.append(str(msg or ""))
        else:
            stdout_lines.append(str(msg or ""))

    ctx = _make_ctx()
    with patch("ancilis.cli.version_check.click.echo", side_effect=_fake_echo):
        check_and_notify(ctx, cache_path=cache)

    assert any("0.2.0" in line for line in stderr_lines), "Notice not on stderr"
    assert stdout_lines == [], "Unexpected stdout output"


# ---------------------------------------------------------------------------
# 13. test_prerelease_installed_still_notifies_stable
# ---------------------------------------------------------------------------


def test_prerelease_installed_still_notifies_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "version-check.json"
    _write_cache_file(cache, "0.1.0")  # latest stable
    monkeypatch.setattr(
        "ancilis.cli.version_check.get_installed_version", lambda: "0.1.0a1"
    )

    output_lines: list[str] = []

    def _fake_echo(msg: Any = None, err: bool = False, **kwargs: Any) -> None:
        if err and msg:
            output_lines.append(str(msg))

    ctx = _make_ctx()
    with patch("ancilis.cli.version_check.click.echo", side_effect=_fake_echo):
        check_and_notify(ctx, cache_path=cache)

    assert any("0.1.0" in line for line in output_lines), "Expected notice for stable upgrade"


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


def test_should_notify_returns_true_when_newer() -> None:
    assert should_notify("0.1.0", "0.2.0") is True


def test_should_notify_returns_false_when_same() -> None:
    assert should_notify("0.1.0", "0.1.0") is False


def test_write_and_read_cache_roundtrip(tmp_path: Path) -> None:
    cache = tmp_path / "vc.json"
    write_cache("0.3.0", cache_path=cache)
    data = read_cache(cache_path=cache)
    assert data is not None
    assert data["latest_version"] == "0.3.0"


def test_is_ci_environment_detects_github_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert is_ci_environment() is True


def test_fetch_latest_version_returns_none_on_error() -> None:
    with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
        result = fetch_latest_version()
    assert result is None
