"""Regression tests for `ancilis connect` (audit finding F4).

`ancilis connect --api-key` must write ~/.ancilis/platform.json with the
api_url/api_key keys that doctor reads, with owner-only permissions.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from click.testing import CliRunner

from ancilis.cli import connect as connect_mod
from ancilis.cli.connect import connect


def test_connect_api_key_writes_platform_json(tmp_path: Path, monkeypatch) -> None:
    platform_path = tmp_path / ".ancilis" / "platform.json"
    monkeypatch.setattr(connect_mod, "_platform_path", lambda: platform_path)

    result = CliRunner().invoke(
        connect,
        ["--api-key", "secret-key-123", "--api-url", "https://api.example.test/"],
    )
    assert result.exit_code == 0, result.output
    assert platform_path.exists()

    data = json.loads(platform_path.read_text())
    # doctor reads api_url || url and api_key || token
    assert data["api_key"] == "secret-key-123"
    assert data["api_url"] == "https://api.example.test"  # trailing slash stripped
    assert "connected" in result.output.lower()

    # File holds a secret: owner-only permissions.
    mode = stat.S_IMODE(platform_path.stat().st_mode)
    assert mode & 0o077 == 0, oct(mode)


def test_connect_without_key_reports_status(tmp_path: Path, monkeypatch) -> None:
    platform_path = tmp_path / ".ancilis" / "platform.json"
    monkeypatch.setattr(connect_mod, "_platform_path", lambda: platform_path)

    result = CliRunner().invoke(connect, [])
    assert result.exit_code == 0
    assert "not connected" in result.output.lower()
    # The help points at the real flag that now exists.
    assert "connect --api-key" in result.output
