"""Tests for anonymous SDK telemetry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.telemetry import (
    bucket_count,
    bucket_duration,
    flush_telemetry_events,
    format_telemetry_status,
    read_telemetry_status,
    record_telemetry_event,
    set_telemetry_enabled,
    telemetry_config_path,
    telemetry_queue_path,
)


class _Response:
    status = 202

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_telemetry_defaults_off_and_respects_do_not_track(tmp_path: Path) -> None:
    assert read_telemetry_status(home_dir=tmp_path).effective_enabled is False

    set_telemetry_enabled(True, home_dir=tmp_path)
    status = read_telemetry_status(home_dir=tmp_path, env={"DO_NOT_TRACK": "1"})

    assert status.enabled is True
    assert status.effective_enabled is False
    assert status.reason == "DO_NOT_TRACK is set"
    assert "No file paths" in format_telemetry_status(status)


def test_telemetry_off_does_not_create_installation_id(tmp_path: Path) -> None:
    disabled = set_telemetry_enabled(False, home_dir=tmp_path)

    assert disabled.installation_id is None
    assert "installation_id" not in telemetry_config_path(tmp_path).read_text()

    enabled = set_telemetry_enabled(True, home_dir=tmp_path)

    assert enabled.installation_id is not None
    assert "enabled = true" in telemetry_config_path(tmp_path).read_text()


def test_telemetry_queues_and_flushes_silently(tmp_path: Path) -> None:
    set_telemetry_enabled(True, home_dir=tmp_path, endpoint="https://telemetry.example.test/events")

    def offline(*_args: object, **_kwargs: object) -> object:
        raise OSError("offline")

    record_telemetry_event(
        "scan_executed",
        {"overlay_ids": ["soc2"]},
        home_dir=tmp_path,
        urlopen=offline,
    )

    assert telemetry_queue_path(tmp_path).exists()
    assert read_telemetry_status(home_dir=tmp_path).queued_events == 1

    payloads: list[dict[str, Any]] = []

    def fake_urlopen(request: object, **_kwargs: object) -> _Response:
        payloads.append(json.loads(request.data.decode("utf-8")))  # type: ignore[attr-defined]
        return _Response()

    result = flush_telemetry_events(home_dir=tmp_path, force=True, urlopen=fake_urlopen)

    assert result == {"sent": True, "count": 1}
    assert read_telemetry_status(home_dir=tmp_path).queued_events == 0
    assert len(payloads) == 1
    assert str(Path.cwd()) not in json.dumps(payloads[0])


def test_telemetry_cli_status_and_off(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    runner = CliRunner()

    status = runner.invoke(cli, ["--no-update-check", "telemetry", "status"])
    assert status.exit_code == 0
    assert "Telemetry: off" in status.output

    off = runner.invoke(cli, ["--no-update-check", "telemetry", "off"])
    assert off.exit_code == 0
    assert "Telemetry disabled" in off.output
    assert "installation_id" not in telemetry_config_path(tmp_path).read_text()


def test_telemetry_cli_records_failing_command_exit_code(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    set_telemetry_enabled(True, home_dir=tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["--no-update-check", "config", "validate", "--config", str(tmp_path / "missing.yaml")],
    )

    assert result.exit_code == 1
    lines = telemetry_queue_path(tmp_path).read_text().strip().splitlines()
    event = json.loads(lines[-1])
    assert event["event_type"] == "cli_command"
    assert event["properties"] == {"command": "config", "exit_code": 1}


def test_telemetry_buckets() -> None:
    assert bucket_count(0) == "0"
    assert bucket_count(10) == "1-10"
    assert bucket_count(100) == "10-100"
    assert bucket_count(101) == "100+"
    assert bucket_duration(0.5) == "<1s"
    assert bucket_duration(5) == "5-30s"
