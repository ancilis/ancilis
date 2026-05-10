"""Anonymous, opt-in SDK usage telemetry."""

from __future__ import annotations

import json
import os
import platform
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

if sys.version_info >= (3, 11):  # pragma: no cover - exercised by runtime version
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from ancilis import __version__

DEFAULT_ENDPOINT = "https://api.ancilis.ai/api/telemetry/events"
FLUSH_INTERVAL_SECONDS = 60 * 60
MAX_BATCH_SIZE = 50

TELEMETRY_EVENT_TYPES = (
    "scan_executed",
    "report_generated",
    "overlay_activated",
    "adapter_used",
    "cli_command",
)

_SKIP_DIRS = {
    ".ancilis",
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
}


@dataclass(frozen=True)
class TelemetryConfig:
    enabled: bool = False
    installation_id: str | None = None
    endpoint: str = DEFAULT_ENDPOINT
    prompted_at: str | None = None


@dataclass(frozen=True)
class TelemetryStatus:
    enabled: bool
    effective_enabled: bool
    reason: str | None
    installation_id: str | None
    endpoint: str
    config_path: Path
    queue_path: Path
    queued_events: int
    event_types: tuple[str, ...] = TELEMETRY_EVENT_TYPES


def _home_dir(home_dir: Path | None = None) -> Path:
    return home_dir or Path.home()


def telemetry_root(home_dir: Path | None = None) -> Path:
    return _home_dir(home_dir) / ".ancilis"


def telemetry_config_path(home_dir: Path | None = None) -> Path:
    return telemetry_root(home_dir) / "config.toml"


def telemetry_queue_path(home_dir: Path | None = None) -> Path:
    return telemetry_root(home_dir) / "telemetry" / "events.ndjson"


def _telemetry_state_path(home_dir: Path | None = None) -> Path:
    return telemetry_root(home_dir) / "telemetry" / "state.json"


def is_do_not_track_enabled(env: Mapping[str, str] | None = None) -> bool:
    resolved_env = env or os.environ
    value = resolved_env.get("DO_NOT_TRACK") or resolved_env.get("DNT")
    return value is not None and value.lower() not in {"", "0", "false", "no", "off"}


def read_telemetry_config(
    *,
    home_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
    endpoint: str | None = None,
) -> TelemetryConfig:
    resolved_env = env or os.environ
    resolved_endpoint = endpoint or resolved_env.get("ANCILIS_TELEMETRY_ENDPOINT") or DEFAULT_ENDPOINT
    path = telemetry_config_path(home_dir)
    if not path.exists():
        return TelemetryConfig(endpoint=resolved_endpoint)

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        telemetry = raw.get("telemetry", {})
        if not isinstance(telemetry, dict):
            return TelemetryConfig(endpoint=resolved_endpoint)
        return TelemetryConfig(
            enabled=bool(telemetry.get("enabled", False)),
            installation_id=telemetry.get("installation_id"),
            endpoint=endpoint
            or resolved_env.get("ANCILIS_TELEMETRY_ENDPOINT")
            or telemetry.get("endpoint")
            or DEFAULT_ENDPOINT,
            prompted_at=telemetry.get("prompted_at"),
        )
    except Exception:
        return TelemetryConfig(endpoint=resolved_endpoint)


def _quote_toml(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _write_telemetry_config(config: TelemetryConfig, *, home_dir: Path | None = None) -> None:
    path = telemetry_config_path(home_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    prompted_at = config.prompted_at or _now_iso()
    lines = [
        "# Ancilis global SDK settings",
        "[telemetry]",
        f"enabled = {'true' if config.enabled else 'false'}",
    ]
    if config.installation_id is not None:
        lines.append(f"installation_id = {_quote_toml(config.installation_id)}")
    lines.extend(
        [
            f"endpoint = {_quote_toml(config.endpoint)}",
            f"prompted_at = {_quote_toml(prompted_at)}",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def set_telemetry_enabled(
    enabled: bool,
    *,
    home_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
    endpoint: str | None = None,
) -> TelemetryConfig:
    current = read_telemetry_config(home_dir=home_dir, env=env, endpoint=endpoint)
    config = TelemetryConfig(
        enabled=enabled,
        installation_id=current.installation_id or str(uuid.uuid4()) if enabled else current.installation_id,
        endpoint=endpoint or current.endpoint,
        prompted_at=current.prompted_at or _now_iso(),
    )
    _write_telemetry_config(config, home_dir=home_dir)
    return config


def _queue_lines(*, home_dir: Path | None = None) -> list[str]:
    path = telemetry_queue_path(home_dir)
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_telemetry_status(
    *,
    home_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> TelemetryStatus:
    config = read_telemetry_config(home_dir=home_dir, env=env)
    dnt = is_do_not_track_enabled(env)
    enabled = config.enabled and config.installation_id is not None
    return TelemetryStatus(
        enabled=enabled,
        effective_enabled=enabled and not dnt,
        reason="DO_NOT_TRACK is set" if dnt else None if enabled else "telemetry is off",
        installation_id=config.installation_id,
        endpoint=config.endpoint,
        config_path=telemetry_config_path(home_dir),
        queue_path=telemetry_queue_path(home_dir),
        queued_events=len(_queue_lines(home_dir=home_dir)),
    )


def format_telemetry_status(status: TelemetryStatus) -> str:
    lines = [
        f"Telemetry: {'on' if status.effective_enabled else 'off'}",
    ]
    if status.reason:
        lines.append(f"Reason: {status.reason}")
    lines.extend(
        [
            f"Config: {status.config_path}",
            f"Queue: {status.queued_events} event(s) at {status.queue_path}",
            f"Endpoint: {status.endpoint}",
            "Collected event types:",
            *[f"  - {event_type}" for event_type in status.event_types],
            "",
            "No file paths, file contents, evidence data, email addresses, or API keys are collected.",
        ]
    )
    return "\n".join(lines)


def maybe_prompt_for_telemetry_consent(
    *,
    home_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    resolved_env = env or os.environ
    if (
        is_do_not_track_enabled(resolved_env)
        or resolved_env.get("CI")
        or resolved_env.get("ANCILIS_TELEMETRY_DISABLE_PROMPT")
    ):
        return False
    current = read_telemetry_config(home_dir=home_dir, env=resolved_env)
    if current.prompted_at is not None or current.installation_id is not None:
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    answer = input("Help improve Ancilis by sharing anonymous usage data? (y/N) ")
    enabled = answer.strip().lower().startswith("y")
    set_telemetry_enabled(enabled, home_dir=home_dir, env=resolved_env)
    return enabled


def bucket_count(count: int) -> str:
    if count <= 0:
        return "0"
    if count <= 10:
        return "1-10"
    if count <= 100:
        return "10-100"
    return "100+"


def bucket_duration(duration_seconds: float) -> str:
    if duration_seconds < 1:
        return "<1s"
    if duration_seconds < 5:
        return "1-5s"
    if duration_seconds < 30:
        return "5-30s"
    return "30s+"


def count_project_files(root: Path, *, limit: int = 101) -> int:
    count = 0
    stack = [root]
    while stack and count < limit:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if count >= limit:
                break
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                count += 1
    return count


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _event(event_type: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "timestamp": _now_iso(),
        "sdk_language": "python",
        "sdk_version": __version__,
        "runtime_version": platform.python_version(),
        "os_platform": f"{platform.system()} {platform.release()}",
        "properties": properties,
    }


def _read_state(*, home_dir: Path | None = None) -> dict[str, Any]:
    path = _telemetry_state_path(home_dir)
    if not path.exists():
        return {}
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}


def _write_state(state: dict[str, Any], *, home_dir: Path | None = None) -> None:
    path = _telemetry_state_path(home_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _flush_allowed(*, home_dir: Path | None = None, force: bool = False) -> bool:
    if force:
        return True
    last_attempt = _read_state(home_dir=home_dir).get("last_attempt_at")
    if not isinstance(last_attempt, str):
        return True
    try:
        last = time.strptime(last_attempt, "%Y-%m-%dT%H:%M:%SZ")
        return time.time() - time.mktime(last) >= FLUSH_INTERVAL_SECONDS
    except ValueError:
        return True


def record_telemetry_event(
    event_type: str,
    properties: dict[str, Any] | None = None,
    *,
    home_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
    urlopen: Callable[..., Any] | None = None,
) -> None:
    status = read_telemetry_status(home_dir=home_dir, env=env)
    if not status.effective_enabled or status.installation_id is None:
        return
    path = telemetry_queue_path(home_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(_event(event_type, properties or {})) + "\n")
    thread = threading.Thread(
        target=flush_telemetry_events,
        kwargs={"home_dir": home_dir, "env": env, "urlopen": urlopen},
        daemon=True,
    )
    thread.start()


def record_adapter_used(adapter_type: str) -> None:
    record_telemetry_event("adapter_used", {"adapter_type": adapter_type})


def flush_telemetry_events(
    *,
    home_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
    force: bool = False,
    urlopen: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    status = read_telemetry_status(home_dir=home_dir, env=env)
    if not status.effective_enabled or status.installation_id is None:
        return {"sent": False, "count": 0}
    if not _flush_allowed(home_dir=home_dir, force=force):
        return {"sent": False, "count": 0}

    lines = _queue_lines(home_dir=home_dir)
    if not lines:
        return {"sent": False, "count": 0}
    batch = [json.loads(line) for line in lines[:MAX_BATCH_SIZE]]
    remaining = lines[len(batch):]
    _write_state({"last_attempt_at": _now_iso()}, home_dir=home_dir)

    payload = json.dumps(
        {"installation_id": status.installation_id, "events": batch}
    ).encode("utf-8")
    request = urllib.request.Request(
        status.endpoint,
        data=payload,
        method="POST",
        headers={"content-type": "application/json"},
    )
    opener = urlopen or urllib.request.urlopen
    try:
        with opener(request, timeout=2) as response:
            if getattr(response, "status", 200) >= 400:
                return {"sent": False, "count": 0, "error": f"HTTP {response.status}"}
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        return {"sent": False, "count": 0, "error": str(exc)}

    path = telemetry_queue_path(home_dir)
    if remaining:
        path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
    else:
        path.unlink(missing_ok=True)
    return {"sent": True, "count": len(batch)}
