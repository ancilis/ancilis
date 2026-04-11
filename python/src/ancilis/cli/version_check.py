"""Non-blocking PyPI version check with disk cache."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

import click

PYPI_URL = "https://pypi.org/pypi/ancilis/json"
CACHE_PATH = Path.home() / ".ancilis" / "version-check.json"
DEFAULT_TTL = 86400  # 24 hours
NETWORK_TIMEOUT = 1.0  # seconds
CI_ENV_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "CIRCLECI",
    "TRAVIS",
    "TF_BUILD",
    "BUILDKITE",
)


def get_installed_version() -> str:
    from importlib.metadata import version as pkg_version

    return pkg_version("ancilis")


def is_ci_environment() -> bool:
    return any(os.environ.get(var) for var in CI_ENV_VARS)


def is_suppressed(ctx: click.Context) -> bool:
    if ctx.params.get("no_update_check"):
        return True
    env_val = os.environ.get("ANCILIS_NO_UPDATE_CHECK", "")
    if env_val.lower() in ("1", "true", "yes"):
        return True
    return bool(is_ci_environment())


def read_cache(cache_path: Path = CACHE_PATH, ttl: int = DEFAULT_TTL) -> dict | None:  # type: ignore[type-arg]
    try:
        data = json.loads(cache_path.read_text())
        if time.time() < data["checked_at"] + ttl:
            return data  # type: ignore[return-value]
        return None
    except Exception:
        return None


def write_cache(latest_version: str, cache_path: Path = CACHE_PATH) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps({"latest_version": latest_version, "checked_at": time.time()})
        )
    except Exception:
        pass


def fetch_latest_version() -> str | None:
    try:
        with urllib.request.urlopen(PYPI_URL, timeout=NETWORK_TIMEOUT) as resp:
            data = json.loads(resp.read())
            return str(data["info"]["version"])
    except Exception:
        return None


def should_notify(installed: str, latest: str) -> bool:
    from packaging.version import parse

    return parse(latest) > parse(installed)


def check_and_notify(ctx: click.Context, cache_path: Path = CACHE_PATH, ttl: int = DEFAULT_TTL) -> None:
    if is_suppressed(ctx):
        return

    cached = read_cache(cache_path=cache_path, ttl=ttl)
    if cached is not None:
        latest = cached["latest_version"]
        try:
            installed = get_installed_version()
        except Exception:
            return
        if should_notify(installed, latest):
            click.echo(
                f"\u26a0 ancilis v{latest} is available (you have v{installed})."
                " Run: pip install --upgrade ancilis",
                err=True,
            )
        return

    # Cache miss — spawn background thread to fetch and cache
    def _fetch_and_cache() -> None:
        try:
            latest = fetch_latest_version()
            if latest:
                write_cache(latest, cache_path=cache_path)
        except Exception:
            pass

    t = threading.Thread(target=_fetch_and_cache, daemon=True)
    t.start()
