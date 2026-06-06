"""ancilis connect — connect to the optional Ancilis platform dashboard."""

from __future__ import annotations

import contextlib
import json
import os
import stat
from pathlib import Path

import click

DEFAULT_API_URL = "https://api.ancilis.ai"


def _platform_path() -> Path:
    return Path.home() / ".ancilis" / "platform.json"


@click.command()
@click.option(
    "--api-key",
    "api_key",
    default=None,
    help="Platform API key. Create one in the Ancilis dashboard Settings. "
    "When supplied, writes ~/.ancilis/platform.json.",
)
@click.option(
    "--api-url",
    "api_url",
    default=DEFAULT_API_URL,
    show_default=True,
    help="Ancilis platform API base URL.",
)
def connect(api_key: str | None, api_url: str) -> None:
    """Connect this SDK to the optional Ancilis platform dashboard.

    With ``--api-key`` this writes ``~/.ancilis/platform.json`` (mode 0600,
    it holds a secret) with ``api_url`` and ``api_key`` so ``ancilis doctor``
    and ``ancilis sync`` can reach the hosted platform. Without it, the command
    reports current connection status.

    The platform is strictly optional — Ancilis evaluates actions and stores
    evidence fully locally with nothing connected.
    """
    platform_path = _platform_path()

    if api_key:
        platform_path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            platform_path.parent.chmod(0o700)
        payload = {"api_url": api_url.rstrip("/"), "api_key": api_key}
        # Tighten any pre-existing file BEFORE writing the secret, so a previously
        # world-readable platform.json is not briefly exposed while we rewrite it.
        with contextlib.suppress(OSError):
            if platform_path.exists():
                platform_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        # Create the file owner-only (0600) from the start so the API key is
        # never briefly world-readable under a permissive umask.
        fd = os.open(platform_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(payload, indent=2) + "\n")
        with contextlib.suppress(OSError):
            # Re-assert 0600 in case the file already existed with looser perms.
            platform_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        click.echo("Ancilis platform connection")
        click.echo()
        click.echo("Status: connected")
        click.echo(f"Config: {platform_path}")
        click.echo(f"API URL: {payload['api_url']}")
        click.echo()
        click.echo("Verify with: ancilis doctor")
        return

    click.echo("Ancilis platform connection")
    click.echo()
    if platform_path.exists():
        click.echo("Status: connected")
        click.echo(f"Config: {platform_path}")
    else:
        click.echo("Status: not connected")
        click.echo()
        click.echo("To connect your SDK to the Ancilis dashboard:")
        click.echo("  1. Sign up at https://ancilis.dev")
        click.echo("  2. Create an API key in Settings")
        click.echo("  3. Run: ancilis connect --api-key <your-key>")
        click.echo()
        click.echo("The dashboard shows your agent security posture")
        click.echo("across all environments in one view.")
        click.echo()
        click.echo("The platform is optional — Ancilis runs fully local without it.")
