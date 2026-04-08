"""ancilis approve-tool — approve a tool for provenance and scope."""

from __future__ import annotations

from typing import Any
from pathlib import Path

import click
import yaml  # type: ignore[import-untyped]


def _read_config(config_path: str) -> dict[str, Any]:
    """Read YAML config from file."""
    return yaml.safe_load(Path(config_path).read_text()) or {}


def _write_config(config_path: str, data: dict[str, Any]) -> None:
    """Write YAML config to file."""
    Path(config_path).write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))


@click.command(name="approve-tool")
@click.argument("tool_name")
@click.option("--config", "config_path", default="ancilis.yaml", help="Path to ancilis.yaml")
def approve_tool(tool_name: str, config_path: str) -> None:
    """Approve a tool so it passes scope and provenance checks.

    Adds the tool to security.tools.allowed in your config file.
    On the next middleware session, the tool will be recognized as
    operator-approved.
    """
    path = Path(config_path)
    if not path.exists():
        click.echo(f"Config file not found: {config_path}", err=True)
        click.echo("Suggested fix: Create ancilis.yaml or run 'ancilis doctor' for setup help", err=True)
        raise SystemExit(1)

    data = _read_config(config_path)

    # Navigate to security.tools.allowed (scope — PR-02)
    security = data.setdefault("security", {})
    tools = security.setdefault("tools", {})
    allowed = tools.setdefault("allowed", [])

    added_to_scope = False
    if tool_name not in allowed:
        allowed.append(tool_name)
        added_to_scope = True

    _write_config(config_path, data)

    if added_to_scope:
        click.echo(f"Approved '{tool_name}' in {config_path}.")
    else:
        click.echo(f"'{tool_name}' was already in the approved tools list.")

    click.echo(f"  Scope: '{tool_name}' is in security.tools.allowed")
    click.echo(f"  Provenance: '{tool_name}' will be recognized on next middleware init")
    click.echo("  To review posture: ancilis status")
