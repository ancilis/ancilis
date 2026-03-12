"""ancilis approve-tool — approve a tool for provenance and scope."""

from __future__ import annotations

from pathlib import Path

import click
import yaml


def _read_config(config_path: str) -> dict:
    """Read YAML config from file."""
    return yaml.safe_load(Path(config_path).read_text()) or {}


def _write_config(config_path: str, data: dict) -> None:
    """Write YAML config to file."""
    Path(config_path).write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))


@click.command(name="approve-tool")
@click.argument("tool_name")
@click.option("--config", "config_path", default="ancilis.yaml", help="Path to ancilis.yaml")
def approve_tool(tool_name: str, config_path: str) -> None:
    """Approve a tool for both scope (PR-02) and provenance (PR-03).

    Adds the tool to security.tools.allowed so it passes scope checks,
    and marks it as approved so it passes provenance verification on the
    next middleware session.
    """
    path = Path(config_path)
    if not path.exists():
        click.echo(f"Config file not found: {config_path}", err=True)
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

    click.echo(f"  Scope (PR-02): '{tool_name}' is in security.tools.allowed")
    click.echo(f"  Provenance (PR-03): '{tool_name}' will be approved on next middleware init")
    click.echo(f"  To review posture: ancilis status")
