"""ancilis approve-tool — quick tool approval."""

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
    """Add a tool to the approved tools list."""
    path = Path(config_path)
    if not path.exists():
        click.echo(f"Config file not found: {config_path}", err=True)
        raise SystemExit(1)

    data = _read_config(config_path)

    # Navigate to security.tools.allowed
    security = data.setdefault("security", {})
    tools = security.setdefault("tools", {})
    allowed = tools.setdefault("allowed", [])

    if tool_name in allowed:
        click.echo(f"'{tool_name}' is already in the approved tools list.")
        return

    allowed.append(tool_name)
    _write_config(config_path, data)

    click.echo(f"Added '{tool_name}' to approved tools in {config_path}.")
    click.echo(f"Scope enforcement will now allow calls to {tool_name}.")
