"""ancilis connect — connect to the Ancilis platform dashboard."""

from __future__ import annotations

from pathlib import Path

import click


@click.command()
def connect() -> None:
    """Connect to the Ancilis platform dashboard."""
    click.echo("Ancilis platform connection")
    click.echo()
    platform_path = Path.home() / ".ancilis" / "platform.json"
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
