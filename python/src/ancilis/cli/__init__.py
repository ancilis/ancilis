"""CLI commands for Ancilis."""

import click

from ancilis.config import format_resolved_config, load_config


@click.group()
def main() -> None:
    """Ancilis — runtime policy enforcement for AI agents."""


@main.group()
def config() -> None:
    """Configuration management commands."""


@config.command()
@click.argument("path", default="ancilis.yaml", type=click.Path())
def validate(path: str) -> None:
    """Validate an ancilis.yaml configuration file and display resolved state."""
    try:
        resolved = load_config(path=path)
        click.echo(format_resolved_config(resolved))
    except FileNotFoundError as e:
        raise click.ClickException(str(e))
    except ValueError as e:
        raise click.ClickException(f"Validation error: {e}")
