"""`ancilis telemetry` CLI commands."""

from __future__ import annotations

import click

from ancilis.telemetry import (
    flush_telemetry_events,
    format_telemetry_status,
    read_telemetry_status,
    set_telemetry_enabled,
)


@click.group(name="telemetry", invoke_without_command=True)
@click.pass_context
def telemetry(ctx: click.Context) -> None:
    """Inspect or change anonymous SDK telemetry settings."""
    if ctx.invoked_subcommand is None:
        click.echo(format_telemetry_status(read_telemetry_status()))


@telemetry.command(name="status")
def telemetry_status() -> None:
    """Show telemetry consent state and collected event types."""
    click.echo(format_telemetry_status(read_telemetry_status()))


@telemetry.command(name="on")
def telemetry_on() -> None:
    """Enable anonymous SDK telemetry."""
    set_telemetry_enabled(True)
    click.echo("Telemetry enabled. Anonymous usage events may be queued and sent at most once per hour.")


@telemetry.command(name="off")
def telemetry_off() -> None:
    """Disable anonymous SDK telemetry."""
    set_telemetry_enabled(False)
    click.echo("Telemetry disabled. No new telemetry events will be queued or sent.")


@telemetry.command(name="flush")
def telemetry_flush() -> None:
    """Flush queued telemetry events immediately."""
    result = flush_telemetry_events(force=True)
    if result.get("sent"):
        click.echo(f"Flushed {result['count']} telemetry event(s).")
    else:
        click.echo("No telemetry events flushed.")
