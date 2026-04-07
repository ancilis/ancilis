"""ancilis evidence — evidence store management commands."""

from __future__ import annotations

import click

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore


@click.group()
def evidence() -> None:
    """Evidence store management commands."""


@evidence.command(name="sessions")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
def evidence_sessions(config_path: str | None, db_path: str | None) -> None:
    """List known evidence sessions with record counts and time ranges."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        sessions = store.list_sessions()
        if not sessions:
            click.echo("No sessions recorded yet.")
            return
        click.echo(f"{'SESSION ID':<40}  {'RECORDS':>7}  {'FIRST SEEN':<24}  {'LAST SEEN':<24}")
        click.echo("-" * 100)
        for s in sessions:
            click.echo(
                f"{s['session_id']:<40}  {s['count']:>7}  "
                f"{s['first_seen']:<24}  {s['last_seen']:<24}"
            )
    finally:
        store.close()


@evidence.command(name="reset")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def evidence_reset(config_path: str | None, db_path: str | None, yes: bool) -> None:
    """Clear ALL evidence records and restart the hash chain from genesis."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1) from None

    if not yes:
        click.confirm(
            "This will permanently delete ALL evidence records and restart the hash chain. Continue?",
            abort=True,
        )

    store = EvidenceStore(config, db_path=db_path)
    try:
        n = store.reset()
        click.echo(f"Evidence store reset: {n} record(s) deleted. Hash chain restarted from genesis.")
    finally:
        store.close()
