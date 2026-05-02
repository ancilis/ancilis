"""`ancilis remediate` command."""

from __future__ import annotations

from datetime import datetime, timezone

import click

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.remediation import (
    build_remediation_recommendations,
    render_remediation_recommendations,
)
from ancilis.report.generator import _parse_period


@click.command(name="remediate")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--period", default="30d", help="Evidence window (e.g. 24h, 7d, 30d)")
@click.option("--session", "session_id", default=None, help="Scope to a specific session ID")
@click.option("--latest/--all", "use_latest", default=True, help="Show latest session (default) or all sessions")
@click.option("--control", "control_id", default=None, help="Show guidance for one control ID")
def remediate(
    config_path: str | None,
    db_path: str | None,
    period: str,
    session_id: str | None,
    use_latest: bool,
    control_id: str | None,
) -> None:
    """Show remediation guidance for current compliance gaps."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        click.echo("Suggested fix: Create ancilis.yaml or run 'ancilis doctor' for setup help", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        if session_id is None and use_latest:
            session_id = store.latest_session_id()
        since = (datetime.now(timezone.utc) - _parse_period(period)).isoformat()
        summary = store.get_summary(since=since, session_id=session_id)
    finally:
        store.close()

    recommendations = build_remediation_recommendations(
        config,
        summary,
        control_id=control_id,
    )
    click.echo(render_remediation_recommendations(recommendations, control_id=control_id))
