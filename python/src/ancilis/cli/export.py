"""ancilis export — local evidence export command."""

from __future__ import annotations

from pathlib import Path

import click

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.report.renderer import render_csv, render_ndjson


def export_records(
    *,
    fmt: str,
    since: str | None,
    config_path: str | None,
    db_path: str | None,
    output_path: str | None,
    session_id: str | None = None,
    quiet: bool = False,
) -> int:
    """Export local evidence records and return the emitted record count."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except FileNotFoundError as exc:
        if db_path is None:
            click.echo(f"Error: {exc}", err=True)
            click.echo("Suggested fix: pass --config path/to/ancilis.yaml or --db path/to/evidence.duckdb", err=True)
            raise SystemExit(1) from None
        config = load_config(raw={"agent": {"name": "evidence-export"}})
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        records = store.get_records(since=since, session_id=session_id, limit=None)
    finally:
        store.close()

    output = render_csv(records) if fmt == "csv" else render_ndjson(records)
    if output and fmt == "ndjson" and not output.endswith("\n"):
        output = f"{output}\n"

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        if not quiet:
            click.echo(f"Export written to {output_path}")
    elif output:
        click.echo(output, nl=not output.endswith("\n"))

    return len(records)


@click.command(name="export")
@click.option(
    "--format",
    "fmt",
    default="ndjson",
    type=click.Choice(["ndjson", "csv"]),
    show_default=True,
)
@click.option("--since", default=None, help="Only include records at or after this ISO-8601 timestamp.")
@click.option("--session", "session_id", default=None, help="Only include records from this session ID.")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--output", "-o", "output_path", default=None, help="Output file path")
def export(
    fmt: str,
    since: str | None,
    session_id: str | None,
    config_path: str | None,
    db_path: str | None,
    output_path: str | None,
) -> None:
    """Export local evidence records as NDJSON or CSV."""
    export_records(
        fmt=fmt,
        since=since,
        config_path=config_path,
        db_path=db_path,
        output_path=output_path,
        session_id=session_id,
    )
