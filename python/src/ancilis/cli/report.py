"""ancilis report — posture report generation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypeVar

import click

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import ReportGenerator, _parse_period
from ancilis.report.renderer import (
    render_csv,
    render_markdown,
    render_ndjson,
    render_pdf,
    render_terminal,
)

F = TypeVar("F", bound=Callable[..., object])


def _parse_period_start(period: str) -> str:
    return (datetime.now(timezone.utc) - _parse_period(period)).isoformat()


def _report_options(func: F) -> F:
    func = click.option("--output", "-o", "output_path", default=None, help="Output file path")(func)
    func = click.option("--db", "db_path", default=None, help="Path to evidence database")(func)
    func = click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")(func)
    func = click.option(
        "--format",
        "fmt",
        default="terminal",
        type=click.Choice(["terminal", "markdown", "pdf", "aiuc1-readiness", "ndjson", "csv"]),
    )(func)
    func = click.option("--period", default="30d", help="Reporting period (e.g. 7d, 30d, 90d, 365d)")(func)
    func = click.option("--session", "session_id", default=None, help="Scope to a specific session ID")(func)
    func = click.option("--latest/--all", "use_latest", default=True, help="Show latest session (default) or all sessions")(func)
    return func


def _emit_report(
    period: str,
    fmt: str,
    config_path: str | None,
    db_path: str | None,
    output_path: str | None,
    session_id: str | None = None,
    use_latest: bool = True,
) -> None:
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Suggested fix: Create ancilis.yaml or run 'ancilis doctor' for setup help", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        if session_id is None and use_latest:
            session_id = store.latest_session_id()
        generator = ReportGenerator(config, store)
        report_data = generator.generate(period=period, report_format=fmt, session_id=session_id)

        if fmt == "terminal":
            output = render_terminal(report_data)
            click.echo(output)
        elif fmt in ("markdown", "aiuc1-readiness"):
            md = render_markdown(report_data)
            if output_path:
                with open(output_path, "w") as f:
                    f.write(md)
                click.echo(f"Report written to {output_path}")
            else:
                click.echo(md)
        elif fmt == "pdf":
            md = render_markdown(report_data)
            requested_path = output_path or "ancilis-report.pdf"
            pdf_result = render_pdf(md, requested_path)
            if pdf_result.format == "pdf":
                click.echo(f"PDF report written to {pdf_result.output_path}")
            else:
                click.echo(
                    "PDF export unavailable "
                    f"({pdf_result.fallback_reason}); "
                    f"wrote Markdown fallback to {pdf_result.output_path}"
                )
        elif fmt == "ndjson":
            records = store.get_records(since=_parse_period_start(period), session_id=session_id, limit=None)
            output = render_ndjson(records)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(output)
                click.echo(f"Report written to {output_path}")
            else:
                click.echo(output)
        elif fmt == "csv":
            records = store.get_records(since=_parse_period_start(period), session_id=session_id, limit=None)
            output = render_csv(records)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(output)
                click.echo(f"Report written to {output_path}")
            else:
                click.echo(output)
    finally:
        store.close()


@click.group(invoke_without_command=True)
@click.pass_context
@_report_options
def report(
    ctx: click.Context,
    period: str,
    fmt: str,
    config_path: str | None,
    db_path: str | None,
    output_path: str | None,
    session_id: str | None,
    use_latest: bool,
) -> None:
    """Generate a posture report."""
    if ctx.invoked_subcommand is None:
        _emit_report(period, fmt, config_path, db_path, output_path, session_id, use_latest)


@report.command(name="generate")
@_report_options
def report_generate(
    period: str,
    fmt: str,
    config_path: str | None,
    db_path: str | None,
    output_path: str | None,
    session_id: str | None,
    use_latest: bool,
) -> None:
    """Generate a posture report."""
    _emit_report(period, fmt, config_path, db_path, output_path, session_id, use_latest)
