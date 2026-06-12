"""ancilis report — posture report generation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypeVar
import time
import urllib.error
import urllib.parse
import urllib.request

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
from ancilis.report.renderers.oscal import render_oscal
from ancilis.telemetry import bucket_duration, record_telemetry_event

F = TypeVar("F", bound=Callable[..., object])


def _parse_period_start(period: str) -> str:
    return (datetime.now(timezone.utc) - _parse_period(period)).isoformat()


def _validate_period(ctx: object, param: object, value: str) -> str:
    """Click callback: reject a malformed --period with a clean usage error."""
    try:
        _parse_period(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc
    return value


def _report_options(func: F) -> F:
    func = click.option("--output", "-o", "output_path", default=None, help="Output file path")(func)
    func = click.option("--db", "db_path", default=None, help="Path to evidence database")(func)
    func = click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")(func)
    func = click.option(
        "--format",
        "fmt",
        default="terminal",
        type=click.Choice(["terminal", "markdown", "pdf", "aiuc1-readiness", "ndjson", "csv", "oscal"]),
    )(func)
    func = click.option(
        "--period", default="30d", callback=_validate_period,
        help="Reporting period (e.g. 7d, 30d, 90d, 365d)",
    )(func)
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
    started_at = time.monotonic()
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
        record_telemetry_event(
            "report_generated",
            {
                "format": fmt,
                "overlay_ids": sorted(config.active_overlays),
                "duration_bucket": bucket_duration(time.monotonic() - started_at),
                "period": period,
            },
        )

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
        elif fmt == "oscal":
            records = store.get_records(since=_parse_period_start(period), session_id=session_id, limit=None)
            output = render_oscal(records)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(output)
                click.echo(f"Report written to {output_path}")
            else:
                click.echo(output)
    finally:
        store.close()


def _export_report(
    fmt: str,
    period: str,
    api_url: str,
    auth_token: str,
    output_path: str | None,
) -> None:
    query = urllib.parse.urlencode({"format": fmt, "period": period})
    url = f"{api_url.rstrip('/')}/v1/evidence/export?{query}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {auth_token}",
            "Accept": _accept_header(fmt),
        },
    )

    try:
        with urllib.request.urlopen(request) as response:
            if output_path:
                with open(output_path, "wb") as f:
                    _copy_response(response, f.write)
                click.echo(f"Export written to {output_path}")
            else:
                _copy_response(response, lambda chunk: click.echo(chunk.decode("utf-8"), nl=False))
    except urllib.error.HTTPError as e:
        click.echo(_export_error_message(e), err=True)
        raise SystemExit(1) from None
    except urllib.error.URLError as e:
        click.echo(f"Export failed: {e.reason}", err=True)
        raise SystemExit(1) from None


def _copy_response(response: object, write: Callable[[bytes], object]) -> int:
    total = 0
    while True:
        chunk = response.read(1024 * 1024)  # type: ignore[attr-defined]
        if not chunk:
            return total
        total += len(chunk)
        write(chunk)


def _accept_header(fmt: str) -> str:
    if fmt == "csv":
        return "text/csv"
    if fmt == "ndjson":
        return "application/x-ndjson"
    return "application/oscal+json, application/json"


def _export_error_message(error: urllib.error.HTTPError) -> str:
    if error.code == 401:
        return "Authentication failed: verify --auth-token is a valid JWT."
    if error.code == 422:
        return "Export failed: no evidence matched the requested export."
    if error.code == 429:
        return "Export failed: platform rate limit exceeded; retry later."
    return f"Export failed: platform returned HTTP {error.code} {error.reason}."


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


@report.command(name="export")
@click.option(
    "--format",
    "fmt",
    default="oscal",
    type=click.Choice(["csv", "ndjson", "oscal"]),
)
@click.option("--period", default="30d", callback=_validate_period, help="Reporting period (e.g. 7d, 30d, 90d, 365d)")
@click.option("--api-url", required=True, help="Platform API base URL")
@click.option("--auth-token", required=True, help="Platform JWT auth token")
@click.option("--output", "-o", "output_path", default=None, help="Output file path")
def report_export(
    fmt: str,
    period: str,
    api_url: str,
    auth_token: str,
    output_path: str | None,
) -> None:
    """Download an evidence export from the platform API."""
    _export_report(fmt, period, api_url, auth_token, output_path)
