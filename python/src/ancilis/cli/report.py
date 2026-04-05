"""ancilis report — posture report generation."""

from __future__ import annotations

import click

from datetime import datetime, timezone

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


def _parse_period_start(period: str) -> str:
    return (datetime.now(timezone.utc) - _parse_period(period)).isoformat()


@click.command()
@click.option("--period", default="30d", help="Reporting period (e.g. 7d, 30d, 90d, 365d)")
@click.option(
    "--format",
    "fmt",
    default="terminal",
    type=click.Choice(["terminal", "markdown", "pdf", "aiuc1-readiness", "ndjson", "csv"]),
)
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--output", "-o", "output_path", default=None, help="Output file path")
def report(period: str, fmt: str, config_path: str | None, db_path: str | None, output_path: str | None) -> None:
    """Generate a posture report."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        generator = ReportGenerator(config, store)
        report_data = generator.generate(period=period, report_format=fmt)

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
            records = store.get_records(since=_parse_period_start(period), limit=None)
            output = render_ndjson(records)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(output)
                click.echo(f"Report written to {output_path}")
            else:
                click.echo(output)
        elif fmt == "csv":
            records = store.get_records(since=_parse_period_start(period), limit=None)
            output = render_csv(records)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(output)
                click.echo(f"Report written to {output_path}")
            else:
                click.echo(output)
    finally:
        store.close()
