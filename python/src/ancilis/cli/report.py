"""ancilis report — posture report generation."""

from __future__ import annotations

import click

from ancilis.config import load_config, ResolvedConfig
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_terminal, render_markdown, render_pdf


@click.command()
@click.option("--period", default="30d", help="Reporting period (e.g. 7d, 30d, 90d, 365d)")
@click.option("--format", "fmt", default="terminal", type=click.Choice(["terminal", "markdown", "pdf", "aiuc1-readiness"]))
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
            if output_path:
                render_pdf(md, output_path)
                click.echo(f"PDF report written to {output_path}")
            else:
                # Default PDF output
                default_path = "ancilis-report.pdf"
                render_pdf(md, default_path)
                click.echo(f"PDF report written to {default_path}")
    finally:
        store.close()
