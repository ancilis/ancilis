"""ancilis certify — framework-scoped evidence coverage reporting."""

from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any

import click

from ancilis.config import load_config
from ancilis.evidence.query import certification_coverage
from ancilis.evidence.store import EvidenceStore


def _load_certify_config(
    config_path: str | None,
    db_path: str | None,
    *,
    fallback_agent_name: str = "certify-cli",
) -> Any:
    try:
        if config_path is not None:
            return load_config(path=config_path)
        return load_config()
    except FileNotFoundError as e:
        if db_path is None or config_path is not None:
            click.echo(f"Error: {e}", err=True)
            click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
            raise SystemExit(1) from None
        return load_config(raw={"agent": {"name": fallback_agent_name}})
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
        raise SystemExit(1) from None


@click.command()
@click.option(
    "--target",
    required=True,
    type=click.Choice(["soc2", "hipaa", "pci", "aiuc1", "eu_ai_act"]),
    help="Framework or certification target to evaluate.",
)
@click.option("--dry-run", is_flag=True, help="Compute coverage without writing certification artifacts.")
@click.option(
    "--format",
    "output_format",
    default="table",
    show_default=True,
    type=click.Choice(["json", "table"]),
)
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
def certify(
    target: str,
    dry_run: bool,
    output_format: str,
    config_path: str | None,
    db_path: str | None,
) -> None:
    """Report control coverage for a target framework or certification."""
    effective_dry_run = True
    config = _load_certify_config(config_path, db_path)
    store = EvidenceStore(config, db_path=db_path)
    try:
        resolved_target, rows = certification_coverage(store, target=target)
    finally:
        store.close()

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "target": target,
                    "target_id": resolved_target.target_id,
                    "target_name": resolved_target.target_name,
                    "dry_run": effective_dry_run,
                    "controls": [asdict(row) for row in rows],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    click.echo(
        f"{'control_id':<10}  {'framework_ref':<36}  {'coverage_status':<15}  "
        f"{'evidence_count':<14}  {'last_evidence_at':<25}"
    )
    click.echo("-" * 112)
    for row in rows:
        click.echo(
            f"{row.control_id:<10}  {row.framework_ref:<36}  {row.coverage_status:<15}  "
            f"{row.evidence_count:<14}  {row.last_evidence_at or '-':<25}"
        )
