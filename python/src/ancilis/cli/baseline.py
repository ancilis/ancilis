"""ancilis baseline — baseline management and drift detection commands."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import click

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.overlays import normalize_overlay_id

if TYPE_CHECKING:
    from ancilis.baselines.manager import BaselineManager


def _make_manager(
    config_path: str | None,
    db_path: str | None,
) -> tuple[BaselineManager, EvidenceStore]:
    from ancilis.baselines.manager import BaselineManager
    from ancilis.config import ResolvedConfig

    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Tip: pass --config path/to/ancilis.yaml or run from a directory with ancilis.yaml", err=True)
        sys.exit(1)

    store = EvidenceStore(config, db_path=db_path)
    return BaselineManager(evidence_store=store, config=config), store


@click.group()
def baseline() -> None:
    """Baseline management and drift detection."""


@baseline.command(name="create")
@click.option("--label", required=True, help="Human-readable name for this baseline snapshot")
@click.option("--overlay", "overlay_id", default=None, help="Scope baseline to a specific overlay ID")
@click.option("--window", "window_hours", default=168, show_default=True, help="Evidence lookback window in hours")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
def baseline_create(
    label: str,
    overlay_id: str | None,
    window_hours: int,
    config_path: str | None,
    db_path: str | None,
) -> None:
    """Snapshot current control posture into a named baseline."""
    overlay_id = normalize_overlay_id(overlay_id) if overlay_id else None
    mgr, store = _make_manager(config_path, db_path)
    try:
        b = mgr.create(label=label, overlay_id=overlay_id, evidence_window_hours=window_hours)
        click.echo(f"Baseline created: {b.baseline_id}")
        click.echo(f"  Label   : {b.label}")
        click.echo(f"  Agent   : {b.agent_id}")
        if b.overlay_id:
            click.echo(f"  Overlay : {b.overlay_id}")
        click.echo(f"  Controls: {len(b.control_snapshots)} snapshot(s)")
        click.echo(f"  Window  : {window_hours}h ending {b.created_at}")
    finally:
        store.close()


@baseline.command(name="list")
@click.option("--overlay", "overlay_id", default=None, help="Filter by overlay ID")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
def baseline_list(
    overlay_id: str | None,
    config_path: str | None,
    db_path: str | None,
) -> None:
    """List stored baselines."""
    overlay_id = normalize_overlay_id(overlay_id) if overlay_id else None
    mgr, store = _make_manager(config_path, db_path)
    try:
        baselines = mgr.list_baselines(overlay_id=overlay_id)
        if not baselines:
            click.echo("No baselines found.")
            return
        click.echo(f"{'ID':<38}  {'LABEL':<24}  {'AGENT':<16}  {'OVERLAY':<16}  {'ACTIVE':<6}  CREATED")
        click.echo("-" * 120)
        for b in baselines:
            active = "YES" if b.is_active else "no"
            overlay = b.overlay_id or "-"
            click.echo(
                f"{b.baseline_id:<38}  {b.label:<24}  {b.agent_id:<16}  "
                f"{overlay:<16}  {active:<6}  {b.created_at}"
            )
    finally:
        store.close()


@baseline.command(name="drift")
@click.option("--id", "baseline_id", default=None, help="Baseline ID to check against (default: latest active)")
@click.option("--overlay", "overlay_id", default=None, help="Scope drift check to a specific overlay")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal", show_default=True)
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
def baseline_drift(
    baseline_id: str | None,
    overlay_id: str | None,
    fmt: str,
    config_path: str | None,
    db_path: str | None,
) -> None:
    """Check for control regressions against the active baseline."""
    overlay_id = normalize_overlay_id(overlay_id) if overlay_id else None
    mgr, store = _make_manager(config_path, db_path)
    try:
        try:
            report = mgr.check_drift(baseline_id=baseline_id, overlay_id=overlay_id)
        except KeyError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

        if fmt == "json":
            import dataclasses
            click.echo(json.dumps(dataclasses.asdict(report), indent=2))
            return

        # Terminal output
        status_color = "green" if report.overall_status == "STABLE" else "red"
        click.echo(f"\nDrift Report — {report.drift_report_id}")
        click.echo(f"  Baseline : {report.baseline_label} ({report.baseline_id})")
        click.echo(f"  Checked  : {report.checked_at}")
        click.echo(f"  Status   : {click.style(report.overall_status, fg=status_color, bold=True)}")
        click.echo(f"  Summary  : {report.summary}")

        if report.control_drifts:
            click.echo("\n  Drifted Controls:")
            click.echo(f"  {'CONTROL':<10}  {'SEV':<8}  {'BASELINE':<10}  {'CURRENT':<10}  {'B-RATE':>7}  {'C-RATE':>7}  DETAIL")
            click.echo("  " + "-" * 90)
            sev_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
            for d in report.control_drifts:
                sev_str = click.style(f"{d.severity:<8}", fg=sev_colors.get(d.severity, "white"))
                click.echo(
                    f"  {d.control_id:<10}  {sev_str}  {d.baseline_result:<10}  "
                    f"{d.current_result:<10}  {d.baseline_pass_rate:>6.1%}  {d.current_pass_rate:>6.1%}  "
                    f"{d.control_name}"
                )
        else:
            click.echo("\n  All controls are stable.")

        # Exit with non-zero if drifted (useful for CI)
        if report.overall_status == "DRIFTED":
            sys.exit(2)
    finally:
        store.close()
