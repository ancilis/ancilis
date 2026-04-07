"""ancilis status — developer's primary interaction point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from ancilis.config import ResolvedConfig, load_config, load_control_definitions
from ancilis.evidence.store import EvidenceStore


def _normalized_decisions(summary: dict[str, Any]) -> dict[str, int]:
    decisions = summary.get("decisions", {})
    normalized: dict[str, int] = {}
    for key, value in decisions.items():
        normalized[str(key).strip().upper()] = int(value)
    return normalized


def _load_config_safe(config_path: str | None) -> ResolvedConfig | None:
    try:
        if config_path:
            return load_config(path=config_path)
        return load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error loading config: {e}", err=True)
        return None


def _format_status(
    config: ResolvedConfig,
    evidence: EvidenceStore,
    verbose: bool,
    session_id: str | None = None,
) -> str:
    lines: list[str] = []
    control_defs = load_control_definitions()

    lines.append(f"Ancilis — {config.agent_name}")
    lines.append(f"  Mode: {config.mode}")

    # Control summary
    enabled = [c for c in config.controls.values() if c.enabled]
    summary = evidence.get_summary(session_id=session_id)
    control_stats = summary.get("control_pass_rates", {})

    all_passing = True
    warnings: list[dict[str, str]] = []
    for cs in enabled:
        stats = control_stats.get(cs.control_id, {})
        if stats.get("FAIL", 0) > 0 or stats.get("ERROR", 0) > 0:
            all_passing = False
        # Collect FLAG results as warnings
        if stats.get("FLAG", 0) > 0:
            cdef = control_defs.get(cs.control_id, {})
            display = cdef.get("display_name", cs.name).lower()
            warnings.append({
                "category": display,
                "message": f"{cdef.get('display_name', cs.name)} flagged deviations",
                "hint": "Review recent activity: ancilis report --period 1d",
            })

    total = summary.get("total_evaluations", 0)
    if total == 0:
        passing_str = "not yet evaluated"
    elif all_passing:
        passing_str = "all passing"
    else:
        passing_str = "issues detected"
    lines.append(f"  Controls: {len(enabled)} active, {passing_str}")

    # Certification one-liners
    if config.active_certifications:
        for cert_id in config.active_certifications:
            lines.append(f"  {cert_id.upper()}: active")

    # Overlay one-liners
    if config.active_overlays:
        for _oid, oa in sorted(config.active_overlays.items()):
            trigger = ""
            if oa.triggered_by:
                first = oa.triggered_by[0]
                if " via " in first:
                    data_type = first.split(" via ")[1]
                    trigger = f" — triggered by {data_type} declaration"
            lines.append(f"  {oa.name}: active{trigger}")
    decisions = _normalized_decisions(summary)
    blocked = decisions.get("BLOCK", 0)
    if total > 0:
        lines.append(f"  Tool calls: {total:,} evaluated, {blocked} blocked")
    else:
        lines.append("  No evaluations recorded yet. Run your agent with Ancilis to start collecting evidence.")

    # Verbose: per-control detail
    if verbose:
        lines.append("")
        lines.append("  Controls:")
        for cs in sorted(enabled, key=lambda c: c.control_id):
            cdef = control_defs.get(cs.control_id, {})
            display_name = cdef.get("display_name", cs.name)
            stats = control_stats.get(cs.control_id, {})
            fail_count = stats.get("FAIL", 0) + stats.get("ERROR", 0)
            flag_count = stats.get("FLAG", 0)

            total_evals = sum(stats.values()) if stats else 0
            if total_evals == 0:
                mark = "–"
                status_str = "not yet evaluated"
            elif fail_count > 0:
                mark = "\u2717"
                status_str = f"failing ({fail_count} failures)"
            elif flag_count > 0:
                mark = "\u2713"
                status_str = f"passing ({flag_count} flags)"
            else:
                mark = "\u2713"
                status_str = "passing"
            lines.append(f"    {mark} {display_name} — {status_str}")

        # Activation details
        if config.active_certifications or config.active_overlays:
            lines.append("")
            lines.append("  Activation:")
            for cert_id in config.active_certifications:
                count = len(enabled)
                lines.append(f"    {cert_id.upper()} certification active — {count} controls enforcing")
            for _oid, oa in sorted(config.active_overlays.items()):
                trigger = ""
                if oa.triggered_by:
                    first = oa.triggered_by[0]
                    if " via " in first:
                        data_type = first.split(" via ")[1]
                        trigger = f" — triggered by {data_type} declaration"
                lines.append(f"    {oa.name} overlay active{trigger}")

        # Evidence summary
        if total > 0:
            chain_valid = summary.get("chain_valid", True)
            chain_status = "intact" if chain_valid else "BROKEN"
            lines.append(f"  Evidence records: {total:,} stored, hash chain {chain_status}")

    # Warnings (always shown)
    if warnings:
        lines.append("")
        lines.append("  Warnings:")
        for w in warnings:
            lines.append(f"    [{w['category']}] {w['message']}")
            lines.append(f"            {w['hint']}")

    return "\n".join(lines)


@click.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed status with per-control breakdown")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--session", "session_id", default=None, help="Scope to a specific session ID")
def status(verbose: bool, config_path: str | None, db_path: str | None, session_id: str | None) -> None:
    """Show current agent security posture."""
    config = _load_config_safe(config_path)
    if config is None:
        raise SystemExit(1)

    store = EvidenceStore(config, db_path=db_path)
    try:
        output = _format_status(config, store, verbose, session_id=session_id)
        click.echo(output)
    finally:
        store.close()
