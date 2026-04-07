"""ancilis scan — CI/CD posture check with exit codes and JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import click

from ancilis.config import ResolvedConfig, load_config, load_control_definitions
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import _parse_period


def _load_config_safe(config_path: str | None) -> ResolvedConfig | None:
    try:
        if config_path:
            return load_config(path=config_path)
        return load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error loading config: {e}", err=True)
        return None


def _period_to_since(period: str) -> str:
    return (datetime.now(timezone.utc) - _parse_period(period)).isoformat()


def _print_human_summary(
    config: ResolvedConfig,
    control_results: list[dict[str, Any]],
    posture: str,
    total_evaluations: int,
) -> None:
    lines = [
        f"Ancilis scan — {config.agent_name}",
        f"  Mode:    {config.mode}",
        f"  Posture: {posture}",
        "",
    ]
    if total_evaluations == 0:
        lines.append("  No evaluations recorded in period. Posture: compliant (nothing to check).")
    else:
        for ctrl in control_results:
            mark = {"pass": "\u2713", "fail": "\u2717", "skip": "\u2013"}.get(ctrl["status"], "?")
            detail = f"{ctrl['evaluations']} evals"
            if ctrl["failures"] > 0:
                detail += f", {ctrl['failures']} failures"
            if ctrl["flags"] > 0:
                detail += f", {ctrl['flags']} flags"
            lines.append(f"  {mark} {ctrl['name']} \u2014 {ctrl['status']} ({detail})")
    click.echo("\n".join(lines))


@click.command()
@click.option("--ci", is_flag=True, help="Machine-readable JSON output with exit codes")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--session", "session_id", default=None, help="Scope to a specific session ID")
@click.option("--latest/--all", "use_latest", default=True, help="Show latest session (default) or all sessions")
@click.option("--period", default="24h", help="Evidence window (e.g. 1h, 24h, 7d)")
def scan(
    ci: bool,
    config_path: str | None,
    db_path: str | None,
    session_id: str | None,
    use_latest: bool,
    period: str,
) -> None:
    """Evaluate evidence posture and return pass/fail for CI/CD pipelines."""
    config = _load_config_safe(config_path)
    if config is None:
        raise SystemExit(2)

    store = EvidenceStore(config, db_path=db_path)
    try:
        if session_id is None and use_latest:
            session_id = store.latest_session_id()
        since = _period_to_since(period)
        summary = store.get_summary(since=since, session_id=session_id)
        control_defs = load_control_definitions()
        enabled = [c for c in config.controls.values() if c.enabled]
        control_stats = summary.get("control_pass_rates", {})
        total_evaluations = summary.get("total_evaluations", 0)

        # Build per-control results
        control_results: list[dict[str, Any]] = []
        passing_count = 0
        failing_count = 0
        skipped_count = 0
        any_failing = False

        for cs in sorted(enabled, key=lambda c: c.control_id):
            cdef = control_defs.get(cs.control_id, {})
            display_name = cdef.get("display_name", cs.name)
            stats = control_stats.get(cs.control_id, {})
            failures = stats.get("FAIL", 0) + stats.get("ERROR", 0)
            flags = stats.get("FLAG", 0)
            total_evals = sum(stats.values()) if stats else 0

            if total_evals == 0:
                ctrl_status = "skip"
                skipped_count += 1
            elif failures > 0:
                ctrl_status = "fail"
                any_failing = True
                failing_count += 1
            else:
                ctrl_status = "pass"
                passing_count += 1

            control_results.append({
                "id": cs.control_id,
                "name": display_name,
                "status": ctrl_status,
                "evaluations": total_evals,
                "failures": failures,
                "flags": flags,
            })

        # Also fail posture if any tool call was blocked
        decisions = summary.get("decisions", {})
        normalized: dict[str, int] = {str(k).strip().upper(): int(v) for k, v in decisions.items()}
        if normalized.get("BLOCK", 0) > 0:
            any_failing = True

        posture = "non_compliant" if any_failing else "compliant"
        exit_code = 1 if any_failing else 0

        if ci:
            output = {
                "version": "0.1.0",
                "agent": config.agent_name,
                "mode": config.mode,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "controls": control_results,
                "summary": {
                    "total_controls": len(enabled),
                    "passing": passing_count,
                    "failing": failing_count,
                    "skipped": skipped_count,
                    "total_evaluations": total_evaluations,
                },
                "posture": posture,
                "exit_code": exit_code,
            }
            click.echo(json.dumps(output, indent=2))
        else:
            _print_human_summary(config, control_results, posture, total_evaluations)

        raise SystemExit(exit_code)
    finally:
        store.close()
