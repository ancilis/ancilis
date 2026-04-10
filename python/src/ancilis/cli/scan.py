"""ancilis scan — CI/CD posture check with exit codes and JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from ancilis.config import ResolvedConfig, load_config, load_control_definitions
from ancilis.deps.scanner import DependencyScanner
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import _parse_period

_SENTINEL = Path.home() / ".ancilis" / ".first-run-complete"


def _load_config_safe(config_path: str | None) -> ResolvedConfig | None:
    try:
        if config_path:
            return load_config(path=config_path)
        return load_config()
    except (FileNotFoundError, ValueError):
        return None


def _default_config() -> ResolvedConfig:
    """Create a minimal in-memory config for zero-config scanning."""
    return load_config(raw={
        "agent": {"name": Path.cwd().name},
        "mode": "audit",
    })


def _period_to_since(period: str) -> str:
    return (datetime.now(timezone.utc) - _parse_period(period)).isoformat()


def _print_human_summary(
    config: ResolvedConfig,
    control_results: list[dict[str, Any]],
    posture: str,
    total_evaluations: int,
    sentinel_exists: bool = False,
    dep_items: list[dict[str, Any]] | None = None,
) -> None:
    if total_evaluations == 0:
        if sentinel_exists:
            click.echo("Ancilis scan \u2014 no evidence found")
            click.echo()
            click.echo("No tool-call evidence in this window.")
            click.echo("Run your agent with Ancilis middleware to collect evidence.")
            click.echo()
            click.echo("Next steps:")
            click.echo("  ancilis report              \u2014 generate a compliance report")
            click.echo("  ancilis status --verbose    \u2014 control-by-control breakdown")
            click.echo("  ancilis scan --ci           \u2014 JSON output for CI/CD pipelines")
        else:
            click.echo("Ancilis \u2014 first run")
            click.echo()
            click.echo("No tool-call evidence found yet. Ancilis records evidence")
            click.echo("when your AI agent runs with the middleware active.")
            click.echo()
            click.echo("Quick start:")
            click.echo("  1. Add middleware to your agent")
            click.echo("  2. Run your agent (tool calls get recorded)")
            click.echo("  3. Run `ancilis scan` again")
            click.echo()
            click.echo("Try the demo:")
            click.echo("  cd examples/demo && ancilis scan")
            click.echo()
            click.echo("Docs: https://ancilis.dev/quickstart")
    else:
        lines = [
            f"Ancilis scan \u2014 {config.agent_name}",
            f"  Mode:    {config.mode}",
            f"  Posture: {posture}",
            "",
        ]
        for ctrl in control_results:
            mark = {"pass": "\u2713", "fail": "\u2717", "skip": "\u2013"}.get(ctrl["status"], "?")
            detail = f"{ctrl['evaluations']} evals"
            if ctrl["failures"] > 0:
                detail += f", {ctrl['failures']} failures"
            if ctrl["flags"] > 0:
                detail += f", {ctrl['flags']} flags"
            lines.append(f"  {mark} {ctrl['name']} \u2014 {ctrl['status']} ({detail})")
        lines.append("")
        lines.append("Next steps:")
        lines.append("  ancilis report              \u2014 generate a compliance report")
        lines.append("  ancilis status --verbose    \u2014 control-by-control breakdown")
        lines.append("  ancilis scan --ci           \u2014 JSON output for CI/CD pipelines")
        click.echo("\n".join(lines))

    if dep_items:
        dep_marks = {"PASS": "\u2713", "FAIL": "\u2717", "FLAG": "\u26a0", "SKIP": "\u2013"}
        dep_lines = ["", "  DEPENDENCIES (DE-01):"]
        for item in dep_items:
            mark = dep_marks.get(item["result"], "?")
            dep_lines.append(f"    {mark} {item['detail']}")
            if item.get("remediation"):
                dep_lines.append(f"      \u2192 {item['remediation']}")
        click.echo("\n".join(dep_lines))


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
        config = _default_config()

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

        # Dependency vulnerability scan (DE-01)
        dep_items: list[dict[str, Any]] = []
        dep_any_failing = False
        for eval_result in DependencyScanner(config).scan():
            for cr in eval_result.control_results:
                dep_item: dict[str, Any] = {"result": cr.result, "detail": cr.detail}
                if cr.remediation_hint:
                    dep_item["remediation"] = cr.remediation_hint
                if cr.evidence_data:
                    dep_item["evidence"] = cr.evidence_data
                dep_items.append(dep_item)
                if cr.result == "FAIL":
                    dep_any_failing = True
                    any_failing = True

        dep_posture = "skip"
        if dep_items:
            if dep_any_failing:
                dep_posture = "non_compliant"
            elif any(i["result"] == "FLAG" for i in dep_items):
                dep_posture = "flag"
            elif all(i["result"] == "SKIP" for i in dep_items):
                dep_posture = "skip"
            elif any(i["result"] == "PASS" for i in dep_items):
                dep_posture = "compliant"

        posture = "non_compliant" if any_failing else "compliant"
        exit_code = 1 if any_failing else 0

        if ci:
            output = {
                "version": "0.1.0",
                "agent": config.agent_name,
                "mode": config.mode,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "controls": control_results,
                "dependencies": {
                    "posture": dep_posture,
                    "findings": dep_items,
                },
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
            sentinel_exists = _SENTINEL.exists()
            _print_human_summary(
                config, control_results, posture, total_evaluations,
                sentinel_exists=sentinel_exists, dep_items=dep_items or None,
            )
            if total_evaluations > 0 and not sentinel_exists:
                _SENTINEL.parent.mkdir(parents=True, exist_ok=True)
                _SENTINEL.touch()

        raise SystemExit(exit_code)
    finally:
        store.close()
