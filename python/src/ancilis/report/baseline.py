"""Baseline security report section."""

from __future__ import annotations

from typing import Any

from ancilis.config import ResolvedConfig


def _normalized_decisions(summary: dict[str, Any]) -> dict[str, int]:
    decisions = summary.get("decisions", {})
    normalized: dict[str, int] = {}
    for key, value in decisions.items():
        normalized[str(key).strip().upper()] = int(value)
    return normalized


def build_baseline_section(
    config: ResolvedConfig,
    summary: dict[str, Any],
    control_defs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the baseline security section of the report."""
    control_stats = summary.get("control_pass_rates", {})
    tools = summary.get("tools_evaluated", [])
    decisions = _normalized_decisions(summary)

    controls: list[dict[str, Any]] = []
    for cs in sorted(config.controls.values(), key=lambda c: c.control_id):
        if not cs.enabled:
            continue
        cdef = control_defs.get(cs.control_id, {})
        stats = control_stats.get(cs.control_id, {})
        total = sum(stats.values()) if stats else 0
        passed = stats.get("PASS", 0)
        failed = stats.get("FAIL", 0) + stats.get("ERROR", 0)
        flagged = stats.get("FLAG", 0)
        skipped = stats.get("SKIP", 0)
        # SKIP means "no evaluator ran", not "passed" — rate only what was evaluated.
        evaluated = total - skipped
        pass_rate = (passed / evaluated * 100) if evaluated > 0 else 0.0

        controls.append({
            "control_id": cs.control_id,
            "display_name": cdef.get("display_name", cs.name),
            "display_detail": cdef.get("display_detail", ""),
            "threshold": cs.threshold,
            "total": total,
            "passed": passed,
            "failed": failed,
            "flagged": flagged,
            "skipped": skipped,
            "evaluated": evaluated,
            "pass_rate": round(pass_rate, 1),
        })

    return {
        "controls": controls,
        "tools_evaluated": tools,
        "total_evaluations": summary.get("total_evaluations", 0),
        "decisions": {
            "allow": decisions.get("ALLOW", 0),
            "block": decisions.get("BLOCK", 0),
            "flag": decisions.get("FLAG", 0),
        },
        "evidence_retention_days": config.evidence_retention_days,
    }
