"""Framework-by-framework compliance report sections."""

from __future__ import annotations

from typing import Any

from ancilis.config import ResolvedConfig


def build_compliance_sections(
    config: ResolvedConfig,
    summary: dict[str, Any],
    control_defs: dict[str, dict[str, Any]],
    overlay_profiles: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build compliance sections for each active overlay."""
    sections: list[dict[str, Any]] = []
    control_stats = summary.get("control_pass_rates", {})

    for oid, activation in sorted(config.active_overlays.items()):
        profile = overlay_profiles.get(oid, {})
        framework_mapping = profile.get("framework_mapping", {})
        adjustments = profile.get("control_adjustments", {})

        trigger = ""
        if activation.triggered_by:
            first = activation.triggered_by[0]
            if " via " in first:
                trigger = first.split(" via ")[1]

        # Build per-control rows with regulatory citations
        controls: list[dict[str, Any]] = []
        strict_controls: list[str] = []
        for cid, citations in sorted(framework_mapping.items()):
            cdef = control_defs.get(cid, {})
            stats = control_stats.get(cid, {})
            total = sum(stats.values()) if stats else 0
            passed = stats.get("PASS", 0)
            failed = stats.get("FAIL", 0) + stats.get("ERROR", 0)
            pass_rate = (passed / total * 100) if total > 0 else 0.0

            adj = adjustments.get(cid, {})
            threshold = adj.get("threshold_adjustment", "standard")
            if threshold == "strict":
                strict_controls.append(cid)

            controls.append({
                "control_id": cid,
                "display_name": cdef.get("display_name", cid),
                "citations": citations,
                "total": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": round(pass_rate, 1),
                "threshold": threshold,
            })

        # Gaps: controls with failures, framed as areas for improvement
        gaps = [c for c in controls if c["failed"] > 0]

        sections.append({
            "overlay_id": oid,
            "overlay_name": profile.get("name", oid),
            "triggered_by": trigger,
            "strict_controls": strict_controls,
            "controls": controls,
            "gaps": gaps,
            "evidence_retention_days": profile.get("evidence_retention_minimum_days", 365),
            "retention_met": config.evidence_retention_days >= profile.get("evidence_retention_minimum_days", 365),
        })

    return sections
