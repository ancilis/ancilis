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

            # support_level distinguishes controls Ancilis evaluates at runtime
            # (runtime_evaluator) from organizational controls it only tracks via
            # attestation — surfaced in the report Type column and the N-of-M
            # scope line.
            support_level = cdef.get("support_level", "")
            controls.append({
                "control_id": cid,
                "display_name": cdef.get("display_name", cid),
                "citations": citations,
                "total": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": round(pass_rate, 1),
                "threshold": threshold,
                "support_level": support_level,
                "runtime_testable": support_level == "runtime_evaluator",
            })

        # Gaps: controls with failures, framed as areas for improvement
        gaps = [c for c in controls if c["failed"] > 0]

        # Runtime-vs-organizational scope: how many mapped criteria Ancilis
        # actually evaluates at runtime vs. those it can only attest to.
        total_criteria = len(controls)
        runtime_criteria = sum(1 for c in controls if c["runtime_testable"])
        organizational_criteria = total_criteria - runtime_criteria
        # A scaffold overlay (top-level scaffold flag, or no framework mapping yet)
        # produces no verifiable criteria — surface that instead of implying coverage.
        is_scaffold = bool(profile.get("scaffold", False)) or total_criteria == 0

        sections.append({
            "overlay_id": oid,
            "overlay_name": profile.get("name", oid),
            "triggered_by": trigger,
            "strict_controls": strict_controls,
            "controls": controls,
            "gaps": gaps,
            "total_criteria": total_criteria,
            "runtime_criteria": runtime_criteria,
            "organizational_criteria": organizational_criteria,
            "scaffold": is_scaffold,
            "evidence_retention_days": profile.get("evidence_retention_minimum_days", 365),
            "evidence_retention_days_configured": config.evidence_retention_days,
            "retention_met": config.evidence_retention_days >= profile.get("evidence_retention_minimum_days", 365),
        })

    return sections
