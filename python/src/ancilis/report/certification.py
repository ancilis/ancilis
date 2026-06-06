"""AIUC-1 certification readiness report section."""

from __future__ import annotations

from typing import Any

from ancilis.config import ResolvedConfig


def build_certification_section(
    config: ResolvedConfig,
    summary: dict[str, Any],
    cert_profiles: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Build the AIUC-1 certification readiness section.

    Readiness percentage reflects actual control posture — a requirement counts
    as "ready" only when its mapped AKSI control has at least one PASS evaluation
    and zero FAILs in the reporting period. Requirements with no evidence or any
    failures are not counted as ready.
    """
    profile = cert_profiles.get("aiuc-1")
    if not profile:
        return None

    control_stats = summary.get("control_pass_rates", {})
    req_map = profile.get("aksi_to_requirement_map", {})
    operator_items = profile.get("operator_action_required", [])

    # Build automated coverage: AKSI control -> AIUC-1 requirement IDs
    automated: list[dict[str, Any]] = []
    total_automated_reqs = 0
    ready_count = 0

    for aksi_id, req_ids in sorted(req_map.items()):
        stats = control_stats.get(aksi_id, {})
        total = sum(stats.values()) if stats else 0
        passed = stats.get("PASS", 0)
        failed = stats.get("FAIL", 0)
        flagged = stats.get("FLAG", 0)
        errored = stats.get("ERROR", 0)

        # A control is "ready" when it has evidence, passes, and has no failures
        control_ready = passed > 0 and failed == 0 and errored == 0

        for req_id in req_ids:
            total_automated_reqs += 1
            if control_ready:
                ready_count += 1

            automated.append({
                "requirement_id": req_id,
                "aksi_control": aksi_id,
                "evidence_count": total,
                "passed": passed,
                "failed": failed,
                "flagged": flagged,
                "ready": control_ready,
            })

    # Operator action items
    operator: list[dict[str, str]] = []
    for item in operator_items:
        operator.append({
            "requirement_id": item.get("requirement_id", ""),
            "description": item.get("description", ""),
            "category": item.get("category", ""),
        })

    total_requirements = total_automated_reqs + len(operator)
    # Readiness = ready automated reqs / total requirements (automated + operator)
    readiness_pct = round(ready_count / total_requirements * 100) if total_requirements > 0 else 0
    # Coverage = automated reqs with any mapping / total (the old metric, kept for context)
    coverage_pct = round(total_automated_reqs / total_requirements * 100) if total_requirements > 0 else 0

    return {
        "certification_id": "aiuc-1",
        "certification_name": profile.get("name", "AIUC-1"),
        "automated_coverage": automated,
        "operator_action_required": operator,
        "total_requirements": total_requirements,
        "automated_count": total_automated_reqs,
        "ready_count": ready_count,
        "operator_count": len(operator),
        "readiness_percentage": readiness_pct,
        "coverage_percentage": coverage_pct,
        "evidence_count": summary.get("total_evaluations", 0),
        "chain_valid": summary.get("chain_valid", True),
        "chain_status": summary.get("chain_status", ""),
    }
