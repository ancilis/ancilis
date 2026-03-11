"""AIUC-1 certification readiness report section."""

from __future__ import annotations

from typing import Any

from ancilis.config import ResolvedConfig


def build_certification_section(
    config: ResolvedConfig,
    summary: dict[str, Any],
    cert_profiles: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Build the AIUC-1 certification readiness section."""
    profile = cert_profiles.get("aiuc-1")
    if not profile:
        return None

    control_stats = summary.get("control_pass_rates", {})
    req_map = profile.get("aksi_to_requirement_map", {})
    operator_items = profile.get("operator_action_required", [])

    # Build automated coverage: AKSI control -> AIUC-1 requirement IDs
    automated: list[dict[str, Any]] = []
    total_automated_reqs = 0
    for aksi_id, req_ids in sorted(req_map.items()):
        stats = control_stats.get(aksi_id, {})
        total = sum(stats.values()) if stats else 0
        passed = stats.get("PASS", 0)
        failed = stats.get("FAIL", 0)
        flagged = stats.get("FLAG", 0)

        for req_id in req_ids:
            total_automated_reqs += 1
            automated.append({
                "requirement_id": req_id,
                "aksi_control": aksi_id,
                "evidence_count": total,
                "passed": passed,
                "failed": failed,
                "flagged": flagged,
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
    automated_pct = round(total_automated_reqs / total_requirements * 100) if total_requirements > 0 else 0

    return {
        "certification_id": "aiuc-1",
        "certification_name": profile.get("name", "AIUC-1"),
        "automated_coverage": automated,
        "operator_action_required": operator,
        "total_requirements": total_requirements,
        "automated_count": total_automated_reqs,
        "operator_count": len(operator),
        "automated_percentage": automated_pct,
        "evidence_count": summary.get("total_evaluations", 0),
        "chain_valid": summary.get("chain_valid", True),
    }
