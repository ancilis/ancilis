"""Remediation guidance loading and current-gap recommendations."""

from __future__ import annotations

# mypy: disable-error-code=import-untyped

from dataclasses import dataclass
from typing import Any

import yaml

from ancilis._shared import iter_shared_paths
from ancilis.config import ResolvedConfig


@dataclass(frozen=True)
class RemediationGuide:
    control_id: str
    title: str
    difficulty: str
    time_estimate: str
    evidence_needed: list[str]
    fix_steps: list[str]
    code_example: str
    explanation: str
    docs_url: str | None = None


@dataclass(frozen=True)
class RemediationRecommendation:
    guide: RemediationGuide
    status: str
    evaluations: int
    failures: int
    flags: int
    pass_rate: float
    code_example: str


def _parse_frontmatter(markdown: str) -> tuple[dict[str, Any], str]:
    if not markdown.startswith("---\n"):
        raise ValueError("Remediation markdown must start with frontmatter")
    _, frontmatter, body = markdown.split("---", 2)
    data = yaml.safe_load(frontmatter) or {}
    if not isinstance(data, dict):
        raise ValueError("Remediation frontmatter must be a mapping")
    return data, body.strip()


def _guide_from_markdown(markdown: str) -> RemediationGuide:
    data, body = _parse_frontmatter(markdown)
    control_id = str(data["control_id"])
    return RemediationGuide(
        control_id=control_id,
        title=str(data.get("title") or control_id),
        difficulty=str(data.get("difficulty") or "medium"),
        time_estimate=str(data.get("time_estimate") or "unknown"),
        evidence_needed=[str(item) for item in data.get("evidence_needed", [])],
        fix_steps=[str(item) for item in data.get("fix_steps", [])],
        code_example=str(data.get("code_example") or ""),
        explanation=body,
        docs_url=str(data["docs_url"]) if data.get("docs_url") else None,
    )


def load_remediation_guides() -> dict[str, RemediationGuide]:
    """Load remediation guide markdown files from shared/remediation/controls."""
    guides: dict[str, RemediationGuide] = {}
    for path in iter_shared_paths("remediation", "controls", pattern="*.md"):
        guide = _guide_from_markdown(path.read_text(encoding="utf-8"))
        guides[guide.control_id] = guide
    return guides


def _stats_for(summary: dict[str, Any], control_id: str) -> tuple[int, int, int, float]:
    rates = summary.get("control_pass_rates", {})
    stats = rates.get(control_id, {}) if isinstance(rates, dict) else {}
    if not isinstance(stats, dict):
        return 0, 0, 0, 0.0
    passed = int(stats.get("PASS", 0) or 0)
    failures = int(stats.get("FAIL", 0) or 0) + int(stats.get("ERROR", 0) or 0)
    flags = int(stats.get("FLAG", 0) or 0)
    skipped = int(stats.get("SKIP", 0) or 0)
    total = passed + failures + flags + skipped
    pass_rate = round((passed / total) * 100, 1) if total else 0.0
    return total, failures, flags, pass_rate


def _status_for(total: int, failures: int, flags: int) -> str:
    if failures > 0:
        return "GAP"
    if flags > 0:
        return "PARTIAL"
    if total == 0:
        return "NO_EVIDENCE"
    return "HEALTHY"


def build_remediation_recommendations(
    config: ResolvedConfig,
    summary: dict[str, Any],
    *,
    control_id: str | None = None,
) -> list[RemediationRecommendation]:
    """Return remediation recommendations for current gaps or one requested control."""
    guides = load_remediation_guides()
    wanted = {control_id.upper()} if control_id else set(guides)
    recommendations: list[RemediationRecommendation] = []

    for cid in sorted(wanted):
        guide = guides.get(cid)
        if guide is None:
            continue
        control = config.controls.get(cid)
        if control is not None and not control.enabled:
            continue
        total, failures, flags, pass_rate = _stats_for(summary, cid)
        status = _status_for(total, failures, flags)
        if control_id is None and status not in {"GAP", "PARTIAL"}:
            continue
        recommendations.append(
            RemediationRecommendation(
                guide=guide,
                status=status,
                evaluations=total,
                failures=failures,
                flags=flags,
                pass_rate=pass_rate,
                code_example=guide.code_example.replace("{{agent_name}}", config.agent_name),
            )
        )

    return sorted(
        recommendations,
        key=lambda item: (0 if item.status == "GAP" else 1 if item.status == "PARTIAL" else 2, item.guide.control_id),
    )


def render_remediation_recommendations(
    recommendations: list[RemediationRecommendation],
    *,
    control_id: str | None = None,
) -> str:
    if not recommendations:
        if control_id:
            return f"No remediation guidance found for {control_id.upper()}."
        return "No current remediation guidance needed for this evidence window."

    lines: list[str] = []
    for rec in recommendations:
        guide = rec.guide
        lines.append(f"{guide.control_id} ({guide.title}) — {rec.status}")
        lines.append(
            f"  Time: {guide.time_estimate} | Difficulty: {guide.difficulty.title()} | "
            f"Evidence: {rec.evaluations} evals, {rec.failures} failures, {rec.flags} flags"
        )
        if guide.explanation:
            lines.append(f"  What is wrong: {guide.explanation}")
        if guide.fix_steps:
            lines.append("  How to fix:")
            for step in guide.fix_steps:
                lines.append(f"    - {step}")
        if guide.evidence_needed:
            lines.append("  Evidence needed:")
            for evidence in guide.evidence_needed:
                lines.append(f"    - {evidence}")
        if rec.code_example:
            lines.append("  Example:")
            for code_line in rec.code_example.rstrip().splitlines():
                lines.append(f"    {code_line}")
        if guide.docs_url:
            lines.append(f"  Docs: {guide.docs_url}")
        lines.append("")

    return "\n".join(lines).rstrip()
