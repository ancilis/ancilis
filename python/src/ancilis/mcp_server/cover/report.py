"""Markdown report rendering for Ancilis Cover onboarding."""

from __future__ import annotations


def render_onboarding_report(
    *,
    summary: str,
    next_steps: list[str],
    confidence: str,
) -> str:
    """Render a short action-oriented onboarding report."""
    lines = [
        "# Ancilis Cover Onboarding Report",
        "",
        f"Confidence: {confidence}",
        "",
        "## Summary",
        "",
        summary,
        "",
        "## Next Steps",
        "",
    ]
    lines.extend(f"- {step}" for step in next_steps)
    return "\n".join(lines) + "\n"
