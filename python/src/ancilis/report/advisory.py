"""Classification advisory section for reports."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ancilis.activation.advisory import ClassificationAdvisory, PatternDetection
from ancilis.config import ResolvedConfig


def build_advisory_section(
    config: ResolvedConfig,
    summary: dict[str, Any],
) -> dict[str, Any] | None:
    """Build advisory section if there are classification recommendations.

    Returns None if no advisories to show.
    """
    pattern_map = summary.get("pattern_detections", {}) or {}
    detections = [
        PatternDetection(pattern_type=pattern_type, count=count)
        for pattern_type, count in sorted(pattern_map.items())
        if isinstance(pattern_type, str) and isinstance(count, int) and count > 0
    ]
    if not detections:
        return None

    advisor = ClassificationAdvisory()
    recommendations, upgrade_advisories = advisor.generate(
        detections,
        active_my_agent_handles=sorted(config.data_classifications.keys()),
        active_certifications=list(config.active_certifications),
    )
    if not recommendations and not upgrade_advisories:
        return None

    return {
        "pattern_detections": [asdict(detection) for detection in detections],
        "recommendations": [asdict(recommendation) for recommendation in recommendations],
        "upgrade_advisories": [asdict(advisory) for advisory in upgrade_advisories],
    }
