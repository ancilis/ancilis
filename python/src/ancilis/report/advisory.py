"""Classification advisory section for reports."""

from __future__ import annotations

from typing import Any

from ancilis.config import ResolvedConfig


def build_advisory_section(
    config: ResolvedConfig,
    summary: dict[str, Any],
) -> dict[str, Any] | None:
    """Build advisory section if there are classification recommendations.

    Returns None if no advisories to show.
    """
    # In v0.1, we surface advisory data from config state.
    # Pattern detections would come from scan results stored in evidence.
    # For now, return None if no data classifications suggest further action.
    return None
