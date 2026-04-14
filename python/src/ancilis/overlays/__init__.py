"""Overlay ID helpers."""

from __future__ import annotations

from collections.abc import Iterable

OVERLAY_ID_ALIASES = {
    "nist-csf-2": "nist-csf",
}


def normalize_overlay_id(overlay_id: str) -> str:
    """Return the canonical overlay ID for a user-provided overlay identifier."""
    return OVERLAY_ID_ALIASES.get(overlay_id.strip().lower(), overlay_id)


def normalize_overlay_ids(overlay_ids: Iterable[str]) -> list[str]:
    """Normalize overlay IDs while preserving first-seen order and de-duplicating."""
    normalized: list[str] = []
    seen: set[str] = set()
    for overlay_id in overlay_ids:
        canonical = normalize_overlay_id(overlay_id)
        if canonical in seen:
            continue
        normalized.append(canonical)
        seen.add(canonical)
    return normalized


__all__ = ["OVERLAY_ID_ALIASES", "normalize_overlay_id", "normalize_overlay_ids"]
