"""Loads overlay profiles and certification profiles from shared JSON data files."""

from __future__ import annotations

import json
import logging
from typing import Any, cast

from ancilis._shared import shared_path

logger = logging.getLogger("ancilis.activation")

SHARED_DIR = shared_path()
OVERLAYS_DIR = SHARED_DIR / "overlays"
CERTIFICATIONS_DIR = OVERLAYS_DIR / "certifications"
CONTROLS_DIR = SHARED_DIR / "controls"
CLASSIFICATIONS_FILE = SHARED_DIR / "classifications" / "taxonomy.json"


def load_overlay_profiles() -> dict[str, dict[str, Any]]:
    """Load all overlay profile JSON files from shared/overlays/."""
    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted(OVERLAYS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        profiles[data["id"]] = data
    return profiles


def load_certification_profile(cert_id: str) -> dict[str, Any] | None:
    """Load a single certification profile by ID. Returns None if not found."""
    path = CERTIFICATIONS_DIR / f"{cert_id}.json"
    if not path.exists():
        logger.warning("Certification profile not found: %s", cert_id)
        return None
    data = json.loads(path.read_text())
    if "version" not in data:
        logger.warning("Certification profile '%s' missing required 'version' field", cert_id)
        return None
    return cast(dict[str, Any], data)


def load_certification_profiles(cert_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Load multiple certification profiles by ID. Warns on missing profiles."""
    profiles: dict[str, dict[str, Any]] = {}
    for cid in cert_ids:
        profile = load_certification_profile(cid)
        if profile is not None:
            profiles[cid] = profile
    return profiles


def load_control_definitions() -> dict[str, dict[str, Any]]:
    """Load all control definition JSON files from shared/controls/."""
    controls: dict[str, dict[str, Any]] = {}
    for path in sorted(CONTROLS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        controls[data["id"]] = data
    return controls


def load_taxonomy() -> dict[str, Any]:
    """Load the classification taxonomy."""
    data = json.loads(CLASSIFICATIONS_FILE.read_text())
    return cast(dict[str, Any], data)
