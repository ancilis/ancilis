"""Loads overlay profiles and certification profiles from shared JSON data files."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any, cast

from ancilis._shared import shared_path
from ancilis.plugins import PluginContext, PluginRegistry

logger = logging.getLogger("ancilis.activation")

SHARED_DIR = shared_path()
OVERLAYS_DIR = SHARED_DIR / "overlays"
CERTIFICATIONS_DIR = OVERLAYS_DIR / "certifications"
CONTROLS_DIR = SHARED_DIR / "controls"
CLASSIFICATIONS_FILE = SHARED_DIR / "classifications" / "taxonomy.json"


def load_overlay_profiles(
    *,
    plugin_registry: PluginRegistry | None = None,
    plugin_configs: Mapping[str, Mapping[str, Any]] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Load built-in and optional plugin overlay profiles."""
    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted(OVERLAYS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        profiles[data["id"]] = data
    if plugin_registry is not None:
        _merge_plugin_overlay_profiles(
            profiles,
            plugin_registry=plugin_registry,
            plugin_configs=plugin_configs or {},
            warnings=warnings,
        )
    return profiles


def _merge_plugin_overlay_profiles(
    profiles: dict[str, dict[str, Any]],
    *,
    plugin_registry: PluginRegistry,
    plugin_configs: Mapping[str, Mapping[str, Any]],
    warnings: list[str] | None,
) -> None:
    for record in plugin_registry.compatible("overlay"):
        plugin_name = record.name
        if record.plugin is None:
            _warn_overlay(plugin_name, "has no plugin object and was skipped", warnings)
            continue
        context = PluginContext(
            sdk_version=plugin_registry.sdk_version,
            config=plugin_configs.get(plugin_name, {}),
        )
        try:
            raw_profile = record.plugin.load_overlay_profile(context)  # type: ignore[attr-defined]
        except Exception as exc:
            _warn_overlay(plugin_name, f"failed to load overlay profile: {exc}", warnings)
            continue
        profile = _validated_plugin_overlay_profile(plugin_name, raw_profile, warnings)
        if profile is None:
            continue
        overlay_id = profile["id"]
        if overlay_id in profiles:
            _warn_overlay(
                plugin_name,
                f"overlay id '{overlay_id}' collides with an existing overlay and was skipped",
                warnings,
            )
            continue
        profiles[overlay_id] = profile


def _validated_plugin_overlay_profile(
    plugin_name: str,
    raw_profile: Any,
    warnings: list[str] | None,
) -> dict[str, Any] | None:
    if not isinstance(raw_profile, Mapping):
        _warn_overlay(plugin_name, "overlay profile must be a mapping", warnings)
        return None

    profile = {str(key): value for key, value in raw_profile.items()}
    overlay_id = profile.get("id")
    if not isinstance(overlay_id, str) or not overlay_id.startswith("plugin:"):
        _warn_overlay(plugin_name, "overlay id must be explicit and namespaced as plugin:<name>", warnings)
        return None

    for field_name in ("name", "trigger_type"):
        if not isinstance(profile.get(field_name), str) or not profile[field_name].strip():
            _warn_overlay(plugin_name, f"overlay profile missing required '{field_name}' field", warnings)
            return None

    for field_name in ("triggered_by", "applicable_data_types"):
        value = profile.get(field_name)
        if value is not None and not _is_string_list(value):
            _warn_overlay(plugin_name, f"overlay profile field '{field_name}' must be a list of strings", warnings)
            return None

    for field_name in ("control_adjustments", "evidence_requirements", "controls"):
        value = profile.get(field_name)
        if value is not None and not isinstance(value, Mapping):
            _warn_overlay(plugin_name, f"overlay profile field '{field_name}' must be a mapping", warnings)
            return None

    return profile


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _warn_overlay(plugin_name: str, detail: str, warnings: list[str] | None) -> None:
    message = f"Skipping Ancilis plugin overlay {plugin_name}: {detail}"
    logger.warning(message)
    if warnings is not None:
        warnings.append(message)


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
