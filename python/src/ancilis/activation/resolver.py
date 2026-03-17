"""Activation resolver — reads config, handles both activation paths, produces unified ActivationSpec."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ancilis.activation.loader import (
    load_certification_profiles,
    load_control_definitions,
    load_overlay_profiles,
    load_taxonomy,
)

logger = logging.getLogger("ancilis.activation")

# All 26 AKSI controls — always active as baseline
ALL_AKSI_CONTROLS = {
    "GOV-01", "GOV-02", "GOV-03", "GOV-04",
    "ID-01", "ID-02", "ID-03", "ID-04", "ID-05",
    "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08",
    "DE-01", "DE-02", "DE-03", "DE-04",
    "RS-01", "RS-02", "RS-03",
    "RC-01", "RC-02",
}

# Legacy aliases for backward compatibility
BASELINE_CONTROLS = ALL_AKSI_CONTROLS
EXTENDED_CONTROLS: set[str] = set()  # All controls are now baseline


@dataclass
class ActivationSpec:
    active_controls: list[str] = field(default_factory=list)
    active_overlays: list[str] = field(default_factory=list)
    active_certifications: list[str] = field(default_factory=list)
    data_classifications: list[str] = field(default_factory=list)
    control_thresholds: dict[str, str] = field(default_factory=dict)
    evidence_requirements: dict[str, list[str]] = field(default_factory=dict)
    activation_source: dict[str, str] = field(default_factory=dict)
    activation_summary: list[str] = field(default_factory=list)
    evidence_retention_days: int = 365
    human_oversight_required: bool = False


class ActivationResolver:
    """Resolves config into a unified ActivationSpec consumed by the engine."""

    def __init__(self) -> None:
        self._control_defs = load_control_definitions()
        self._overlay_profiles = load_overlay_profiles()
        self._taxonomy = load_taxonomy()

    def resolve(
        self,
        my_agent_handles: list[str] | None = None,
        certification_targets: list[str] | None = None,
    ) -> ActivationSpec:
        spec = ActivationSpec()

        # 1. Start with all 26 AKSI controls (all are baseline)
        for cid in sorted(ALL_AKSI_CONTROLS):
            spec.active_controls.append(cid)
            spec.control_thresholds[cid] = "standard"
            spec.activation_source[cid] = "baseline"

        # 2. NIST CSF baseline overlay (always active)
        nist_csf = self._overlay_profiles.get("nist-csf")
        if nist_csf and nist_csf.get("trigger_type") == "baseline":
            spec.active_overlays.append("nist-csf")
            spec.activation_source["nist-csf"] = "baseline"

        # 3. Path 1 — data classification
        if my_agent_handles:
            self._resolve_data_path(spec, my_agent_handles)

        # 4. Path 2 — certification intent
        if certification_targets:
            self._resolve_certification_path(spec, certification_targets)

        # Sort controls for consistency
        spec.active_controls = sorted(set(spec.active_controls))

        # Build activation summary
        spec.activation_summary = self._build_summary(spec)

        return spec

    def _resolve_data_path(self, spec: ActivationSpec, my_agent_handles: list[str]) -> None:
        """Path 1: Translate data types → DC codes → overlay activations."""
        type_mapping = self._taxonomy.get("developer_type_mapping", {})

        # Build DC code → overlay lookup
        classification_lookup: dict[str, list[str]] = {}
        for entry in self._taxonomy.get("classifications", []):
            classification_lookup[entry["code"]] = entry.get("overlays", [])

        all_dc_codes: set[str] = set()
        for data_type in my_agent_handles:
            dc_codes = type_mapping.get(data_type, [])
            all_dc_codes.update(dc_codes)

            # Determine which overlays to activate
            for dc_code in dc_codes:
                overlay_ids = classification_lookup.get(dc_code, [])
                for oid in overlay_ids:
                    # Skip baseline overlays (already activated)
                    if oid in self._overlay_profiles:
                        profile = self._overlay_profiles[oid]
                        if profile.get("trigger_type") == "baseline":
                            continue
                        if oid not in spec.active_overlays:
                            spec.active_overlays.append(oid)
                            spec.activation_source[oid] = f"my_agent_handles:{data_type}"
                    else:
                        # Overlay not available — log informational message for roadmap items
                        logger.info(
                            "Data classification %s active. Overlay profile '%s' is on the roadmap. "
                            "Baseline controls apply.",
                            dc_code, oid,
                        )

        spec.data_classifications = sorted(all_dc_codes)

        # Apply overlay control overrides (strictest wins)
        max_retention = spec.evidence_retention_days
        for oid in spec.active_overlays:
            profile = self._overlay_profiles[oid]
            self._apply_overlay(spec, profile, f"overlay:{oid}")

            retention = profile.get("evidence_retention_minimum_days", 365)
            if retention > max_retention:
                max_retention = retention

            if profile.get("human_oversight_required", False):
                spec.human_oversight_required = True

        spec.evidence_retention_days = max_retention

    def _resolve_certification_path(self, spec: ActivationSpec, cert_targets: list[str]) -> None:
        """Path 2: Load certification profiles and activate required controls."""
        cert_profiles = load_certification_profiles(cert_targets)

        for cid_target in cert_targets:
            profile = cert_profiles.get(cid_target)
            if profile is None:
                logger.warning("Unknown certification target '%s' — skipping", cid_target)
                continue

            spec.active_certifications.append(cid_target)

            # Activate required controls
            required = profile.get("required_aksi_controls", [])
            for control_id in required:
                if control_id not in spec.active_controls:
                    spec.active_controls.append(control_id)
                if control_id not in spec.activation_source or spec.activation_source[control_id] == "baseline":
                    spec.activation_source[control_id] = f"certification_targets:{cid_target}"
                spec.control_thresholds.setdefault(control_id, "standard")

            # Merge evidence requirements from certification
            evidence_packaging = profile.get("evidence_packaging", {})
            retention = evidence_packaging.get("retention_days", 365)
            if retention > spec.evidence_retention_days:
                spec.evidence_retention_days = retention

    def _apply_overlay(self, spec: ActivationSpec, profile: dict[str, Any], source: str) -> None:
        """Apply overlay control overrides. Strictest threshold wins."""
        adjustments = profile.get("control_adjustments", {})
        for control_id, adj in adjustments.items():
            threshold = adj.get("threshold_adjustment", "standard")

            current = spec.control_thresholds.get(control_id, "standard")
            if threshold == "strict" and current != "strict":
                spec.control_thresholds[control_id] = "strict"
                spec.activation_source[f"{control_id}_threshold"] = source

            if control_id not in spec.active_controls:
                spec.active_controls.append(control_id)

        # Merge evidence requirements (union)
        evidence_reqs = profile.get("evidence_requirements", {})
        for control_id, reqs in evidence_reqs.items():
            existing = spec.evidence_requirements.get(control_id, [])
            merged = list(existing)
            for req in reqs:
                if req not in merged:
                    merged.append(req)
            spec.evidence_requirements[control_id] = merged

    def _build_summary(self, spec: ActivationSpec) -> list[str]:
        """Build plain-language activation summary."""
        summary: list[str] = []

        for cert_id in spec.active_certifications:
            count = len(spec.active_controls)
            summary.append(
                f"{cert_id.upper()} certification active — {count} controls enforcing"
            )

        for oid in spec.active_overlays:
            profile = self._overlay_profiles.get(oid, {})
            name = profile.get("name", oid)
            source_key = spec.activation_source.get(oid, "")
            # Skip baseline overlays from detailed summary unless it's the only overlay
            if profile.get("trigger_type") == "baseline":
                continue
            triggered = ""
            if "my_agent_handles:" in source_key:
                data_type = source_key.split(":", 1)[1]
                triggered = f" — triggered by {data_type} declaration"
            summary.append(f"{name} overlay active{triggered}")

        if not summary:
            count = len(spec.active_controls)
            summary.append(f"Baseline security active — {count} controls enforcing")

        return summary
