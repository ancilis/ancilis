"""Ancilis configuration parser — loads, validates, and resolves ancilis.yaml configs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, field_validator, model_validator

from ancilis._shared import shared_path
from ancilis.errors import config_invalid

# Resolve shared/ directory from packaged assets
SHARED_DIR = shared_path()
CONTROLS_DIR = SHARED_DIR / "controls"
OVERLAYS_DIR = SHARED_DIR / "overlays"
CLASSIFICATIONS_FILE = SHARED_DIR / "classifications" / "taxonomy.json"


# --- Pydantic Models ---


class AgentConfig(BaseModel):
    name: str
    description: str = ""
    owner: str = ""
    agent_id: str | None = None
    llm_provider: str | None = None

    @field_validator("name")
    @classmethod
    def name_must_be_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("agent.name must be a non-empty string")
        return v


class ControlOverride(BaseModel):
    enabled: bool = True


class ToolsConfig(BaseModel):
    allowed: list[str] = Field(default_factory=list)
    blocked: list[str] = Field(default_factory=list)


class ScopeConfig(BaseModel):
    max_actions_per_minute: int | None = None
    allowed_destinations: list[str] = Field(default_factory=list)
    blocked_destinations: list[str] = Field(default_factory=list)


class SecurityConfig(BaseModel):
    mode: str = "audit"
    controls: dict[str, ControlOverride] = Field(default_factory=dict)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)

    @field_validator("mode")
    @classmethod
    def mode_must_be_valid(cls, v: str) -> str:
        if v not in ("audit", "enforce"):
            raise ValueError("security.mode must be 'audit' or 'enforce'")
        return v


class EvidenceConfig(BaseModel):
    storage: str = "local"
    retention_days: int = 365


class ComplianceConfig(BaseModel):
    overlays: list[str] | None = None
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)


class CliConfig(BaseModel):
    update_check: bool = True
    update_check_interval: int = 86400


_VALID_SEVERITY_THRESHOLDS = {"critical", "high", "medium", "low"}


class ScanDepsConfig(BaseModel):
    enabled: bool = True
    severity_threshold: str = "high"
    ignore: list[str] = Field(default_factory=list)

    @field_validator("severity_threshold")
    @classmethod
    def validate_severity_threshold(cls, v: str) -> str:
        if v not in _VALID_SEVERITY_THRESHOLDS:
            raise ValueError(
                "scan.dependencies.severity_threshold must be one of: "
                f"{', '.join(sorted(_VALID_SEVERITY_THRESHOLDS))}"
            )
        return v


class ScanConfig(BaseModel):
    dependencies: ScanDepsConfig = Field(default_factory=ScanDepsConfig)


class AncilisConfig(BaseModel):
    agent: AgentConfig
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    my_agent_handles: list[str] = Field(default_factory=list)
    certification_targets: list[str] = Field(default_factory=list)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    cli: CliConfig = Field(default_factory=CliConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)

    @model_validator(mode="before")
    @classmethod
    def warn_unknown_keys(cls, values: Any) -> Any:
        if isinstance(values, dict):
            known = {
                "agent",
                "security",
                "my_agent_handles",
                "certification_targets",
                "compliance",
                "cli",
                "scan",
            }
            unknown = set(values.keys()) - known
            if unknown:
                # Store warnings for later reporting
                values.setdefault("_warnings", [])
                for key in sorted(unknown):
                    values["_warnings"].append(f"Unknown top-level key: '{key}'")
        return values

    model_config = {"extra": "ignore"}


# --- Shared JSON Loaders ---

VALID_CONTROL_IDS = {
    "GOV-01", "GOV-02", "GOV-03", "GOV-04",
    "ID-01", "ID-02", "ID-03", "ID-04", "ID-05",
    "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08",
    "DE-01", "DE-02", "DE-03", "DE-04",
    "RS-01", "RS-02", "RS-03",
    "RC-01", "RC-02",
}
CERTIFICATIONS_DIR = SHARED_DIR / "overlays" / "certifications"

VALID_CERTIFICATION_TARGETS: set[str] = set()


def _load_valid_certification_targets() -> set[str]:
    """Discover available certification targets from shared/overlays/certifications/."""
    global VALID_CERTIFICATION_TARGETS
    if VALID_CERTIFICATION_TARGETS:
        return VALID_CERTIFICATION_TARGETS
    targets: set[str] = set()
    if CERTIFICATIONS_DIR.exists():
        for path in CERTIFICATIONS_DIR.glob("*.json"):
            targets.add(path.stem)
    VALID_CERTIFICATION_TARGETS = targets
    return targets


def load_control_definitions() -> dict[str, dict[str, Any]]:
    """Load all control definitions from shared/controls/."""
    controls: dict[str, dict[str, Any]] = {}
    for path in sorted(CONTROLS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        controls[data["id"]] = data
    return controls


def load_overlay_definitions() -> dict[str, dict[str, Any]]:
    """Load all overlay definitions from shared/overlays/."""
    overlays: dict[str, dict[str, Any]] = {}
    for path in sorted(OVERLAYS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        overlays[data["id"]] = data
    return overlays


def load_taxonomy() -> dict[str, Any]:
    """Load the classification taxonomy from shared/classifications/."""
    data = json.loads(CLASSIFICATIONS_FILE.read_text())
    return cast(dict[str, Any], data)


# --- Resolution Result ---


class ControlStatus:
    def __init__(self, control_id: str, name: str, enabled: bool, threshold: str = "standard"):
        self.control_id = control_id
        self.name = name
        self.enabled = enabled
        self.threshold = threshold
        self.overlay_citations: list[str] = []


class OverlayActivation:
    def __init__(self, overlay_id: str, name: str, triggered_by: list[str]):
        self.overlay_id = overlay_id
        self.name = name
        self.triggered_by = triggered_by  # list of "DC-XXX via data_type" strings


class UnavailableOverlay:
    def __init__(self, overlay_id: str, triggered_by: str, data_type: str):
        self.overlay_id = overlay_id
        self.triggered_by = triggered_by
        self.data_type = data_type


class ResolvedConfig:
    def __init__(self) -> None:
        self.agent_name: str = ""
        self.agent_owner: str = ""
        self.agent_id: str | None = None
        self.mode: str = "audit"
        self.controls: dict[str, ControlStatus] = {}
        self.data_classifications: dict[str, list[str]] = {}  # data_type -> [DC codes]
        self.active_overlays: dict[str, OverlayActivation] = {}
        self.unavailable_overlays: list[UnavailableOverlay] = []
        self.overlay_adjustments: list[str] = []
        self.evidence_retention_days: int = 365
        self.human_oversight_required: bool = False
        self.warnings: list[str] = []
        self.tools_allowed: list[str] = []
        self.tools_blocked: list[str] = []
        self.scope_max_actions_per_minute: int | None = None
        self.scope_allowed_destinations: list[str] = []
        self.scope_blocked_destinations: list[str] = []
        self.active_certifications: list[str] = []
        self.llm_provider: str | None = None
        # Per-control overlay requirements: control_id -> {overlay_id: {evidence_requirements, framework_reference}}
        self.overlay_requirements: dict[str, dict[str, Any]] = {}
        # Dependency scan config
        self.scan_dependencies_enabled: bool = True
        self.scan_dependencies_severity_threshold: str = "high"
        self.scan_dependencies_ignore: list[str] = []


# --- Config Parser ---


def validate_config(raw: dict[str, Any]) -> tuple[AncilisConfig, list[str]]:
    """Validate raw config dict and return (config, warnings)."""
    warnings: list[str] = raw.pop("_warnings", [])

    # Validate control IDs in overrides
    security = raw.get("security", {})
    if isinstance(security, dict):
        controls = security.get("controls", {})
        if isinstance(controls, dict):
            for key in controls:
                if key not in VALID_CONTROL_IDS:
                    raise config_invalid(f"Unknown control ID in security.controls: '{key}'")

    # Validate my_agent_handles types
    taxonomy = load_taxonomy()
    valid_types = set(taxonomy["developer_type_mapping"].keys())
    my_agent_handles = raw.get("my_agent_handles", [])
    if isinstance(my_agent_handles, list):
        for dt in my_agent_handles:
            if dt not in valid_types:
                raise config_invalid(
                    f"Unknown data type in my_agent_handles: '{dt}'. "
                    f"Valid types: {', '.join(sorted(valid_types))}"
                )

    # Validate certification_targets
    cert_targets = raw.get("certification_targets", [])
    if isinstance(cert_targets, list):
        valid_certs = _load_valid_certification_targets()
        for ct in cert_targets:
            if ct not in valid_certs:
                available = ", ".join(sorted(valid_certs)) if valid_certs else "none available"
                warnings.append(
                    f"certification_targets contains unrecognized value '{ct}'. "
                    f"Available targets: {available}"
                )

    config = AncilisConfig(**raw)
    return config, warnings


def resolve_config(config: AncilisConfig, warnings: list[str] | None = None) -> ResolvedConfig:
    """Resolve a validated config into full runtime configuration."""
    result = ResolvedConfig()
    result.agent_name = config.agent.name
    result.agent_owner = config.agent.owner
    result.agent_id = config.agent.agent_id
    result.llm_provider = config.agent.llm_provider
    result.mode = config.security.mode
    result.warnings = warnings or []
    result.tools_allowed = list(config.security.tools.allowed)
    result.scan_dependencies_enabled = config.scan.dependencies.enabled
    result.scan_dependencies_severity_threshold = config.scan.dependencies.severity_threshold
    result.scan_dependencies_ignore = list(config.scan.dependencies.ignore)
    result.tools_blocked = list(config.security.tools.blocked)
    result.scope_max_actions_per_minute = config.security.scope.max_actions_per_minute
    result.scope_allowed_destinations = list(config.security.scope.allowed_destinations)
    result.scope_blocked_destinations = list(config.security.scope.blocked_destinations)

    # Load shared data
    control_defs = load_control_definitions()
    overlay_defs = load_overlay_definitions()
    taxonomy = load_taxonomy()

    # Resolve controls
    for cid, cdef in sorted(control_defs.items()):
        override = config.security.controls.get(cid)
        enabled = override.enabled if override else cdef.get("default_enabled", True)
        result.controls[cid] = ControlStatus(cid, cdef["name"], enabled)

    # Resolve data classifications
    type_mapping = taxonomy["developer_type_mapping"]
    for data_type in config.my_agent_handles:
        dc_codes = type_mapping.get(data_type, [])
        result.data_classifications[data_type] = dc_codes

    # Collect all DC codes
    all_dc_codes: set[str] = set()
    for codes in result.data_classifications.values():
        all_dc_codes.update(codes)

    # Build classification-to-overlay lookup from taxonomy
    classification_lookup: dict[str, list[str]] = {}
    for cls_entry in taxonomy["classifications"]:
        classification_lookup[cls_entry["code"]] = cls_entry.get("overlays", [])

    # Determine which overlays should activate
    overlay_triggers: dict[str, list[str]] = {}  # overlay_id -> ["DC-XXX via data_type", ...]
    for data_type, dc_codes in result.data_classifications.items():
        for dc_code in dc_codes:
            overlay_ids = classification_lookup.get(dc_code, [])
            for oid in overlay_ids:
                overlay_triggers.setdefault(oid, [])
                trigger_str = f"{dc_code} via {data_type}"
                if trigger_str not in overlay_triggers[oid]:
                    overlay_triggers[oid].append(trigger_str)

    # If compliance.overlays is set, filter to only those
    if config.compliance.overlays is not None:
        explicit_overlays = set(config.compliance.overlays)
        overlay_triggers = {k: v for k, v in overlay_triggers.items() if k in explicit_overlays}
        # Add explicitly requested overlays that aren't triggered by data
        for oid in explicit_overlays:
            if oid not in overlay_triggers:
                overlay_triggers[oid] = []

    # Activate overlays
    available_overlay_ids = set(overlay_defs.keys())
    for oid, triggers in sorted(overlay_triggers.items()):
        if oid in available_overlay_ids:
            odef = overlay_defs[oid]
            result.active_overlays[oid] = OverlayActivation(oid, odef["name"], triggers)
        else:
            # Determine which data types triggered this
            for trigger in triggers:
                parts = trigger.split(" via ")
                dc_code = parts[0]
                data_type = parts[1] if len(parts) > 1 else "unknown"
                result.unavailable_overlays.append(
                    UnavailableOverlay(oid, dc_code, data_type)
                )

    # Apply overlay adjustments
    max_retention = config.compliance.evidence.retention_days
    for oid, _activation in result.active_overlays.items():
        odef = overlay_defs[oid]
        adjustments = odef.get("control_adjustments", {})
        for cid, adj in adjustments.items():
            if cid in result.controls and result.controls[cid].enabled:
                threshold = adj.get("threshold_adjustment", "standard")
                citation = adj.get("regulatory_citation", "")
                # Only upgrade threshold, never downgrade
                if threshold == "strict" and result.controls[cid].threshold != "strict":
                    result.controls[cid].threshold = "strict"
                result.controls[cid].overlay_citations.append(citation)
                if threshold == "strict":
                    result.overlay_adjustments.append(
                        f"{cid}: threshold -> strict ({citation})"
                    )

        retention = odef.get("evidence_retention_minimum_days", 365)
        if retention > max_retention:
            max_retention = retention

        if odef.get("human_oversight_required", False):
            result.human_oversight_required = True

    result.evidence_retention_days = max_retention

    # Build per-control overlay requirements from the controls sections of active overlays.
    # This populates overlay_requirements[control_id][overlay_id] = {evidence_requirements, framework_reference}
    # so the engine can surface meaningful metadata for controls that have no evaluator yet (SKIP).
    for oid, _activation in result.active_overlays.items():
        odef = overlay_defs[oid]
        controls_section = odef.get("controls", {})
        for cid, ctrl_data in controls_section.items():
            if not ctrl_data.get("applicable", True):
                continue
            if cid not in result.overlay_requirements:
                result.overlay_requirements[cid] = {}
            result.overlay_requirements[cid][oid] = {
                "evidence_requirements": ctrl_data.get("evidence_requirements", []),
                "framework_reference": ctrl_data.get("framework_reference", ""),
            }

    # Resolve certification targets — use activation resolver for richer logic
    valid_certs = _load_valid_certification_targets()
    for ct in config.certification_targets:
        if ct in valid_certs:
            result.active_certifications.append(ct)

    # When certifications are active, apply their control and evidence requirements
    if result.active_certifications:
        from ancilis.activation.resolver import ActivationResolver

        resolver = ActivationResolver()
        spec = resolver.resolve(
            my_agent_handles=config.my_agent_handles or None,
            certification_targets=result.active_certifications,
        )

        # Activate any controls required by certifications that aren't already active
        for cid in spec.active_controls:
            if cid in result.controls:
                result.controls[cid].enabled = True
            # Apply stricter thresholds from certification profiles
            threshold = spec.control_thresholds.get(cid, "standard")
            if threshold == "strict" and cid in result.controls:
                result.controls[cid].threshold = "strict"

        # Honour the strictest evidence retention from certification profiles
        if spec.evidence_retention_days > result.evidence_retention_days:
            result.evidence_retention_days = spec.evidence_retention_days

        # Merge human oversight requirement
        if spec.human_oversight_required:
            result.human_oversight_required = True

    return result


def load_config(
    path: str | Path | None = None,
    raw: dict[str, Any] | None = None,
) -> ResolvedConfig:
    """Load and resolve an Ancilis configuration.

    Args:
        path: Path to ancilis.yaml file.
        raw: Raw config dict (alternative to file path).

    Returns:
        ResolvedConfig with all controls, overlays, and classifications resolved.
    """
    if raw is not None:
        config_dict = dict(raw)
    elif path is not None:
        config_dict = yaml.safe_load(Path(path).read_text()) or {}
    else:
        # Try to find ancilis.yaml in current directory
        default_path = Path("ancilis.yaml")
        if default_path.exists():
            config_dict = yaml.safe_load(default_path.read_text()) or {}
        else:
            raise FileNotFoundError("No ancilis.yaml found and no config provided")

    config, warnings = validate_config(config_dict)
    return resolve_config(config, warnings)


def format_resolved_config(resolved: ResolvedConfig) -> str:
    """Format resolved config for display."""
    lines: list[str] = []
    lines.append("Ancilis Configuration Loaded")
    lines.append("-" * 32)
    lines.append(f"Agent: {resolved.agent_name}")
    lines.append(f"Mode: {resolved.mode}")
    lines.append("")

    # Controls
    active = sum(1 for c in resolved.controls.values() if c.enabled)
    total = len(resolved.controls)
    lines.append(f"Baseline Controls ({active}/{total} active):")
    for _cid, cs in sorted(resolved.controls.items()):
        mark = "+" if cs.enabled else "-"
        lines.append(f"  {mark} {cs.control_id}  {cs.name}")
    lines.append("")

    # Data classifications
    if resolved.data_classifications:
        lines.append("Data Classifications:")
        for dt, codes in sorted(resolved.data_classifications.items()):
            codes_str = ", ".join(codes)
            lines.append(f"  {dt} -> {codes_str}")
        lines.append("")

    # Active overlays
    if resolved.active_overlays:
        lines.append("Active Overlays:")
        for _oid, oa in sorted(resolved.active_overlays.items()):
            triggers = ", ".join(oa.triggered_by) if oa.triggered_by else "explicit"
            lines.append(f"  + {oa.name} (triggered by {triggers})")
        lines.append("")

    # Unavailable overlays
    if resolved.unavailable_overlays:
        lines.append("Unavailable Overlays (roadmap):")
        for uo in resolved.unavailable_overlays:
            lines.append(
                f"  ? {uo.overlay_id} would be activated by {uo.triggered_by} "
                f"via {uo.data_type} but is not yet available"
            )
        lines.append("")

    # Overlay adjustments
    if resolved.overlay_adjustments:
        lines.append("Overlay Adjustments Applied:")
        for adj in resolved.overlay_adjustments:
            lines.append(f"  {adj}")
        lines.append(f"  Evidence retention: {resolved.evidence_retention_days} days")
        if resolved.human_oversight_required:
            lines.append("  Human oversight: REQUIRED")
        lines.append("")

    # Warnings
    if resolved.warnings:
        lines.append("Warnings:")
        for w in resolved.warnings:
            lines.append(f"  ! {w}")
        lines.append("")

    return "\n".join(lines)
