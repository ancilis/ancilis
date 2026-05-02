"""Ancilis configuration parser — loads, validates, and resolves ancilis.yaml configs."""

from __future__ import annotations

import json
from difflib import get_close_matches
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, field_validator, model_validator

from ancilis._shared import shared_path
from ancilis.activation.loader import load_overlay_profiles
from ancilis.errors import config_invalid
from ancilis.overlays import normalize_overlay_id, normalize_overlay_ids
from ancilis.plugins import PluginRegistry

if TYPE_CHECKING:
    from ancilis.controls.custom import CustomControlDefinition

# Resolve shared/ directory from packaged assets
SHARED_DIR = shared_path()
CONTROLS_DIR = SHARED_DIR / "controls"
OVERLAYS_DIR = SHARED_DIR / "overlays"
CLASSIFICATIONS_FILE = SHARED_DIR / "classifications" / "taxonomy.json"
CURRENT_CONFIG_VERSION = 2


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


class PlatformConfig(BaseModel):
    url: str | None = None
    api_key_env: str = "ANCILIS_API_KEY"


_VALID_SYNC_OFFLINE_MODES = {"auto", "always_offline", "always_online"}


class SyncConfig(BaseModel):
    offline_mode: str = "auto"
    interval_seconds: int = 300
    max_retries: int = 8
    backoff_base_seconds: int = 2
    max_queue_size: int = 10000
    batch_size: int = 100

    @field_validator("offline_mode")
    @classmethod
    def validate_offline_mode(cls, v: str) -> str:
        if v not in _VALID_SYNC_OFFLINE_MODES:
            raise ValueError(
                "sync.offline_mode must be one of: "
                f"{', '.join(sorted(_VALID_SYNC_OFFLINE_MODES))}"
            )
        return v

    @field_validator("interval_seconds", "max_queue_size", "batch_size")
    @classmethod
    def validate_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("sync numeric values must be positive")
        return v

    @field_validator("max_retries", "backoff_base_seconds")
    @classmethod
    def validate_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("sync retry values must be non-negative")
        return v

    @field_validator("batch_size")
    @classmethod
    def validate_batch_size_cap(cls, v: int) -> int:
        if v > 100:
            raise ValueError("sync.batch_size must be <= 100")
        return v


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
    config_version: int = CURRENT_CONFIG_VERSION
    agent: AgentConfig
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    my_agent_handles: list[str] = Field(default_factory=list)
    certification_targets: list[str] = Field(default_factory=list)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    platform: PlatformConfig = Field(default_factory=PlatformConfig)
    sync: SyncConfig = Field(default_factory=SyncConfig)
    cli: CliConfig = Field(default_factory=CliConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)

    @model_validator(mode="before")
    @classmethod
    def warn_unknown_keys(cls, values: Any) -> Any:
        if isinstance(values, dict):
            known = {
                "agent",
                "config_version",
                "security",
                "my_agent_handles",
                "certification_targets",
                "compliance",
                "platform",
                "sync",
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

DEFAULT_CONTROL_ACTIVATION_SOURCE = "default"
EXPLICIT_CONTROL_ACTIVATION_SOURCE = "explicit:security.controls"
CERTIFICATION_CONTROL_ACTIVATION_SOURCE_PREFIX = "certification_targets:"
CUSTOM_CONTROL_ACTIVATION_SOURCE = "custom:local"


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


def load_overlay_definitions(
    *,
    plugin_registry: PluginRegistry | None = None,
    plugin_configs: dict[str, dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Load built-in overlay definitions plus optional plugin overlays."""
    return load_overlay_profiles(
        plugin_registry=plugin_registry,
        plugin_configs=plugin_configs,
        warnings=warnings,
    )


def _plugin_overlay_candidate_ids(plugin_registry: PluginRegistry | None) -> set[str]:
    """Return explicit overlay IDs that plugin records may satisfy at resolution time."""
    if plugin_registry is None:
        return set()

    candidates: set[str] = set()
    for record in plugin_registry.compatible("overlay"):
        plugin_name = record.name.strip()
        if not plugin_name:
            continue
        candidates.add(plugin_name)
        candidates.add(f"plugin:{plugin_name.removeprefix('plugin:')}")
    return candidates


def load_taxonomy() -> dict[str, Any]:
    """Load the classification taxonomy from shared/classifications/."""
    data = json.loads(CLASSIFICATIONS_FILE.read_text())
    return cast(dict[str, Any], data)


def _config_version_from(raw: dict[str, Any]) -> int:
    value = raw.get("config_version", 1)
    if isinstance(value, str):
        value = value.removeprefix("v")
    try:
        version = int(value)
    except (TypeError, ValueError) as exc:
        raise config_invalid(
            f"config_version must be a positive integer; received {raw.get('config_version')!r}"
        ) from exc
    if version < 1:
        raise config_invalid(f"config_version must be a positive integer; received {raw.get('config_version')!r}")
    if version > CURRENT_CONFIG_VERSION:
        raise config_invalid(
            f"config_version {version} is newer than this SDK supports (current {CURRENT_CONFIG_VERSION})"
        )
    return version


def inspect_config_migration(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a migrated config preview plus migration metadata."""
    original_version = _config_version_from(raw)
    migrated = dict(raw)
    changes: list[str] = []

    if isinstance(migrated.get("agent_name"), str):
        agent = dict(migrated.get("agent") or {})
        if "name" not in agent:
            agent["name"] = migrated["agent_name"]
            changes.append("moved deprecated agent_name to agent.name")
        migrated["agent"] = agent
        migrated.pop("agent_name", None)

    if isinstance(migrated.get("data_classifications"), list) and "my_agent_handles" not in migrated:
        migrated["my_agent_handles"] = migrated.pop("data_classifications")
        changes.append("renamed deprecated data_classifications to my_agent_handles")

    if original_version < CURRENT_CONFIG_VERSION or "config_version" not in migrated:
        migrated["config_version"] = CURRENT_CONFIG_VERSION
        changes.append(f"added config_version: {CURRENT_CONFIG_VERSION}")

    return {
        "original_version": original_version,
        "current_version": CURRENT_CONFIG_VERSION,
        "changed": bool(changes),
        "changes": changes,
        "config": migrated,
    }


def inspect_config_file_migration(path: str | Path) -> dict[str, Any]:
    """Preview migration metadata for a config file."""
    config_path = Path(path)
    raw = yaml.safe_load(config_path.read_text()) or {}
    return inspect_config_migration(cast(dict[str, Any], raw))


def migrate_config_file(path: str | Path, *, apply: bool = False) -> dict[str, Any]:
    """Preview or apply config migration. Applying writes a .bak backup first."""
    config_path = Path(path)
    original = config_path.read_text()
    raw = yaml.safe_load(original) or {}
    result = inspect_config_migration(cast(dict[str, Any], raw))
    if apply and result["changed"]:
        backup_path = config_path.with_name(f"{config_path.name}.bak")
        backup_path.write_text(original)
        config_path.write_text(yaml.safe_dump(result["config"], sort_keys=False))
        result["backup_path"] = str(backup_path)
    return result


def _add_plugin_data_classification_overlays(
    classification_lookup: dict[str, list[str]],
    overlay_defs: dict[str, dict[str, Any]],
) -> None:
    """Allow plugin overlays to declare data-classification triggers directly."""
    for oid, profile in overlay_defs.items():
        if not oid.startswith("plugin:"):
            continue
        if profile.get("trigger_type") != "data_classification":
            continue
        for dc_code in profile.get("triggered_by", []):
            overlay_ids = classification_lookup.setdefault(dc_code, [])
            if oid not in overlay_ids:
                overlay_ids.append(oid)


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
        self.config_version: int = CURRENT_CONFIG_VERSION
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
        self.platform_url: str | None = None
        self.platform_api_key_env: str = "ANCILIS_API_KEY"
        self.sync_offline_mode: str = "auto"
        self.sync_interval_seconds: int = 300
        self.sync_max_retries: int = 8
        self.sync_backoff_base_seconds: int = 2
        self.sync_max_queue_size: int = 10000
        self.sync_batch_size: int = 100
        self.control_activation_sources: dict[str, set[str]] = {}
        self.custom_controls: dict[str, CustomControlDefinition] = {}
        # Per-control overlay requirements: control_id -> {overlay_id: {evidence_requirements, framework_reference}}
        self.overlay_requirements: dict[str, dict[str, Any]] = {}
        # Dependency scan config
        self.scan_dependencies_enabled: bool = True
        self.scan_dependencies_severity_threshold: str = "high"
        self.scan_dependencies_ignore: list[str] = []

    def control_has_activation_source(self, control_id: str, *source_prefixes: str) -> bool:
        """Return whether a control was activated by any exact source or source prefix."""
        sources = self.control_activation_sources.get(control_id, set())
        return any(
            source == prefix or source.startswith(prefix)
            for source in sources
            for prefix in source_prefixes
        )


def _apply_overlay_effects(
    result: ResolvedConfig,
    overlay_defs: dict[str, dict[str, Any]],
    overlay_ids: list[str],
    max_retention: int,
) -> int:
    for oid in overlay_ids:
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

    return max_retention


# --- Config Parser ---


def validate_config(
    raw: dict[str, Any],
    *,
    valid_overlay_ids: set[str] | None = None,
) -> tuple[AncilisConfig, list[str]]:
    """Validate raw config dict and return (config, warnings)."""
    warnings: list[str] = raw.pop("_warnings", [])

    # Validate control IDs in overrides
    security = raw.get("security", {})
    if isinstance(security, dict):
        controls = security.get("controls", {})
        if isinstance(controls, dict):
            custom_control_ids: set[str] | None = None
            for key in controls:
                if key.startswith("custom:"):
                    if custom_control_ids is None:
                        from ancilis.controls.custom import list_custom_controls

                        custom_control_ids = set(list_custom_controls())
                    if key not in custom_control_ids:
                        raise config_invalid(
                            f"Unknown custom control ID in security.controls: '{key}'"
                        )
                elif key not in VALID_CONTROL_IDS:
                    raise config_invalid(f"Unknown control ID in security.controls: '{key}'")

    # Validate my_agent_handles types
    taxonomy = load_taxonomy()
    valid_types = set(taxonomy["developer_type_mapping"].keys())
    my_agent_handles = raw.get("my_agent_handles", [])
    if isinstance(my_agent_handles, list):
        for dt in my_agent_handles:
            if dt not in valid_types:
                suggestion = get_close_matches(dt, sorted(valid_types), n=1, cutoff=0.75)
                suggestion_text = f" Did you mean '{suggestion[0]}'?" if suggestion else ""
                raise config_invalid(
                    f"Unknown data type in my_agent_handles: '{dt}'.{suggestion_text} "
                    f"Valid types: {', '.join(sorted(valid_types))}"
                )

    # Validate explicit overlay IDs
    compliance = raw.get("compliance", {})
    if isinstance(compliance, dict) and isinstance(compliance.get("overlays"), list):
        valid_overlays = (
            valid_overlay_ids
            if valid_overlay_ids is not None
            else set(load_overlay_definitions())
        )
        for overlay in compliance["overlays"]:
            if not isinstance(overlay, str):
                continue
            normalized = normalize_overlay_id(overlay)
            if normalized not in valid_overlays:
                suggestion = get_close_matches(overlay, sorted(valid_overlays), n=1, cutoff=0.75)
                suggestion_text = f" Did you mean '{suggestion[0]}'?" if suggestion else ""
                raise config_invalid(
                    f"Unknown overlay profile '{overlay}'.{suggestion_text} "
                    f"Available overlays: {', '.join(sorted(valid_overlays))}"
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


def resolve_config(
    config: AncilisConfig,
    warnings: list[str] | None = None,
    *,
    plugin_registry: PluginRegistry | None = None,
    plugin_configs: dict[str, dict[str, Any]] | None = None,
    overlay_defs: dict[str, dict[str, Any]] | None = None,
) -> ResolvedConfig:
    """Resolve a validated config into full runtime configuration."""
    result = ResolvedConfig()
    result.config_version = config.config_version
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
    result.platform_url = config.platform.url
    result.platform_api_key_env = config.platform.api_key_env
    result.sync_offline_mode = config.sync.offline_mode
    result.sync_interval_seconds = config.sync.interval_seconds
    result.sync_max_retries = config.sync.max_retries
    result.sync_backoff_base_seconds = config.sync.backoff_base_seconds
    result.sync_max_queue_size = config.sync.max_queue_size
    result.sync_batch_size = config.sync.batch_size
    result.tools_blocked = list(config.security.tools.blocked)
    result.scope_max_actions_per_minute = config.security.scope.max_actions_per_minute
    result.scope_allowed_destinations = list(config.security.scope.allowed_destinations)
    result.scope_blocked_destinations = list(config.security.scope.blocked_destinations)

    # Load shared data
    control_defs = load_control_definitions()
    if overlay_defs is None and plugin_registry is None and plugin_configs is None:
        overlay_defs = load_overlay_definitions()
    elif overlay_defs is None:
        overlay_defs = load_overlay_definitions(
            plugin_registry=plugin_registry,
            plugin_configs=plugin_configs,
            warnings=result.warnings,
        )
    taxonomy = load_taxonomy()

    # Resolve controls
    for cid, cdef in sorted(control_defs.items()):
        override = config.security.controls.get(cid)
        enabled = override.enabled if override else cdef.get("default_enabled", True)
        result.controls[cid] = ControlStatus(cid, cdef["name"], enabled)
        result.control_activation_sources[cid] = set()
        if enabled:
            source = (
                EXPLICIT_CONTROL_ACTIVATION_SOURCE
                if override is not None
                else DEFAULT_CONTROL_ACTIVATION_SOURCE
            )
            result.control_activation_sources[cid].add(source)

    from ancilis.controls.custom import list_custom_controls

    for cid, definition in sorted(list_custom_controls().items()):
        override = config.security.controls.get(cid)
        enabled = override.enabled if override else True
        result.controls[cid] = ControlStatus(cid, definition.title, enabled)
        result.control_activation_sources[cid] = set()
        if enabled:
            result.control_activation_sources[cid].add(CUSTOM_CONTROL_ACTIVATION_SOURCE)
            if override is not None:
                result.control_activation_sources[cid].add(EXPLICIT_CONTROL_ACTIVATION_SOURCE)
        result.custom_controls[cid] = definition

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
        classification_lookup[cls_entry["code"]] = normalize_overlay_ids(
            cls_entry.get("overlays", [])
        )
    _add_plugin_data_classification_overlays(classification_lookup, overlay_defs)

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
        explicit_overlays = set(normalize_overlay_ids(config.compliance.overlays))
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

    result.evidence_retention_days = _apply_overlay_effects(
        result,
        overlay_defs,
        list(result.active_overlays),
        config.compliance.evidence.retention_days,
    )

    # Resolve certification targets — use activation resolver for richer logic
    valid_certs = _load_valid_certification_targets()
    for ct in config.certification_targets:
        if ct in valid_certs:
            result.active_certifications.append(ct)

    # When certifications are active, apply their control and evidence requirements
    if result.active_certifications:
        from ancilis.activation.resolver import ActivationResolver

        resolver = ActivationResolver(
            plugin_registry=plugin_registry,
            plugin_configs=plugin_configs,
            warnings=result.warnings,
        )
        spec = resolver.resolve(
            my_agent_handles=config.my_agent_handles or None,
            certification_targets=result.active_certifications,
            compliance_overlays=config.compliance.overlays,
        )

        new_certification_overlays: list[str] = []
        for oid in spec.active_overlays:
            source = spec.activation_source.get(oid, "")
            if (
                source.startswith("certification_targets:")
                and oid in overlay_defs
                and oid not in result.active_overlays
            ):
                result.active_overlays[oid] = OverlayActivation(
                    oid,
                    overlay_defs[oid]["name"],
                    [source],
                )
                new_certification_overlays.append(oid)

        if new_certification_overlays:
            result.evidence_retention_days = _apply_overlay_effects(
                result,
                overlay_defs,
                new_certification_overlays,
                result.evidence_retention_days,
            )

        # Activate any controls required by certifications that aren't already active
        for cid in spec.active_controls:
            if cid in result.controls:
                result.controls[cid].enabled = True
                activation_source = spec.activation_source.get(cid)
                if activation_source and activation_source.startswith(
                    CERTIFICATION_CONTROL_ACTIVATION_SOURCE_PREFIX
                ):
                    result.control_activation_sources.setdefault(cid, set()).add(
                        activation_source
                    )
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
    *,
    plugin_registry: PluginRegistry | None = None,
    plugin_configs: dict[str, dict[str, Any]] | None = None,
) -> ResolvedConfig:
    """Load and resolve an Ancilis configuration.

    Args:
        path: Path to ancilis.yaml file.
        raw: Raw config dict (alternative to file path).

    Returns:
        ResolvedConfig with all controls, overlays, and classifications resolved.
    """
    custom_warnings: list[str] = []
    if raw is not None:
        config_dict = dict(raw)
    elif path is not None:
        config_path = Path(path)
        config_dict = yaml.safe_load(config_path.read_text()) or {}
        from ancilis.controls.custom import load_custom_controls_from_directory

        custom_warnings.extend(
            load_custom_controls_from_directory(config_path.parent / ".ancilis" / "controls")
        )
    else:
        # Try to find ancilis.yaml in current directory
        default_path = Path("ancilis.yaml")
        if default_path.exists():
            config_dict = yaml.safe_load(default_path.read_text()) or {}
            from ancilis.controls.custom import load_custom_controls_from_directory

            custom_warnings.extend(
                load_custom_controls_from_directory(
                    default_path.parent / ".ancilis" / "controls"
                )
            )
        else:
            raise FileNotFoundError("No ancilis.yaml found and no config provided")

    overlay_warnings: list[str] = []
    overlay_defs = load_overlay_definitions(
        plugin_registry=plugin_registry,
        plugin_configs=plugin_configs,
        warnings=overlay_warnings,
    )
    migration = inspect_config_migration(config_dict)
    migrated_config = migration["config"]
    if overlay_warnings:
        migrated_config.setdefault("_warnings", []).extend(overlay_warnings)
    valid_overlay_ids = set(overlay_defs) | _plugin_overlay_candidate_ids(plugin_registry)
    config, warnings = validate_config(migrated_config, valid_overlay_ids=valid_overlay_ids)
    warnings.extend(custom_warnings)
    return resolve_config(
        config,
        warnings,
        plugin_registry=plugin_registry,
        plugin_configs=plugin_configs,
        overlay_defs=overlay_defs,
    )


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
