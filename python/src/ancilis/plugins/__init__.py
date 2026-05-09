"""Public plugin contracts and discovery registry for Ancilis SDK extensions."""

from __future__ import annotations

import importlib.metadata
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Protocol, runtime_checkable

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ancilis import __version__

PluginType = Literal["producer", "overlay", "adapter"]

ENTRY_POINT_GROUPS: dict[str, PluginType] = {
    "ancilis.producers": "producer",
    "ancilis.overlays": "overlay",
    "ancilis.adapters": "adapter",
}

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PluginMetadata:
    """Metadata every Ancilis plugin must expose without running runtime hooks."""

    name: str
    plugin_type: PluginType
    package_name: str
    package_version: str
    min_sdk_version: str
    max_sdk_version: str | None = None


@dataclass(frozen=True)
class PluginContext:
    """Read-only context passed to plugin hook construction."""

    sdk_version: str
    config: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


@runtime_checkable
class ProducerPlugin(Protocol):
    """Plugin that contributes an ActionProducer-compatible producer."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return metadata for discovery and compatibility checks."""
        ...

    def create_producer(self, context: PluginContext) -> Any:
        """Build the producer for runtime use."""
        ...


@runtime_checkable
class OverlayPlugin(Protocol):
    """Plugin that contributes an overlay profile document."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return metadata for discovery and compatibility checks."""
        ...

    def load_overlay_profile(self, context: PluginContext) -> Mapping[str, Any]:
        """Return an overlay profile with the same shape as built-in overlays."""
        ...


@runtime_checkable
class AdapterPlugin(Protocol):
    """Plugin that contributes an evidence adapter implementation."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return metadata for discovery and compatibility checks."""
        ...

    def create_adapter(self, context: PluginContext) -> Any:
        """Build an adapter exposing store(), query(), and export() capabilities."""
        ...


@dataclass(frozen=True)
class PluginRecord:
    """Discovery result for a compatible or skipped plugin entry point."""

    name: str
    plugin_type: PluginType
    entry_point_group: str
    entry_point_name: str
    package_name: str | None
    package_version: str | None
    metadata: PluginMetadata | None = None
    plugin: object | None = None
    compatible: bool = False
    skip_reason: str | None = None


class PluginRegistry:
    """Discovers Ancilis plugin entry points and records compatibility results."""

    def __init__(self, records: Iterable[PluginRecord] = (), sdk_version: str | None = None) -> None:
        self.records = list(records)
        self.sdk_version = sdk_version or __version__

    @classmethod
    def discover(cls, sdk_version: str | None = None, package: str | None = None) -> PluginRegistry:
        """Discover plugins from all supported Ancilis entry point groups."""
        registry = cls(sdk_version=sdk_version)
        registry.refresh(package=package)
        return registry

    def refresh(self, package: str | None = None) -> None:
        """Reload plugin discovery records from importlib.metadata entry points."""
        self.records = []
        for group, plugin_type in ENTRY_POINT_GROUPS.items():
            for entry_point in _entry_points_for_group(group):
                if package and not _entry_point_matches_package(entry_point, package):
                    continue
                self.records.append(self._load_entry_point(entry_point, group, plugin_type))

    def compatible(self, plugin_type: PluginType | None = None) -> list[PluginRecord]:
        """Return records that are valid and SDK-compatible."""
        return [
            record
            for record in self.records
            if record.compatible and (plugin_type is None or record.plugin_type == plugin_type)
        ]

    def skipped(self) -> list[PluginRecord]:
        """Return records skipped because they failed validation or compatibility checks."""
        return [record for record in self.records if not record.compatible]

    def _load_entry_point(
        self,
        entry_point: Any,
        entry_point_group: str,
        expected_type: PluginType,
    ) -> PluginRecord:
        entry_point_name = str(getattr(entry_point, "name", "<unknown>"))
        package_name = _entry_point_distribution_name(entry_point)
        try:
            plugin = _construct_plugin(entry_point.load())
        except Exception as exc:
            return _skipped_record(
                entry_point,
                entry_point_group,
                expected_type,
                package_name,
                f"failed to load entry point: {exc}",
            )

        try:
            metadata = _plugin_metadata(plugin)
        except Exception as exc:
            return _skipped_record(
                entry_point,
                entry_point_group,
                expected_type,
                package_name,
                f"failed to read plugin metadata: {exc}",
                plugin=plugin,
            )
        if metadata is None:
            return _skipped_record(
                entry_point,
                entry_point_group,
                expected_type,
                package_name,
                "missing PluginMetadata",
                plugin=plugin,
            )

        if metadata.plugin_type != expected_type:
            return _skipped_record(
                entry_point,
                entry_point_group,
                expected_type,
                package_name,
                f"declares plugin_type {metadata.plugin_type!r}; expected {expected_type!r}",
                metadata=metadata,
                plugin=plugin,
            )

        skip_reason = _compatibility_skip_reason(metadata, self.sdk_version)
        if skip_reason is not None:
            return _skipped_record(
                entry_point,
                entry_point_group,
                expected_type,
                package_name,
                skip_reason,
                metadata=metadata,
                plugin=plugin,
            )

        return PluginRecord(
            name=metadata.name,
            plugin_type=metadata.plugin_type,
            entry_point_group=entry_point_group,
            entry_point_name=entry_point_name,
            package_name=metadata.package_name,
            package_version=metadata.package_version,
            metadata=metadata,
            plugin=plugin,
            compatible=True,
        )


def _entry_points_for_group(group: str) -> Sequence[Any]:
    discovered = importlib.metadata.entry_points()
    if hasattr(discovered, "select"):
        return list(discovered.select(group=group))
    legacy_group_lookup = getattr(discovered, "get", None)
    if callable(legacy_group_lookup):
        return list(legacy_group_lookup(group, ()))
    return []


def _construct_plugin(loaded: Any) -> object:
    if isinstance(loaded, type):
        return loaded()
    if hasattr(loaded, "metadata"):
        return loaded
    if callable(loaded):
        return loaded()
    return loaded


def _plugin_metadata(plugin: object) -> PluginMetadata | None:
    metadata = getattr(plugin, "metadata", None)
    if callable(metadata) and not isinstance(metadata, PluginMetadata):
        metadata = metadata()
    if isinstance(metadata, PluginMetadata):
        return metadata
    return None


def _compatibility_skip_reason(metadata: PluginMetadata, sdk_version: str) -> str | None:
    try:
        current = Version(sdk_version)
        minimum = Version(metadata.min_sdk_version)
    except InvalidVersion as exc:
        return f"invalid SDK compatibility version: {exc}"

    if current < minimum:
        return f"requires Ancilis SDK >={metadata.min_sdk_version}"

    if metadata.max_sdk_version is not None:
        try:
            maximum = Version(metadata.max_sdk_version)
        except InvalidVersion as exc:
            return f"invalid SDK compatibility version: {exc}"
        if current > maximum:
            return f"requires Ancilis SDK <={metadata.max_sdk_version}"

    return None


def _entry_point_distribution_name(entry_point: Any) -> str | None:
    dist = getattr(entry_point, "dist", None)
    if dist is None:
        return None
    metadata = getattr(dist, "metadata", {}) or {}
    return metadata.get("Name") or getattr(dist, "name", None)


def _entry_point_matches_package(entry_point: Any, package_or_module: str) -> bool:
    target = canonicalize_name(package_or_module)
    dist_name = _entry_point_distribution_name(entry_point)
    if dist_name and canonicalize_name(dist_name) == target:
        return True

    module = getattr(entry_point, "module", None)
    if module is None:
        value = str(getattr(entry_point, "value", ""))
        module = value.split(":", 1)[0]

    module_root = module.split(".", 1)[0]
    return canonicalize_name(module) == target or canonicalize_name(module_root) == target


def _skipped_record(
    entry_point: Any,
    entry_point_group: str,
    plugin_type: PluginType,
    package_name: str | None,
    skip_reason: str,
    metadata: PluginMetadata | None = None,
    plugin: object | None = None,
) -> PluginRecord:
    name = metadata.name if metadata is not None else str(getattr(entry_point, "name", "<unknown>"))
    logger.warning("Skipping Ancilis plugin %s: %s", name, skip_reason)
    return PluginRecord(
        name=name,
        plugin_type=metadata.plugin_type if metadata is not None else plugin_type,
        entry_point_group=entry_point_group,
        entry_point_name=str(getattr(entry_point, "name", "<unknown>")),
        package_name=metadata.package_name if metadata is not None else package_name,
        package_version=metadata.package_version if metadata is not None else None,
        metadata=metadata,
        plugin=plugin,
        compatible=False,
        skip_reason=skip_reason,
    )


__all__ = [
    "AdapterPlugin",
    "ENTRY_POINT_GROUPS",
    "OverlayPlugin",
    "PluginContext",
    "PluginMetadata",
    "PluginRecord",
    "PluginRegistry",
    "PluginType",
    "ProducerPlugin",
]
