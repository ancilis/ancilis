"""Plugin evidence adapter contracts and explicit runtime selection."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from ancilis.config import ResolvedConfig
from ancilis.evidence.record import EvidenceRecord
from ancilis.plugins import PluginContext, PluginRegistry

logger = logging.getLogger(__name__)


def _empty_mapping() -> Mapping[str, Any]:
    return MappingProxyType({})


@dataclass(frozen=True)
class EvidenceAdapterPayload:
    """Canonical SDK evidence plus adapter-local metadata."""

    record: EvidenceRecord
    adapter_metadata: Mapping[str, Any] = field(default_factory=_empty_mapping)


@dataclass(frozen=True)
class EvidenceAdapterQuery:
    """Optional evidence query filters exposed to plugin adapters."""

    agent_id: str | None = None
    session_id: str | None = None
    tool_name: str | None = None
    decision: str | None = None
    since: str | None = None
    limit: int | None = 100


@dataclass(frozen=True)
class EvidenceAdapterExport:
    """Evidence export request exposed to plugin adapters."""

    format: str = "json"
    query: EvidenceAdapterQuery = field(default_factory=EvidenceAdapterQuery)


@runtime_checkable
class EvidenceAdapter(Protocol):
    """Plugin evidence adapter shape supported by the SDK runtime."""

    def store(self, payload: EvidenceAdapterPayload) -> None:
        """Store or forward a canonical evidence payload."""
        ...

    def query(self, query: EvidenceAdapterQuery | None = None) -> object:
        """Query adapter-managed evidence."""
        ...

    def export(self, export: EvidenceAdapterExport | None = None) -> object:
        """Export adapter-managed evidence."""
        ...


@dataclass(frozen=True)
class EvidenceAdapterSelection:
    """Resolved plugin evidence adapter plus non-fatal selection warnings."""

    adapter: EvidenceAdapter | None
    warnings: tuple[str, ...] = ()


def resolve_evidence_adapter(
    config: ResolvedConfig,
    *,
    plugin_name: str | None = None,
    plugin_configs: Mapping[str, Mapping[str, Any]] | None = None,
    plugin_registry: PluginRegistry | None = None,
) -> EvidenceAdapterSelection:
    """Resolve one explicitly selected plugin evidence adapter.

    No adapter is selected by default, leaving the DuckDB-backed ``EvidenceStore``
    as the SDK-owned canonical evidence store.
    """

    del config
    warnings: list[str] = []
    adapter_name = _requested_adapter_name(plugin_name, warnings)
    if adapter_name is None:
        return EvidenceAdapterSelection(adapter=None, warnings=tuple(warnings))

    discovered = plugin_registry or PluginRegistry.discover()
    record = next(
        (
            candidate
            for candidate in discovered.compatible("adapter")
            if candidate.name == adapter_name and candidate.metadata is not None
        ),
        None,
    )
    if record is None:
        _warn(warnings, f"Plugin evidence adapter '{adapter_name}' was not discovered or compatible.")
        return EvidenceAdapterSelection(adapter=None, warnings=tuple(warnings))
    if record.plugin is None:
        _warn(warnings, f"Plugin evidence adapter '{adapter_name}' has no plugin object and was skipped.")
        return EvidenceAdapterSelection(adapter=None, warnings=tuple(warnings))

    plugin_config_map = plugin_configs or {}
    context = PluginContext(
        sdk_version=discovered.sdk_version,
        config=plugin_config_map.get(adapter_name, {}),
    )
    try:
        adapter = record.plugin.create_adapter(context)  # type: ignore[attr-defined]
    except Exception as exc:
        _warn(warnings, f"failed to create plugin evidence adapter '{adapter_name}': {exc}")
        return EvidenceAdapterSelection(adapter=None, warnings=tuple(warnings))

    if not isinstance(adapter, EvidenceAdapter):
        _warn(
            warnings,
            f"Plugin evidence adapter '{adapter_name}' did not expose store(), query(), and export().",
        )
        return EvidenceAdapterSelection(adapter=None, warnings=tuple(warnings))

    return EvidenceAdapterSelection(adapter=adapter, warnings=tuple(warnings))


def _requested_adapter_name(plugin_name: str | None, warnings: list[str]) -> str | None:
    if plugin_name is None:
        return None
    if not plugin_name.startswith("plugin:"):
        _warn(
            warnings,
            f"Plugin evidence adapter selector '{plugin_name}' is not namespaced as plugin:<name>.",
        )
        return None
    name = plugin_name.split(":", 1)[1].strip()
    if not name:
        _warn(warnings, "Empty plugin evidence adapter selector was skipped.")
        return None
    return name


def _warn(warnings: list[str], message: str) -> None:
    warnings.append(message)
    logger.warning(message)


__all__ = [
    "EvidenceAdapter",
    "EvidenceAdapterExport",
    "EvidenceAdapterPayload",
    "EvidenceAdapterQuery",
    "EvidenceAdapterSelection",
    "resolve_evidence_adapter",
]
