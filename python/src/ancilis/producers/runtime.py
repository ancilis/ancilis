"""Runtime producer selection for built-in and plugin ActionProducer sources."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore
from ancilis.plugins import PluginContext, PluginRegistry
from ancilis.producers.cli import CLIActionProducer
from ancilis.producers.http import HTTPActionProducer
from ancilis.producers.mcp import MCPActionProducer
from ancilis.producers.protocol import ActionProducer
from ancilis.producers.tool import ToolActionProducer

logger = logging.getLogger(__name__)

BUILTIN_PRODUCER_NAMES = ("tool", "mcp", "cli", "http")
_BUILTIN_PRODUCER_SET = frozenset(BUILTIN_PRODUCER_NAMES)


@dataclass(frozen=True)
class RuntimeProducerSelection:
    """Resolved runtime producers plus non-fatal selection warnings."""

    producers: Mapping[str, ActionProducer]
    warnings: tuple[str, ...] = ()


def resolve_runtime_producers(
    config: ResolvedConfig,
    *,
    builtin_names: Iterable[str] | None = None,
    plugin_names: Iterable[str] = (),
    plugin_configs: Mapping[str, Mapping[str, Any]] | None = None,
    plugin_registry: PluginRegistry | None = None,
    engine: Engine | None = None,
    registry: ToolRegistry | None = None,
    evidence_store: EvidenceStore | None = None,
) -> RuntimeProducerSelection:
    """Resolve built-in producers and explicitly selected plugin producers.

    Built-in Tool/MCP/CLI/HTTP producers remain the default set. Plugin producers
    are additive, selected with ``plugin:<name>``, and skipped rather than allowed
    to override a built-in producer name.
    """

    warnings: list[str] = []
    runtime_registry = registry or (engine.registry if engine is not None else ToolRegistry())
    runtime_engine = engine or Engine(config, registry=runtime_registry)

    producers: dict[str, ActionProducer] = {}
    selected_builtins = tuple(builtin_names) if builtin_names is not None else BUILTIN_PRODUCER_NAMES
    for name in selected_builtins:
        if name not in _BUILTIN_PRODUCER_SET:
            _warn(warnings, f"Unknown built-in producer '{name}' was skipped.")
            continue
        producers[name] = _build_builtin_producer(
            name,
            config=config,
            engine=runtime_engine,
            registry=runtime_registry,
            evidence_store=evidence_store,
        )

    requested_plugins = _requested_plugin_names(plugin_names, warnings)
    if requested_plugins:
        discovered = plugin_registry or PluginRegistry.discover()
        plugin_config_map = plugin_configs or {}
        records_by_name = {
            record.name: record
            for record in discovered.compatible("producer")
            if record.metadata is not None
        }
        for plugin_name in requested_plugins:
            if plugin_name in _BUILTIN_PRODUCER_SET:
                _warn(
                    warnings,
                    f"Plugin producer '{plugin_name}' collides with built-in producer "
                    f"'{plugin_name}' and was skipped.",
                )
                continue

            record = records_by_name.get(plugin_name)
            if record is None:
                _warn(warnings, f"Plugin producer '{plugin_name}' was not discovered or compatible.")
                continue
            if record.plugin is None:
                _warn(warnings, f"Plugin producer '{plugin_name}' has no plugin object and was skipped.")
                continue

            context = PluginContext(
                sdk_version=discovered.sdk_version,
                config=plugin_config_map.get(plugin_name, {}),
            )
            try:
                producer = record.plugin.create_producer(context)  # type: ignore[attr-defined]
            except Exception as exc:
                _warn(
                    warnings,
                    f"Plugin producer '{plugin_name}' failed to create plugin producer "
                    f"'{plugin_name}': {exc}",
                )
                continue

            if not isinstance(producer, ActionProducer):
                _warn(
                    warnings,
                    f"Plugin producer '{plugin_name}' did not return an ActionProducer and was skipped.",
                )
                continue

            producers[f"plugin:{plugin_name}"] = producer

    return RuntimeProducerSelection(
        producers=MappingProxyType(producers),
        warnings=tuple(warnings),
    )


def translate_runtime_action(producer: ActionProducer, raw_invocation: Any) -> Action:
    """Translate a runtime invocation and validate the standardized Action shape."""

    action = producer.translate(raw_invocation)
    if not isinstance(action, Action):
        raise TypeError(
            f"Runtime producer {producer.__class__.__name__} returned "
            f"{type(action).__name__}; expected Action."
        )
    return action


def _build_builtin_producer(
    name: str,
    *,
    config: ResolvedConfig,
    engine: Engine,
    registry: ToolRegistry,
    evidence_store: EvidenceStore | None,
) -> ActionProducer:
    if name == "tool":
        return ToolActionProducer(
            config=config,
            engine=engine,
            registry=registry,
            evidence_store=evidence_store,
        )
    if name == "mcp":
        return MCPActionProducer(config=config, registry=registry)
    if name == "cli":
        return CLIActionProducer(
            config=config,
            engine=engine,
            registry=registry,
            evidence_store=evidence_store,
        )
    if name == "http":
        return HTTPActionProducer(
            config=config,
            engine=engine,
            registry=registry,
            evidence_store=evidence_store,
        )
    raise ValueError(f"Unknown built-in producer: {name}")


def _requested_plugin_names(plugin_names: Iterable[str], warnings: list[str]) -> list[str]:
    requested: list[str] = []
    for selector in plugin_names:
        if not selector.startswith("plugin:"):
            _warn(
                warnings,
                f"Plugin producer selector '{selector}' is not namespaced as plugin:<name>.",
            )
            continue
        name = selector.split(":", 1)[1].strip()
        if not name:
            _warn(warnings, "Empty plugin producer selector was skipped.")
            continue
        if name not in requested:
            requested.append(name)
    return requested


def _warn(warnings: list[str], message: str) -> None:
    warnings.append(message)
    logger.warning(message)


__all__ = [
    "BUILTIN_PRODUCER_NAMES",
    "RuntimeProducerSelection",
    "resolve_runtime_producers",
    "translate_runtime_action",
]
