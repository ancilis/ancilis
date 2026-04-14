from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.evidence.store import EvidenceStore
from ancilis.plugins import PluginContext, PluginMetadata, PluginRecord, PluginRegistry
from ancilis.producers.protocol import ProducerType
from ancilis.producers.runtime import resolve_runtime_producers, translate_runtime_action


def _config() -> ResolvedConfig:
    return load_config(
        raw={
            "agent": {"name": "runtime-agent"},
            "security": {"mode": "audit"},
        }
    )


@dataclass
class FakeProducerPlugin:
    name: str = "fake-producer"
    fail_create: bool = False

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            plugin_type="producer",
            package_name=f"{self.name}-package",
            package_version="1.0.0",
            min_sdk_version="0.1.0",
        )

    def create_producer(self, context: PluginContext) -> Any:
        if self.fail_create:
            raise RuntimeError("boom")
        return FakePluginActionProducer(context)


class FakePluginActionProducer:
    def __init__(self, context: PluginContext) -> None:
        self._tool_name = str(context.config.get("tool_name", "plugin:fake.lookup"))
        self._agent_name = str(context.config.get("agent_name", "runtime-agent"))
        self._hash = self.compute_tool_hash(self._tool_name)

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.FRAMEWORK

    @property
    def producer_version(self) -> str:
        return "1.0.0"

    def translate(self, raw_invocation: dict[str, Any]) -> Action:
        payload = {"raw": raw_invocation}
        return Action(
            action_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self._agent_name,
            source_type=self.producer_type.value,
            action_type="tool_call",
            tool=ToolInfo(name=self._tool_name, description_hash=self._hash),
            parameters=ActionParameters(
                raw=payload,
                parameter_hash=hashlib.sha256(repr(payload).encode()).hexdigest(),
            ),
            context=ActionContext(session_id="plugin-session"),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registry.register(
            ToolEntry(
                name=self._tool_name,
                description_hash=self._hash,
                status=ToolStatus.APPROVED,
                approved_by="plugin-test",
            )
        )
        return [self._tool_name]


def _plugin_registry(*plugins: FakeProducerPlugin) -> PluginRegistry:
    records = [
        PluginRecord(
            name=plugin.metadata.name,
            plugin_type="producer",
            entry_point_group="ancilis.producers",
            entry_point_name=plugin.metadata.name,
            package_name=plugin.metadata.package_name,
            package_version=plugin.metadata.package_version,
            metadata=plugin.metadata,
            plugin=plugin,
            compatible=True,
        )
        for plugin in plugins
    ]
    return PluginRegistry(records=records, sdk_version="0.1.0")


def test_plugin_producer_can_be_selected_and_evaluated_by_explicit_name() -> None:
    config = _config()
    engine = Engine(config)
    store = EvidenceStore(config, in_memory=True)
    plugin_registry = _plugin_registry(FakeProducerPlugin())

    selection = resolve_runtime_producers(
        config,
        engine=engine,
        evidence_store=store,
        plugin_registry=plugin_registry,
        plugin_names=["plugin:fake-producer"],
        plugin_configs={"fake-producer": {"tool_name": "plugin:fake.lookup"}},
    )

    assert set(selection.producers) == {"tool", "mcp", "cli", "http", "plugin:fake-producer"}
    plugin_producer = selection.producers["plugin:fake-producer"]
    assert plugin_producer.register_tools(engine.registry) == ["plugin:fake.lookup"]

    action = translate_runtime_action(plugin_producer, {"query": "status"})
    evaluation = engine.evaluate(action)
    store.store(evaluation, tool_name=action.tool.name)

    assert action.tool.name == "plugin:fake.lookup"
    assert action.producer_type == "framework"
    assert evaluation.decision == "ALLOW"
    assert store.get_summary(session_id="plugin-session")["total_evaluations"] == 1


def test_plugin_producer_collisions_and_create_failures_warn_and_keep_builtins(
    caplog: Any,
) -> None:
    caplog.set_level(logging.WARNING)
    config = _config()
    plugin_registry = _plugin_registry(
        FakeProducerPlugin(name="tool"),
        FakeProducerPlugin(name="broken-producer", fail_create=True),
    )

    selection = resolve_runtime_producers(
        config,
        plugin_registry=plugin_registry,
        plugin_names=["plugin:tool", "plugin:broken-producer"],
    )

    assert set(selection.producers) == {"tool", "mcp", "cli", "http"}
    assert "collides with built-in producer 'tool'" in caplog.text
    assert "failed to create plugin producer 'broken-producer': boom" in caplog.text
    assert any("collides with built-in producer 'tool'" in warning for warning in selection.warnings)
    assert any("failed to create plugin producer 'broken-producer': boom" in warning for warning in selection.warnings)


def test_builtin_selection_uses_explicit_registry_without_engine() -> None:
    config = _config()
    registry = ToolRegistry()
    registry.register(
        ToolEntry(
            name="read_file",
            description_hash="registered-hash",
            status=ToolStatus.APPROVED,
            approved_by="plugin-test",
        )
    )

    selection = resolve_runtime_producers(
        config,
        builtin_names=["mcp"],
        registry=registry,
    )

    action = translate_runtime_action(
        selection.producers["mcp"],
        {"name": "read_file", "arguments": {"path": "/tmp/example"}},
    )
    assert action.tool.description_hash == "registered-hash"


def test_runtime_selection_helpers_are_exported() -> None:
    from ancilis import resolve_runtime_producers as root_resolve_runtime_producers
    from ancilis import translate_runtime_action as root_translate_runtime_action
    import ancilis.producers as producers

    assert producers.resolve_runtime_producers is resolve_runtime_producers
    assert producers.translate_runtime_action is translate_runtime_action
    assert root_resolve_runtime_producers is resolve_runtime_producers
    assert root_translate_runtime_action is translate_runtime_action
