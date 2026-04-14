from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.adapter import (
    EvidenceAdapterExport,
    EvidenceAdapterPayload,
    EvidenceAdapterQuery,
    resolve_evidence_adapter,
)
from ancilis.evidence.chain import GENESIS_SEED
from ancilis.evidence.store import EvidenceStore
from ancilis.plugins import PluginContext, PluginMetadata, PluginRecord, PluginRegistry


def _config() -> ResolvedConfig:
    return load_config(
        raw={
            "agent": {"name": "adapter-agent"},
            "security": {"mode": "audit"},
        }
    )


def _evaluation(evaluation_id: str = "eval-adapter-001") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id="action-adapter-001",
        timestamp="2026-04-14T03:55:00Z",
        agent_id="adapter-agent",
        source_type="framework",
        mode="audit",
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Agent identity verified",
                evidence_data={"agent_id": "adapter-agent"},
                duration_ms=1.5,
            )
        ],
        decision="ALLOW",
        active_overlays=["financial"],
        data_classifications=["internal"],
        detected_data_types=["email"],
        total_duration_ms=6.0,
        session_id="adapter-session",
    )


@dataclass
class FakeEvidenceAdapter:
    payloads: list[EvidenceAdapterPayload] = field(default_factory=list)
    fail_store: bool = False

    def store(self, payload: EvidenceAdapterPayload) -> None:
        if self.fail_store:
            raise RuntimeError("adapter store boom")
        self.payloads.append(payload)

    def query(self, query: EvidenceAdapterQuery | None = None) -> list[object]:
        if query is None or query.tool_name is None:
            return [payload.record for payload in self.payloads]
        return [
            payload.record
            for payload in self.payloads
            if payload.record.tool_name == query.tool_name
        ]

    def export(self, export: EvidenceAdapterExport | None = None) -> dict[str, object]:
        return {
            "format": "json" if export is None else export.format,
            "records": [payload.record.record_id for payload in self.payloads],
        }


@dataclass
class FakeEvidenceAdapterPlugin:
    name: str = "fake-evidence"
    adapter: FakeEvidenceAdapter = field(default_factory=FakeEvidenceAdapter)
    fail_create: bool = False

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            plugin_type="adapter",
            package_name=f"{self.name}-package",
            package_version="1.0.0",
            min_sdk_version="0.1.0",
        )

    def create_adapter(self, context: PluginContext) -> FakeEvidenceAdapter:
        if self.fail_create:
            raise RuntimeError("adapter create boom")
        assert context.config["sink"] == "fake"
        return self.adapter


def _plugin_registry(*plugins: FakeEvidenceAdapterPlugin) -> PluginRegistry:
    return PluginRegistry(
        records=[
            PluginRecord(
                name=plugin.metadata.name,
                plugin_type="adapter",
                entry_point_group="ancilis.adapters",
                entry_point_name=plugin.metadata.name,
                package_name=plugin.metadata.package_name,
                package_version=plugin.metadata.package_version,
                metadata=plugin.metadata,
                plugin=plugin,
                compatible=True,
            )
            for plugin in plugins
        ],
        sdk_version="0.1.0",
    )


def test_plugin_evidence_adapter_can_be_selected_and_receives_canonical_record() -> None:
    config = _config()
    plugin = FakeEvidenceAdapterPlugin()
    selection = resolve_evidence_adapter(
        config,
        plugin_name="plugin:fake-evidence",
        plugin_registry=_plugin_registry(plugin),
        plugin_configs={"fake-evidence": {"sink": "fake"}},
    )
    store = EvidenceStore(
        config,
        in_memory=True,
        evidence_adapter=selection.adapter,
        evidence_adapter_name=selection.adapter_name,
        evidence_adapter_metadata={"adapter_sink": "fake"},
    )

    record = store.store(_evaluation(), tool_name="plugin:fake.lookup")

    assert selection.warnings == ()
    assert selection.adapter_name == "fake-evidence"
    assert store.get_summary(session_id="adapter-session")["total_evaluations"] == 1
    assert plugin.adapter.payloads == [
        EvidenceAdapterPayload(
            record=record,
            adapter_metadata={"adapter_sink": "fake"},
        )
    ]
    payload = plugin.adapter.payloads[0]
    assert payload.record.record_hash == record.record_hash
    assert payload.record.previous_hash == GENESIS_SEED
    assert payload.record.detected_data_types == ["email"]
    assert payload.record.classification_context == {}
    assert payload.adapter_metadata == {"adapter_sink": "fake"}
    assert plugin.adapter.query(EvidenceAdapterQuery(tool_name="plugin:fake.lookup")) == [record]
    assert plugin.adapter.export(EvidenceAdapterExport(format="json")) == {
        "format": "json",
        "records": [record.record_id],
    }


def test_duckdb_store_remains_default_when_plugin_adapter_is_not_selected() -> None:
    config = _config()
    selection = resolve_evidence_adapter(config)
    store = EvidenceStore(config, in_memory=True, evidence_adapter=selection.adapter)

    record = store.store(_evaluation(), tool_name="builtin-tool")

    assert selection.adapter is None
    assert selection.adapter_name is None
    assert selection.warnings == ()
    assert record.tool_name == "builtin-tool"
    assert store.get_summary(session_id="adapter-session")["total_evaluations"] == 1


def test_broken_plugin_adapter_hooks_warn_and_duckdb_store_still_succeeds(
    caplog: Any,
) -> None:
    caplog.set_level(logging.WARNING)
    config = _config()
    create_failure = resolve_evidence_adapter(
        config,
        plugin_name="plugin:broken-create",
        plugin_registry=_plugin_registry(FakeEvidenceAdapterPlugin(name="broken-create", fail_create=True)),
        plugin_configs={"broken-create": {"sink": "fake"}},
    )
    broken_store_adapter = FakeEvidenceAdapter(fail_store=True)
    store = EvidenceStore(
        config,
        in_memory=True,
        evidence_adapter=broken_store_adapter,
        evidence_adapter_name="broken-store",
    )

    record = store.store(_evaluation(), tool_name="plugin:broken.lookup")

    assert create_failure.adapter is None
    assert create_failure.adapter_name == "broken-create"
    assert "failed to create plugin evidence adapter 'broken-create': adapter create boom" in caplog.text
    assert "plugin evidence adapter 'broken-store' store hook failed: adapter store boom" in caplog.text
    assert record.tool_name == "plugin:broken.lookup"
    assert store.count(session_id="adapter-session") == 1
