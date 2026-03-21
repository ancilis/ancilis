from __future__ import annotations

import importlib
import sys
from pathlib import Path

from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config, load_control_definitions, load_taxonomy
from ancilis.engine.action import Action, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.evidence.store import EvidenceStore


def _config(**overrides):
    raw = {"agent": {"name": "test-agent"}}
    raw.update(overrides)
    return load_config(raw=raw)


def _action(*, tool_name: str = "read_file", source_type: str = "tool") -> Action:
    return Action(
        action_id="act-001",
        timestamp="2026-03-20T00:00:00Z",
        agent_id="test-agent",
        source_type=source_type,
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw={"path": "/tmp/demo"}),
    )


def test_shared_assets_load_from_runtime_tree():
    taxonomy = load_taxonomy()
    controls = load_control_definitions()
    assert taxonomy["version"]
    assert controls["PR-01"]["id"] == "PR-01"


def test_optional_mcp_import_remains_lazy(monkeypatch):
    sys.modules.pop("ancilis.producers", None)
    original_import = importlib.import_module

    def guarded_import(name: str, package: str | None = None):
        if name == "mcp":
            raise ImportError("simulated missing optional dependency")
        return original_import(name, package)

    monkeypatch.setattr(importlib, "import_module", guarded_import)
    producers = importlib.import_module("ancilis.producers")
    assert producers.CLIActionProducer is not None
    assert producers.HTTPActionProducer is not None


def test_source_type_flows_into_evidence_record():
    config = _config()
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)
    evaluation = engine.evaluate(_action(source_type="http"))
    store = EvidenceStore(config, in_memory=True)
    try:
        record = store.store(evaluation, tool_name="read_file")
        assert record.agent_id == "test-agent"
        assert record.source_type == "http"
        assert store.get_records()[0].source_type == "http"
    finally:
        store.close()


def test_status_and_report_handle_empty_store(tmp_path: Path):
    cfg = tmp_path / "ancilis.yaml"
    cfg.write_text("agent:\n  name: empty-agent\n")
    db = tmp_path / "empty.duckdb"
    runner = CliRunner()

    status_result = runner.invoke(cli, ["status", "--config", str(cfg), "--db", str(db)])
    report_result = runner.invoke(cli, ["report", "--config", str(cfg), "--db", str(db)])

    assert status_result.exit_code == 0
    assert "No evaluations recorded yet" in status_result.output
    assert report_result.exit_code == 0
    assert "0 total" in report_result.output or "0 records" in report_result.output


def test_evidence_store_repeated_writes_are_stable():
    config = _config()
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)
    store = EvidenceStore(config, in_memory=True)
    try:
        for idx in range(10):
            action = _action(tool_name="read_file", source_type="tool")
            action.action_id = f"act-{idx}"
            evaluation = engine.evaluate(action)
            store.store(evaluation, tool_name="read_file")
        valid, errors = store.verify_chain()
        assert valid is True
        assert errors == []
        assert store.count() == 10
    finally:
        store.close()
