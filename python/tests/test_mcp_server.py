"""Tests for Ancilis MCP server mode."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from click.testing import CliRunner
from pytest import MonkeyPatch

from ancilis.activation.loader import load_overlay_profiles
from ancilis.cli.main import cli
from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.engine import Engine
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.mcp_server import MCPServerContext, create_mcp_server
from ancilis.producers.tool import ToolActionProducer


EXPECTED_TOOL_NAMES = {
    "ancilis_check_posture",
    "ancilis_evaluate_action",
    "ancilis_get_evidence",
    "ancilis_report",
    "ancilis_list_overlays",
    "ancilis_inspect_project",
    "ancilis_classify_project",
    "ancilis_recommend_setup",
    "ancilis_review_code",
    "ancilis_onboarding_report",
    "ancilis_assess_gap",
}


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "ancilis.yaml"
    config_path.write_text(
        "\n".join(
            [
                "agent:",
                "  name: mcp-test-agent",
                "security:",
                "  mode: audit",
                "",
            ]
        )
    )
    return config_path


def _write_evaluate_config(
    tmp_path: Path,
    *,
    mode: str,
    allowed: list[str] | None = None,
    blocked: list[str] | None = None,
) -> Path:
    config_path = tmp_path / "ancilis.yaml"
    lines = [
        "agent:",
        "  name: mcp-test-agent",
        "security:",
        f"  mode: {mode}",
        "  tools:",
    ]
    if allowed is not None:
        lines.append("    allowed:")
        lines.extend(f"      - {tool}" for tool in allowed)
    else:
        lines.append("    allowed: []")
    if blocked is not None:
        lines.append("    blocked:")
        lines.extend(f"      - {tool}" for tool in blocked)
    else:
        lines.append("    blocked: []")
    config_path.write_text("\n".join(lines) + "\n")
    return config_path


def _financial_context() -> MCPServerContext:
    config = load_config(
        raw={
            "agent": {"name": "mcp-test-agent", "agent_id": "agent-1"},
            "my_agent_handles": ["financial_data"],
            "security": {"mode": "audit"},
        }
    )
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, evidence_store=store)
    return MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=store,
        action_producer=ToolActionProducer(
            config,
            engine,
            registry=engine.registry,
            evidence_store=store,
        ),
    )


def _financial_context_with_store(
    config: ResolvedConfig,
    store: EvidenceStore,
) -> MCPServerContext:
    engine = Engine(config, evidence_store=store)
    return MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=store,
        action_producer=ToolActionProducer(
            config,
            engine,
            registry=engine.registry,
            evidence_store=store,
        ),
    )


def _evaluation(
    *,
    evaluation_id: str,
    session_id: str,
    timestamp: str,
    control_results: list[ControlResult],
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id=f"action-{evaluation_id}",
        timestamp=timestamp,
        agent_id="agent-1",
        source_type="tool",
        mode="audit",
        control_results=control_results,
        decision="ALLOW",
        decision_reason="test",
        active_overlays=["glba", "soc2"],
        data_classifications=["DC-FIN"],
        total_duration_ms=1.0,
        session_id=session_id,
    )


def _iso(hour: int) -> str:
    return datetime(2026, 1, 1, hour, tzinfo=timezone.utc).isoformat()


def _call_tool_structured(
    server: Any,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _content, structured = cast(
        tuple[list[Any], dict[str, Any]],
        asyncio.run(server.call_tool(tool_name, arguments or {})),
    )
    return structured


def test_create_mcp_server_registers_tools(tmp_path: Path) -> None:
    server = create_mcp_server(config_path=str(_write_config(tmp_path)))

    assert server.name == "ancilis"
    tools = asyncio.run(server.list_tools())
    tool_names = {tool.name for tool in tools}
    assert EXPECTED_TOOL_NAMES.issubset(tool_names)


def test_check_posture_returns_latest_session_active_evaluator_results() -> None:
    context = _financial_context()
    context.evidence_store.store(
        _evaluation(
            evaluation_id="older",
            session_id="older-session",
            timestamp=_iso(1),
            control_results=[
                ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "older pass"),
            ],
        ),
        tool_name="old_tool",
    )
    context.evidence_store.store(
        _evaluation(
            evaluation_id="latest",
            session_id="latest-session",
            timestamp=_iso(2),
            control_results=[
                ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "allowlisted"),
                ControlResult("PR-02", "Scoped Permissions", "FAIL", "scope violation"),
                ControlResult("PR-05", "Audit Logging", "SKIP", "disabled in action"),
                ControlResult("GOV-01", "Governance", "FAIL", "not runtime active"),
            ],
        ),
        tool_name="latest_tool",
    )
    server = create_mcp_server(context=context)

    structured = _call_tool_structured(server, "ancilis_check_posture")

    assert structured["session_id"] == "latest-session"
    assert structured["posture_score"] == 0.1
    assert structured["active_overlays"] == ["glba", "soc2"]
    assert structured["evaluated_at"]
    assert [control["id"] for control in structured["controls"]] == ["PR-01", "PR-02"]
    assert [control["name"] for control in structured["controls"]] == [
        "Tool Identity & Allowlist",
        "Scoped Permissions",
    ]
    assert [control["status"] for control in structured["controls"]] == ["PASS", "FAIL"]


def test_check_posture_handles_no_evidence() -> None:
    server = create_mcp_server(context=_financial_context())

    structured = _call_tool_structured(server, "ancilis_check_posture")

    assert structured["session_id"] is None
    assert structured["posture_score"] == 0.0
    assert structured["controls"] == []
    assert structured["active_overlays"] == ["glba", "soc2"]


def test_list_overlays_reports_active_overlay_coverage() -> None:
    context = _financial_context()
    context.evidence_store.store(
        _evaluation(
            evaluation_id="coverage",
            session_id="coverage-session",
            timestamp=_iso(3),
            control_results=[
                ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "allowlisted"),
                ControlResult("PR-05", "Audit Logging", "FAIL", "missing log sink"),
                ControlResult("GOV-01", "Governance", "SKIP", "no runtime evaluator"),
            ],
        ),
        tool_name="coverage_tool",
    )
    server = create_mcp_server(context=context)

    structured = _call_tool_structured(server, "ancilis_list_overlays")

    overlays = {overlay["name"]: overlay for overlay in structured["overlays"]}
    overlay_profiles = load_overlay_profiles()
    for overlay_id in ("glba", "soc2"):
        expected_controls = {
            control_id
            for control_id, control_data in overlay_profiles[overlay_id].get("controls", {}).items()
            if control_data.get("applicable", True)
        }
        expected_covered = len({"PR-01", "PR-05"} & expected_controls)
        expected_percent = round((expected_covered / len(expected_controls)) * 100, 2)

        assert overlays[overlay_id]["controls_covered"] == expected_covered
        assert overlays[overlay_id]["controls_total"] == len(expected_controls)
        assert overlays[overlay_id]["coverage_pct"] == expected_percent


def test_list_overlays_handles_no_evidence() -> None:
    server = create_mcp_server(context=_financial_context())

    structured = _call_tool_structured(server, "ancilis_list_overlays")

    assert {
        (overlay["name"], overlay["coverage_pct"], overlay["controls_covered"])
        for overlay in structured["overlays"]
    } == {("glba", 0.0, 0), ("soc2", 0.0, 0)}


def test_read_only_posture_tools_do_not_create_missing_evidence_db(tmp_path: Path) -> None:
    config = load_config(
        raw={
            "agent": {"name": "mcp-test-agent", "agent_id": "agent-1"},
            "my_agent_handles": ["financial_data"],
            "security": {"mode": "audit"},
        }
    )
    db_file = tmp_path / "missing.duckdb"
    store = EvidenceStore(config, db_path=db_file)
    server = create_mcp_server(context=_financial_context_with_store(config, store))

    posture = _call_tool_structured(server, "ancilis_check_posture")
    overlays = _call_tool_structured(server, "ancilis_list_overlays")

    assert posture["session_id"] is None
    assert posture["controls"] == []
    assert {
        (overlay["name"], overlay["coverage_pct"], overlay["controls_covered"])
        for overlay in overlays["overlays"]
    } == {("glba", 0.0, 0), ("soc2", 0.0, 0)}
    assert not db_file.exists()
    store.close()


def test_serve_help_shows_transport_options() -> None:
    result = CliRunner().invoke(cli, ["serve", "--help"])

    assert result.exit_code == 0
    assert "--config" in result.output
    assert "--transport" in result.output
    assert "--port" in result.output


def test_serve_stdio_runs_created_server(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    calls: dict[str, object] = {}

    class DummyServer:
        def run(self, *, transport: str) -> None:
            calls["transport"] = transport

    def fake_create_mcp_server(config_path: str | None = None) -> DummyServer:
        calls["config_path"] = config_path
        return DummyServer()

    monkeypatch.setattr("ancilis.cli.serve.create_mcp_server", fake_create_mcp_server)

    result = CliRunner().invoke(cli, ["serve", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert calls == {
        "config_path": str(config_path),
        "transport": "stdio",
    }


def test_evaluate_action_returns_blocked_for_blocked_tool(tmp_path: Path) -> None:
    server = create_mcp_server(
        config_path=str(
            _write_evaluate_config(
                tmp_path,
                mode="enforce",
                blocked=["dangerous_delete"],
            )
        )
    )

    structured = _call_tool_structured(
        server,
        "ancilis_evaluate_action",
        {
            "tool_name": "dangerous_delete",
            "parameters": {"path": "/etc/passwd"},
            "description": "Delete a sensitive file",
        },
    )

    assert structured["verdict"] == "blocked"
    assert structured["tool_name"] == "dangerous_delete"
    pr02 = next(item for item in structured["evaluations"] if item["control"] == "PR-02")
    assert pr02["result"] == "fail"
    assert structured["recommendation"] == "Do not execute"


def test_evaluate_action_returns_allowed_for_approved_tool(tmp_path: Path) -> None:
    server = create_mcp_server(
        config_path=str(
            _write_evaluate_config(
                tmp_path,
                mode="enforce",
                allowed=["safe_read"],
            )
        )
    )

    structured = _call_tool_structured(
        server,
        "ancilis_evaluate_action",
        {
            "tool_name": "safe_read",
            "parameters": {"path": "README.md"},
            "description": "Read project documentation",
        },
    )

    assert structured["verdict"] == "allowed"
    assert structured["tool_name"] == "safe_read"
    assert structured["recommendation"] == "Safe to proceed"
    assert all(item["result"] not in {"fail", "error", "flag"} for item in structured["evaluations"])


def test_evaluate_action_handles_unknown_tool_without_error(tmp_path: Path) -> None:
    server = create_mcp_server(
        config_path=str(
            _write_evaluate_config(
                tmp_path,
                mode="audit",
            )
        )
    )

    structured = _call_tool_structured(
        server,
        "ancilis_evaluate_action",
        {
            "tool_name": "mystery_tool",
            "parameters": {"query": "hello"},
        },
    )

    assert structured["verdict"] == "warning"
    assert structured["tool_name"] == "mystery_tool"
    pr03 = next(item for item in structured["evaluations"] if item["control"] == "PR-03")
    assert pr03["result"] == "fail"
    assert structured["recommendation"] == "Proceed with caution"


def test_evaluate_action_does_not_persist_synthetic_action(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    stores: list[FakeEvidenceStore] = []

    class FakeEvidenceStore:
        def __init__(self, config: object) -> None:
            self.config = config
            self.store_calls = 0
            stores.append(self)

        def count(self) -> int:
            return 0

        def verify_chain(self) -> tuple[bool, list[str]]:
            return True, []

        def store(self, *args: object, **kwargs: object) -> None:
            self.store_calls += 1

    monkeypatch.setattr("ancilis.mcp_server.EvidenceStore", FakeEvidenceStore)
    server = create_mcp_server(
        config_path=str(
            _write_evaluate_config(
                tmp_path,
                mode="enforce",
                allowed=["safe_read"],
            )
        )
    )

    structured = _call_tool_structured(
        server,
        "ancilis_evaluate_action",
        {
            "tool_name": "safe_read",
            "parameters": {"path": "README.md"},
        },
    )

    assert structured["verdict"] == "allowed"
    assert stores
    assert stores[0].store_calls == 0


def test_get_evidence_returns_latest_session_records_descending_with_limit() -> None:
    context = _financial_context()
    context.evidence_store.store(
        _evaluation(
            evaluation_id="older",
            session_id="older-session",
            timestamp=_iso(1),
            control_results=[
                ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "older"),
            ],
        ),
        tool_name="older_tool",
    )
    context.evidence_store.store(
        _evaluation(
            evaluation_id="latest-one",
            session_id="latest-session",
            timestamp=_iso(2),
            control_results=[
                ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "first"),
            ],
        ),
        tool_name="first_tool",
    )
    context.evidence_store.store(
        _evaluation(
            evaluation_id="latest-two",
            session_id="latest-session",
            timestamp=_iso(3),
            control_results=[
                ControlResult("PR-02", "Scoped Permissions", "FAIL", "second"),
            ],
        ),
        tool_name="second_tool",
    )
    server = create_mcp_server(context=context)

    structured = _call_tool_structured(server, "ancilis_get_evidence", {"limit": 1})

    assert structured["session_id"] == "latest-session"
    assert structured["total_count"] == 2
    assert structured["returned_count"] == 1
    assert structured["evidence"][0]["timestamp"] == _iso(3)
    assert structured["evidence"][0]["tool_name"] == "second_tool"
    assert structured["evidence"][0]["control_id"] == "PR-02"
    assert structured["evidence"][0]["result"] == "fail"
    assert len(structured["evidence"][0]["chain_hash"]) == 64


def test_get_evidence_filters_by_control_id() -> None:
    context = _financial_context()
    context.evidence_store.store(
        _evaluation(
            evaluation_id="record-one",
            session_id="filter-session",
            timestamp=_iso(1),
            control_results=[
                ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "allowlisted"),
                ControlResult("PR-02", "Scoped Permissions", "FAIL", "scope violation"),
            ],
        ),
        tool_name="mixed_tool",
    )
    server = create_mcp_server(context=context)

    structured = _call_tool_structured(
        server,
        "ancilis_get_evidence",
        {"session_id": "filter-session", "control_id": "PR-01"},
    )

    assert structured["session_id"] == "filter-session"
    assert structured["total_count"] == 1
    assert structured["returned_count"] == 1
    assert [item["control_id"] for item in structured["evidence"]] == ["PR-01"]


def test_get_evidence_handles_empty_store() -> None:
    server = create_mcp_server(context=_financial_context())

    structured = _call_tool_structured(server, "ancilis_get_evidence")

    assert structured == {
        "evidence": [],
        "total_count": 0,
        "returned_count": 0,
        "session_id": None,
    }


def test_read_only_tools_do_not_create_missing_evidence_db(tmp_path: Path) -> None:
    config = load_config(raw={"agent": {"name": "mcp-test-agent", "agent_id": "agent-1"}})
    db_file = tmp_path / "missing.duckdb"
    store = EvidenceStore(config, db_path=db_file)
    server = create_mcp_server(context=_financial_context_with_store(config, store))

    evidence = _call_tool_structured(server, "ancilis_get_evidence")
    report = _call_tool_structured(server, "ancilis_report")

    assert evidence["evidence"] == []
    assert evidence["session_id"] is None
    assert report["session_id"] is None
    assert "# Ancilis Posture Report" in report["report"]
    assert not db_file.exists()
    store.close()


def test_report_generates_markdown_for_latest_session() -> None:
    context = _financial_context()
    context.evidence_store.store(
        _evaluation(
            evaluation_id="report-record",
            session_id="report-session",
            timestamp=_iso(1),
            control_results=[
                ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "allowlisted"),
                ControlResult("PR-02", "Scoped Permissions", "FAIL", "scope violation"),
            ],
        ),
        tool_name="report_tool",
    )
    server = create_mcp_server(context=context)

    structured = _call_tool_structured(server, "ancilis_report")

    assert structured["format"] == "markdown"
    assert structured["session_id"] == "report-session"
    assert structured["generated_at"]
    assert "# Ancilis Posture Report" in structured["report"]
    assert "## Executive Summary" in structured["report"]
    assert "Baseline Security" in structured["report"]
    assert "Evidence Integrity" in structured["report"]


def test_report_rejects_non_markdown_format() -> None:
    server = create_mcp_server(context=_financial_context())

    structured = _call_tool_structured(server, "ancilis_report", {"format": "json"})

    assert structured == {
        "error": "unsupported_format",
        "format": "json",
        "supported_formats": ["markdown"],
    }
