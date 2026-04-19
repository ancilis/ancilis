"""End-to-end MCP client tests for the Ancilis stdio server."""

from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

from ancilis.config import load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import DEFAULT_DB_NAME, EvidenceStore


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "python" / "src"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

EXPECTED_TOOL_NAMES = {
    "ancilis_check_posture",
    "ancilis_evaluate_action",
    "ancilis_get_evidence",
    "ancilis_report",
    "ancilis_list_overlays",
}


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "ancilis.yaml"
    config_path.write_text((FIXTURES / "mcp_test_config.yaml").read_text())
    return config_path


def _server_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(SRC)
        if not existing_pythonpath
        else f"{SRC}{os.pathsep}{existing_pythonpath}"
    )
    env["HOME"] = str(home)
    env["ANCILIS_NO_UPDATE_CHECK"] = "1"
    return env


@asynccontextmanager
async def _client_session(tmp_path: Path) -> AsyncIterator[ClientSession]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    config_path = _write_config(tmp_path)
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "ancilis.cli.main",
            "--no-update-check",
            "serve",
            "--config",
            str(config_path),
        ],
        cwd=tmp_path,
        env=_server_env(home),
    )
    async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


def _structured(result: CallToolResult) -> dict[str, Any]:
    assert result.isError is not True
    assert isinstance(result.structuredContent, dict)
    return result.structuredContent


def _iso(hour: int) -> str:
    return datetime(2026, 1, 1, hour, tzinfo=timezone.utc).isoformat()


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
        active_overlays=["glba"],
        data_classifications=["DC-FIN"],
        total_duration_ms=1.0,
        session_id=session_id,
    )


def _default_evidence_path(home: Path, cwd: Path, agent_name: str) -> Path:
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_name)
    cwd_hash = hashlib.sha256(str(cwd).encode()).hexdigest()[:8]
    return home / ".ancilis" / f"{safe_name}-{cwd_hash}" / DEFAULT_DB_NAME


def _seed_evidence(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    config_path = _write_config(tmp_path)
    config = load_config(path=config_path)
    store = EvidenceStore(
        config,
        db_path=_default_evidence_path(home, tmp_path, "mcp-test-agent"),
    )
    try:
        store.store(
            _evaluation(
                evaluation_id="latest-one",
                session_id="integration-session",
                timestamp=_iso(1),
                control_results=[
                    ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "allowlisted"),
                    ControlResult("PR-02", "Scoped Permissions", "FAIL", "scope violation"),
                ],
            ),
            tool_name="safe_read",
        )
        store.store(
            _evaluation(
                evaluation_id="latest-two",
                session_id="integration-session",
                timestamp=_iso(2),
                control_results=[
                    ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "still allowed"),
                ],
            ),
            tool_name="safe_read",
        )
    finally:
        store.close()


async def test_server_starts_and_lists_tools(tmp_path: Path) -> None:
    async with _client_session(tmp_path) as session:
        result = await session.list_tools()

    tools = {tool.name: tool for tool in result.tools}
    assert EXPECTED_TOOL_NAMES.issubset(tools)
    for tool_name in EXPECTED_TOOL_NAMES:
        assert tools[tool_name].description
        assert isinstance(tools[tool_name].inputSchema, dict)


async def test_check_posture_returns_valid_structure(tmp_path: Path) -> None:
    _seed_evidence(tmp_path)

    async with _client_session(tmp_path) as session:
        structured = _structured(await session.call_tool("ancilis_check_posture"))

    assert 0.0 <= structured["posture_score"] <= 1.0
    assert structured["session_id"] == "integration-session"
    assert isinstance(structured["active_overlays"], list)
    controls = structured["controls"]
    assert isinstance(controls, list)
    assert controls
    for control in controls:
        assert {"id", "status", "name"}.issubset(control)


async def test_evaluate_action_allowed(tmp_path: Path) -> None:
    async with _client_session(tmp_path) as session:
        structured = _structured(
            await session.call_tool(
                "ancilis_evaluate_action",
                {
                    "tool_name": "safe_read",
                    "parameters": {"path": "README.md"},
                    "description": "Read project documentation",
                },
            )
        )

    assert structured["verdict"] == "allowed"
    assert structured["tool_name"] == "safe_read"


async def test_evaluate_action_blocked(tmp_path: Path) -> None:
    async with _client_session(tmp_path) as session:
        structured = _structured(
            await session.call_tool(
                "ancilis_evaluate_action",
                {
                    "tool_name": "dangerous_delete",
                    "parameters": {"path": "/etc/passwd"},
                    "description": "Delete a sensitive file",
                },
            )
        )

    assert structured["verdict"] == "blocked"
    assert any(item["result"] == "fail" for item in structured["evaluations"])


async def test_evaluate_action_does_not_persist(tmp_path: Path) -> None:
    async with _client_session(tmp_path) as session:
        structured = _structured(
            await session.call_tool(
                "ancilis_evaluate_action",
                {
                    "tool_name": "safe_read",
                    "parameters": {"path": "README.md"},
                    "description": "Read project documentation",
                },
            )
        )
        evidence = _structured(await session.call_tool("ancilis_get_evidence"))

    assert structured["verdict"] == "allowed"
    assert evidence["evidence"] == []
    assert evidence["total_count"] == 0


async def test_get_evidence_empty_session(tmp_path: Path) -> None:
    async with _client_session(tmp_path) as session:
        structured = _structured(await session.call_tool("ancilis_get_evidence"))

    assert structured == {
        "evidence": [],
        "total_count": 0,
        "returned_count": 0,
        "session_id": None,
    }


async def test_get_evidence_with_control_filter(tmp_path: Path) -> None:
    _seed_evidence(tmp_path)

    async with _client_session(tmp_path) as session:
        structured = _structured(
            await session.call_tool(
                "ancilis_get_evidence",
                {"control_id": "PR-01"},
            )
        )

    assert structured["session_id"] == "integration-session"
    assert structured["evidence"]
    assert all(item["control_id"] == "PR-01" for item in structured["evidence"])


async def test_report_generates_markdown(tmp_path: Path) -> None:
    _seed_evidence(tmp_path)

    async with _client_session(tmp_path) as session:
        structured = _structured(await session.call_tool("ancilis_report"))

    assert structured["format"] == "markdown"
    assert structured["session_id"] == "integration-session"
    assert "# Ancilis Posture Report" in structured["report"]


async def test_list_overlays_returns_coverage(tmp_path: Path) -> None:
    _seed_evidence(tmp_path)

    async with _client_session(tmp_path) as session:
        structured = _structured(await session.call_tool("ancilis_list_overlays"))

    assert isinstance(structured["overlays"], list)
    assert structured["overlays"]
    for overlay in structured["overlays"]:
        assert {"name", "controls_total", "coverage_pct"}.issubset(overlay)
        assert 0.0 <= overlay["coverage_pct"] <= 100.0
