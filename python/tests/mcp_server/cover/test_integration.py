"""End-to-end MCP client tests for Ancilis Cover stdio server."""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "python" / "src"


@asynccontextmanager
async def _client_session(tmp_path: Path) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(SRC)
        if not existing_pythonpath
        else f"{SRC}{os.pathsep}{existing_pythonpath}"
    )
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ancilis.mcp_server.cover.server"],
        cwd=tmp_path,
        env=env,
    )
    async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


def _structured(result: CallToolResult) -> dict[str, Any]:
    assert result.isError is not True
    assert isinstance(result.structuredContent, dict)
    return result.structuredContent


async def test_cover_stdio_server_lists_and_calls_tools(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = ['langchain', 'openai']\n",
        encoding="utf-8",
    )

    async with _client_session(tmp_path) as session:
        tools = await session.list_tools()
        tool_names = {tool.name for tool in tools.tools}
        result = await session.call_tool(
            "ancilis_inspect_project",
            {"root": str(tmp_path)},
        )
        gap_result = await session.call_tool(
            "ancilis_assess_gap",
            {
                "root": str(tmp_path),
                "business_context": "Customer agent handles email and needs SOC 2.",
            },
        )

    assert "ancilis_inspect_project" in tool_names
    assert "ancilis_onboarding_report" in tool_names
    assert "ancilis_check_posture" in tool_names
    assert "ancilis_assess_gap" in tool_names
    structured = _structured(result)
    assert "python" in structured["languages"]
    assert "langchain" in structured["frameworks"]
    gap = _structured(gap_result)
    assert gap["target"]["my_agent_handles"] == ["personal_info"]
    assert gap["target"]["active_overlays"] == ["soc2"]
