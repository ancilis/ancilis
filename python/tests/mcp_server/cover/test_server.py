"""Tests for Ancilis Cover FastMCP server wiring."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

import ancilis.mcp_server.cover as cover_pkg
from ancilis.mcp_server.cover.server import create_cover_mcp_server


EXPECTED_TOOL_NAMES = {
    "ancilis_inspect_project",
    "ancilis_classify_project",
    "ancilis_recommend_setup",
    "ancilis_review_code",
    "ancilis_onboarding_report",
}


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


def test_create_cover_mcp_server_registers_tools() -> None:
    server = create_cover_mcp_server()

    assert server.name == "ancilis-cover"
    tools = asyncio.run(server.list_tools())
    tool_names = {tool.name for tool in tools}
    assert EXPECTED_TOOL_NAMES.issubset(tool_names)


def test_cover_package_exposes_main() -> None:
    assert callable(cover_pkg.main)


def test_cover_tools_return_structured_content(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = ['openai', 'stripe']\n",
        encoding="utf-8",
    )
    server = create_cover_mcp_server()

    inspection = _call_tool_structured(
        server,
        "ancilis_inspect_project",
        {"root": str(tmp_path)},
    )
    classification = _call_tool_structured(
        server,
        "ancilis_classify_project",
        {
            "root": str(tmp_path),
            "description": "Stripe checkout agent",
        },
    )
    setup = _call_tool_structured(
        server,
        "ancilis_recommend_setup",
        {
            "project": inspection,
            "classification": classification,
            "language": "python",
        },
    )
    review = _call_tool_structured(
        server,
        "ancilis_review_code",
        {
            "root": str(tmp_path),
            "snippets": [{"name": "agent.py", "text": "import subprocess\n"}],
        },
    )
    report = _call_tool_structured(
        server,
        "ancilis_onboarding_report",
        {
            "root": str(tmp_path),
            "description": "Stripe checkout agent",
        },
    )

    assert "openai" in inspection["frameworks"]
    assert "credit_cards" in classification["my_agent_handles"]
    assert "config_yaml" in setup
    assert review["findings"]
    assert "# Ancilis Cover Onboarding Report" in report["report_markdown"]
