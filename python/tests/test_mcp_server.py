"""Tests for Ancilis MCP server mode."""

from __future__ import annotations

import asyncio
from pathlib import Path

from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.mcp_server import create_mcp_server


EXPECTED_TOOL_NAMES = {
    "ancilis_check_posture",
    "ancilis_evaluate_action",
    "ancilis_get_evidence",
    "ancilis_report",
    "ancilis_list_overlays",
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


def test_create_mcp_server_registers_placeholder_tools(tmp_path: Path) -> None:
    server = create_mcp_server(config_path=str(_write_config(tmp_path)))

    assert server.name == "ancilis"
    tools = asyncio.run(server.list_tools())
    tool_names = {tool.name for tool in tools}
    assert EXPECTED_TOOL_NAMES.issubset(tool_names)

    _content, structured = asyncio.run(server.call_tool("ancilis_check_posture", {}))
    assert structured == {"status": "not_implemented"}


def test_serve_help_shows_transport_options() -> None:
    result = CliRunner().invoke(cli, ["serve", "--help"])

    assert result.exit_code == 0
    assert "--config" in result.output
    assert "--transport" in result.output
    assert "--port" in result.output


def test_serve_stdio_runs_created_server(monkeypatch, tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    calls: dict[str, object] = {}

    class DummyServer:
        def run(self, *, transport: str) -> None:
            calls["transport"] = transport

    def fake_create_mcp_server(config_path: str | None = None):
        calls["config_path"] = config_path
        return DummyServer()

    monkeypatch.setattr("ancilis.cli.serve.create_mcp_server", fake_create_mcp_server)

    result = CliRunner().invoke(cli, ["serve", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert calls == {
        "config_path": str(config_path),
        "transport": "stdio",
    }
