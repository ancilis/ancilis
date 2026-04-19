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


def _write_evaluate_config(tmp_path: Path, *, mode: str, allowed: list[str] | None = None, blocked: list[str] | None = None) -> Path:
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

    _content, structured = asyncio.run(
        server.call_tool(
            "ancilis_evaluate_action",
            {
                "tool_name": "dangerous_delete",
                "parameters": {"path": "/etc/passwd"},
                "description": "Delete a sensitive file",
            },
        )
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

    _content, structured = asyncio.run(
        server.call_tool(
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

    _content, structured = asyncio.run(
        server.call_tool(
            "ancilis_evaluate_action",
            {
                "tool_name": "mystery_tool",
                "parameters": {"query": "hello"},
            },
        )
    )

    assert structured["verdict"] == "warning"
    assert structured["tool_name"] == "mystery_tool"
    pr03 = next(item for item in structured["evaluations"] if item["control"] == "PR-03")
    assert pr03["result"] == "fail"
    assert structured["recommendation"] == "Proceed with caution"


def test_evaluate_action_does_not_persist_synthetic_action(monkeypatch, tmp_path: Path) -> None:
    stores: list[FakeEvidenceStore] = []

    class FakeEvidenceStore:
        def __init__(self, config):
            self.config = config
            self.store_calls = 0
            stores.append(self)

        def count(self) -> int:
            return 0

        def verify_chain(self) -> tuple[bool, list[str]]:
            return True, []

        def store(self, *args, **kwargs):
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

    _content, structured = asyncio.run(
        server.call_tool(
            "ancilis_evaluate_action",
            {
                "tool_name": "safe_read",
                "parameters": {"path": "README.md"},
            },
        )
    )

    assert structured["verdict"] == "allowed"
    assert stores
    assert stores[0].store_calls == 0
