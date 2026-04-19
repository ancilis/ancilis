"""FastMCP server factory for Ancilis self-inspection tools."""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore


@dataclass(frozen=True)
class MCPServerContext:
    config: ResolvedConfig
    engine: Engine
    evidence_store: EvidenceStore


def _not_implemented(_context: MCPServerContext) -> dict[str, str]:
    return {"status": "not_implemented"}


def create_mcp_server(config_path: str | None = None) -> FastMCP:
    """Create an Ancilis MCP server with placeholder tool registrations."""
    config = load_config(path=config_path) if config_path is not None else load_config()
    evidence_store = EvidenceStore(config)
    engine = Engine(config, evidence_store=evidence_store)
    context = MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=evidence_store,
    )

    server = FastMCP(name="ancilis")

    @server.tool(name="ancilis_check_posture")
    def ancilis_check_posture() -> dict[str, str]:
        return _not_implemented(context)

    @server.tool(name="ancilis_evaluate_action")
    def ancilis_evaluate_action() -> dict[str, str]:
        return _not_implemented(context)

    @server.tool(name="ancilis_get_evidence")
    def ancilis_get_evidence() -> dict[str, str]:
        return _not_implemented(context)

    @server.tool(name="ancilis_report")
    def ancilis_report() -> dict[str, str]:
        return _not_implemented(context)

    @server.tool(name="ancilis_list_overlays")
    def ancilis_list_overlays() -> dict[str, str]:
        return _not_implemented(context)

    return server
