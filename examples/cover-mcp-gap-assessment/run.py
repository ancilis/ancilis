"""Run a deterministic demo of the Ancilis Cover MCP gap assessment tool."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.mcp_server import MCPServerContext
from ancilis.mcp_server.cover.server import create_cover_mcp_server
from ancilis.producers.tool import ToolActionProducer


def _demo_context() -> MCPServerContext:
    config = load_config(
        raw={
            "agent": {"name": "cover-gap-demo"},
            "security": {"mode": "audit"},
        }
    )
    evidence_store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, evidence_store=evidence_store)
    return MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=evidence_store,
        action_producer=ToolActionProducer(
            config,
            engine,
            registry=engine.registry,
            evidence_store=evidence_store,
        ),
    )


async def _call_tool(
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    server = create_cover_mcp_server(context=_demo_context())
    tools = await server.list_tools()
    tool_names = sorted(tool.name for tool in tools)

    print("Ancilis Cover MCP demo")
    print(f"server: {server.name}")
    print(f"tools: {len(tool_names)} registered")
    print(f"contains {tool_name}: {tool_name in tool_names}")
    print()

    _content, structured = cast(
        tuple[list[Any], dict[str, Any]],
        await server.call_tool(tool_name, arguments),
    )
    return structured


async def main() -> None:
    sample_project = Path(__file__).parent / "sample_project"
    result = await _call_tool(
        "ancilis_assess_gap",
        {
            "root": str(sample_project),
            "business_context": "We handle patient records and need HIPAA readiness.",
        },
    )

    summary = {
        "mode": result["mode"],
        "confidence": result["confidence"],
        "target": result["target"],
        "config_gap": result["config_gap"],
        "missing_producers": result["instrumentation_gap"]["missing_producers"],
        "evidence_gap": {
            "session_id": result["evidence_gap"]["session_id"],
            "requested_overlays": result["evidence_gap"]["requested_overlays"],
            "controls_total": result["evidence_gap"]["controls_total"],
            "controls_with_evidence": result["evidence_gap"]["controls_with_evidence"],
        },
        "next_steps": result["next_steps"],
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
