"""MCP Middleware Example — intercept and enforce tool calls.

This example demonstrates Ancilis MCP middleware:
1. Wrapping an MCP client session with policy enforcement
2. Allowed tools passing through with evidence
3. Blocked tools intercepted in enforce mode
4. The same scenario in audit mode (logged but allowed)
5. Tool inventory with OBSERVED/APPROVED/BLOCKED states

Requires: pip install ancilis[mcp]
Run from this directory: python run.py
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import logging

# Suppress middleware logger for cleaner demo output
logging.getLogger("ancilis.middleware").setLevel(logging.CRITICAL)

from ancilis.config import load_config
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError
from ancilis.evidence.store import EvidenceStore
from ancilis.engine.registry import ToolStatus


# --- Mock MCP types (no real server needed) ---

@dataclass
class MockTextContent:
    type: str = "text"
    text: str = ""


@dataclass
class MockCallToolResult:
    content: list[Any] = field(default_factory=list)
    isError: bool = False
    structuredContent: Any = None
    meta: Any = None


@dataclass
class MockTool:
    name: str = ""
    description: str = ""
    inputSchema: dict[str, Any] = field(default_factory=dict)


@dataclass
class MockListToolsResult:
    tools: list[MockTool] = field(default_factory=list)


class MockMCPSession:
    """Simulates an MCP ClientSession."""

    def __init__(self) -> None:
        self._tools = [
            MockTool(name="get-status", description="Get system status"),
            MockTool(name="get-transactions", description="Retrieve transactions"),
            MockTool(name="send-email", description="Send an email"),
            MockTool(name="delete-database", description="Drop the database"),
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> MockCallToolResult:
        responses = {
            "get-status": "All systems operational.",
            "get-transactions": "Transaction #1: $42.00 at Merchant A",
            "send-email": "Email sent to user@example.com",
            "delete-database": "Database dropped.",
        }
        return MockCallToolResult(content=[MockTextContent(text=responses.get(name, "OK"))])

    async def list_tools(self) -> MockListToolsResult:
        return MockListToolsResult(tools=list(self._tools))


# --- Enforce mode demo ---

async def demo_enforce_mode() -> None:
    print("=== Enforce Mode ===")
    print("Config: get-status and get-transactions allowed, delete-database blocked\n")

    config = load_config(path=Path(__file__).parent / "ancilis.yaml")
    session = MockMCPSession()
    evidence = EvidenceStore(config, in_memory=True)
    mw = AncilisMiddleware(session, config=config, evidence_store=evidence)  # type: ignore[arg-type]

    # Discover tools from the server
    await mw.list_tools()
    print(f"Discovered {len(session._tools)} tools from MCP server")

    # Show tool registry
    print("\nTool registry:")
    for entry in mw.registry.get_all():
        print(f"  {entry.name}: {entry.status.value}")

    # 1. Allowed tool
    print("\n1. Calling 'get-status' (allowed)...")
    result = await mw.call_tool("get-status", {"subsystem": "all"})
    print(f"   Result: {result.content[0].text}")
    ev = mw.get_last_evaluation()
    print(f"   Decision: {ev.decision}")

    # 2. Another allowed tool
    print("\n2. Calling 'get-transactions' (allowed)...")
    result = await mw.call_tool("get-transactions", {"customer": "C-001"})
    print(f"   Result: {result.content[0].text}")
    ev = mw.get_last_evaluation()
    print(f"   Decision: {ev.decision}")

    # 3. Unapproved tool (not in allowed list)
    print("\n3. Calling 'send-email' (not in allowed list, enforce mode)...")
    try:
        await mw.call_tool("send-email", {"to": "user@example.com"})
    except BlockedToolCallError as e:
        print(f"   BLOCKED: {e.display_message}")

    # 4. Explicitly blocked tool
    print("\n4. Calling 'delete-database' (explicitly blocked)...")
    try:
        await mw.call_tool("delete-database", {})
    except BlockedToolCallError as e:
        print(f"   BLOCKED: {e.display_message}")

    print(f"\n{mw.get_summary_line()}")
    evidence.close()
    mw.close()


# --- Audit mode demo ---

async def demo_audit_mode() -> None:
    print("\n=== Audit Mode ===")
    print("Same tools, same calls — but mode is audit (log everything, block nothing)\n")

    config = load_config(raw={
        "agent": {"name": "mcp-demo-agent"},
        "security": {
            "mode": "audit",
            "tools": {
                "allowed": ["get-status", "get-transactions"],
                "blocked": ["delete-database"],
            },
        },
    })
    session = MockMCPSession()
    evidence = EvidenceStore(config, in_memory=True)
    mw = AncilisMiddleware(session, config=config, evidence_store=evidence)  # type: ignore[arg-type]
    await mw.list_tools()

    # Same unapproved call — audit mode allows it through
    print("Calling 'send-email' (not in allowed list, audit mode)...")
    result = await mw.call_tool("send-email", {"to": "user@example.com"})
    print(f"  Result: {result.content[0].text}")
    ev = mw.get_last_evaluation()
    print(f"  Decision: {ev.decision}")
    print(f"  Mode: {ev.mode}")
    print(f"  Failures logged: {[r.control_id for r in ev.control_results if r.result == 'FAIL']}")

    # Same blocked call — audit mode allows it through
    print("\nCalling 'delete-database' (explicitly blocked, audit mode)...")
    result = await mw.call_tool("delete-database", {})
    print(f"  Result: {result.content[0].text}")
    ev = mw.get_last_evaluation()
    print(f"  Decision: {ev.decision}")
    print(f"  Failures logged: {[r.control_id for r in ev.control_results if r.result == 'FAIL']}")

    print(f"\n{mw.get_summary_line()}")
    evidence.close()
    mw.close()


async def main() -> None:
    await demo_enforce_mode()
    await demo_audit_mode()
    print("\nDone. Same policy, two modes. Enforce blocks. Audit logs.")


if __name__ == "__main__":
    asyncio.run(main())
