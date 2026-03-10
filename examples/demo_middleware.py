"""
Ancilis SDK — Middleware Demo

Demonstrates:
1. Middleware wrapping an MCP client session
2. Tool call interception and evaluation
3. Blocked unauthorized tool call (enforce mode)
4. Pattern detection on response data
5. Classification recommendations

Run: python examples/demo_middleware.py
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ancilis.config import load_config
from ancilis.engine.registry import ToolEntry
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError

console = Console()


# --- Mock MCP Session (no real server needed) ---


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
    """Simulates an MCP ClientSession for demo purposes."""

    def __init__(self) -> None:
        self._tools = [
            MockTool(name="patient-lookup", description="Look up patient records by ID"),
            MockTool(name="send-email", description="Send an email notification"),
            MockTool(name="get-status", description="Get system status"),
        ]
        self._responses: dict[str, str] = {
            "patient-lookup": (
                "Patient Record Found:\n"
                "  Name: Jane Doe\n"
                "  MRN: MRN-00847291\n"
                "  SSN: 000-00-1234\n"
                "  DOB: 1985-03-15\n"
                "  Diagnosis: Routine checkup\n"
                "  Insurance: BlueCross PPO"
            ),
            "send-email": "Email sent successfully to recipient.",
            "get-status": (
                "System Status: All services operational.\n"
                "Auth Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeXN0ZW0ifQ."
                "dBjftJeZ4CVP_mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            ),
        }

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> MockCallToolResult:
        text = self._responses.get(name, f"Tool '{name}' executed successfully.")
        return MockCallToolResult(content=[MockTextContent(text=text)])

    async def list_tools(self) -> MockListToolsResult:
        return MockListToolsResult(tools=list(self._tools))


# --- Demo Functions ---


def print_header() -> None:
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Ancilis SDK — Middleware Demo[/bold cyan]\n"
        "[dim]Runtime policy enforcement for AI agent tool calls[/dim]",
        border_style="cyan",
    ))
    console.print()


def print_evaluation(mw: AncilisMiddleware, tool_name: str, blocked: bool = False) -> None:
    ev = mw.get_last_evaluation()
    if not ev:
        return

    status = "[bold red]BLOCKED[/bold red]" if blocked else "[bold green]ALLOWED[/bold green]"
    mode_label = f"[yellow]{ev.mode}[/yellow]"

    console.print(f"  Tool: [bold]{tool_name}[/bold]  |  Decision: {status}  |  Mode: {mode_label}")

    table = Table(show_header=True, header_style="bold", padding=(0, 1), show_edge=False)
    table.add_column("Control", style="cyan", width=8)
    table.add_column("Name", width=36)
    table.add_column("Result", width=8)
    table.add_column("Detail", max_width=50)

    for cr in ev.control_results:
        result_style = {
            "PASS": "[green]PASS[/green]",
            "FAIL": "[red]FAIL[/red]",
            "SKIP": "[dim]SKIP[/dim]",
            "ERROR": "[red]ERROR[/red]",
        }.get(cr.result, cr.result)

        table.add_row(cr.control_id, cr.control_name, result_style, cr.detail[:50])

    console.print(table)
    console.print()


async def demo_scenario_1(mw: AncilisMiddleware) -> None:
    """Scenario 1: Authorized tool call — all controls pass."""
    console.print(Panel("[bold]Scenario 1:[/bold] Authorized tool call to registered tool", border_style="green"))
    console.print("  Agent calls [bold]get-status[/bold] — a registered, authorized tool.\n")

    await mw.call_tool("get-status", {"subsystem": "all"})
    print_evaluation(mw, "get-status")


async def demo_scenario_2(mw_enforce: AncilisMiddleware) -> None:
    """Scenario 2: Unauthorized tool blocked in enforce mode."""
    console.print(Panel("[bold]Scenario 2:[/bold] Unregistered tool call in ENFORCE mode", border_style="red"))
    console.print("  Agent calls [bold]malicious-exfil[/bold] — not in the tool registry.\n")

    try:
        await mw_enforce.call_tool("malicious-exfil", {"target": "external-server"})
    except BlockedToolCallError:
        pass

    print_evaluation(mw_enforce, "malicious-exfil", blocked=True)


async def demo_scenario_3(mw: AncilisMiddleware) -> None:
    """Scenario 3: Response contains sensitive data — patterns detected."""
    console.print(Panel("[bold]Scenario 3:[/bold] Response scanning detects sensitive data", border_style="yellow"))
    console.print("  Agent calls [bold]patient-lookup[/bold] — response contains SSN and MRN patterns.\n")

    await mw.call_tool("patient-lookup", {"patient_id": "P-12345"})
    print_evaluation(mw, "patient-lookup")

    recs = mw.get_recommendations()
    if recs:
        console.print("  [bold yellow]Classification Recommendations:[/bold yellow]")
        for rec in recs:
            console.print(f"    [yellow]![/yellow] {rec}")
        console.print()


async def demo_scenario_4(mw: AncilisMiddleware) -> None:
    """Scenario 4: Encrypted data detected — positive security finding."""
    console.print(Panel("[bold]Scenario 4:[/bold] Encrypted data detection (positive finding)", border_style="blue"))
    console.print("  Agent calls [bold]get-status[/bold] — response contains a JWT token.\n")

    await mw.call_tool("get-status", {})

    if mw.scan_results:
        for scan in mw.scan_results:
            for finding in scan.encryption_findings:
                console.print(f"  [bold blue]Positive Finding:[/bold blue] {finding.detail}")
    console.print()


async def main() -> None:
    print_header()

    # Create mock MCP session
    session = MockMCPSession()

    # --- Setup: Audit mode middleware ---
    config_audit = load_config(raw={
        "agent": {"name": "claims-processor", "owner": "ops-team"},
        "security": {"mode": "audit"},
        "data_handling": ["health_records", "personal_info"],
    })
    mw_audit = AncilisMiddleware(session, config=config_audit)  # type: ignore[arg-type]

    # Auto-discover tools
    await mw_audit.list_tools()
    console.print(f"  [dim]Auto-discovered {len(session._tools)} tools from MCP server[/dim]\n")

    # --- Setup: Enforce mode middleware (separate instance) ---
    config_enforce = load_config(raw={
        "agent": {"name": "claims-processor", "owner": "ops-team"},
        "security": {"mode": "enforce"},
    })
    mw_enforce = AncilisMiddleware(session, config=config_enforce)  # type: ignore[arg-type]
    await mw_enforce.list_tools()

    # --- Run Scenarios ---
    await demo_scenario_1(mw_audit)
    await demo_scenario_2(mw_enforce)
    await demo_scenario_3(mw_audit)
    await demo_scenario_4(mw_audit)

    # --- Summary ---
    console.print(Panel.fit(
        f"[bold]Demo Complete[/bold]\n"
        f"  Evaluations logged: {len(mw_audit.evaluation_log) + len(mw_enforce.evaluation_log)}\n"
        f"  Recommendations: {len(mw_audit.get_recommendations())}\n"
        f"  Tools discovered: {len(session._tools)}",
        border_style="cyan",
    ))


if __name__ == "__main__":
    asyncio.run(main())
