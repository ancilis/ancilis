"""Financial demo agent showing Ancilis runtime enforcement and evidence capture."""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

logging.getLogger("ancilis.middleware").setLevel(logging.CRITICAL)

from ancilis.cli.status import _format_status
from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError
from ancilis.engine.registry import ToolEntry, ToolStatus
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_markdown

DEFAULT_CONFIG_PATH = Path(__file__).with_name("ancilis.yaml")
BANNER = "Ancilis Demo - Financial AI Agent with Runtime Controls"


@dataclass
class MockTextContent:
    type: str = "text"
    text: str = ""


@dataclass
class MockCallToolResult:
    content: list[Any] = field(default_factory=list)
    isError: bool = False  # noqa: N815
    structuredContent: Any = None  # noqa: N815
    meta: Any = None


@dataclass
class MockTool:
    name: str = ""
    description: str = ""
    inputSchema: dict[str, Any] = field(default_factory=dict)  # noqa: N815


@dataclass
class MockListToolsResult:
    tools: list[MockTool] = field(default_factory=list)


@dataclass(frozen=True)
class DemoRunResult:
    db_path: Path
    status_output: str
    report_markdown: str
    decisions: dict[str, int]


class MockMCPSession:
    """Simulates an MCP session with a fixed financial tool catalog."""

    def __init__(self) -> None:
        self._tools = [
            MockTool(name="check_balance", description="Retrieve the current account balance"),
            MockTool(name="get_transactions", description="Retrieve recent account transactions"),
            MockTool(name="transfer_funds", description="Transfer funds to another account"),
            MockTool(name="export_customer_list", description="Export all customer account records"),
            MockTool(name="drop_audit_log", description="Delete the audit evidence log"),
            MockTool(name="lookup_credit_score", description="Retrieve a customer credit score"),
        ]

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> MockCallToolResult:
        del arguments
        responses = {
            "check_balance": "Account holder: Jane Smith, Account: ****4521, Balance: $12,450.00",
            "get_transactions": "2026-03-15: $89.99 at TechMart, Card ending 4521",
            "transfer_funds": "Transfer of $500.00 to external account completed. Ref: TXN-2026-0415",
            "export_customer_list": "Export completed for 4,200 customers.",
            "drop_audit_log": "Audit log deleted.",
            "lookup_credit_score": "Credit score: 742 (Excellent). Report date: 2026-04-01. SSN on file: ***-**-6789",
        }
        return MockCallToolResult(content=[MockTextContent(text=responses.get(name, "OK"))])

    async def list_tools(self) -> MockListToolsResult:
        return MockListToolsResult(tools=list(self._tools))


def _print(stream: TextIO, line: str = "") -> None:
    print(line, file=stream)


def _resolve_demo_db_path(
    config: Any,
    db_path: str | Path | None,
    fresh: bool = False,
) -> str | Path | None:
    if db_path is not None:
        resolved_db_path = db_path
    elif fresh:
        agent_name = getattr(config, "agent_name", "") or "default"
        resolved_db_path = _agent_db_path(agent_name)
    else:
        return None

    target_db_path = Path(resolved_db_path)
    if fresh and target_db_path.parent.is_dir():
        # Remove all DuckDB artifacts (WAL, WAL-index, tmp) to ensure a clean slate
        for artifact in target_db_path.parent.glob(f"{target_db_path.name}*"):
            artifact.unlink(missing_ok=True)
        if target_db_path.exists():
            target_db_path.unlink()
    return resolved_db_path


def _mark_blocked_tools(middleware: AncilisMiddleware) -> None:
    for tool_name in middleware.config.tools_blocked:
        entry = middleware.registry.lookup(tool_name)
        if entry is None:
            middleware.registry.register(ToolEntry(name=tool_name, status=ToolStatus.BLOCKED))
            continue
        entry.status = ToolStatus.BLOCKED


async def _call_allowed(
    middleware: AncilisMiddleware,
    name: str,
    arguments: dict[str, Any],
    stream: TextIO,
    note: str | None = None,
) -> None:
    result = await middleware.call_tool(name, arguments)
    evaluation = middleware.get_last_evaluation()
    decision = evaluation.decision.upper() if evaluation is not None else "ALLOW"
    text = result.content[0].text if result.content else ""
    _print(stream, f"[{decision}] {name} -> {text}")
    if note:
        _print(stream, f"  Note: {note}")


async def _call_blocked(
    middleware: AncilisMiddleware,
    name: str,
    arguments: dict[str, Any],
    stream: TextIO,
) -> None:
    try:
        await middleware.call_tool(name, arguments)
    except BlockedToolCallError as exc:
        message = exc.display_message.splitlines()[0]
        _print(stream, f"[{exc.evaluation.decision.upper()}] {name} -> {message}")


async def _run_demo(
    config_path: Path,
    db_path: str | Path | None,
    stream: TextIO,
    fresh: bool = True,
) -> DemoRunResult:
    config = load_config(path=config_path)
    resolved_db_path = _resolve_demo_db_path(config, db_path, fresh=fresh)
    session = MockMCPSession()
    middleware = AncilisMiddleware(
        session,
        config=config,
        evidence_store=EvidenceStore(config, db_path=resolved_db_path, in_memory=False),
    )

    try:
        _print(stream, BANNER)
        _print(stream)
        await middleware.list_tools()
        _mark_blocked_tools(middleware)

        _print(stream, "Tool Registry")
        for tool in session._tools:
            entry = middleware.registry.lookup(tool.name)
            status = entry.status if entry is not None else ToolStatus.OBSERVED
            _print(stream, f"  - {tool.name}: {status.name}")

        _print(stream)
        await _call_allowed(middleware, "check_balance", {"account_id": "CHK-4521"}, stream)
        await _call_allowed(middleware, "get_transactions", {"account_id": "CHK-4521"}, stream)
        await _call_allowed(
            middleware,
            "transfer_funds",
            {"from_account": "CHK-4521", "to_account": "EXT-9090", "amount": 500.0},
            stream,
            note="Exposure control evaluated for outbound financial movement.",
        )
        await _call_blocked(middleware, "export_customer_list", {"segment": "all_customers"}, stream)
        await _call_blocked(middleware, "drop_audit_log", {"scope": "all"}, stream)
        await _call_allowed(
            middleware,
            "lookup_credit_score",
            {"customer_id": "CUS-1001"},
            stream,
            note="GLBA overlay active for financial records handling.",
        )

        _print(stream)
        summary_line = middleware.get_summary_line()
        _print(stream, summary_line)

        status_output = _format_status(config, middleware.evidence_store, verbose=True)
        _print(stream)
        _print(stream, "=== ancilis status --verbose ===")
        _print(stream, status_output)

        report_markdown = render_markdown(
            ReportGenerator(config, middleware.evidence_store).generate(
                period="30d",
                report_format="markdown",
            )
        )

        decisions = middleware.evidence_store.get_summary()["decisions"]
        _print(stream)
        _print(stream, f"Evidence stored at: {middleware.evidence_store.db_path}")
        _print(
            stream,
            "Run the full SDK-to-Platform walkthrough from the repo root: bash examples/demo/run-all.sh",
        )

        return DemoRunResult(
            db_path=Path(middleware.evidence_store.db_path),
            status_output=status_output,
            report_markdown=report_markdown,
            decisions=decisions,
        )
    finally:
        middleware.close()


def main(
    config_path: str | Path | None = None,
    db_path: str | Path | None = None,
    stream: TextIO | None = None,
    fresh: bool = True,
) -> DemoRunResult:
    """Run the financial middleware demo and return its generated artifacts."""
    target_stream = stream or sys.stdout
    target_config = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
    return asyncio.run(_run_demo(target_config, db_path, target_stream, fresh=fresh))


if __name__ == "__main__":
    main(fresh=True)
