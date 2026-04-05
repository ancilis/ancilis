"""Financial demo agent showing Ancilis runtime enforcement and evidence capture."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from ancilis.cli.status import _format_status
from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError
from ancilis.engine.registry import ToolEntry, ToolStatus
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_markdown

logging.getLogger("ancilis.middleware").setLevel(logging.CRITICAL)

DEFAULT_CONFIG_PATH = Path(__file__).with_name("ancilis.yaml")
BANNER = "Ancilis Demo - Financial AI Agent with Runtime Controls"
FRAME_WIDTH = 62
ANSI_PATTERN = re.compile(r"\033\[[0-9;]*m")


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


@dataclass(frozen=True)
class DemoCallRecord:
    decision: str
    name: str
    text: str
    note: str | None = None


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
            "check_balance": "Balance: $12,450.00 (Jane Smith, ****4521)",
            "get_transactions": "2026-03-15: $89.99 at TechMart",
            "transfer_funds": "$500.00 to EXT-9090 (Ref: TXN-2026-0415)",
            "export_customer_list": "Export completed for 4,200 customers.",
            "drop_audit_log": "Audit log deleted.",
            "lookup_credit_score": "Score: 742 (SSN on file: ***-**-6789)",
        }
        return MockCallToolResult(content=[MockTextContent(text=responses.get(name, "OK"))])

    async def list_tools(self) -> MockListToolsResult:
        return MockListToolsResult(tools=list(self._tools))


def _print(stream: TextIO, line: str = "") -> None:
    print(line, file=stream)


def _use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def _style(text: str, enabled: bool, *, color: str | None = None, bold: bool = False) -> str:
    if not enabled:
        return text

    codes: list[str] = []
    if bold:
        codes.append("1")
    if color == "green":
        codes.append("32")
    elif color == "red":
        codes.append("31")
    elif color == "yellow":
        codes.append("33")

    if not codes:
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def _strip_ansi(text: str) -> str:
    return ANSI_PATTERN.sub("", text)


def _pad_visible(text: str, width: int) -> str:
    visible = len(_strip_ansi(text))
    if visible >= width:
        return text
    return f"{text}{' ' * (width - visible)}"


def _banner_line(text: str) -> str:
    return f"║{text.center(FRAME_WIDTH)}║"


def _section_line(title: str) -> str:
    return f"├─ {title} " + ("─" * max(0, FRAME_WIDTH - len(title) - 4))


def _tool_registry_row(name: str, status: ToolStatus, color_enabled: bool) -> str:
    if status == ToolStatus.APPROVED:
        symbol = _style("✓", color_enabled, color="green", bold=True)
        label = _style("APPROVED", color_enabled, color="green", bold=True)
    elif status == ToolStatus.BLOCKED:
        symbol = _style("✗", color_enabled, color="red", bold=True)
        label = _style("BLOCKED", color_enabled, color="red", bold=True)
    else:
        symbol = _style("✗", color_enabled, color="red", bold=True)
        label = _style("UNAPPROVED", color_enabled, color="red", bold=True)

    return f"│  {symbol} {_pad_visible(name, 22)} {label}"


def _tool_call_row(record: DemoCallRecord, color_enabled: bool) -> str:
    color = "green" if record.decision == "ALLOW" else "red"
    decision = _style(f"[{record.decision}]", color_enabled, color=color, bold=True)
    return f"│  {decision} {_pad_visible(record.name, 20)} -> {record.text}"


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
    note: str | None = None,
) -> DemoCallRecord:
    result = await middleware.call_tool(name, arguments)
    evaluation = middleware.get_last_evaluation()
    decision = evaluation.decision.upper() if evaluation is not None else "ALLOW"
    text = result.content[0].text if result.content else ""
    return DemoCallRecord(decision=decision, name=name, text=text, note=note)


async def _call_blocked(
    middleware: AncilisMiddleware,
    name: str,
    arguments: dict[str, Any],
) -> DemoCallRecord:
    try:
        await middleware.call_tool(name, arguments)
    except BlockedToolCallError as exc:
        custom_messages = {
            "export_customer_list": "Blocked: not in security.tools.allowed",
            "drop_audit_log": "Blocked: explicitly in security.tools.blocked",
        }
        return DemoCallRecord(
            decision=exc.evaluation.decision.upper(),
            name=name,
            text=custom_messages.get(name, exc.display_message.splitlines()[0]),
        )
    raise AssertionError(f"Expected {name} to be blocked in the demo")


async def _run_demo(
    config_path: Path,
    db_path: str | Path | None,
    stream: TextIO,
    fresh: bool = True,
) -> DemoRunResult:
    config = load_config(path=config_path)
    resolved_db_path = _resolve_demo_db_path(config, db_path, fresh=fresh)
    color_enabled = _use_color(stream)
    session = MockMCPSession()
    middleware = AncilisMiddleware(
        session,
        config=config,
        evidence_store=EvidenceStore(config, db_path=resolved_db_path, in_memory=False),
    )

    try:
        _print(stream, f"╔{'═' * FRAME_WIDTH}╗")
        _print(stream, _banner_line(BANNER))
        _print(stream, _banner_line("Runtime Controls · Evidence Chain · Compliance"))
        _print(stream, f"╚{'═' * FRAME_WIDTH}╝")
        _print(stream)
        await middleware.list_tools()
        _mark_blocked_tools(middleware)

        data_handles = ", ".join(config.data_classifications.keys())
        _print(stream, f"Agent: {config.agent_name}")
        _print(stream, f"Mode:  {config.mode}")
        _print(stream, f"Data:  {data_handles}")
        _print(stream)
        _print(stream, _section_line("Tool Registry"))
        for tool in session._tools:
            entry = middleware.registry.lookup(tool.name)
            status = entry.status if entry is not None else ToolStatus.OBSERVED
            _print(stream, _tool_registry_row(tool.name, status, color_enabled))

        _print(stream)
        _print(stream, _section_line("Tool Calls"))
        call_records = [
            await _call_allowed(middleware, "check_balance", {"account_id": "CHK-4521"}),
            await _call_allowed(middleware, "get_transactions", {"account_id": "CHK-4521"}),
            await _call_allowed(
                middleware,
                "transfer_funds",
                {"from_account": "CHK-4521", "to_account": "EXT-9090", "amount": 500.0},
                note="Exposure control: outbound financial movement",
            ),
            await _call_blocked(middleware, "export_customer_list", {"segment": "all_customers"}),
            await _call_blocked(middleware, "drop_audit_log", {"scope": "all"}),
            await _call_allowed(
                middleware,
                "lookup_credit_score",
                {"customer_id": "CUS-1001"},
                note="GLBA overlay active: financial records handling",
            ),
        ]
        for record in call_records:
            _print(stream, _tool_call_row(record, color_enabled))
            if record.note:
                _print(stream, f"│    └─ {record.note}")

        session_summary = middleware.evidence_store.get_summary(session_id=middleware.session_id)
        decisions = session_summary["decisions"]
        overlay_names = ", ".join(
            activation.name for _oid, activation in sorted(config.active_overlays.items())
        )
        cert_status = ", ".join(cert.upper() for cert in config.active_certifications) or "none"

        _print(stream)
        _print(stream, _section_line("Summary"))
        _print(
            stream,
            f"│  Evaluated: {session_summary['total_evaluations']} tool calls | "
            f"Allowed: {decisions.get('ALLOW', 0)} | Blocked: {decisions.get('BLOCK', 0)}",
        )
        _print(stream, f"│  Overlays:  {len(config.active_overlays)} active ({overlay_names})")
        _print(
            stream,
            f"│  Evidence:  {session_summary['total_evaluations']} records -> DuckDB (SHA-256 hash chain)",
        )
        _print(stream, f"│  Cert:      {cert_status} readiness tracking active")
        _print(stream, f"╰{'─' * FRAME_WIDTH}")

        status_output = _format_status(
            config,
            middleware.evidence_store,
            verbose=True,
            session_id=middleware.session_id,
        )

        report_markdown = render_markdown(
            ReportGenerator(config, middleware.evidence_store).generate(
                period="30d",
                report_format="markdown",
                session_id=middleware.session_id,
            )
        )

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
