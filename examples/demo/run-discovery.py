"""Seed a multi-agent discovery demo with hash-chained SDK evidence stores."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TextIO

import yaml

from ancilis.config import load_config
from ancilis.engine.registry import ToolEntry, ToolStatus
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError

logging.getLogger("ancilis.middleware").setLevel(logging.CRITICAL)

DEFAULT_OUTPUT_DIR = Path(__file__).with_name("discovery")
DISCOVERY_AGENT_ROOT = DEFAULT_OUTPUT_DIR / "agents"
DEFAULT_MANIFEST_PATH = DEFAULT_OUTPUT_DIR / "discovery-manifest.json"
BANNER = "Ancilis Discovery Demo - Seeded Agent Fleet"


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
class DemoCall:
    name: str
    arguments: dict[str, Any]
    note: str = ""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    response: str
    description: str


@dataclass(frozen=True)
class DiscoveryAgentScenario:
    name: str
    runtime_type: str
    tools: tuple[ToolSpec, ...]
    pre_discovery_calls: tuple[DemoCall, ...] = ()
    allowed_calls: tuple[DemoCall, ...] = ()
    blocked_calls: tuple[DemoCall, ...] = ()


@dataclass(frozen=True)
class DiscoveryAgent:
    name: str
    runtime_type: str
    config_path: str
    db_path: str
    tool_count: int
    data_types: list[str]
    evidence_summary: dict[str, int]
    description: str = ""
    classifications: list[str] = field(default_factory=list)
    active_overlays: list[str] = field(default_factory=list)
    active_certifications: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DiscoveryDemoResult:
    agents: list[DiscoveryAgent]
    manifest_path: str
    total_evidence_records: int


DISCOVERY_SCENARIOS: tuple[DiscoveryAgentScenario, ...] = (
    DiscoveryAgentScenario(
        name="payments-processor",
        runtime_type="bedrock",
        tools=(
            ToolSpec("process_payment", "Payment captured for INV-1042.", "Process a customer card payment."),
            ToolSpec("issue_refund", "Refund issued for charge CH-8821.", "Issue a partial or full refund."),
            ToolSpec("get_payment_status", "Payment CH-8821 settled successfully.", "Fetch settlement status."),
            ToolSpec("verify_card", "Card ending 4242 passed verification.", "Verify card token and AVS data."),
            ToolSpec("get_merchant_info", "Merchant account ACME-US is active.", "Fetch merchant profile details."),
            ToolSpec("generate_receipt", "Receipt emailed to customer@example.com.", "Generate a payment receipt."),
            ToolSpec("delete_transaction_log", "Transaction log deleted.", "Delete payment processing logs."),
        ),
        allowed_calls=(
            DemoCall("process_payment", {"invoice_id": "INV-1042", "amount": 189.55, "currency": "USD"}),
            DemoCall("verify_card", {"card_token": "tok_4242", "merchant_id": "mrc_001"}),
            DemoCall("get_payment_status", {"charge_id": "CH-8821"}),
            DemoCall("issue_refund", {"charge_id": "CH-8821", "amount": 40.00}),
            DemoCall("get_merchant_info", {"merchant_id": "mrc_001"}),
        ),
        blocked_calls=(
            DemoCall("delete_transaction_log", {"merchant_id": "mrc_001", "days": 30}),
        ),
    ),
    DiscoveryAgentScenario(
        name="fraud-sentinel",
        runtime_type="agentcore",
        tools=(
            ToolSpec("score_transaction", "Risk score 0.18, action: approve.", "Score a payment transaction for fraud."),
            ToolSpec("get_fraud_rules", "Loaded 24 active fraud rules.", "Fetch the active fraud rule set."),
            ToolSpec("flag_suspicious", "Transaction CH-8821 flagged for review.", "Escalate a suspicious payment."),
            ToolSpec("get_account_history", "Retrieved 12 months of account activity.", "Fetch historical account activity."),
            ToolSpec("verify_identity", "Identity verified for customer CUS-9001.", "Run identity verification."),
            ToolSpec("override_fraud_flag", "Fraud flag override saved.", "Override a fraud decision."),
            ToolSpec("bulk_export_scores", "Exported 150 score rows.", "Bulk export fraud scores."),
        ),
        allowed_calls=(
            DemoCall("score_transaction", {"charge_id": "CH-8821", "merchant_id": "mrc_001"}),
            DemoCall("get_fraud_rules", {"version": "current"}),
            DemoCall("flag_suspicious", {"charge_id": "CH-8821", "reason": "velocity_spike"}),
            DemoCall("verify_identity", {"customer_id": "CUS-9001"}),
        ),
        blocked_calls=(
            DemoCall("override_fraud_flag", {"charge_id": "CH-8821", "reason": "manual_override"}),
            DemoCall("bulk_export_scores", {"days": 7}),
        ),
    ),
    DiscoveryAgentScenario(
        name="compliance-auditor",
        runtime_type="openclaw",
        tools=(
            ToolSpec("check_aml_status", "AML screening clear for transfer TX-9102.", "Check AML screening state."),
            ToolSpec("run_kyc_verification", "KYC verification complete for customer CUS-9001.", "Run KYC verification."),
            ToolSpec("get_sanctions_list", "Loaded OFAC sanctions snapshot 2026-04-01.", "Fetch sanctions data."),
            ToolSpec("generate_sar_report", "SAR draft generated for case SAR-2204.", "Generate a suspicious activity report."),
            ToolSpec("check_transaction_limits", "Transaction amount is within policy limits.", "Validate configured transaction limits."),
            ToolSpec("modify_compliance_rules", "Compliance rules updated.", "Modify compliance policies."),
        ),
        allowed_calls=(
            DemoCall("check_aml_status", {"transaction_id": "TX-9102"}),
            DemoCall("run_kyc_verification", {"customer_id": "CUS-9001"}),
            DemoCall("get_sanctions_list", {"list": "ofac"}),
            DemoCall("generate_sar_report", {"case_id": "SAR-2204"}),
            DemoCall("check_transaction_limits", {"transaction_id": "TX-9102"}),
        ),
        blocked_calls=(
            DemoCall("modify_compliance_rules", {"rule_id": "aml-threshold", "value": "off"}),
        ),
    ),
    DiscoveryAgentScenario(
        name="invoice-extractor",
        runtime_type="mcp",
        tools=(
            ToolSpec("extract_invoice_data", "Extracted invoice INV-7781 with 5 line items.", "Extract fields from an invoice image."),
            ToolSpec("validate_line_items", "Validated 5 line items against the invoice schema.", "Validate invoice line items."),
            ToolSpec("match_purchase_order", "Matched invoice INV-7781 to PO-1007.", "Match invoice data to a purchase order."),
            ToolSpec("get_vendor_info", "Vendor ACME Supply is active and approved.", "Fetch vendor metadata."),
            ToolSpec("submit_for_approval", "Invoice INV-7781 submitted for approval.", "Send invoice for finance approval."),
            ToolSpec("delete_invoice", "Invoice INV-7781 deleted.", "Delete an invoice document."),
        ),
        pre_discovery_calls=(
            DemoCall(
                "extract_invoice_data",
                {"document_id": "DOC-7781"},
                "Pre-discovery approval baseline intentionally missing to surface a PR-03 flag.",
            ),
        ),
        allowed_calls=(
            DemoCall("extract_invoice_data", {"document_id": "DOC-7781"}),
            DemoCall("validate_line_items", {"invoice_id": "INV-7781"}),
            DemoCall("match_purchase_order", {"invoice_id": "INV-7781", "purchase_order_id": "PO-1007"}),
            DemoCall("get_vendor_info", {"vendor_id": "V-240"}),
            DemoCall("submit_for_approval", {"invoice_id": "INV-7781", "approver": "finops-team"}),
        ),
        blocked_calls=(
            DemoCall("delete_invoice", {"invoice_id": "INV-7781"}),
        ),
    ),
    DiscoveryAgentScenario(
        name="customer-assist",
        runtime_type="claude",
        tools=(
            ToolSpec("lookup_customer", "Customer Jane Smith located successfully.", "Look up a customer profile."),
            ToolSpec("check_balance", "Checking balance for account AC-1201 is $12,450.00.", "Check a payment account balance."),
            ToolSpec("get_transactions", "Retrieved 10 recent transactions for account AC-1201.", "Get recent account transactions."),
            ToolSpec("create_support_ticket", "Support ticket SUP-445 created.", "Open a payment support case."),
            ToolSpec("update_contact_info", "Customer contact information updated.", "Update customer contact details."),
            ToolSpec("lookup_credit_score", "Credit score 742 retrieved.", "Look up the customer credit score."),
            ToolSpec("transfer_funds", "Funds transferred successfully.", "Transfer funds between accounts."),
            ToolSpec("close_account", "Account AC-1201 closed.", "Close a payment account."),
        ),
        allowed_calls=(
            DemoCall("lookup_customer", {"customer_id": "CUS-1201"}),
            DemoCall("check_balance", {"account_id": "AC-1201"}),
            DemoCall("get_transactions", {"account_id": "AC-1201", "limit": 10}),
            DemoCall("create_support_ticket", {"customer_id": "CUS-1201", "topic": "statement_help"}),
            DemoCall("lookup_credit_score", {"customer_id": "CUS-1201"}),
        ),
        blocked_calls=(
            DemoCall("transfer_funds", {"from_account": "AC-1201", "to_account": "EXT-2002", "amount": 200.0}),
            DemoCall("close_account", {"account_id": "AC-1201"}),
        ),
    ),
)


class MockDiscoverySession:
    """Simulates an MCP session backed by a fixed discovery tool catalog."""

    def __init__(self, tools: tuple[ToolSpec, ...]) -> None:
        self._tool_map = {tool.name: tool for tool in tools}

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> MockCallToolResult:
        del arguments
        tool = self._tool_map.get(name)
        response_text = tool.response if tool is not None else "OK"
        return MockCallToolResult(content=[MockTextContent(text=response_text)])

    async def list_tools(self) -> MockListToolsResult:
        return MockListToolsResult(
            tools=[
                MockTool(name=tool.name, description=tool.description)
                for tool in self._tool_map.values()
            ]
        )


def _print(stream: TextIO, line: str = "") -> None:
    print(line, file=stream)


def _load_raw_config(config_path: Path) -> dict[str, Any]:
    return yaml.safe_load(config_path.read_text(encoding="utf-8"))


def _resolve_agent_db_path(agent_name: str, fresh: bool) -> Path:
    db_path = _agent_db_path(agent_name)
    if fresh and db_path.parent.is_dir():
        for artifact in db_path.parent.glob(f"{db_path.name}*"):
            artifact.unlink(missing_ok=True)
        if db_path.exists():
            db_path.unlink()
    return db_path


def _mark_blocked_tools(middleware: AncilisMiddleware) -> None:
    for tool_name in middleware.config.tools_blocked:
        entry = middleware.registry.lookup(tool_name)
        if entry is None:
            middleware.registry.register(ToolEntry(name=tool_name, status=ToolStatus.BLOCKED))
            continue
        entry.status = ToolStatus.BLOCKED


def _classifications(config: Any) -> list[str]:
    codes: list[str] = []
    for values in getattr(config, "data_classifications", {}).values():
        for value in values:
            if value not in codes:
                codes.append(value)
    return sorted(codes)


def _posture_summary(records: list[Any]) -> dict[str, int]:
    summary = {"allow": 0, "block": 0, "flag": 0}
    for record in records:
        results = {item["result"] for item in record.control_results}
        if {"FAIL", "ERROR"} & results:
            summary["block"] += 1
        elif "FLAG" in results:
            summary["flag"] += 1
        else:
            summary["allow"] += 1
    return summary


async def _call_allowed(
    middleware: AncilisMiddleware,
    call: DemoCall,
    stream: TextIO,
) -> None:
    result = await middleware.call_tool(call.name, call.arguments)
    text = result.content[0].text if result.content else ""
    _print(stream, f"[ALLOW] {call.name} -> {text}")
    if call.note:
        _print(stream, f"  Note: {call.note}")


async def _call_blocked(
    middleware: AncilisMiddleware,
    call: DemoCall,
    stream: TextIO,
) -> None:
    try:
        result = await middleware.call_tool(call.name, call.arguments)
    except BlockedToolCallError as exc:
        message = exc.display_message.splitlines()[0]
        _print(stream, f"[BLOCK] {call.name} -> {message}")
        return

    text = result.content[0].text if result.content else ""
    _print(stream, f"[AUDIT-BLOCK] {call.name} -> {text}")


async def _seed_agent(
    scenario: DiscoveryAgentScenario,
    stream: TextIO,
    *,
    fresh: bool,
) -> DiscoveryAgent:
    config_path = DISCOVERY_AGENT_ROOT / scenario.name / "ancilis.yaml"
    raw_config = _load_raw_config(config_path)
    config = load_config(path=config_path)
    db_path = _resolve_agent_db_path(config.agent_name, fresh=fresh)
    middleware = AncilisMiddleware(
        MockDiscoverySession(scenario.tools),
        config=config,
        evidence_store=EvidenceStore(config, db_path=db_path, in_memory=False),
    )

    try:
        _print(stream, f"[{scenario.runtime_type}] {scenario.name}")

        for call in scenario.pre_discovery_calls:
            await _call_allowed(middleware, call, stream)

        await middleware.list_tools()
        _mark_blocked_tools(middleware)

        for call in scenario.allowed_calls:
            await _call_allowed(middleware, call, stream)

        for call in scenario.blocked_calls:
            await _call_blocked(middleware, call, stream)

        records = middleware.evidence_store.get_records(
            session_id=middleware.session_id,
            limit=None,
        )
        summary = _posture_summary(records)
        _print(
            stream,
            f"  Summary: allow={summary['allow']} block={summary['block']} flag={summary['flag']}",
        )
        _print(stream, f"  Evidence: {middleware.evidence_store.db_path}")

        return DiscoveryAgent(
            name=scenario.name,
            runtime_type=scenario.runtime_type,
            config_path=str(config_path),
            db_path=middleware.evidence_store.db_path,
            tool_count=len(scenario.tools),
            data_types=sorted(raw_config.get("my_agent_handles", [])),
            evidence_summary=summary,
            description=raw_config.get("agent", {}).get("description", ""),
            classifications=_classifications(config),
            active_overlays=sorted(config.active_overlays.keys()),
            active_certifications=sorted(getattr(config, "active_certifications", [])),
        )
    finally:
        middleware.close()


def _write_manifest(output_dir: Path, agents: list[DiscoveryAgent]) -> Path:
    manifest_path = output_dir / DEFAULT_MANIFEST_PATH.name
    payload = {
        "agents": [asdict(agent) for agent in agents],
        "total_evidence_records": sum(sum(agent.evidence_summary.values()) for agent in agents),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return manifest_path


async def _run_discovery(
    output_dir: Path,
    stream: TextIO,
    *,
    fresh: bool,
) -> DiscoveryDemoResult:
    _print(stream, BANNER)
    _print(stream)

    agents: list[DiscoveryAgent] = []
    for scenario in DISCOVERY_SCENARIOS:
        agent = await _seed_agent(scenario, stream, fresh=fresh)
        agents.append(agent)
        _print(stream)

    manifest_path = _write_manifest(output_dir, agents)
    total_records = sum(sum(agent.evidence_summary.values()) for agent in agents)

    _print(stream, f"Discovery demo manifest: {manifest_path}")
    _print(stream, f"Total evidence records: {total_records}")

    return DiscoveryDemoResult(
        agents=agents,
        manifest_path=str(manifest_path),
        total_evidence_records=total_records,
    )


def main(
    output_dir: str | Path | None = None,
    stream: TextIO | None = None,
    *,
    fresh: bool = True,
) -> DiscoveryDemoResult:
    """Seed the discovery demo evidence stores and manifest."""
    target_stream = stream or sys.stdout
    target_output_dir = Path(output_dir) if output_dir is not None else DEFAULT_OUTPUT_DIR
    target_output_dir.mkdir(parents=True, exist_ok=True)
    return asyncio.run(_run_discovery(target_output_dir, target_stream, fresh=fresh))


if __name__ == "__main__":
    main()
