"""Seed a multi-agent discovery demo with hash-chained SDK evidence stores."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TextIO

import yaml

from ancilis.config import load_config
from ancilis.engine.engine import PATTERN_TO_DC
from ancilis.engine.result import EvaluationResult
from ancilis.engine.registry import ToolEntry, ToolStatus
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.middleware import AncilisMiddleware, BlockedToolCallError

logging.getLogger("ancilis.middleware").setLevel(logging.CRITICAL)

DEFAULT_OUTPUT_DIR = Path(__file__).with_name("discovery")
DISCOVERY_AGENT_ROOT = DEFAULT_OUTPUT_DIR / "agents"
DEFAULT_MANIFEST_PATH = DEFAULT_OUTPUT_DIR / "discovery-manifest.json"
BANNER = "Ancilis Discovery Demo - Seeded Agent Fleet"
DEMO_TIMELINE_ANCHOR = datetime(2026, 4, 14, 15, 0, tzinfo=timezone.utc)
DEMO_FLEET_INTEGRATION_NAME = "Discovery Demo SDK Fleet"


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
    detected_data_types: list[str] = field(default_factory=list)
    classification_findings: list[dict[str, Any]] = field(default_factory=list)
    active_overlays: list[str] = field(default_factory=list)
    active_certifications: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


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
            ToolSpec("process_payment", "Payment captured for INV-1042 using Bedrock action plan PAY-778.", "Process a customer card payment."),
            ToolSpec("issue_refund", "Refund issued for charge CH-8821 after Bedrock policy review.", "Issue a partial or full refund."),
            ToolSpec("get_payment_status", "Payment CH-8821 settled successfully.", "Fetch settlement status."),
            ToolSpec("verify_card", "Card ending 1111 passed verification.", "Verify card token and AVS data."),
            ToolSpec("get_merchant_info", "Merchant account ACME-US is active.", "Fetch merchant profile details."),
            ToolSpec("generate_receipt", "Receipt queued for ava.patel@example.com.", "Generate a payment receipt."),
            ToolSpec("delete_transaction_log", "Transaction log deleted.", "Delete payment processing logs."),
        ),
        allowed_calls=(
            DemoCall(
                "process_payment",
                {
                    "invoice_id": "INV-1042",
                    "amount": 189.55,
                    "currency": "USD",
                    "card_number": "4111-1111-1111-1111",
                    "billing_email": "ava.patel@example.com",
                },
            ),
            DemoCall("verify_card", {"card_number": "4242 4242 4242 4242", "merchant_id": "mrc_001"}),
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
        runtime_type="cli",
        tools=(
            ToolSpec("score_transaction", "CLI score complete: risk 0.18, action approve.", "Score a payment transaction for fraud."),
            ToolSpec("get_fraud_rules", "Loaded 24 active fraud rules.", "Fetch the active fraud rule set."),
            ToolSpec("flag_suspicious", "Transaction CH-8821 flagged for review.", "Escalate a suspicious payment."),
            ToolSpec("get_account_history", "Retrieved 12 months of account activity.", "Fetch historical account activity."),
            ToolSpec("verify_identity", "Identity verified for customer CUS-9001.", "Run identity verification."),
            ToolSpec("override_fraud_flag", "Fraud flag override saved.", "Override a fraud decision."),
            ToolSpec("bulk_export_scores", "Exported 150 score rows.", "Bulk export fraud scores."),
        ),
        allowed_calls=(
            DemoCall(
                "score_transaction",
                {
                    "charge_id": "CH-8821",
                    "merchant_id": "mrc_001",
                    "card_number": "5555-5555-5555-4444",
                    "customer_email": "marco.lee@example.com",
                },
            ),
            DemoCall("get_fraud_rules", {"version": "current"}),
            DemoCall("flag_suspicious", {"charge_id": "CH-8821", "reason": "velocity_spike"}),
            DemoCall("verify_identity", {"customer_id": "CUS-9001", "ssn": "123-45-6789"}),
        ),
        blocked_calls=(
            DemoCall("override_fraud_flag", {"charge_id": "CH-8821", "reason": "manual_override"}),
            DemoCall("bulk_export_scores", {"days": 7}),
        ),
    ),
    DiscoveryAgentScenario(
        name="compliance-auditor",
        runtime_type="framework",
        tools=(
            ToolSpec("review_claim_exception", "Claim exception CLM-7721 reviewed for member M-481.", "Review a claim exception."),
            ToolSpec("verify_member_consent", "Consent verified for MRN-493827.", "Verify consent before PHI processing."),
            ToolSpec("inspect_access_log", "Access log retained and sampled for audit.", "Inspect clinical data access logs."),
            ToolSpec("generate_audit_packet", "HIPAA audit packet generated for case HIP-221.", "Generate an audit evidence packet."),
            ToolSpec("check_retention_policy", "Retention policy is active for claim artifacts.", "Validate retention policy status."),
            ToolSpec("disable_retention_policy", "Retention policy disabled.", "Disable retention controls."),
        ),
        allowed_calls=(
            DemoCall("review_claim_exception", {"claim_id": "CLM-7721", "member_mrn": "MRN-493827"}),
            DemoCall("verify_member_consent", {"member_mrn": "MRN-493827", "email": "nora.banks@example.com"}),
            DemoCall("inspect_access_log", {"system": "ehr-prod", "auditor": "compliance-team"}),
            DemoCall("generate_audit_packet", {"case_id": "HIP-221", "member_mrn": "MRN-493827"}),
            DemoCall("check_retention_policy", {"artifact_type": "claim_pdf", "policy": "hipaa-6y"}),
        ),
        blocked_calls=(
            DemoCall("disable_retention_policy", {"policy": "hipaa-6y", "requested_by": "break_glass"}),
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
                {"document_id": "DOC-7781", "vendor_email": "ap@acme-supply.example"},
                "Pre-discovery approval baseline intentionally missing to surface a PR-03 flag.",
            ),
        ),
        allowed_calls=(
            DemoCall("extract_invoice_data", {"document_id": "DOC-7781", "vendor_email": "ap@acme-supply.example"}),
            DemoCall("validate_line_items", {"invoice_id": "INV-7781"}),
            DemoCall("match_purchase_order", {"invoice_id": "INV-7781", "purchase_order_id": "PO-1007"}),
            DemoCall("get_vendor_info", {"vendor_id": "V-240", "contact_phone": "415-555-0198"}),
            DemoCall("submit_for_approval", {"invoice_id": "INV-7781", "approver": "finops-team"}),
        ),
        blocked_calls=(
            DemoCall("delete_invoice", {"invoice_id": "INV-7781"}),
        ),
    ),
    DiscoveryAgentScenario(
        name="customer-assist",
        runtime_type="http",
        tools=(
            ToolSpec("lookup_customer", "Customer Jane Smith located through CRM API.", "Look up a customer profile."),
            ToolSpec("check_balance", "Checking balance for account AC-1201 is $12,450.00.", "Check a payment account balance."),
            ToolSpec("get_transactions", "Retrieved 10 recent transactions for account AC-1201.", "Get recent account transactions."),
            ToolSpec("create_support_ticket", "Support ticket SUP-445 created.", "Open a payment support case."),
            ToolSpec("update_contact_info", "Customer contact information updated.", "Update customer contact details."),
            ToolSpec("lookup_credit_score", "Credit score 742 retrieved through partner API.", "Look up the customer credit score."),
            ToolSpec("transfer_funds", "Funds transferred successfully.", "Transfer funds between accounts."),
            ToolSpec("close_account", "Account AC-1201 closed.", "Close a payment account."),
        ),
        allowed_calls=(
            DemoCall("lookup_customer", {"customer_id": "CUS-1201", "email": "jane.smith@example.com", "member_mrn": "MRN-100221"}),
            DemoCall("check_balance", {"account_id": "AC-1201", "card_number": "4000-0566-5566-5556"}),
            DemoCall("get_transactions", {"account_id": "AC-1201", "limit": 10}),
            DemoCall("create_support_ticket", {"customer_id": "CUS-1201", "topic": "statement_help", "phone": "212-555-0144"}),
            DemoCall("lookup_credit_score", {"customer_id": "CUS-1201", "ssn": "987-65-4321"}),
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


class TimelineEvidenceStore(EvidenceStore):
    """Evidence store wrapper that stamps demo records with a believable timeline."""

    def __init__(
        self,
        *args: Any,
        timestamps: list[str],
        source_type: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._timestamps = list(timestamps)
        self._source_type = source_type

    def store(
        self,
        evaluation: EvaluationResult,
        tool_name: str,
        output_summary: str | None = None,
    ):
        timestamp = self._timestamps.pop(0) if self._timestamps else evaluation.timestamp
        stamped_evaluation = replace(
            evaluation,
            timestamp=timestamp,
            source_type=self._source_type,
        )
        return super().store(stamped_evaluation, tool_name=tool_name, output_summary=output_summary)


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


def _timeline_for(scenario_index: int, record_count: int) -> list[str]:
    """Return deterministic timestamps spread across several demo days."""
    start = DEMO_TIMELINE_ANCHOR - timedelta(days=4 - scenario_index, hours=2 * scenario_index)
    return [
        (start + timedelta(hours=6 * offset)).isoformat()
        for offset in range(record_count)
    ]


def _pattern_findings(record: Any) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for control in record.control_results:
        if control.get("control_id") != "PR-04":
            continue
        evidence_data = control.get("evidence_data") or {}
        for pattern in evidence_data.get("patterns_detected") or []:
            pattern_type = pattern.get("type") or pattern.get("pattern_type")
            dc_code = PATTERN_TO_DC.get(str(pattern_type))
            if dc_code is None:
                continue
            findings.append(
                {
                    "data_type": dc_code,
                    "pattern_type": str(pattern_type),
                    "redacted_sample": str(pattern.get("redacted_sample") or ""),
                }
            )
    return findings


def _detected_data_types(records: list[Any]) -> list[str]:
    detected: set[str] = set()
    for record in records:
        detected.update(record.detected_data_types or [])
        detected.update(finding["data_type"] for finding in _pattern_findings(record))
    return sorted(detected)


def _classification_findings(records: list[Any]) -> list[dict[str, Any]]:
    by_data_type: dict[str, dict[str, Any]] = {}
    for record in records:
        record_types = set(record.detected_data_types or [])
        pattern_findings = _pattern_findings(record)
        record_types.update(finding["data_type"] for finding in pattern_findings)
        samples_by_type: dict[str, set[str]] = {}
        for finding in pattern_findings:
            sample = finding["redacted_sample"]
            if sample:
                samples_by_type.setdefault(finding["data_type"], set()).add(sample)

        for data_type in record_types:
            item = by_data_type.setdefault(
                data_type,
                {
                    "data_type": data_type,
                    "status": "pending_confirmation",
                    "evidence_count": 0,
                    "redacted_samples": set(),
                    "source": "sdk_runtime",
                },
            )
            item["evidence_count"] += 1
            item["redacted_samples"].update(samples_by_type.get(data_type, set()))

    findings: list[dict[str, Any]] = []
    for item in by_data_type.values():
        findings.append(
            {
                **item,
                "redacted_samples": sorted(item["redacted_samples"])[:3],
            }
        )
    return sorted(findings, key=lambda finding: finding["data_type"])


def _first_last_seen(records: list[Any]) -> tuple[str, str]:
    if not records:
        return "", ""
    timestamps = sorted(record.timestamp for record in records)
    return timestamps[0], timestamps[-1]


def _build_sdk_direct_integration_payload(agents: list[DiscoveryAgent]) -> dict[str, Any]:
    return {
        "name": DEMO_FLEET_INTEGRATION_NAME,
        "source_type": "sdk_direct",
        "config": {
            "api_key_hint": "demo-local",
            "transport": {
                "mode": "local_file",
                "paths": [agent.db_path for agent in agents],
                "scan_home_dir": False,
            },
            "sync": {
                "mode": "incremental",
                "batch_size": 500,
            },
        },
    }


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
    scenario_index: int,
) -> DiscoveryAgent:
    config_path = DISCOVERY_AGENT_ROOT / scenario.name / "ancilis.yaml"
    raw_config = _load_raw_config(config_path)
    config = load_config(path=config_path)
    db_path = _resolve_agent_db_path(config.agent_name, fresh=fresh)
    record_count = (
        len(scenario.pre_discovery_calls)
        + len(scenario.allowed_calls)
        + len(scenario.blocked_calls)
    )
    evidence_store = TimelineEvidenceStore(
        config,
        db_path=db_path,
        in_memory=False,
        timestamps=_timeline_for(scenario_index, record_count),
        source_type=scenario.runtime_type,
    )
    middleware = AncilisMiddleware(
        MockDiscoverySession(scenario.tools),
        config=config,
        evidence_store=evidence_store,
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
        detected_data_types = _detected_data_types(records)
        classification_findings = _classification_findings(records)
        first_seen, last_seen = _first_last_seen(records)
        _print(
            stream,
            f"  Summary: allow={summary['allow']} block={summary['block']} flag={summary['flag']}",
        )
        if detected_data_types:
            _print(stream, f"  Classification findings: {', '.join(detected_data_types)}")
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
            detected_data_types=detected_data_types,
            classification_findings=classification_findings,
            active_overlays=sorted(config.active_overlays.keys()),
            active_certifications=sorted(getattr(config, "active_certifications", [])),
            first_seen=first_seen,
            last_seen=last_seen,
        )
    finally:
        middleware.close()


def _write_manifest(output_dir: Path, agents: list[DiscoveryAgent]) -> Path:
    manifest_path = output_dir / DEFAULT_MANIFEST_PATH.name
    payload = {
        "agents": [asdict(agent) for agent in agents],
        "total_evidence_records": sum(sum(agent.evidence_summary.values()) for agent in agents),
        "sdk_direct_integration": _build_sdk_direct_integration_payload(agents),
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
    for scenario_index, scenario in enumerate(DISCOVERY_SCENARIOS):
        agent = await _seed_agent(
            scenario,
            stream,
            fresh=fresh,
            scenario_index=scenario_index,
        )
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
