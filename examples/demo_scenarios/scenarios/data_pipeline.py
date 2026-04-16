"""Data pipeline CLI demo scenario."""

from __future__ import annotations

from scenarios.common import DemoCall, DemoScenario


def scenario() -> DemoScenario:
    return DemoScenario(
        agent_id="data_pipeline_agent",
        display_name="Data Pipeline Agent",
        architecture="CLI",
        agent_owner="Sam Rivera, Data Platform",
        llm_provider="local/llama-3.1-70b",
        handles=("controlled_unclassified", "financial_records"),
        allowed_tools=(
            "fetch_procurement_feed",
            "normalize_vendor_payments",
            "publish_control_report",
        ),
        blocked_tools=("copy_cui_to_personal_drive",),
        calls=(
            DemoCall(
                tool_name="fetch_procurement_feed",
                arguments={
                    "command": ["aws", "s3", "cp", "s3://gov-contract-cui/feed.ndjson", "-"],
                    "contract": "W52P1J-24-C-0042",
                    "marking": "CUI//SP-PROCURE",
                    "destination": "data-lake.internal",
                },
                response="Fetched 8,214 procurement rows with CUI markings preserved.",
                detected_data_types=("DC-CUI",),
                description="Fetch CUI-marked procurement data from a governed bucket.",
            ),
            DemoCall(
                tool_name="normalize_vendor_payments",
                arguments={
                    "batch_id": "FIN-2026-04-15",
                    "routing_number": "021000021",
                    "amount_total": "2849912.44",
                    "destination": "warehouse.internal",
                },
                response="Normalized vendor payment ledger for finance reconciliation.",
                detected_data_types=("DC-FIN",),
                description="Normalize payment records for finance reporting.",
            ),
            DemoCall(
                tool_name="publish_control_report",
                arguments={
                    "report": "cui-finance-daily-controls",
                    "recipient": "security-ops@example.com",
                    "destination": "gRC.internal",
                },
                response="Control report published with CMMC and GLBA evidence links.",
                outcome="FLAG",
                detected_data_types=("DC-CUI", "DC-FIN"),
                reason="Flagged because cross-framework control reports need analyst signoff.",
                description="Publish a cross-framework control report.",
            ),
            DemoCall(
                tool_name="copy_cui_to_personal_drive",
                arguments={
                    "source": "s3://gov-contract-cui/feed.ndjson",
                    "destination": "gdrive://sam.personal/archive",
                    "marking": "CUI//SP-PROCURE",
                },
                response="Blocked before CUI moved to personal storage.",
                outcome="BLOCK",
                detected_data_types=("DC-CUI",),
                reason="Blocked because CUI cannot be copied to personal storage.",
                description="Unsafe attempt to copy CUI outside managed storage.",
            ),
        ),
    )
