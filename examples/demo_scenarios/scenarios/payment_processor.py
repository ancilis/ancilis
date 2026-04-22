"""Payment processor Bedrock demo scenario."""

from __future__ import annotations

from scenarios.common import DemoCall, DemoScenario


def scenario() -> DemoScenario:
    return DemoScenario(
        agent_id="payment_processor",
        display_name="Payment Processor",
        architecture="Bedrock",
        agent_owner="Nora Kim, Payments Ops",
        llm_provider="aws-bedrock/anthropic.claude-3-haiku",
        handles=("credit_cards", "personal_info"),
        allowed_tools=(
            "validate_card",
            "authorize_charge",
            "reconcile_dispute",
        ),
        blocked_tools=("copy_pan_to_ticket",),
        calls=(
            DemoCall(
                tool_name="validate_card",
                arguments={
                    "cardholder": "Avery Stone",
                    "pan": "4532 1488 0343 6467",
                    "expiration": "09/29",
                    "destination": "payments.tokenizer.internal",
                },
                response="PAN validated and token tok_live_demo_4532 created.",
                detected_data_types=("DC-CHD", "DC-PII"),
                description="Validate a card through a tokenization service.",
            ),
            DemoCall(
                tool_name="authorize_charge",
                arguments={
                    "token": "tok_live_demo_4532",
                    "amount": "184.37",
                    "currency": "USD",
                    "merchant": "Northwind Health Supplies",
                    "destination": "payments.gateway.internal",
                },
                response="Authorization approved, auth_id=AUTH-20260415-00981.",
                detected_data_types=("DC-CHD",),
                description="Authorize a card-not-present purchase through the gateway.",
            ),
            DemoCall(
                tool_name="reconcile_dispute",
                arguments={
                    "case_id": "DSP-10491",
                    "customer_email": "avery.stone@example.com",
                    "last4": "6467",
                    "destination": "chargeback-review",
                },
                response="Dispute evidence packet generated for analyst review.",
                outcome="FLAG",
                detected_data_types=("DC-CHD", "DC-PII"),
                reason="Flagged because dispute packet includes cardholder identifiers.",
                description="Prepare a chargeback evidence packet for human review.",
            ),
            DemoCall(
                tool_name="copy_pan_to_ticket",
                arguments={
                    "ticket": "PAY-8831",
                    "pan": "4532 1488 0343 6467",
                    "destination": "jira.example",
                },
                response="Blocked before cardholder data was copied into a ticket.",
                outcome="BLOCK",
                detected_data_types=("DC-CHD",),
                reason="Blocked because raw PAN must not be copied into support tickets.",
                description="Unsafe attempt to paste full PAN into ticketing workflow.",
            ),
        ),
    )
