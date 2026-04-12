"""Standalone finance demo agent using Ancilis SDK ToolActionProducer directly.

Run from repo root:
    python demo/demo_agent.py
"""

from __future__ import annotations

from pathlib import Path

from ancilis import load_config, EvidenceStore, BlockedActionError
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.producers.tool import ToolActionProducer

AGENT_NAME = "finance-demo-agent"
CONFIG_PATH = Path(__file__).with_name("ancilis.yaml")
DB_PATH = Path(__file__).with_name("evidence.duckdb")


def main() -> None:
    # Fresh run — remove any prior DuckDB artifacts
    for artifact in DB_PATH.parent.glob(f"{DB_PATH.name}*"):
        artifact.unlink(missing_ok=True)

    config = load_config(path=CONFIG_PATH)
    evidence_store = EvidenceStore(config, db_path=DB_PATH)
    registry = ToolRegistry()
    engine = Engine(config, registry=registry)
    producer = ToolActionProducer(config, engine, registry, evidence_store)

    # --- Tool definitions ---

    def _check_balance(account: str) -> str:
        return f"Balance for {account}: $12,450.00"

    def _get_transactions(account: str, days: int) -> str:
        return (
            f"Transactions for {account} (last {days} days):\n"
            "  2026-04-01: -$89.99 at TechMart\n"
            "  2026-04-05: -$234.56 at GroceryCo\n"
            "  2026-04-10: +$1,500.00 Direct Deposit"
        )

    def _transfer_funds(from_acct: str, to_acct: str, amount: float) -> str:
        # Credit card number included in response to illustrate output-layer exposure surfacing
        return (
            f"Transferred ${amount:.2f} from {from_acct} to {to_acct} "
            f"(Ref: TXN-2026-0412). On-file card: 4111-1111-1111-1111"
        )

    def _drop_audit_log() -> str:
        # This body never executes — blocked by security.tools.blocked
        return "Audit log dropped"

    # Wrap tools with Ancilis enforcement
    check_balance = producer.wrap_tool(_check_balance, agent_name=AGENT_NAME, tool_name="check_balance")
    get_transactions = producer.wrap_tool(_get_transactions, agent_name=AGENT_NAME, tool_name="get_transactions")
    transfer_funds = producer.wrap_tool(_transfer_funds, agent_name=AGENT_NAME, tool_name="transfer_funds")
    drop_audit_log = producer.wrap_tool(_drop_audit_log, agent_name=AGENT_NAME, tool_name="drop_audit_log")

    tool_dispatch: dict[str, object] = {
        "check_balance": check_balance,
        "get_transactions": get_transactions,
        "transfer_funds": transfer_funds,
        "drop_audit_log": drop_audit_log,
    }

    # --- Execute tool call sequence ---
    calls = [
        ("check_balance", {"account": "ACCT-7890"}),
        ("get_transactions", {"account": "ACCT-7890", "days": 30}),
        ("transfer_funds", {"from_acct": "ACCT-7890", "to_acct": "ACCT-1234", "amount": 500.00}),
        ("drop_audit_log", {}),
    ]

    print(f"Agent: {AGENT_NAME}  |  Mode: {config.mode}")
    print()
    for tool_name, kwargs in calls:
        fn = tool_dispatch[tool_name]
        try:
            fn(**kwargs)  # type: ignore[operator]
            print(f"  ALLOW  {tool_name}")
        except BlockedActionError:
            print(f"  BLOCK  {tool_name}")

    # --- Summary ---
    summary = evidence_store.get_summary(session_id=producer.session_id)
    valid, errors = evidence_store.verify_chain()
    print()
    print(f"Evidence records: {summary['total_evaluations']}")
    print(f"Decisions: {summary['decisions']}")
    print(f"Chain valid: {valid}")
    print(f"Evidence DB: {DB_PATH}")


if __name__ == "__main__":
    main()
