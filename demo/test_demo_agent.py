"""Tests for the standalone finance demo agent."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow running from repo root: python demo/test_demo_agent.py
sys.path.insert(0, str(Path(__file__).parent.parent / "python" / "src"))

from ancilis import load_config, EvidenceStore, BlockedActionError
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.producers.tool import ToolActionProducer

AGENT_NAME = "finance-demo-agent"
CONFIG_PATH = Path(__file__).with_name("ancilis.yaml")


@pytest.fixture()
def demo_db_path(tmp_path: Path) -> Path:
    return tmp_path / "evidence_test.duckdb"


@pytest.fixture()
def producer_and_store(demo_db_path: Path):
    config = load_config(path=CONFIG_PATH)
    evidence_store = EvidenceStore(config, db_path=demo_db_path)
    registry = ToolRegistry()
    engine = Engine(config, registry=registry)
    producer = ToolActionProducer(config, engine, registry, evidence_store)
    return producer, evidence_store, config


def _run_demo_calls(producer: ToolActionProducer, evidence_store: EvidenceStore) -> dict:
    """Execute the demo tool call sequence and return decision counts."""

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
        return (
            f"Transferred ${amount:.2f} from {from_acct} to {to_acct} "
            "(Ref: TXN-2026-0412). On-file card: 4111-1111-1111-1111"
        )

    def _drop_audit_log() -> str:
        return "Audit log dropped"

    check_balance = producer.wrap_tool(_check_balance, agent_name=AGENT_NAME, tool_name="check_balance")
    get_transactions = producer.wrap_tool(_get_transactions, agent_name=AGENT_NAME, tool_name="get_transactions")
    transfer_funds = producer.wrap_tool(_transfer_funds, agent_name=AGENT_NAME, tool_name="transfer_funds")
    drop_audit_log = producer.wrap_tool(_drop_audit_log, agent_name=AGENT_NAME, tool_name="drop_audit_log")

    tool_dispatch = {
        "check_balance": check_balance,
        "get_transactions": get_transactions,
        "transfer_funds": transfer_funds,
        "drop_audit_log": drop_audit_log,
    }

    calls = [
        ("check_balance", {"account": "ACCT-7890"}),
        ("get_transactions", {"account": "ACCT-7890", "days": 30}),
        ("transfer_funds", {"from_acct": "ACCT-7890", "to_acct": "ACCT-1234", "amount": 500.00}),
        ("drop_audit_log", {}),
    ]

    decisions = {"ALLOW": 0, "BLOCK": 0}
    for tool_name, kwargs in calls:
        fn = tool_dispatch[tool_name]
        try:
            fn(**kwargs)  # type: ignore[operator]
            decisions["ALLOW"] += 1
        except BlockedActionError:
            decisions["BLOCK"] += 1

    return decisions


def test_demo_creates_evidence_db(producer_and_store, demo_db_path: Path) -> None:
    producer, evidence_store, _ = producer_and_store
    _run_demo_calls(producer, evidence_store)
    assert demo_db_path.exists(), "Evidence DuckDB file should be created after tool calls"


def test_demo_evidence_record_count(producer_and_store) -> None:
    producer, evidence_store, _ = producer_and_store
    _run_demo_calls(producer, evidence_store)

    summary = evidence_store.get_summary(session_id=producer.session_id)
    total = summary["total_evaluations"]
    # One evidence record per tool call (controls are aggregated within each record)
    assert total >= 4, (
        f"Expected at least 4 evidence records (one per tool call), got {total}"
    )


def test_demo_block_decision(producer_and_store) -> None:
    producer, evidence_store, _ = producer_and_store
    decisions = _run_demo_calls(producer, evidence_store)
    assert decisions["BLOCK"] >= 1, "drop_audit_log should be blocked"


def test_demo_allow_decisions(producer_and_store) -> None:
    producer, evidence_store, _ = producer_and_store
    decisions = _run_demo_calls(producer, evidence_store)
    assert decisions["ALLOW"] >= 3, (
        f"Expected at least 3 ALLOW decisions (check_balance, get_transactions, transfer_funds), got {decisions['ALLOW']}"
    )


def test_demo_chain_valid(producer_and_store) -> None:
    producer, evidence_store, _ = producer_and_store
    _run_demo_calls(producer, evidence_store)
    valid, errors = evidence_store.verify_chain()
    assert valid is True, f"Evidence chain should be valid, errors: {errors}"
    assert errors == [], f"No chain errors expected, got: {errors}"


def test_demo_summary_decisions_match(producer_and_store) -> None:
    producer, evidence_store, _ = producer_and_store
    local_decisions = _run_demo_calls(producer, evidence_store)

    summary = evidence_store.get_summary(session_id=producer.session_id)
    store_decisions = summary["decisions"]

    # Both counts should agree on ALLOW and BLOCK totals
    assert store_decisions.get("ALLOW", 0) == local_decisions["ALLOW"]
    assert store_decisions.get("BLOCK", 0) == local_decisions["BLOCK"]


def test_drop_audit_log_raises_blocked_action_error(producer_and_store) -> None:
    """drop_audit_log is in security.tools.blocked — must raise BlockedActionError."""
    producer, evidence_store, _ = producer_and_store

    def _drop_audit_log() -> str:
        return "Audit log dropped"

    drop_audit_log = producer.wrap_tool(_drop_audit_log, agent_name=AGENT_NAME, tool_name="drop_audit_log")

    with pytest.raises(BlockedActionError) as exc_info:
        drop_audit_log()

    assert exc_info.value.tool_name == "drop_audit_log"


def test_allowed_tools_do_not_raise(producer_and_store) -> None:
    """check_balance, get_transactions, transfer_funds must execute without raising."""
    producer, evidence_store, _ = producer_and_store

    def _check_balance(account: str) -> str:
        return f"Balance for {account}: $12,450.00"

    check_balance = producer.wrap_tool(_check_balance, agent_name=AGENT_NAME, tool_name="check_balance")
    result = check_balance(account="ACCT-7890")
    assert "12,450.00" in result
