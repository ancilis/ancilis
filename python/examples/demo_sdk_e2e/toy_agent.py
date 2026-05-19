"""Toy LangChain-core agent wired through Ancilis production SDK paths."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from langchain_core.tools import StructuredTool

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.langchain import LangChainActionProducer, LangChainCallbackHandler


AGENT_NAME = "sdk-demo-langchain-agent"
TOOL_NAME = "process_customer_record"
LANGCHAIN_TOOL_NAME = f"langchain:tool:{TOOL_NAME}"
SUMMARY_PATH = Path(__file__).with_name("processed_records.ndjson")


@dataclass(frozen=True)
class AgentRun:
    """Result of one demo agent invocation."""

    scenario: str
    input_record: dict[str, Any]
    summary: str
    evidence_record: EvidenceRecord


def _redacted_record(record: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in record.items():
        lowered = key.lower()
        if lowered in {"ssn", "card", "dob"}:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def process_customer_record(record: dict[str, Any]) -> str:
    """Process a customer record and append a durable summary line.

    This is intentionally a real tool function. It writes a small redacted
    summary so the demo exercises an actual side effect after Ancilis evaluates
    the tool call.
    """
    if not isinstance(record, dict):
        raise TypeError("record must be a dictionary")

    customer = str(record.get("name") or record.get("customer") or "unknown")
    summary = {
        "customer": customer,
        "field_count": len(record),
        "fields": sorted(str(key) for key in record),
        "redacted_record": _redacted_record(record),
    }
    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SUMMARY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, sort_keys=True) + "\n")
    return f"Processed {customer}: {len(record)} fields summarized."


class StubChatModel:
    """Deterministic local LLM stand-in that emits LangChain callbacks."""

    name = "StubChatModel"

    def invoke(
        self,
        prompt: str,
        *,
        callbacks: list[LangChainCallbackHandler],
        field_names: list[str],
    ) -> str:
        for callback in callbacks:
            callback.on_chat_model_start(
                {"name": self.name, "id": ["langchain", "chat_models", self.name]},
                [[f"HumanMessage(content={prompt!r})"]],
                run_id=uuid4(),
                fields=field_names,
                stub=True,
            )
        return "Use process_customer_record for the supplied customer record."


class DemoLangChainAgent:
    """Small real-path LangChain-core agent for the SDK demo."""

    def __init__(self, *, db_path: Path) -> None:
        self.config = load_config(
            raw={
                "agent": {
                    "name": AGENT_NAME,
                    "owner": "sdk-demo",
                    "llm_provider": "local-stub",
                },
                "security": {
                    "mode": "audit",
                    "tools": {"allowed": [LANGCHAIN_TOOL_NAME]},
                },
            }
        )
        self.store = EvidenceStore(self.config, db_path=db_path)
        self.engine = Engine(self.config)
        self.producer = LangChainActionProducer(
            config=self.config,
            engine=self.engine,
            evidence_store=self.store,
        )
        self.handler = LangChainCallbackHandler(self.producer, agent_name=AGENT_NAME)
        self.llm = StubChatModel()
        self.tool = StructuredTool.from_function(
            process_customer_record,
            name=TOOL_NAME,
            description="Process a customer record and write a redacted summary.",
        )

    def run(self, scenario: str, record: dict[str, Any]) -> AgentRun:
        prompt = (
            "Plan the next step for a customer-record workflow. "
            f"Scenario={scenario}; fields={', '.join(sorted(record))}."
        )
        self.llm.invoke(
            prompt,
            callbacks=[self.handler],
            field_names=sorted(record),
        )
        summary = self.tool.invoke(
            {"record": record},
            config={"callbacks": [self.handler]},
        )
        evidence_record = self.store.get_records(limit=None)[-1]
        return AgentRun(
            scenario=scenario,
            input_record=record,
            summary=str(summary),
            evidence_record=evidence_record,
        )

    def close(self) -> None:
        self.store.close()
