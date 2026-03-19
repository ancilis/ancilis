from __future__ import annotations

from pathlib import Path

import pytest

from ancilis import evaluate_and_execute
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.http import HTTPActionProducer, HTTPRequest
from ancilis.producers.tool import BlockedActionError, ToolActionProducer, tool, wrap_tool


def _config(*, mode: str = "audit", tools_allowed: list[str] | None = None) -> object:
    raw = {"agent": {"name": "runtime-agent"}, "security": {"mode": mode, "tools": {"allowed": tools_allowed or []}}}
    return load_config(raw=raw)


class TestToolActionProducer:
    def test_decorator_wraps_and_records_evidence(self) -> None:
        config = _config(mode="audit")
        store = EvidenceStore(config, in_memory=True)
        producer = ToolActionProducer(config=config, engine=Engine(config), evidence_store=store)

        @tool(producer=producer, agent_name="runtime-agent")
        def add(left: int, right: int) -> int:
            return left + right

        assert add(2, 3) == 5
        summary = store.get_summary()
        assert summary["total_evaluations"] == 1
        assert "tool:" in summary["tools_evaluated"][0]

    def test_manual_evaluate_and_execute_blocks_in_enforce_mode(self) -> None:
        tool_name = "tool:payments.refund"
        config = _config(mode="enforce", tools_allowed=[tool_name])
        engine = Engine(config)
        store = EvidenceStore(config, in_memory=True)
        producer = ToolActionProducer(config=config, engine=engine, evidence_store=store)

        def refund(payment_id: str) -> str:
            return f"refunded:{payment_id}"

        result = evaluate_and_execute(
            refund,
            producer=producer,
            agent_name="runtime-agent",
            tool_name=tool_name,
            args=("pay_123",),
        )
        assert result.return_value == "refunded:pay_123"
        assert result.evaluation.decision == "ALLOW"

        with pytest.raises(BlockedActionError):
            evaluate_and_execute(
                refund,
                producer=producer,
                agent_name="runtime-agent",
                tool_name="tool:payments.exfiltrate",
                args=("pay_123",),
            )

    def test_explicit_evaluate_is_first_class(self) -> None:
        tool_name = "tool:payments.lookup"
        config = _config(mode="audit")
        store = EvidenceStore(config, in_memory=True)
        producer = ToolActionProducer(config=config, engine=Engine(config), evidence_store=store)

        def lookup(payment_id: str) -> str:
            return payment_id

        action, evaluation = producer.evaluate(
            lookup,
            agent_name="runtime-agent",
            tool_name=tool_name,
            args=("pay_123",),
        )

        assert action.tool.name == tool_name
        assert action.action_type == "tool_call"
        assert evaluation.agent_id == "runtime-agent"
        assert store.get_summary()["total_evaluations"] == 1

    def test_function_wrapper_helper(self) -> None:
        config = _config(mode="audit")
        producer = ToolActionProducer(config=config, engine=Engine(config), evidence_store=EvidenceStore(config, in_memory=True))

        def say_hello(name: str) -> str:
            return f"hello {name}"

        wrapped = wrap_tool(say_hello, producer=producer, agent_name="runtime-agent")
        assert wrapped("team") == "hello team"


class TestHTTPActionProducer:
    def test_observe_records_http_action(self) -> None:
        config = _config(mode="audit")
        store = EvidenceStore(config, in_memory=True)
        producer = HTTPActionProducer(config=config, engine=Engine(config), evidence_store=store)

        observation = producer.observe(
            HTTPRequest(
                method="POST",
                url="https://api.example.com/v1/payments",
                agent_name="runtime-agent",
                metadata={"purpose": "create_payment"},
            )
        )

        assert observation.action.action_type == "api_request"
        assert observation.action.tool.name == "http:POST:api.example.com"
        assert store.get_summary()["total_evaluations"] == 1

    def test_explicit_http_wrapper_can_block_before_transport(self) -> None:
        allowed_tool = "http:GET:allowed.example.com"
        config = _config(mode="enforce", tools_allowed=[allowed_tool])
        producer = HTTPActionProducer(config=config, engine=Engine(config), evidence_store=EvidenceStore(config, in_memory=True))

        calls: list[tuple[str, str]] = []

        def fake_request(method: str, url: str, **_: object) -> dict[str, str]:
            calls.append((method, url))
            return {"status": "ok"}

        wrapped = producer.wrap_transport(fake_request, agent_name="runtime-agent", enforce=True)
        allowed = wrapped("GET", "https://allowed.example.com/healthz")
        assert allowed.response == {"status": "ok"}
        assert calls == [("GET", "https://allowed.example.com/healthz")]

        with pytest.raises(BlockedActionError):
            wrapped("GET", "https://blocked.example.com/export")
        assert calls == [("GET", "https://allowed.example.com/healthz")]

    def test_http_wrapper_defaults_to_observe_first(self) -> None:
        config = _config(mode="enforce", tools_allowed=["http:GET:allowed.example.com"])
        producer = HTTPActionProducer(
            config=config,
            engine=Engine(config),
            evidence_store=EvidenceStore(config, in_memory=True),
        )

        calls: list[tuple[str, str]] = []

        def fake_request(method: str, url: str, **_: object) -> dict[str, str]:
            calls.append((method, url))
            return {"status": "ok"}

        wrapped = producer.wrap_transport(fake_request, agent_name="runtime-agent")
        result = wrapped("GET", "https://blocked.example.com/export")

        assert result.response == {"status": "ok"}
        assert result.evaluation.decision == "BLOCK"
        assert calls == [("GET", "https://blocked.example.com/export")]
