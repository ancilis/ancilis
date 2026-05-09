"""Tests for LLM SDK producers (Anthropic, OpenAI, Gemini)."""

from __future__ import annotations

import pytest

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.llm import (
    AnthropicActionProducer,
    GeminiActionProducer,
    LLMActionProducer,
    LLMInvocation,
    OpenAIActionProducer,
)
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.tool import BlockedActionError


def _config(*, mode: str = "audit", tools_allowed: list[str] | None = None) -> object:
    raw = {
        "agent": {"name": "llm-agent", "owner": "test-owner"},
        "security": {"mode": mode, "tools": {"allowed": tools_allowed or []}},
    }
    return load_config(raw=raw)


def _make(
    cls: type[LLMActionProducer], *, mode: str = "audit", tools_allowed: list[str] | None = None
) -> tuple[LLMActionProducer, EvidenceStore]:
    config = _config(mode=mode, tools_allowed=tools_allowed)
    store = EvidenceStore(config, in_memory=True)
    producer = cls(config=config, engine=Engine(config), evidence_store=store)
    return producer, store


class TestProtocolCompliance:
    @pytest.mark.parametrize(
        "cls", [AnthropicActionProducer, OpenAIActionProducer, GeminiActionProducer]
    )
    def test_satisfies_action_producer_protocol(self, cls: type[LLMActionProducer]) -> None:
        producer, _ = _make(cls)
        assert isinstance(producer, ActionProducer)
        assert producer.producer_type is ProducerType.FRAMEWORK
        assert producer.producer_version == "0.1.0"

    @pytest.mark.parametrize(
        "cls,expected_provider",
        [
            (AnthropicActionProducer, "anthropic"),
            (OpenAIActionProducer, "openai"),
            (GeminiActionProducer, "gemini"),
        ],
    )
    def test_provider_string(
        self, cls: type[LLMActionProducer], expected_provider: str
    ) -> None:
        producer, _ = _make(cls)
        assert producer.provider == expected_provider


class TestObserve:
    def test_anthropic_observe_records_action(self) -> None:
        producer, store = _make(AnthropicActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="claude-sonnet-4-6",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "hello"}],
            )
        )
        assert observation.action.action_type == "api_request"
        assert observation.action.tool.name == "llm:anthropic:claude-sonnet-4-6"
        assert observation.action.tool.server == "anthropic"
        assert store.get_summary()["total_evaluations"] == 1

    def test_openai_observe_records_action(self) -> None:
        producer, store = _make(OpenAIActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="gpt-4o",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "ping"}],
            )
        )
        assert observation.action.tool.name == "llm:openai:gpt-4o"
        assert store.get_summary()["total_evaluations"] == 1

    def test_gemini_observe_records_action(self) -> None:
        producer, store = _make(GeminiActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="gemini-2.5-flash",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "hi"}],
            )
        )
        assert observation.action.tool.name == "llm:gemini:gemini-2.5-flash"
        assert store.get_summary()["total_evaluations"] == 1

    def test_unknown_model_falls_back_safely(self) -> None:
        producer, _ = _make(AnthropicActionProducer)
        observation = producer.observe(
            LLMInvocation(model="", agent_name="llm-agent")
        )
        assert observation.action.tool.name == "llm:anthropic:unknown-model"


class TestExtractInvocation:
    def test_anthropic_extracts_messages_and_system(self) -> None:
        producer, _ = _make(AnthropicActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "hi"}],
                "system": "you are helpful",
                "tools": [{"name": "search"}],
                "max_tokens": 1024,
            },
            agent_name="llm-agent",
        )
        assert invocation.model == "claude-sonnet-4-6"
        assert invocation.system == "you are helpful"
        assert invocation.tools == [{"name": "search"}]
        assert invocation.metadata == {"max_tokens": 1024}

    def test_openai_responses_input_string_normalized_to_messages(self) -> None:
        producer, _ = _make(OpenAIActionProducer)
        invocation = producer._extract_invocation(
            {"model": "gpt-4o", "input": "summarize this"},
            agent_name="llm-agent",
        )
        assert invocation.messages == [{"role": "user", "content": "summarize this"}]

    def test_openai_responses_input_list_kept(self) -> None:
        producer, _ = _make(OpenAIActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "gpt-4o",
                "input": [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}],
            },
            agent_name="llm-agent",
        )
        assert len(invocation.messages) == 2

    def test_openai_instructions_treated_as_system(self) -> None:
        producer, _ = _make(OpenAIActionProducer)
        invocation = producer._extract_invocation(
            {"model": "gpt-4o", "input": "x", "instructions": "be terse"},
            agent_name="llm-agent",
        )
        assert invocation.system == "be terse"

    def test_gemini_contents_string_normalized(self) -> None:
        producer, _ = _make(GeminiActionProducer)
        invocation = producer._extract_invocation(
            {"model": "gemini-2.5-flash", "contents": "hello"},
            agent_name="llm-agent",
        )
        assert invocation.messages == [{"role": "user", "content": "hello"}]

    def test_gemini_config_dict_extracts_system_and_tools(self) -> None:
        producer, _ = _make(GeminiActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "gemini-2.5-flash",
                "contents": "x",
                "config": {
                    "system_instruction": "be terse",
                    "tools": [{"name": "search"}],
                },
            },
            agent_name="llm-agent",
        )
        assert invocation.system == "be terse"
        assert invocation.tools == [{"name": "search"}]


class TestExecuteAndWrap:
    def test_execute_returns_transport_response_in_audit(self) -> None:
        producer, store = _make(AnthropicActionProducer, mode="audit")

        def fake_create(**_: object) -> dict[str, str]:
            return {"id": "msg_1"}

        result = producer.execute(
            LLMInvocation(model="claude-sonnet-4-6", agent_name="llm-agent"),
            transport=fake_create,
            transport_kwargs={"model": "claude-sonnet-4-6"},
        )
        assert result.response == {"id": "msg_1"}
        assert result.blocked is False
        assert store.get_summary()["total_evaluations"] == 1

    def test_enforce_blocks_disallowed_model(self) -> None:
        allowed = "llm:anthropic:claude-sonnet-4-6"
        producer, _ = _make(
            AnthropicActionProducer, mode="enforce", tools_allowed=[allowed]
        )

        calls: list[str] = []

        def fake_create(**kwargs: object) -> dict[str, str]:
            calls.append(str(kwargs.get("model")))
            return {"id": "msg_1"}

        wrapped = producer.wrap_create(fake_create, agent_name="llm-agent", enforce=True)
        ok = wrapped(model="claude-sonnet-4-6", messages=[{"role": "user", "content": "hi"}])
        assert ok.response == {"id": "msg_1"}
        assert calls == ["claude-sonnet-4-6"]

        with pytest.raises(BlockedActionError):
            wrapped(model="claude-opus-4", messages=[{"role": "user", "content": "hi"}])
        assert calls == ["claude-sonnet-4-6"]

    def test_wrap_create_observe_first_default(self) -> None:
        producer, store = _make(
            OpenAIActionProducer,
            mode="enforce",
            tools_allowed=["llm:openai:gpt-4o"],
        )

        called = {"count": 0}

        def fake_create(**_: object) -> dict[str, str]:
            called["count"] += 1
            return {"id": "resp_1"}

        wrapped = producer.wrap_create(fake_create, agent_name="llm-agent")
        result = wrapped(model="gpt-4o-mini", messages=[{"role": "user", "content": "x"}])
        assert result.response == {"id": "resp_1"}
        assert called["count"] == 1
        assert result.evaluation.decision == "BLOCK"
        assert store.get_summary()["total_evaluations"] == 1

    def test_session_id_is_unique_per_instance(self) -> None:
        a, _ = _make(AnthropicActionProducer)
        b, _ = _make(AnthropicActionProducer)
        assert a.session_id != b.session_id


class TestExportsAndLazyImport:
    def test_lazy_re_export_from_producers_package(self) -> None:
        from ancilis import producers as producers_pkg

        assert producers_pkg.AnthropicActionProducer is AnthropicActionProducer
        assert producers_pkg.OpenAIActionProducer is OpenAIActionProducer
        assert producers_pkg.GeminiActionProducer is GeminiActionProducer
        assert producers_pkg.LLMInvocation is LLMInvocation
