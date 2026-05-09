"""Tests for CrewAIActionProducer (step / task / crew callbacks)."""

from __future__ import annotations

from dataclasses import dataclass

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.crewai import (
    CrewAIActionProducer,
    CrewAIEvent,
    _step_name,
    _task_name,
    _crew_name,
    _serializable,
)
from ancilis.producers.protocol import ActionProducer, ProducerType


def _config() -> object:
    raw = {"agent": {"name": "crew-agent", "owner": "test-owner"}}
    return load_config(raw=raw)


def _make() -> tuple[CrewAIActionProducer, EvidenceStore]:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    return CrewAIActionProducer(config=config, engine=Engine(config), evidence_store=store), store


@dataclass
class _StepLike:
    tool: str = ""
    agent_role: str = ""


@dataclass
class _TaskLike:
    description: str = ""


@dataclass
class _CrewLike:
    name: str = ""


class _Pydanticish:
    def __init__(self, name: str) -> None:
        self.name = name

    def model_dump(self) -> dict[str, str]:
        return {"name": self.name}


class TestNameExtraction:
    def test_step_name_prefers_tool_attribute(self) -> None:
        assert _step_name(_StepLike(tool="search"), "fb") == "search"

    def test_step_name_falls_back_to_agent_role(self) -> None:
        assert _step_name(_StepLike(agent_role="researcher"), "fb") == "researcher"

    def test_step_name_uses_dict_keys(self) -> None:
        assert _step_name({"tool": "calc"}, "fb") == "calc"

    def test_step_name_falls_back_when_unknown(self) -> None:
        assert _step_name(object(), "fallback") == "fallback"

    def test_task_name_uses_description(self) -> None:
        assert _task_name(_TaskLike(description="research"), "fb") == "research"

    def test_crew_name_uses_name_attribute(self) -> None:
        assert _crew_name(_CrewLike(name="market-research"), "fb") == "market-research"


class TestSerializable:
    def test_primitives_pass_through(self) -> None:
        assert _serializable("a") == "a"
        assert _serializable(42) == 42
        assert _serializable([1, 2]) == [1, 2]
        assert _serializable({"k": 1}) == {"k": 1}

    def test_pydantic_like_uses_model_dump(self) -> None:
        assert _serializable(_Pydanticish("x")) == {"name": "x"}

    def test_unknown_object_falls_back_to_repr(self) -> None:
        class Opaque:
            def __repr__(self) -> str:
                return "<opaque>"

        assert _serializable(Opaque()) == "<opaque>"


class TestProducerProtocol:
    def test_satisfies_protocol(self) -> None:
        producer, _ = _make()
        assert isinstance(producer, ActionProducer)
        assert producer.producer_type is ProducerType.FRAMEWORK
        assert producer.producer_version == "0.1.0"

    def test_translate_step_event_emits_tool_call_action(self) -> None:
        producer, _ = _make()
        action = producer.translate(
            CrewAIEvent(kind="step", name="search", agent_name="crew-agent")
        )
        assert action.action_type == "tool_call"
        assert action.tool.name == "crewai:step:search"

    def test_translate_task_event_emits_api_request(self) -> None:
        producer, _ = _make()
        action = producer.translate(
            CrewAIEvent(kind="task", name="research", agent_name="crew-agent")
        )
        assert action.action_type == "api_request"
        assert action.tool.name == "crewai:task:research"


class TestCallbackFactories:
    def test_step_callback_records_evidence(self) -> None:
        producer, store = _make()
        cb = producer.step_callback("researcher")
        cb(_StepLike(tool="search"))
        assert store.get_summary()["total_evaluations"] == 1

    def test_task_callback_records_evidence(self) -> None:
        producer, store = _make()
        cb = producer.task_callback("researcher")
        cb(_TaskLike(description="market research"))
        assert store.get_summary()["total_evaluations"] == 1

    def test_crew_callback_records_evidence(self) -> None:
        producer, store = _make()
        cb = producer.crew_callback("crew-agent")
        cb(_CrewLike(name="finalizer"))
        assert store.get_summary()["total_evaluations"] == 1

    def test_callbacks_chain_for_full_crew_run(self) -> None:
        producer, store = _make()
        step_cb = producer.step_callback("researcher")
        task_cb = producer.task_callback("research-task")
        crew_cb = producer.crew_callback("crew-1")
        step_cb(_StepLike(tool="search"))
        step_cb(_StepLike(tool="summarize"))
        task_cb(_TaskLike(description="research"))
        crew_cb(_CrewLike(name="market-research"))
        assert store.get_summary()["total_evaluations"] == 4

    def test_factory_uses_default_agent_name(self) -> None:
        producer, store = _make()
        cb = producer.step_callback()
        cb(_StepLike(tool="search"))
        assert store.get_summary()["total_evaluations"] == 1


class TestExportFromPackage:
    def test_lazy_re_export(self) -> None:
        from ancilis import producers as p

        assert p.CrewAIActionProducer is CrewAIActionProducer
        assert p.CrewAIEvent is CrewAIEvent
