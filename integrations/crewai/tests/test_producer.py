"""Tests for CrewAIProducer.translate()."""

from __future__ import annotations

from typing import Any

import pytest


def test_translate_crew_start(crew_start_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer(agent_id="test-agent")
    action = producer.translate(crew_start_raw)

    assert action.tool.name == "ResearchCrew"
    assert action.tool.server == "crewai"
    assert action.agent_id == "test-agent"
    assert action.parameters.raw["event"] == "crew_start"
    assert action.parameters.raw["agent_count"] == 2
    assert action.parameters.raw["task_count"] == 3


def test_translate_crew_end(crew_end_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(crew_end_raw)

    assert action.parameters.raw["event"] == "crew_end"
    # Output length captured, not content
    assert action.parameters.raw["output_length"] == len("Final report with 500 words.")
    assert "Final report" not in str(action.parameters.raw)


def test_translate_task_start(task_start_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(task_start_raw)

    assert action.tool.name == "task:researcher"
    assert action.parameters.raw["event"] == "task_start"
    assert action.parameters.raw["agent_role"] == "researcher"
    assert action.parameters.raw["task_description_length"] == len("Research the topic")
    assert action.parameters.raw["expected_output_length"] == len("A detailed report")
    # Actual content not stored
    assert "Research the topic" not in str(action.parameters.raw["task_description_length"])


def test_translate_task_end(task_end_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(task_end_raw)

    assert action.parameters.raw["event"] == "task_end"
    assert action.parameters.raw["output_length"] == len("Completed research with 300 words.")


def test_translate_tool_use(tool_use_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(tool_use_raw)

    assert action.tool.name == "web_search"
    assert action.parameters.raw["event"] == "tool_use"
    assert action.parameters.raw["tool_name"] == "web_search"
    assert action.parameters.raw["tool_input_preview"] == "latest AI news"
    assert action.parameters.raw["tool_input_length"] == len("latest AI news")


def test_translate_tool_use_truncates_long_input():
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    long_input = "x" * 1000
    raw = {
        "event": "tool_use",
        "tool_name": "search",
        "tool_input": long_input,
        "execution_id": "abc",
    }
    action = producer.translate(raw)
    assert len(action.parameters.raw["tool_input_preview"]) == 512
    assert action.parameters.raw["tool_input_length"] == 1000


def test_translate_delegation(delegation_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(delegation_raw)

    assert action.tool.name == "delegation"
    assert action.parameters.raw["event"] == "delegation"
    assert action.parameters.raw["from_agent"] == "researcher"
    assert action.parameters.raw["to_agent"] == "writer"
    assert action.parameters.raw["delegated_task_length"] == len("Write the report")


def test_parameter_hash_set(crew_start_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(crew_start_raw)
    assert action.parameters.parameter_hash != ""


def test_session_id_in_context():
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer(session_id="sess-999")
    raw = {"event": "crew_start", "crew_name": "X", "execution_id": "e1"}
    action = producer.translate(raw)
    assert action.context.session_id == "sess-999"


def test_action_id_is_execution_id(crew_start_raw):
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(crew_start_raw)
    assert action.action_id == "abc123"


def test_output_content_not_in_params(crew_end_raw):
    """crew_end should store output_length, not raw output text."""
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    action = producer.translate(crew_end_raw)
    assert "Final report" not in str(action.parameters.raw)
    assert "output_length" in action.parameters.raw
