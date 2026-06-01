"""Tests for ancilis_dspy._producer.DSPyProducer.translate()."""

from __future__ import annotations

import hashlib

from ancilis_dspy import DSPyProducer

from conftest import MockExample, MockPrediction


def _producer() -> DSPyProducer:
    return DSPyProducer(agent_id="dspy-1", session_id="sess-1")


def test_lm_call_event_maps_to_tool_call() -> None:
    p = _producer()
    action = p.translate(
        {
            "kind": "lm_call",
            "id": "call-7",
            "lm_name": "openai/gpt-4o",
            "model": "openai/gpt-4o",
            "prompt": "what is 2+2?",
            "completion": "4",
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 3,
                "total_tokens": 13,
            },
        }
    )
    assert action.action_type == "tool_call"
    assert action.tool.name == "dspy:lm:openai/gpt-4o"
    assert action.tool.server == "dspy"
    assert action.action_id == "call-7"
    # Prompt + completion are sanitized — only length + sha256.
    assert action.parameters.raw["prompt_length"] == len("what is 2+2?")
    assert (
        action.parameters.raw["prompt_sha256"]
        == hashlib.sha256(b"what is 2+2?").hexdigest()
    )
    assert "what is 2+2?" not in repr(action.parameters.raw)
    assert action.parameters.raw["usage"]["total_tokens"] == 13


def test_module_call_event_maps_to_tool_call_with_sanitized_io() -> None:
    p = _producer()
    inputs = MockExample(
        question="what is the SSN for 999-00-1234?",
        context="kevin@example.com",
    )
    outputs = MockPrediction(answer="999-00-1234", rationale="from ledger")
    action = p.translate(
        {
            "kind": "module_call",
            "id": "mod-1",
            "module_name": "ChainOfThought",
            "inputs": inputs,
            "outputs": outputs,
        }
    )
    assert action.action_type == "tool_call"
    assert action.tool.name == "dspy:module:ChainOfThought"
    rendered = repr(action.parameters.raw)
    # PII never leaks.
    assert "999-00-1234" not in rendered
    assert "kevin@example.com" not in rendered
    assert "from ledger" not in rendered
    # Field names + count + values_sha256 are recorded.
    assert sorted(action.parameters.raw["inputs"]["field_names"]) == [
        "context",
        "question",
    ]
    assert action.parameters.raw["inputs"]["field_count"] == 2
    assert action.parameters.raw["inputs"]["values_sha256"]
    assert action.parameters.raw["outputs"]["field_count"] == 2


def test_evaluate_event_records_score_and_dataset_size() -> None:
    p = _producer()
    action = p.translate(
        {
            "kind": "evaluate",
            "id": "ev-1",
            "metric_name": "accuracy",
            "dataset_size": 50,
            "score": 0.84,
        }
    )
    assert action.action_type == "tool_call"
    assert action.tool.name == "dspy:evaluate:accuracy"
    assert action.parameters.raw["dataset_size"] == 50
    # Score IS captured — optimization scores are posture-relevant.
    assert action.parameters.raw["score"] == 0.84


def test_compile_event_with_trainset_sanitizes() -> None:
    p = _producer()
    trainset = [
        MockExample(q="ssn 111-22-3333", a="redacted"),
        MockExample(q="card 4111111111111111", a="redacted"),
    ]
    action = p.translate(
        {
            "kind": "compile",
            "id": "compile-1",
            "optimizer": "BootstrapFewShot",
            "trainset": trainset,
            "score": 0.71,
            "step": 3,
        }
    )
    assert action.action_type == "tool_call"
    assert action.tool.name == "dspy:compile:BootstrapFewShot"
    rendered = repr(action.parameters.raw)
    # Training-set values never leak.
    assert "111-22-3333" not in rendered
    assert "4111111111111111" not in rendered
    # Size + sha256 only.
    assert action.parameters.raw["trainset_size"] == 2
    assert action.parameters.raw["trainset_sha256"]
    assert len(action.parameters.raw["trainset_sha256"]) == 64
    # Score + step captured numerically.
    assert action.parameters.raw["score"] == 0.71
    assert action.parameters.raw["step"] == 3


def test_retrieve_event_maps_to_data_access_with_sanitized_query() -> None:
    p = _producer()
    secret_query = "user records for ssn 999-00-1234"
    action = p.translate(
        {
            "kind": "retrieve",
            "id": "ret-1",
            "rm_name": "colbertv2",
            "query": secret_query,
            "k": 5,
            "results": [{"id": "p1"}, {"id": "p2"}],
        }
    )
    assert action.action_type == "data_access"
    assert action.tool.name == "dspy:retrieve:colbertv2"
    assert action.parameters.raw["k"] == 5
    assert action.parameters.raw["result_count"] == 2
    rendered = repr(action.parameters.raw)
    # Raw query value never leaks.
    assert "999-00-1234" not in rendered
    assert action.parameters.raw["query_length"] == len(secret_query)
    assert (
        action.parameters.raw["query_sha256"]
        == hashlib.sha256(secret_query.encode()).hexdigest()
    )


def test_dspy_example_field_sanitization() -> None:
    """dspy.Example values must never appear in evidence."""
    p = _producer()
    secret_value = "supersecret-token-XYZ"
    inputs = MockExample(token=secret_value, user_id="u-99")
    action = p.translate(
        {"kind": "module_call", "module_name": "Predict", "inputs": inputs}
    )
    rendered = repr(action.parameters.raw)
    assert secret_value not in rendered
    # But the field NAMES are recorded.
    assert "token" in rendered
    assert "user_id" in rendered
    assert action.parameters.raw["inputs"]["field_names"] == ["token", "user_id"]


def test_dspy_prediction_field_sanitization() -> None:
    """dspy.Prediction values must never appear in evidence."""
    p = _producer()
    secret_pred = "leaked-credit-card 4111111111111111"
    outputs = MockPrediction(answer=secret_pred, confidence=0.99)
    action = p.translate(
        {"kind": "module_call", "module_name": "Predict", "outputs": outputs}
    )
    rendered = repr(action.parameters.raw)
    assert "4111111111111111" not in rendered
    assert action.parameters.raw["outputs"]["field_names"] == [
        "answer",
        "confidence",
    ]


def test_trainset_size_only_when_no_examples_supplied() -> None:
    """If only trainset_size is given (not the trainset), still capture cleanly."""
    p = _producer()
    action = p.translate(
        {
            "kind": "compile",
            "optimizer": "MIPROv2",
            "trainset_size": 100,
            "score": 0.91,
        }
    )
    assert action.parameters.raw["trainset_size"] == 100
    # No raw trainset → no trainset_sha256 either.
    assert "trainset_sha256" not in action.parameters.raw


def test_lm_call_exception_capture_records_error_type() -> None:
    p = _producer()
    err = ValueError("rate limit")
    action = p.translate(
        {
            "kind": "lm_call",
            "lm_name": "openai/gpt-4o",
            "prompt": "hi",
            "error": err,
        }
    )
    assert action.parameters.raw["error_type"] == "ValueError"


def test_lm_call_with_chat_messages_format() -> None:
    """DSPy LM calls may pass messages=[{role, content}, ...]."""
    p = _producer()
    secret = "user account 9876"
    action = p.translate(
        {
            "kind": "lm_call",
            "lm_name": "anthropic/claude",
            "prompt": [
                {"role": "user", "content": secret},
                {"role": "assistant", "content": "ok"},
            ],
        }
    )
    rendered = repr(action.parameters.raw)
    assert secret not in rendered
    assert action.parameters.raw["prompt_length"] >= len(secret)


def test_unknown_event_falls_back_to_tool_call() -> None:
    p = _producer()
    action = p.translate({"kind": "weird_new_event", "id": "x-1"})
    assert action.action_type == "tool_call"
    assert action.parameters.raw["semantic_kind"] == "unknown"
    assert action.tool.server == "dspy"


def test_producer_metadata_fields() -> None:
    assert DSPyProducer.producer_type == "framework"
    assert DSPyProducer.producer_version == "0.1.0"
    p = _producer()
    action = p.translate({"kind": "lm_call", "id": "x", "lm_name": "lm"})
    assert action.producer_type == "framework"
    assert action.producer_version == "0.1.0"
    assert action.context.session_id == "sess-1"


def test_parent_call_id_correlation() -> None:
    """Parent call ids are propagated into the action context."""
    p = _producer()
    action = p.translate(
        {
            "kind": "lm_call",
            "id": "child-1",
            "lm_name": "lm",
            "parent_call_id": "parent-99",
        }
    )
    assert action.context.parent_action_id == "parent-99"
    assert action.parameters.raw["parent_call_id"] == "parent-99"
