from __future__ import annotations

import hashlib
import json

from ancilis.adapters.openai_assistants import (
    OpenAIAssistantsActionProducer,
    OpenAIAssistantsInvocation,
)
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType


def _producer() -> OpenAIAssistantsActionProducer:
    config = load_config(raw={"agent": {"name": "openai-assistants-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return OpenAIAssistantsActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
    )


def _run_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "id": "run_abc123",
        "thread_id": "thread_xyz",
        "assistant_id": "asst_123",
        "model": "gpt-4o-2024-08-06",
        "status": "completed",
        "tools": [],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }
    body.update(overrides)
    return body


def test_translate_runs_create_minimal() -> None:
    producer = _producer()

    action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.create",
            thread_id="thread_xyz",
            assistant_id="asst_123",
            run_body=_run_body(),
            http_status=200,
            request_id="req_assistants_1",
            latency_ms=12.5,
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "openai-assistants:Runs.create"
    assert action.tool.server == "api.openai.com"
    assert action.action_type == "api_request"
    assert action.producer_type == ProducerType.FRAMEWORK.value
    assert raw["provider"] == "openai-assistants"
    assert raw["operation"] == "Runs.create"
    assert raw["model"] == "gpt-4o-2024-08-06"
    assert raw["model_id"] == "gpt-4o-2024-08-06"
    assert raw["endpoint_host"] == "api.openai.com"
    assert raw["custom_base_url"] is False
    assert raw["http_status"] == 200
    assert raw["request_id"] == "req_assistants_1"
    assert raw["latency_ms"] == 12.5
    assert raw["thread_id"] == "thread_xyz"
    assert raw["assistant_id"] == "asst_123"
    assert raw["run_id"] == "run_abc123"
    assert raw["status"] == "completed"
    assert raw["terminal_status"] is False
    assert raw["prompt_tokens"] == 10
    assert raw["completion_tokens"] == 20
    assert raw["total_tokens"] == 30
    assert raw["input_tokens"] == 10
    assert raw["output_tokens"] == 20
    assert raw["deployment"]["model_family"] == "gpt-4o"
    assert raw["code_interpreter_used"] is False
    assert raw["file_search_used"] is False
    assert raw["function_tool_used"] is False
    assert isinstance(producer, ActionProducer)


def test_observe_emits_evidence() -> None:
    producer = _producer()

    observation = producer.observe(
        {
            "operation": "Runs.create",
            "thread_id": "thread_xyz",
            "assistant_id": "asst_456",
            "run_body": _run_body(model="gpt-4.1-mini"),
        }
    )

    assert observation.action.tool.name == "openai-assistants:Runs.create"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "openai-assistants:Runs.create"
    assert "openai-assistants Runs.create gpt-4.1-mini" in observation.evidence.output_summary
    assert "status=completed" in observation.evidence.output_summary


def test_status_failed_captured_in_payload() -> None:
    producer = _producer()
    body = _run_body(
        status="failed",
        last_error={"code": "rate_limit_exceeded", "message": "internal error blob"},
    )

    action = producer.translate(
        OpenAIAssistantsInvocation(operation="Runs.retrieve", run_body=body)
    )

    raw = action.parameters.raw
    assert raw["status"] == "failed"
    assert raw["terminal_status"] is True
    assert raw["last_error"]["code"] == "rate_limit_exceeded"
    assert raw["last_error"]["message_present"] is True
    # We surface message length but never the message text itself.
    serialized = json.dumps(raw)
    assert "internal error blob" not in serialized
    assert "DE-01" in raw["control_surfacing"]
    assert "PR-05" in raw["control_surfacing"]


def test_status_expired_captured_in_payload() -> None:
    producer = _producer()
    body = _run_body(
        status="expired",
        incomplete_details={"reason": "max_completion_tokens"},
    )

    action = producer.translate(
        OpenAIAssistantsInvocation(operation="Runs.retrieve", run_body=body)
    )

    raw = action.parameters.raw
    assert raw["status"] == "expired"
    assert raw["terminal_status"] is True
    assert raw["incomplete_details"]["reason"] == "max_completion_tokens"
    assert "DE-01" in raw["control_surfacing"]
    assert "PR-05" in raw["control_surfacing"]


def test_code_interpreter_use_surfaced() -> None:
    producer = _producer()
    body = _run_body(
        tools=[{"type": "code_interpreter"}],
    )
    steps = [
        {
            "id": "step_1",
            "type": "tool_calls",
            "step_details": {
                "type": "tool_calls",
                "tool_calls": [
                    {
                        "id": "tc_1",
                        "type": "code_interpreter",
                        "code_interpreter": {
                            "input": "print('exfil')",
                            "outputs": [{"type": "logs", "logs": "exfil"}],
                        },
                    }
                ],
            },
            "usage": {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10},
        }
    ]

    action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.steps.list", run_body=body, steps=steps
        )
    )

    raw = action.parameters.raw
    assert raw["code_interpreter_used"] is True
    assert raw["steps"]["code_interpreter_executions"] == 1
    assert "PR-03" in raw["control_surfacing"]
    serialized = json.dumps(raw)
    # We do not store the raw code or its output.
    assert "print('exfil')" not in serialized
    assert "exfil" not in raw.get("steps", {}).get("function_tool_names", [])


def test_file_search_use_surfaced() -> None:
    producer = _producer()
    body = _run_body(
        tools=[{"type": "file_search"}],
    )
    steps = [
        {
            "id": "step_2",
            "type": "tool_calls",
            "step_details": {
                "type": "tool_calls",
                "tool_calls": [
                    {
                        "id": "tc_2",
                        "type": "file_search",
                        "file_search": {
                            "ranking_options": {"score_threshold": 0.7},
                            "results": [
                                {"file_id": "file_aaa", "score": 0.9},
                                {"file_id": "file_bbb", "score": 0.8},
                                {"file_id": "file_ccc", "score": 0.75},
                            ],
                        },
                    }
                ],
            },
        }
    ]

    action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.steps.list", run_body=body, steps=steps
        )
    )

    raw = action.parameters.raw
    assert raw["file_search_used"] is True
    assert raw["steps"]["file_search_invocations"] == 1
    assert raw["steps"]["file_search_total_results"] == 3
    assert "PR-04" in raw["control_surfacing"]


def test_function_tool_args_sanitized() -> None:
    producer = _producer()
    body = _run_body(
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "lookup_customer",
                    "description": "lookup",
                },
            }
        ],
    )
    secret_args = {"customer_ssn": "123-45-6789", "email": "victim@example.com"}
    steps = [
        {
            "id": "step_3",
            "type": "tool_calls",
            "step_details": {
                "type": "tool_calls",
                "tool_calls": [
                    {
                        "id": "tc_3",
                        "type": "function",
                        "function": {
                            "name": "lookup_customer",
                            "arguments": json.dumps(secret_args),
                        },
                    }
                ],
            },
        }
    ]

    action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.steps.list", run_body=body, steps=steps
        )
    )

    raw = action.parameters.raw
    assert raw["function_tool_used"] is True
    fn_summaries = raw["function_arguments"]
    assert len(fn_summaries) == 1
    summary = fn_summaries[0]
    assert summary["name"] == "lookup_customer"
    assert sorted(summary["top_level_keys"]) == ["customer_ssn", "email"]
    expected_hash = hashlib.sha256(json.dumps(secret_args).encode()).hexdigest()
    assert summary["argument_sha256"] == expected_hash
    assert summary["argument_length"] == len(json.dumps(secret_args))
    serialized = json.dumps(raw)
    # Raw values must never appear in the payload.
    assert "123-45-6789" not in serialized
    assert "victim@example.com" not in serialized


def test_instructions_field_redacted() -> None:
    producer = _producer()
    secret_instructions = (
        "You are a financial agent. The shared API key is sk-INSTRUCTIONLEAK."
    )
    body = _run_body(instructions=secret_instructions)

    action = producer.translate(
        OpenAIAssistantsInvocation(operation="Runs.create", run_body=body)
    )

    raw = action.parameters.raw
    assert raw["instructions"]["length"] == len(secret_instructions)
    assert raw["instructions"]["sha256"] == hashlib.sha256(
        secret_instructions.encode()
    ).hexdigest()
    serialized = json.dumps(raw)
    assert secret_instructions not in serialized
    assert "sk-INSTRUCTIONLEAK" not in serialized


def test_step_usage_summed_across_steps() -> None:
    producer = _producer()
    body = _run_body(
        # Run-level usage will be overwritten by step aggregate when present.
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    )
    steps = [
        {
            "id": "s1",
            "type": "message_creation",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
        {
            "id": "s2",
            "type": "tool_calls",
            "usage": {"prompt_tokens": 4, "completion_tokens": 11, "total_tokens": 15},
            "step_details": {"type": "tool_calls", "tool_calls": []},
        },
        {
            "id": "s3",
            "type": "message_creation",
            "usage": {"prompt_tokens": 6, "completion_tokens": 4, "total_tokens": 10},
        },
    ]

    action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.steps.list", run_body=body, steps=steps
        )
    )

    raw = action.parameters.raw
    assert raw["prompt_tokens"] == 20
    assert raw["completion_tokens"] == 20
    assert raw["total_tokens"] == 40
    assert raw["input_tokens"] == 20
    assert raw["output_tokens"] == 20
    assert raw["steps"]["count"] == 3
    assert "message_creation" in raw["steps"]["types"]
    assert "tool_calls" in raw["steps"]["types"]


def test_truncation_strategy_captured() -> None:
    producer = _producer()
    body = _run_body(
        truncation_strategy={"type": "last_messages", "last_messages": 4},
        parallel_tool_calls=True,
        response_format={"type": "json_object"},
    )

    action = producer.translate(
        OpenAIAssistantsInvocation(operation="Runs.create", run_body=body)
    )

    raw = action.parameters.raw
    assert raw["truncation_strategy"]["type"] == "last_messages"
    assert raw["truncation_strategy"]["audit_completeness_flag"] is True
    assert raw["parallel_tool_calls"] is True
    assert raw["response_format"] == {"type": "json_object"}
    assert "PR-05" in raw["control_surfacing"]


def test_auth_modes_detected() -> None:
    producer = _producer()

    # api_key — sk-* on default OpenAI endpoint
    api_key_action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.create",
            run_body=_run_body(),
            headers={"x-api-key": "sk-test-1234"},
        )
    )
    assert api_key_action.parameters.raw["auth_mode"] == "api_key"

    # bearer — Bearer header without sk- prefix
    bearer_action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.create",
            run_body=_run_body(),
            headers={"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.token"},
        )
    )
    assert bearer_action.parameters.raw["auth_mode"] == "bearer"

    # bring_your_own — custom (non-OpenAI) base_url
    byok_action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.create",
            run_body=_run_body(),
            headers={"authorization": "Bearer sk-internal"},
            base_url="https://together.example.com/v1",
        )
    )
    raw = byok_action.parameters.raw
    assert raw["auth_mode"] == "bring_your_own"
    assert raw["custom_base_url"] is True
    assert raw["endpoint_host"] == "together.example.com"

    # Explicit auth_mode override
    explicit = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.create",
            run_body=_run_body(),
            auth_mode="bring-your-own",
        )
    )
    assert explicit.parameters.raw["auth_mode"] == "bring_your_own"


def test_register_tools() -> None:
    producer = _producer()
    registry = ToolRegistry()

    registered = producer.register_tools(registry)

    assert registered == [
        "openai-assistants:Runs.create",
        "openai-assistants:Runs.retrieve",
        "openai-assistants:Runs.steps.list",
        "openai-assistants:Runs.cancel",
        "openai-assistants:Threads.messages.create",
    ]
    for name in registered:
        entry = registry.lookup(name)
        assert entry is not None
        assert entry.description_hash == producer.compute_tool_hash(name)


def test_sensitive_headers_not_leaked() -> None:
    producer = _producer()

    action = producer.translate(
        OpenAIAssistantsInvocation(
            operation="Runs.create",
            run_body=_run_body(),
            headers={
                "x-api-key": "sk-leak-1",
                "authorization": "Bearer sk-leak-2",
                "openai-api-key": "sk-leak-3",
            },
        )
    )

    serialized = json.dumps(action.parameters.raw)
    assert "sk-leak-1" not in serialized
    assert "sk-leak-2" not in serialized
    assert "sk-leak-3" not in serialized
