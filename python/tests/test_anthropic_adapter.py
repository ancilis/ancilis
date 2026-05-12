from __future__ import annotations

import json

from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.adapters.anthropic import (
    AnthropicActionProducer,
    AnthropicInvocation,
)


def _producer() -> AnthropicActionProducer:
    config = load_config(raw={"agent": {"name": "anthropic-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return AnthropicActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
    )


def test_anthropic_producer_satisfies_protocol_without_anthropic_sdk() -> None:
    import ancilis

    producer = _producer()

    assert isinstance(producer, ActionProducer)
    assert producer.producer_type == ProducerType.FRAMEWORK
    assert ancilis.AnthropicActionProducer is AnthropicActionProducer


def test_translate_messages_create() -> None:
    producer = _producer()

    action = producer.translate(
        AnthropicInvocation(
            operation="Messages.create",
            model="claude-opus-4-5-20250929",
            request_body={
                "model": "claude-opus-4-5-20250929",
                "messages": [{"role": "user", "content": "sensitive prompt"}],
                "max_tokens": 64,
            },
            response_body={
                "id": "msg_anthropic_1",
                "type": "message",
                "model": "claude-opus-4-5-20250929",
                "usage": {
                    "input_tokens": 12,
                    "output_tokens": 34,
                },
            },
            http_status=200,
            request_id="req_011anthropic",
            latency_ms=88.0,
            headers={"x-api-key": "sk-ant-secret"},
            agent_id="anthropic-agent",
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "anthropic:Messages.create"
    assert action.tool.server == "api.anthropic.com"
    assert action.action_type == "api_request"
    assert action.producer_type == "framework"
    assert raw["provider"] == "anthropic"
    assert raw["operation"] == "Messages.create"
    assert raw["model"] == "claude-opus-4-5-20250929"
    assert raw["model_id"] == "claude-opus-4-5-20250929"
    assert raw["endpoint_host"] == "api.anthropic.com"
    assert raw["custom_base_url"] is False
    assert raw["latency_ms"] == 88.0
    assert raw["request_id"] == "req_011anthropic"
    assert raw["http_status"] == 200
    assert raw["input_tokens"] == 12
    assert raw["output_tokens"] == 34
    assert raw["auth_mode"] == "api_key"
    assert raw["streaming"] is False
    assert raw["deployment"]["provider"] == "anthropic"
    assert raw["deployment"]["model_family"] == "claude-opus"
    assert raw["request"]["body_keys"] == ["max_tokens", "messages", "model"]
    serialized = json.dumps(raw)
    assert "sensitive prompt" not in serialized
    assert "sk-ant-secret" not in serialized


def test_observe_emits_evidence() -> None:
    producer = _producer()

    observation = producer.observe(
        {
            "operation": "Messages.create",
            "model": "claude-haiku-4-5",
            "response_body": {
                "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 1, "output_tokens": 2},
            },
        }
    )

    assert observation.action.tool.name == "anthropic:Messages.create"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "anthropic:Messages.create"
    assert "anthropic Messages.create claude-haiku-4-5" in observation.evidence.output_summary


def test_streaming_aggregates_usage() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Messages.stream",
            "model": "claude-sonnet-4-5",
            "request_body": {"messages": [{"role": "user", "content": "stream prompt secret"}]},
            "stream_chunks": [
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_stream_1",
                        "model": "claude-sonnet-4-5",
                        "usage": {"input_tokens": 7, "output_tokens": 0},
                    },
                },
                {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "streamed secret text"}},
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn"},
                    "usage": {"output_tokens": 21},
                },
            ],
            "http_status": 200,
            "latency_ms": 250,
            "agent_id": "anthropic-agent",
        }
    )

    raw = action.parameters.raw
    assert raw["operation"] == "Messages.stream"
    assert raw["streaming"] is True
    assert raw["stream"]["chunk_count"] == 3
    assert raw["input_tokens"] == 7
    assert raw["output_tokens"] == 21
    assert raw["request_id"] == "msg_stream_1"
    assert raw["model"] == "claude-sonnet-4-5"
    assert raw["deployment"]["model_family"] == "claude-sonnet"
    serialized = json.dumps(raw)
    assert "stream prompt secret" not in serialized
    assert "streamed secret text" not in serialized


def test_sensitive_headers_redacted() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Messages.create",
            "model": "claude-opus-4-5",
            "request_body": {
                "messages": [{"role": "user", "content": "hi"}],
                "x-api-key": "sk-ant-leak",
                "anthropic-api-key": "sk-ant-also-leak",
                "Authorization": "Bearer leak-token",
            },
            "response_body": {"usage": {"input_tokens": 1, "output_tokens": 2}},
            "headers": {
                "x-api-key": "sk-ant-secret-1",
                "anthropic-api-key": "sk-ant-secret-2",
                "authorization": "Bearer not-for-evidence",
            },
        }
    )

    body_keys = action.parameters.raw["request"]["body_keys"]
    assert "messages" in body_keys
    assert all("api" not in key.lower() for key in body_keys)
    assert all("authoriz" not in key.lower() for key in body_keys)

    assert action.parameters.raw["auth_mode"] == "api_key"
    serialized = json.dumps(action.parameters.raw).lower()
    assert "sk-ant-secret" not in serialized
    assert "sk-ant-also-leak" not in serialized
    assert "sk-ant-leak" not in serialized
    assert "not-for-evidence" not in serialized
    assert "leak-token" not in serialized


def test_register_tools() -> None:
    producer = _producer()
    registry = ToolRegistry()

    registered = producer.register_tools(registry)

    assert registered == ["anthropic:Messages.create", "anthropic:Messages.stream"]
    for name in registered:
        entry = registry.lookup(name)
        assert entry is not None
        assert entry.description_hash == producer.compute_tool_hash(name)


def test_cache_token_metrics_extracted() -> None:
    producer = _producer()

    action = producer.translate(
        AnthropicInvocation(
            operation="Messages.create",
            model="claude-sonnet-4-5",
            request_body={"messages": [{"role": "user", "content": "cached"}]},
            response_body={
                "model": "claude-sonnet-4-5",
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "cache_creation_input_tokens": 1024,
                    "cache_read_input_tokens": 2048,
                },
            },
        )
    )

    raw = action.parameters.raw
    assert raw["input_tokens"] == 100
    assert raw["output_tokens"] == 50
    assert raw["cache_creation_input_tokens"] == 1024
    assert raw["cache_read_input_tokens"] == 2048


def test_oauth_and_bearer_auth_modes() -> None:
    producer = _producer()

    bearer_action = producer.translate(
        {
            "operation": "Messages.create",
            "model": "claude-haiku-4-5",
            "response_body": {"usage": {"input_tokens": 1, "output_tokens": 2}},
            "headers": {"authorization": "Bearer abc123"},
        }
    )
    assert bearer_action.parameters.raw["auth_mode"] == "bearer"

    oauth_action = producer.translate(
        AnthropicInvocation(
            operation="Messages.create",
            model="claude-haiku-4-5",
            response_body={"usage": {"input_tokens": 1, "output_tokens": 2}},
            auth_mode="oauth",
        )
    )
    assert oauth_action.parameters.raw["auth_mode"] == "oauth"


def test_custom_base_url_inferred() -> None:
    producer = _producer()

    action = producer.translate(
        AnthropicInvocation(
            operation="Messages.create",
            model="claude-opus-4-5",
            response_body={"usage": {"input_tokens": 1, "output_tokens": 2}},
            base_url="https://anthropic-proxy.internal.example/v1",
        )
    )

    raw = action.parameters.raw
    assert raw["endpoint_host"] == "anthropic-proxy.internal.example"
    assert raw["custom_base_url"] is True
    assert action.tool.server == "anthropic-proxy.internal.example"
