"""Tests for BedrockActionProducer (Python parity with TS)."""

from __future__ import annotations

import json

import pytest

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.bedrock import (
    BedrockActionProducer,
    BedrockAdapter,
    BedrockInvocation,
    _model_metadata,
)
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.tool import BlockedActionError


def _config(*, mode: str = "audit", tools_allowed: list[str] | None = None) -> object:
    raw = {
        "agent": {"name": "bedrock-agent", "owner": "test-owner"},
        "security": {"mode": mode, "tools": {"allowed": tools_allowed or []}},
    }
    return load_config(raw=raw)


def _make(*, mode: str = "audit", tools_allowed: list[str] | None = None) -> tuple[BedrockActionProducer, EvidenceStore]:
    config = _config(mode=mode, tools_allowed=tools_allowed)
    store = EvidenceStore(config, in_memory=True)
    producer = BedrockActionProducer(config=config, engine=Engine(config), evidence_store=store)
    return producer, store


class TestProtocol:
    def test_satisfies_protocol(self) -> None:
        producer, _ = _make()
        assert isinstance(producer, ActionProducer)
        assert producer.producer_type is ProducerType.FRAMEWORK
        assert producer.producer_version == "0.1.0"

    def test_alias_matches_class(self) -> None:
        assert BedrockAdapter is BedrockActionProducer


class TestModelMetadata:
    @pytest.mark.parametrize(
        "model_id,family,provider",
        [
            ("anthropic.claude-sonnet-4-6", "anthropic.claude", "anthropic"),
            ("us.anthropic.claude-3-5-sonnet-v1", "anthropic.claude", "anthropic"),
            ("amazon.titan-text-express-v1", "amazon.titan", "amazon"),
            ("meta.llama3-70b-v1", "meta.llama3-70b-v1", "meta"),
            ("unknown-model", "unknown", "unknown"),
        ],
    )
    def test_family_provider_extraction(self, model_id: str, family: str, provider: str) -> None:
        meta = _model_metadata(model_id)
        assert meta["provider"] == provider
        assert meta["family"] == family

    def test_inference_profile_arn_captured(self) -> None:
        arn = "arn:aws:bedrock:us-east-1:123:inference-profile/anthropic.claude-sonnet-4-6"
        meta = _model_metadata(arn)
        assert meta["inference_profile_arn"] == arn
        assert meta["family"] == "anthropic.claude"


class TestObserve:
    def test_observe_translates_dataclass_invocation(self) -> None:
        producer, store = _make()
        observation = producer.observe(
            BedrockInvocation(
                operation="InvokeModel",
                model_id="anthropic.claude-sonnet-4-6",
                region="us-east-1",
                request_body=json.dumps({"messages": [{"role": "user", "content": "hi"}]}),
                response_body=json.dumps(
                    {"content": [{"type": "text", "text": "hello"}], "usage": {"input_tokens": 5, "output_tokens": 2}}
                ),
                http_status=200,
                request_id="req-123",
            )
        )
        assert observation.action.tool.name == "aws-bedrock:InvokeModel"
        assert observation.action.tool.server == "bedrock-runtime.us-east-1.amazonaws.com"
        payload = observation.action.parameters.raw
        assert payload["model"]["family"] == "anthropic.claude"
        assert payload["input_tokens"] == 5
        assert payload["output_tokens"] == 2
        assert payload["request_id"] == "req-123"
        assert store.get_summary()["total_evaluations"] == 1

    def test_observe_translates_mapping_with_camelcase_keys(self) -> None:
        producer, _ = _make()
        observation = producer.observe(
            {
                "operation": "InvokeModelWithResponseStream",
                "modelId": "amazon.titan-text-express-v1",
                "regionName": "eu-west-1",
                "responseMetadata": {
                    "RequestId": "abc",
                    "HTTPStatusCode": 200,
                    "HTTPHeaders": {"x-amzn-requestid": "abc"},
                },
                "streamChunks": [{"chunk": 1}, {"chunk": 2}],
            }
        )
        payload = observation.action.parameters.raw
        assert payload["operation"] == "InvokeModelWithResponseStream"
        assert payload["streaming"] is True
        assert payload["stream"]["chunk_count"] == 2
        assert payload["request_id"] == "abc"
        assert payload["http_status"] == 200
        assert observation.action.tool.server == "bedrock-runtime.eu-west-1.amazonaws.com"

    def test_default_endpoint_when_no_region(self) -> None:
        producer, _ = _make()
        observation = producer.observe(BedrockInvocation(model_id="amazon.titan-text-express-v1"))
        assert observation.action.tool.server == "bedrock-runtime.amazonaws.com"

    def test_register_tools_seeds_both_operations(self) -> None:
        producer, _ = _make()
        registered = producer.register_tools(producer._registry)
        assert "aws-bedrock:InvokeModel" in registered
        assert "aws-bedrock:InvokeModelWithResponseStream" in registered


class TestExecuteAndWrap:
    def test_execute_calls_transport_in_audit(self) -> None:
        producer, _ = _make()

        def fake_invoke(**_: object) -> dict[str, str]:
            return {"body": "ok"}

        result = producer.execute(
            BedrockInvocation(model_id="anthropic.claude-sonnet-4-6"),
            transport=fake_invoke,
            transport_kwargs={"modelId": "anthropic.claude-sonnet-4-6", "body": b"{}"},
        )
        assert result.response == {"body": "ok"}
        assert result.blocked is False

    def test_enforce_blocks_disallowed_operation(self) -> None:
        allowed = "aws-bedrock:InvokeModel"
        producer, _ = _make(mode="enforce", tools_allowed=[allowed])

        called: list[str] = []

        def fake_invoke(**kwargs: object) -> dict[str, str]:
            called.append(str(kwargs.get("modelId")))
            return {"body": "ok"}

        wrapped = producer.wrap_invoke_model(fake_invoke, agent_name="bedrock-agent", enforce=True)
        ok = wrapped(modelId="anthropic.claude-sonnet-4-6", body=b"{}")
        assert ok.response == {"body": "ok"}
        assert called == ["anthropic.claude-sonnet-4-6"]

        # Streaming-op wrap is not allowed by config -> BLOCK -> raise
        wrapped_stream = producer.wrap_invoke_model(
            fake_invoke,
            agent_name="bedrock-agent",
            operation="InvokeModelWithResponseStream",
            enforce=True,
        )
        with pytest.raises(BlockedActionError):
            wrapped_stream(modelId="anthropic.claude-sonnet-4-6", body=b"{}")
        assert called == ["anthropic.claude-sonnet-4-6"]

    def test_lazy_export_from_package(self) -> None:
        from ancilis import producers as p

        assert p.BedrockActionProducer is BedrockActionProducer
        assert p.BedrockInvocation is BedrockInvocation
        assert p.BedrockAdapter is BedrockAdapter
