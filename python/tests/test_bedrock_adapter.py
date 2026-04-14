from __future__ import annotations

import json

from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.adapters.bedrock import BedrockActionProducer, BedrockInvocation


def _producer() -> BedrockActionProducer:
    config = load_config(raw={"agent": {"name": "bedrock-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return BedrockActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
    )


def test_bedrock_producer_satisfies_protocol_without_boto3() -> None:
    import ancilis

    producer = _producer()

    assert isinstance(producer, ActionProducer)
    assert producer.producer_type == ProducerType.FRAMEWORK
    assert ancilis.BedrockActionProducer is BedrockActionProducer


def test_invoke_model_normalizes_claude_metadata() -> None:
    producer = _producer()

    action = producer.translate(
        BedrockInvocation(
            operation="InvokeModel",
            model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
            region="us-east-1",
            request_body={
                "anthropic_version": "bedrock-2023-05-31",
                "messages": [{"role": "user", "content": "sensitive prompt"}],
                "max_tokens": 64,
            },
            response_body={
                "id": "msg_123",
                "type": "message",
                "usage": {"input_tokens": 12, "output_tokens": 34},
            },
            http_status=200,
            request_id="req-123",
            latency_ms=87.5,
            headers={
                "Authorization": "AWS4-HMAC-SHA256 Credential=AKIASECRET/20260413/us-east-1/bedrock/aws4_request",
                "X-Amz-Security-Token": "session-token-secret",
            },
            agent_id="bedrock-agent",
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "aws-bedrock:InvokeModel"
    assert action.tool.server == "bedrock-runtime.us-east-1.amazonaws.com"
    assert action.action_type == "api_request"
    assert action.producer_type == "framework"
    assert raw["provider"] == "aws-bedrock"
    assert raw["operation"] == "InvokeModel"
    assert raw["model_id"] == "anthropic.claude-3-5-sonnet-20240620-v1:0"
    assert raw["region"] == "us-east-1"
    assert raw["latency_ms"] == 87.5
    assert raw["request_id"] == "req-123"
    assert raw["input_tokens"] == 12
    assert raw["output_tokens"] == 34
    assert raw["auth_mode"] == "session"
    assert raw["deployment"]["provider"] == "aws-bedrock"
    assert raw["deployment"]["model_family"] == "anthropic.claude"
    assert raw["request"]["body_keys"] == ["anthropic_version", "max_tokens", "messages"]
    assert "sensitive prompt" not in json.dumps(raw)
    assert "AKIASECRET" not in json.dumps(raw)
    assert "session-token-secret" not in json.dumps(raw)


def test_invoke_model_accepts_raw_boto_style_envelope_and_inference_profile_arn() -> None:
    producer = _producer()
    model_arn = "arn:aws:bedrock:us-west-2:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0"

    action = producer.translate(
        {
            "operation_name": "InvokeModel",
            "modelId": model_arn,
            "region_name": "us-west-2",
            "body": json.dumps({"inputText": "private customer prompt"}),
            "response": {
                "ResponseMetadata": {
                    "HTTPStatusCode": 200,
                    "RequestId": "aws-request-456",
                },
                "body": json.dumps(
                    {
                        "inputTextTokenCount": 8,
                        "results": [{"tokenCount": 21, "outputText": "private output"}],
                    }
                ),
            },
            "latencyMs": 102,
            "agent": "bedrock-agent",
        }
    )

    raw = action.parameters.raw
    assert raw["model_id"] == model_arn
    assert raw["request_id"] == "aws-request-456"
    assert raw["http_status"] == 200
    assert raw["input_tokens"] == 8
    assert raw["output_tokens"] == 21
    assert raw["deployment"]["inference_profile_arn"] == model_arn
    assert raw["deployment"]["model_family"] == "anthropic.claude"
    assert "private customer prompt" not in json.dumps(raw)
    assert "private output" not in json.dumps(raw)


def test_streaming_translation_records_usage_without_buffering_chunks() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "InvokeModelWithResponseStream",
            "modelId": "amazon.titan-text-premier-v1:0",
            "region": "us-east-2",
            "request_body": {"inputText": "stream prompt secret"},
            "stream_chunks": [
                {"chunk": {"bytes": b'{"outputText": "streamed secret text"}'}},
                {
                    "metadata": {
                        "usage": {"input_tokens": 4, "output_tokens": 9},
                        "request_id": "stream-request-789",
                    }
                },
            ],
            "response_metadata": {"HTTPStatusCode": 200},
            "latency_ms": 250,
            "agent_id": "bedrock-agent",
        }
    )

    raw = action.parameters.raw
    assert raw["operation"] == "InvokeModelWithResponseStream"
    assert raw["streaming"] is True
    assert raw["stream"]["chunk_count"] == 2
    assert raw["input_tokens"] == 4
    assert raw["output_tokens"] == 9
    assert raw["request_id"] == "stream-request-789"
    assert raw["deployment"]["model_family"] == "amazon.titan"
    serialized = json.dumps(raw)
    assert "stream prompt secret" not in serialized
    assert "streamed secret text" not in serialized


def test_credentials_and_signed_request_material_are_redacted() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "InvokeModel",
            "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
            "region": "us-east-1",
            "body": {"prompt": "hello"},
            "response_body": {"usage": {"input_tokens": 1, "output_tokens": 2}},
            "headers": {
                "authorization": "AWS4-HMAC-SHA256 Credential=AKIASECRET",
                "x-amz-security-token": "token-secret",
            },
            "credentials": {
                "aws_access_key_id": "AKIASECRET",
                "aws_secret_access_key": "not-for-evidence",
                "aws_session_token": "token-secret",
            },
            "canonical_request": "POST\n/model\nsecret-signature-material",
            "signed_headers": "authorization;x-amz-security-token",
        }
    )

    assert action.parameters.raw["auth_mode"] == "session"
    serialized = json.dumps(action.parameters.raw).lower()
    assert "akia" not in serialized
    assert "not-for-evidence" not in serialized
    assert "token-secret" not in serialized
    assert "authorization" not in serialized
    assert "canonical_request" not in serialized
    assert "signed_headers" not in serialized


def test_unrecognized_auth_mode_is_not_persisted() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "InvokeModel",
            "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
            "region": "us-east-1",
            "response_body": {"usage": {"input_tokens": 1, "output_tokens": 2}},
            "auth_mode": "AKIASECRET",
        }
    )

    assert "auth_mode" not in action.parameters.raw
    assert "akiasecret" not in json.dumps(action.parameters.raw).lower()


def test_observe_records_bedrock_evidence_summary() -> None:
    producer = _producer()

    observation = producer.observe(
        {
            "operation": "InvokeModel",
            "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
            "region": "us-east-1",
            "response_body": {"usage": {"input_tokens": 1, "output_tokens": 2}},
        }
    )

    assert observation.action.tool.name == "aws-bedrock:InvokeModel"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "aws-bedrock:InvokeModel"
    assert "aws-bedrock InvokeModel anthropic.claude-3-haiku-20240307-v1:0" in observation.evidence.output_summary
