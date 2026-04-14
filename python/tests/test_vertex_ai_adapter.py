from __future__ import annotations

import json
from importlib import import_module
from typing import Any

from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType


def _vertex_module() -> Any:
    return import_module("ancilis.adapters.vertex_ai")


def _producer() -> Any:
    vertex = _vertex_module()
    config = load_config(raw={"agent": {"name": "vertex-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return vertex.VertexAIActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
    )


def test_vertex_ai_producer_satisfies_protocol_without_google_packages() -> None:
    import ancilis

    vertex = _vertex_module()
    producer = _producer()

    assert isinstance(producer, ActionProducer)
    assert producer.producer_type == ProducerType.FRAMEWORK
    assert ancilis.VertexAIActionProducer is vertex.VertexAIActionProducer


def test_predict_normalizes_endpoint_metadata_without_prompt_or_credentials() -> None:
    vertex = _vertex_module()
    producer = _producer()

    action = producer.translate(
        vertex.VertexAIInvocation(
            method="predict",
            project_id="demo-project",
            location="us-central1",
            endpoint_id="123456789",
            request_body={
                "instances": [{"prompt": "private customer prompt"}],
                "parameters": {"temperature": 0.2},
            },
            response_body={
                "predictions": [{"content": "private model output"}],
                "metadata": {
                    "tokenMetadata": {
                        "inputTokenCount": {"totalTokens": 7},
                        "outputTokenCount": {"totalTokens": 11},
                    }
                },
            },
            http_status=200,
            request_id="vertex-req-123",
            latency_ms=91.2,
            headers={"Authorization": "Bearer secret-oauth-token"},
            auth_mode="adc",
            agent_id="vertex-agent",
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "google-vertex-ai:predict"
    assert action.tool.server == "us-central1-aiplatform.googleapis.com"
    assert action.action_type == "api_request"
    assert action.producer_type == "framework"
    assert raw["provider"] == "google-vertex-ai"
    assert raw["operation"] == "predict"
    assert raw["project_id"] == "demo-project"
    assert raw["location"] == "us-central1"
    assert raw["endpoint_id"] == "123456789"
    assert raw["latency_ms"] == 91.2
    assert raw["request_id"] == "vertex-req-123"
    assert raw["input_tokens"] == 7
    assert raw["output_tokens"] == 11
    assert raw["auth_mode"] == "adc"
    assert raw["deployment"]["provider"] == "google-vertex-ai"
    assert raw["deployment"]["project_id"] == "demo-project"
    assert raw["deployment"]["location"] == "us-central1"
    assert raw["deployment"]["endpoint_id"] == "123456789"
    assert raw["model"]["endpoint_id"] == "123456789"
    assert raw["request"]["body_keys"] == ["instances", "parameters"]
    assert raw["response"]["body_keys"] == ["metadata", "predictions"]
    serialized = json.dumps(raw)
    assert "private customer prompt" not in serialized
    assert "private model output" not in serialized
    assert "secret-oauth-token" not in serialized


def test_generate_content_normalizes_publisher_model_and_usage_metadata() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "method": "generateContent",
            "projectId": "demo-project",
            "location": "us-central1",
            "publisherModelId": "publishers/google/models/gemini-1.5-pro",
            "request": {
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": "private generate content prompt"}],
                    }
                ]
            },
            "response": {
                "candidates": [{"content": {"parts": [{"text": "private answer"}]}}],
                "usageMetadata": {
                    "promptTokenCount": 13,
                    "candidatesTokenCount": 21,
                    "totalTokenCount": 34,
                },
            },
            "responseMetadata": {"requestId": "vertex-req-456", "httpStatus": 200},
            "latencyMs": 150,
        }
    )

    raw = action.parameters.raw
    assert action.tool.name == "google-vertex-ai:generateContent"
    assert raw["operation"] == "generateContent"
    assert raw["publisher_model_id"] == "publishers/google/models/gemini-1.5-pro"
    assert raw["model"]["id"] == "publishers/google/models/gemini-1.5-pro"
    assert raw["model"]["family"] == "gemini"
    assert raw["deployment"]["publisher_model_id"] == "publishers/google/models/gemini-1.5-pro"
    assert raw["request_id"] == "vertex-req-456"
    assert raw["http_status"] == 200
    assert raw["latency_ms"] == 150
    assert raw["input_tokens"] == 13
    assert raw["output_tokens"] == 21
    serialized = json.dumps(raw)
    assert "private generate content prompt" not in serialized
    assert "private answer" not in serialized


def test_google_credentials_and_signed_material_are_redacted() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "method": "generateContent",
            "project_id": "demo-project",
            "location": "europe-west4",
            "model": "publishers/google/models/gemini-1.5-flash",
            "request_body": {"contents": [{"parts": [{"text": "hello"}]}]},
            "response_body": {"usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 2}},
            "headers": {
                "authorization": "Bearer ya29.secret-oauth-token",
                "x-goog-api-key": "google-api-key-secret",
            },
            "credentials": {
                "client_email": "robot@example.iam.gserviceaccount.com",
                "private_key": "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----",
                "token": "access-token-secret",
                "refresh_token": "refresh-token-secret",
            },
            "signed_jwt": "signed-jwt-secret",
            "auth_mode": "service-account",
        }
    )

    assert action.parameters.raw["auth_mode"] == "service-account"
    serialized = json.dumps(action.parameters.raw).lower()
    assert "secret-oauth-token" not in serialized
    assert "google-api-key-secret" not in serialized
    assert "private key" not in serialized
    assert "access-token-secret" not in serialized
    assert "refresh-token-secret" not in serialized
    assert "signed-jwt-secret" not in serialized
    assert "robot@example" not in serialized
    assert "authorization" not in serialized
    assert "x-goog-api-key" not in serialized


def test_unrecognized_vertex_auth_mode_is_not_persisted() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "method": "predict",
            "endpointId": "123456789",
            "location": "us-central1",
            "auth_mode": "ya29.secret-oauth-token",
        }
    )

    assert "auth_mode" not in action.parameters.raw
    assert "secret-oauth-token" not in json.dumps(action.parameters.raw).lower()


def test_observe_records_vertex_evidence_summary() -> None:
    producer = _producer()

    observation = producer.observe(
        {
            "method": "predict",
            "project_id": "demo-project",
            "location": "us-central1",
            "endpointId": "123456789",
            "response_body": {
                "metadata": {
                    "tokenMetadata": {
                        "inputTokenCount": {"totalTokens": 1},
                        "outputTokenCount": {"totalTokens": 2},
                    }
                }
            },
        }
    )

    assert observation.action.tool.name == "google-vertex-ai:predict"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "google-vertex-ai:predict"
    assert "google-vertex-ai predict 123456789" in observation.evidence.output_summary
