from __future__ import annotations

import json

from ancilis.adapters.azure_openai import AzureOpenAIActionProducer, AzureOpenAIInvocation
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType


def _producer(deployment_model_map: dict[str, str] | None = None) -> AzureOpenAIActionProducer:
    config = load_config(raw={"agent": {"name": "azure-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return AzureOpenAIActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
        deployment_model_map=deployment_model_map,
    )


def test_azure_openai_producer_satisfies_protocol_without_openai_package() -> None:
    import ancilis

    producer = _producer()

    assert isinstance(producer, ActionProducer)
    assert producer.producer_type == ProducerType.FRAMEWORK
    assert ancilis.__getattr__("AzureOpenAIActionProducer") is AzureOpenAIActionProducer


def test_chat_completions_normalizes_deployment_metadata_without_prompt_or_api_key() -> None:
    producer = _producer()

    action = producer.translate(
        AzureOpenAIInvocation(
            operation="chat.completions.create",
            azure_deployment="customer-chat",
            endpoint_host="https://customer.openai.azure.com",
            api_version="2024-10-21",
            region="eastus",
            request_body={
                "messages": [{"role": "user", "content": "private customer prompt"}],
                "temperature": 0.2,
            },
            response_body={
                "id": "chatcmpl_123",
                "model": "gpt-4o-2024-08-06",
                "usage": {"prompt_tokens": 12, "completion_tokens": 34},
            },
            http_status=200,
            request_id="azure-request-123",
            latency_ms=88.5,
            headers={"api-key": "azure-api-key-secret"},
            auth_mode="api-key",
            agent_id="azure-agent",
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "azure-openai:chat.completions.create"
    assert action.tool.server == "customer.openai.azure.com"
    assert action.action_type == "api_request"
    assert action.producer_type == "framework"
    assert raw["provider"] == "azure-openai"
    assert raw["operation"] == "chat.completions.create"
    assert raw["deployment_name"] == "customer-chat"
    assert raw["model_id"] == "gpt-4o-2024-08-06"
    assert raw["endpoint_host"] == "customer.openai.azure.com"
    assert raw["api_version"] == "2024-10-21"
    assert raw["region"] == "eastus"
    assert raw["latency_ms"] == 88.5
    assert raw["request_id"] == "azure-request-123"
    assert raw["input_tokens"] == 12
    assert raw["output_tokens"] == 34
    assert raw["auth_mode"] == "api-key"
    assert raw["deployment"]["provider"] == "azure-openai"
    assert raw["deployment"]["name"] == "customer-chat"
    assert raw["deployment"]["endpoint_host"] == "customer.openai.azure.com"
    assert raw["model"]["id"] == "gpt-4o-2024-08-06"
    assert raw["model"]["family"] == "gpt-4o"
    assert raw["request"]["body_keys"] == ["messages", "temperature"]
    serialized = json.dumps(raw)
    assert "private customer prompt" not in serialized
    assert "azure-api-key-secret" not in serialized


def test_raw_url_envelope_extracts_deployment_api_version_and_uses_configured_model_map() -> None:
    producer = _producer(deployment_model_map={"prod-chat": "gpt-4.1-mini"})

    action = producer.translate(
        {
            "operation": "chat.completions.create",
            "url": "https://contoso.openai.azure.com/openai/deployments/prod-chat/chat/completions?api-version=2024-02-15-preview",
            "request": {"messages": [{"role": "user", "content": "private mapped prompt"}]},
            "response": {
                "id": "chatcmpl_456",
                "usage": {
                    "prompt_tokens": 7,
                    "completion_tokens": 11,
                    "total_tokens": 18,
                },
            },
            "response_metadata": {"request_id": "azure-request-456", "status_code": 200},
            "latencyMs": 101,
        }
    )

    raw = action.parameters.raw
    assert raw["deployment_name"] == "prod-chat"
    assert raw["model_id"] == "gpt-4.1-mini"
    assert raw["model"]["resolved_from"] == "deployment_model_map"
    assert raw["endpoint_host"] == "contoso.openai.azure.com"
    assert raw["api_version"] == "2024-02-15-preview"
    assert raw["http_status"] == 200
    assert raw["request_id"] == "azure-request-456"
    assert raw["input_tokens"] == 7
    assert raw["output_tokens"] == 11
    assert "private mapped prompt" not in json.dumps(raw)


def test_unmapped_deployment_retains_deployment_name_without_inventing_model() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "responses.create",
            "azure_deployment": "unmapped-prod",
            "endpoint": "https://contoso.openai.azure.com",
            "api_version": "2025-03-01-preview",
        }
    )

    raw = action.parameters.raw
    assert raw["deployment_name"] == "unmapped-prod"
    assert raw["model_id"] is None
    assert raw["model"]["id"] is None
    assert raw["model"]["resolved"] is False
    assert raw["deployment"]["name"] == "unmapped-prod"


def test_azure_credentials_and_token_provider_outputs_are_redacted() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "chat.completions.create",
            "azure_deployment": "secure-chat",
            "endpoint": "https://secure.openai.azure.com",
            "request_body": {"messages": [{"role": "user", "content": "hello"}]},
            "response_body": {"usage": {"prompt_tokens": 1, "completion_tokens": 2}},
            "headers": {
                "Authorization": "Bearer secret-entra-token",
                "api-key": "azure-api-key-secret",
            },
            "credentials": {
                "api_key": "azure-api-key-secret",
                "access_token": "secret-entra-token",
            },
            "token_provider_output": "managed-identity-token-secret",
            "auth": {"mode": "azure-ad"},
        }
    )

    assert action.parameters.raw["auth_mode"] == "azure-ad"
    serialized = json.dumps(action.parameters.raw).lower()
    assert "secret-entra-token" not in serialized
    assert "azure-api-key-secret" not in serialized
    assert "managed-identity-token-secret" not in serialized
    assert "authorization" not in serialized
    assert "api-key" not in serialized
    assert "token_provider_output" not in serialized


def test_endpoint_userinfo_is_not_persisted_from_url_or_endpoint() -> None:
    producer = _producer()

    url_action = producer.translate(
        {
            "url": "https://client:secret-pass@secure.openai.azure.com/openai/deployments/secure-chat/chat/completions?api-version=2024-02-15-preview",
            "request_body": {"messages": [{"role": "user", "content": "hello"}]},
        }
    )
    endpoint_action = producer.translate(
        {
            "operation": "responses.create",
            "azure_deployment": "secure-responses",
            "endpoint": "https://client:secret-pass@secure-responses.openai.azure.com:443",
        }
    )

    url_raw = url_action.parameters.raw
    endpoint_raw = endpoint_action.parameters.raw
    assert url_raw["endpoint_host"] == "secure.openai.azure.com"
    assert url_raw["destination"] == "secure.openai.azure.com"
    assert endpoint_raw["endpoint_host"] == "secure-responses.openai.azure.com:443"
    assert endpoint_raw["destination"] == "secure-responses.openai.azure.com:443"
    serialized = json.dumps({"url": url_raw, "endpoint": endpoint_raw}).lower()
    assert "secret-pass" not in serialized
    assert "client:" not in serialized


def test_unrecognized_azure_auth_mode_is_not_persisted() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "chat.completions.create",
            "azure_deployment": "secure-chat",
            "auth_mode": "Bearer secret-entra-token",
        }
    )

    assert "auth_mode" not in action.parameters.raw
    assert "secret-entra-token" not in json.dumps(action.parameters.raw).lower()


def test_observe_records_azure_openai_evidence_summary() -> None:
    producer = _producer(deployment_model_map={"prod-chat": "gpt-4.1-mini"})

    observation = producer.observe(
        {
            "operation": "chat.completions.create",
            "azure_deployment": "prod-chat",
            "endpoint": "https://contoso.openai.azure.com",
            "response_body": {"usage": {"prompt_tokens": 1, "completion_tokens": 2}},
        }
    )

    assert observation.action.tool.name == "azure-openai:chat.completions.create"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "azure-openai:chat.completions.create"
    assert observation.evidence.output_summary is not None
    assert "azure-openai chat.completions.create gpt-4.1-mini" in observation.evidence.output_summary
