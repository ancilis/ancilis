from __future__ import annotations

import json

from ancilis.adapters.cloudflare_workers_ai import (
    CloudflareWorkersAIActionProducer,
    CloudflareWorkersAIInvocation,
)
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType


def _producer() -> CloudflareWorkersAIActionProducer:
    config = load_config(raw={"agent": {"name": "cf-edge-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return CloudflareWorkersAIActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
    )


def test_producer_satisfies_protocol_without_cloudflare_sdk() -> None:
    import ancilis

    producer = _producer()
    assert isinstance(producer, ActionProducer)
    assert producer.producer_type == ProducerType.FRAMEWORK
    assert ancilis.CloudflareWorkersAIActionProducer is CloudflareWorkersAIActionProducer


def test_translate_llama_llm() -> None:
    producer = _producer()

    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct_abc",
            request_body={
                "messages": [
                    {"role": "system", "content": "you are helpful"},
                    {"role": "user", "content": "secret user prompt"},
                ],
                "max_tokens": 64,
            },
            response_body={
                "result": {"response": "the model response text", "usage": {"prompt_tokens": 12, "completion_tokens": 30, "total_tokens": 42}},
                "success": True,
                "errors": [],
                "messages": [],
            },
            http_status=200,
            latency_ms=42.5,
            headers={
                "cf-ray": "9abcdef0123-IAD",
                "cf-ipcountry": "US",
                "cf-iata": "IAD",
                "cf-cache-status": "MISS",
                "Authorization": "Bearer cf_super_secret_token",
            },
        )
    )

    raw = action.parameters.raw
    assert raw["provider"] == "cloudflare-workers-ai"
    assert raw["model_kind"] == "llm"
    assert raw["publisher"] == "meta"
    assert raw["owner_kind"] == "first_party"
    assert raw["model_basename"] == "llama-3.1-8b-instruct"
    assert raw["account_id"] == "acct_abc"
    assert raw["pop_country"] == "US"
    assert raw["pop_iata"] == "IAD"
    assert raw["cf_ray"] == "9abcdef0123-IAD"
    assert raw["cache_status"] == "miss"
    assert raw["cache_hit"] is False
    assert raw["success"] is True
    assert raw["http_status"] == 200
    assert raw["prompt_tokens"] == 12
    assert raw["completion_tokens"] == 30
    assert raw["total_tokens"] == 42
    assert raw["auth_mode"] == "api_token"
    assert raw["request_id"] == "9abcdef0123-IAD"
    assert raw["endpoint_host"] == "api.cloudflare.com"
    assert action.tool.name == "cloudflare-workers-ai:Models.run:llm"
    serialized = json.dumps(raw)
    assert "secret user prompt" not in serialized
    assert "you are helpful" not in serialized
    assert "cf_super_secret_token" not in serialized
    assert "the model response text" not in serialized


def test_translate_mistral_llm() -> None:
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/mistral/mistral-7b-instruct-v0.1",
            account_id="acct",
            request_body={"prompt": "private prompt about user"},
            response_body={
                "result": {"response": "response text"},
                "success": True,
            },
            http_status=200,
            headers={"cf-ipcountry": "DE", "cf-iata": "FRA"},
        )
    )
    raw = action.parameters.raw
    assert raw["model_kind"] == "llm"
    assert raw["publisher"] == "mistral"
    assert raw["owner_kind"] == "first_party"
    assert raw["pop_country"] == "DE"
    assert raw["pop_iata"] == "FRA"
    assert raw["request"]["prompt_present"] is True
    assert raw["request"]["prompt_length"] == len("private prompt about user")
    serialized = json.dumps(raw)
    assert "private prompt about user" not in serialized


def test_translate_bge_embedding() -> None:
    producer = _producer()
    action = producer.translate(
        {
            "operation": "Models.run",
            "model_id": "@cf/baai/bge-large-en-v1.5",
            "account_id": "acct",
            "request_body": {"text": ["sensitive doc one", "sensitive doc two"]},
            "response_body": {
                "result": {"data": [[0.1, 0.2], [0.3, 0.4]]},
                "success": True,
            },
            "http_status": 200,
            "headers": {"cf-ipcountry": "FR"},
        }
    )
    raw = action.parameters.raw
    assert raw["model_kind"] == "embedding"
    assert raw["publisher"] == "baai"
    assert raw["owner_kind"] == "first_party"
    assert raw["request"]["input_present"] is True
    assert raw["request"]["input_count"] == 2
    assert "input_sha256" in raw["request"]
    serialized = json.dumps(raw)
    assert "sensitive doc" not in serialized


def test_translate_flux_image_gen() -> None:
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/black-forest-labs/flux-1-schnell",
            account_id="acct",
            request_body={"prompt": "an image of a private subject"},
            response_body={
                "result": {"image": "BASE64_BINARY_DATA_REDACTED"},
                "success": True,
            },
            http_status=200,
            headers={"cf-ipcountry": "GB"},
        )
    )
    raw = action.parameters.raw
    assert raw["model_kind"] == "image-gen"
    assert raw["publisher"] == "black-forest-labs"
    assert raw["owner_kind"] == "first_party"
    assert raw["request"]["prompt_present"] is True
    assert raw["request"].get("image_gen_prompt_present") is True
    serialized = json.dumps(raw)
    assert "private subject" not in serialized
    assert "BASE64_BINARY_DATA_REDACTED" not in serialized


def test_translate_whisper_audio() -> None:
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/openai/whisper",
            account_id="acct",
            request_body={"audio": [1, 2, 3]},
            response_body={
                "result": {"text": "transcribed sensitive content"},
                "success": True,
            },
            http_status=200,
        )
    )
    raw = action.parameters.raw
    assert raw["model_kind"] == "speech-to-text"
    assert raw["publisher"] == "openai"
    assert raw["owner_kind"] == "first_party"
    assert raw["request"]["audio_input_present"] is True
    serialized = json.dumps(raw)
    assert "transcribed sensitive content" not in serialized


def test_observe_emits_evidence() -> None:
    producer = _producer()
    observation = producer.observe(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct",
            request_body={"prompt": "hi"},
            response_body={"result": {"response": "ok"}, "success": True},
            http_status=200,
            headers={"cf-ipcountry": "US", "cf-ray": "abc123"},
        )
    )
    assert observation.action.tool.name == "cloudflare-workers-ai:Models.run:llm"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "cloudflare-workers-ai:Models.run:llm"
    assert "@cf/meta/llama-3.1-8b-instruct" in observation.evidence.output_summary
    assert "pop=US" in observation.evidence.output_summary


def test_pop_country_captured() -> None:
    """Geographic POP routing must be captured for GDPR / data-residency posture.

    A request from a US agent that is served by an EU POP transits EU
    territory; downstream reports need ``pop_country`` to flag this.
    """
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct",
            request_body={"prompt": "hello"},
            response_body={"result": {"response": "world"}, "success": True},
            http_status=200,
            headers={
                "cf-ipcountry": "DE",
                "cf-iata": "FRA",
                "cf-ray": "ray-eu",
            },
        )
    )
    raw = action.parameters.raw
    assert raw["pop_country"] == "DE"
    assert raw["pop_iata"] == "FRA"
    assert raw["deployment"]["pop_country"] == "DE"
    assert raw["deployment"]["pop_iata"] == "FRA"


def test_cache_hit_via_gateway_captured() -> None:
    """Gateway + cache HIT must be flagged — cached responses may be from a prior session."""
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct",
            gateway_id="gw_prod",
            request_body={"prompt": "cached"},
            response_body={"result": {"response": "cached resp"}, "success": True},
            http_status=200,
            headers={"cf-cache-status": "HIT", "cf-ipcountry": "US"},
        )
    )
    raw = action.parameters.raw
    assert raw["gateway_id"] == "gw_prod"
    assert raw["gateway_present"] is True
    assert raw["cache_status"] == "hit"
    assert raw["cache_hit"] is True
    assert raw["endpoint_host"] == "gateway.ai.cloudflare.com"


def test_owner_kind_first_party() -> None:
    producer = _producer()
    for model_id, expected_publisher in [
        ("@cf/meta/llama-3.1-8b-instruct", "meta"),
        ("@cf/mistral/mistral-7b-instruct-v0.1", "mistral"),
        ("@cf/openai/whisper", "openai"),
        ("@cf/microsoft/resnet-50", "microsoft"),
        ("@cf/huggingface/distilbert-sst-2-int8", "huggingface"),
        ("@cf/baai/bge-large-en-v1.5", "baai"),
        ("@cf/black-forest-labs/flux-1-schnell", "black-forest-labs"),
    ]:
        action = producer.translate(
            CloudflareWorkersAIInvocation(
                operation="Models.run",
                model_id=model_id,
                account_id="acct",
                response_body={"result": {}, "success": True},
                http_status=200,
            )
        )
        raw = action.parameters.raw
        assert raw["publisher"] == expected_publisher
        assert raw["owner_kind"] == "first_party", model_id


def test_owner_kind_community() -> None:
    """User-supplied or community publishers (e.g. lykon LCM) must not be first_party."""
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/lykon/dreamshaper-8-lcm",
            account_id="acct",
            request_body={"prompt": "x"},
            response_body={"result": {}, "success": True},
            http_status=200,
        )
    )
    raw = action.parameters.raw
    assert raw["publisher"] == "lykon"
    assert raw["owner_kind"] == "community"
    assert raw["model_kind"] == "image-gen"

    action2 = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/some-random-user/custom-finetune",
            account_id="acct",
            response_body={"result": {}, "success": True},
            http_status=200,
        )
    )
    raw2 = action2.parameters.raw
    assert raw2["publisher"] == "some-random-user"
    assert raw2["owner_kind"] == "community"


def test_request_body_sanitized() -> None:
    """Prompts, messages, and embedding inputs must NOT appear in serialized payload."""
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct",
            request_body={
                "messages": [
                    {"role": "system", "content": "PII_SYSTEM_GIVEN"},
                    {"role": "user", "content": "PII_USER_PROMPT"},
                ],
                "x-api-key": "should-be-stripped-from-keys",
                "Authorization": "Bearer should-be-stripped",
            },
            response_body={"result": {}, "success": True},
            http_status=200,
            headers={
                "Authorization": "Bearer header-secret-token",
                "x-auth-key": "another-secret",
            },
        )
    )
    raw = action.parameters.raw
    serialized = json.dumps(raw).lower()
    assert "pii_system_given" not in serialized
    assert "pii_user_prompt" not in serialized
    assert "header-secret-token" not in serialized
    assert "another-secret" not in serialized
    body_keys = raw["request"]["body_keys"]
    assert "messages" in body_keys
    assert all("api_key" not in k.lower().replace("-", "_") for k in body_keys)
    assert all("authoriz" not in k.lower() for k in body_keys)
    assert raw["request"]["messages_present"] is True
    assert raw["request"]["messages_count"] == 2
    assert raw["request"]["messages_role_distribution"] == {"system": 1, "user": 1}
    assert "messages_sha256" in raw["request"]


def test_response_result_not_stored_raw() -> None:
    """Response ``result`` must be reduced to structural shape only."""
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct",
            request_body={"prompt": "hi"},
            response_body={
                "result": {
                    "response": "VERY_SECRET_OUTPUT_TEXT",
                    "data": [{"k": "v1"}, {"k": "v2"}, {"k": "v3"}],
                },
                "success": True,
            },
            http_status=200,
        )
    )
    raw = action.parameters.raw
    serialized = json.dumps(raw)
    assert "VERY_SECRET_OUTPUT_TEXT" not in serialized
    assert raw["response"]["result_present"] is True
    assert raw["response"]["result_kind"] == "object"
    assert raw["response"]["result_response_length"] == len("VERY_SECRET_OUTPUT_TEXT")
    assert raw["response"]["result_data_count"] == 3
    # No raw text should leak via result_keys (even key names are sanitised
    # against sensitive markers).
    assert "response" in raw["response"]["result_keys"]


def test_failed_request_captured() -> None:
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct",
            request_body={"prompt": "hi"},
            response_body={
                "success": False,
                "errors": [
                    {"code": 7003, "message": "Could not reach upstream model server: secret-internal-host:9000"}
                ],
                "result": None,
            },
            http_status=502,
            headers={"cf-ray": "fail-ray", "cf-ipcountry": "US"},
        )
    )
    raw = action.parameters.raw
    assert raw["success"] is False
    assert raw["http_status"] == 502
    assert "errors_summary" in raw
    err = raw["errors_summary"][0]
    assert err["code"] == 7003
    assert err["preview"].startswith("Could not reach upstream model server")
    assert err["sha256"]
    assert err["length"] > 0


def test_register_tools() -> None:
    producer = _producer()
    registry = ToolRegistry()
    registered = producer.register_tools(registry)
    expected = [
        "cloudflare-workers-ai:Models.run:llm",
        "cloudflare-workers-ai:Models.run:embedding",
        "cloudflare-workers-ai:Models.run:image-gen",
        "cloudflare-workers-ai:Models.run:speech-to-text",
        "cloudflare-workers-ai:Models.run:image-classification",
        "cloudflare-workers-ai:Models.run:classification",
        "cloudflare-workers-ai:Models.run:translation",
        "cloudflare-workers-ai:Models.run:unknown",
    ]
    assert registered == expected
    for name in registered:
        entry = registry.lookup(name)
        assert entry is not None
        assert entry.description_hash == producer.compute_tool_hash(name)


def test_streaming_detected_from_request() -> None:
    producer = _producer()
    action = producer.translate(
        CloudflareWorkersAIInvocation(
            operation="Models.run",
            model_id="@cf/meta/llama-3.1-8b-instruct",
            account_id="acct",
            request_body={"prompt": "hi", "stream": True},
            response_body={"result": {"response": "ok"}, "success": True},
            http_status=200,
        )
    )
    assert action.parameters.raw["is_streaming"] is True
