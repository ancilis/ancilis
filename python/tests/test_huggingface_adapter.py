from __future__ import annotations

import json

from ancilis.adapters.huggingface import (
    HuggingFaceActionProducer,
    HuggingFaceInvocation,
)
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType


def _producer(long_generation_tokens: int = 1000) -> HuggingFaceActionProducer:
    config = load_config(raw={"agent": {"name": "huggingface-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return HuggingFaceActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
        long_generation_tokens=long_generation_tokens,
    )


def test_huggingface_producer_satisfies_protocol_without_huggingface_sdk() -> None:
    import ancilis

    producer = _producer()

    assert isinstance(producer, ActionProducer)
    assert producer.producer_type == ProducerType.FRAMEWORK
    assert ancilis.HuggingFaceActionProducer is HuggingFaceActionProducer


def test_translate_text_generation() -> None:
    producer = _producer()

    action = producer.translate(
        HuggingFaceInvocation(
            operation="Models.run",
            model_owner="meta-llama",
            model_name="Llama-3-8B-Instruct",
            model_revision="abcdef0123456",
            task_type="text-generation",
            request_body={
                "inputs": "Tell me a deeply private secret about user X",
                "parameters": {"max_new_tokens": 256, "temperature": 0.7},
            },
            response_body=[
                {"generated_text": "Once upon a time the answer was confidential..."}
            ],
            http_status=200,
            request_id="req_text_gen_001",
            latency_ms=482.0,
            headers={
                "Authorization": "Bearer hf_super_secret_token",
                "x-compute-type": "gpu",
                "x-compute-time": "482",
                "x-cached": "false",
                "x-request-id": "req_text_gen_001",
            },
            base_url="https://api-inference.huggingface.co/models/meta-llama/Llama-3-8B-Instruct",
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "huggingface:Models.run:text-generation"
    assert action.tool.server == "api-inference.huggingface.co"
    assert raw["provider"] == "huggingface"
    assert raw["task_type"] == "text-generation"
    assert raw["model_owner"] == "meta-llama"
    assert raw["model_name"] == "Llama-3-8B-Instruct"
    assert raw["model_revision"] == "abcdef0123456"
    assert raw["model_id"] == "meta-llama/Llama-3-8B-Instruct@abcdef0123456"
    assert raw["owner_kind"] == "first_party"
    assert raw["compute_type"] == "gpu"
    assert raw["cache_hit"] is False
    assert raw["endpoint_kind"] == "serverless"
    assert raw["auth_mode"] == "api_token"
    assert raw["request"]["inputs_present"] is True
    assert raw["request"]["inputs_kind"] == "string"
    assert isinstance(raw["request"]["inputs_sha256"], str)
    assert len(raw["request"]["inputs_sha256"]) == 64
    assert raw["response"]["generated_text_length"] > 0
    assert isinstance(raw["response"]["generated_text_sha256"], str)

    serialized = json.dumps(raw)
    assert "deeply private secret" not in serialized
    assert "Once upon a time" not in serialized
    assert "hf_super_secret_token" not in serialized
    assert "unpinned_model_revision" not in raw["flags"]


def test_translate_text_to_image() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "stabilityai",
            "model_name": "stable-diffusion-xl-base-1.0",
            "model_revision": "v1.0.0",
            "task_type": "text-to-image",
            "request_body": {"inputs": "a sensitive private prompt"},
            "response_body": b"\x89PNG\r\n\x1a\nFAKE-IMAGE-BYTES" * 100,
            "http_status": 200,
            "headers": {"x-compute-type": "gpu"},
        }
    )

    raw = action.parameters.raw
    assert raw["task_type"] == "text-to-image"
    assert raw["owner_kind"] == "first_party"
    assert raw["response"]["binary_byte_length"] > 0
    assert isinstance(raw["response"]["binary_sha256"], str)
    serialized = json.dumps(raw)
    assert "sensitive private prompt" not in serialized
    assert "FAKE-IMAGE-BYTES" not in serialized


def test_translate_embeddings() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "sentence-transformers",
            "model_name": "all-MiniLM-L6-v2",
            "task_type": "embeddings",
            "request_body": {"inputs": ["sentence one", "sentence two", "sentence three"]},
            "response_body": [
                [0.01] * 384,
                [0.02] * 384,
                [0.03] * 384,
            ],
            "http_status": 200,
        }
    )

    raw = action.parameters.raw
    assert raw["task_type"] == "embeddings"
    assert raw["owner_kind"] == "first_party"
    assert raw["response"]["embeddings_count"] == 3
    assert raw["response"]["embedding_dim"] == 384
    serialized = json.dumps(raw)
    assert "sentence one" not in serialized
    assert "sentence two" not in serialized


def test_translate_speech_to_text() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "openai",
            "model_name": "whisper-large-v3",
            "model_revision": "main",
            "task_type": "automatic-speech-recognition",
            "request_body": b"<<RAW-AUDIO-BYTES-DO-NOT-PERSIST>>",
            "response_body": {"text": "the secret board meeting transcript content"},
            "http_status": 200,
        }
    )

    raw = action.parameters.raw
    assert raw["task_type"] == "speech-to-text"
    assert raw["response"]["transcript_length"] > 0
    assert isinstance(raw["response"]["transcript_sha256"], str)
    serialized = json.dumps(raw)
    assert "secret board meeting" not in serialized
    assert "RAW-AUDIO-BYTES" not in serialized


def test_translate_classification() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "google-bert",
            "model_name": "bert-base-uncased",
            "task_type": "text-classification",
            "request_body": {"inputs": "I really enjoyed this product"},
            "response_body": [
                [
                    {"label": "POSITIVE", "score": 0.99},
                    {"label": "NEGATIVE", "score": 0.01},
                ]
            ],
            "http_status": 200,
        }
    )

    raw = action.parameters.raw
    assert raw["task_type"] == "text-classification"
    assert raw["response"]["label_count"] == 2
    assert raw["response"]["top_label"] == "POSITIVE"


def test_translate_conversational() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "mistralai",
            "model_name": "Mixtral-8x7B-Instruct-v0.1",
            "model_revision": "v0.1",
            "task_type": "conversational",
            "request_body": {
                "model": "mistralai/Mixtral-8x7B-Instruct-v0.1",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Tell me about ancilis."},
                ],
            },
            "response_body": {
                "choices": [
                    {"message": {"role": "assistant", "content": "Ancilis is a runtime control layer."}}
                ],
                "usage": {"prompt_tokens": 25, "completion_tokens": 12, "total_tokens": 37},
            },
            "http_status": 200,
        }
    )

    raw = action.parameters.raw
    assert raw["task_type"] == "conversational"
    assert raw["request"]["messages_present"] is True
    assert raw["request"]["messages_count"] == 2
    assert raw["request"]["has_system_message"] is True
    assert raw["prompt_tokens"] == 25
    assert raw["completion_tokens"] == 12
    assert raw["total_tokens"] == 37
    assert raw["response"]["generated_text_length"] > 0
    assert "conversational_no_system_message" not in raw["flags"]
    serialized = json.dumps(raw)
    assert "Tell me about ancilis" not in serialized
    assert "Ancilis is a runtime control layer" not in serialized


def test_endpoint_kind_serverless_detected() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
            "base_url": "https://api-inference.huggingface.co/models/meta-llama/Llama-3-8B@v1",
        }
    )
    raw = action.parameters.raw
    assert raw["endpoint_kind"] == "serverless"
    assert raw["endpoint_host"] == "api-inference.huggingface.co"


def test_endpoint_kind_dedicated_detected() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
            "base_url": "https://my-private-endpoint.endpoints.huggingface.cloud",
            "headers": {"Authorization": "Bearer hf_dedicated_endpoint_token"},
        }
    )
    raw = action.parameters.raw
    assert raw["endpoint_kind"] == "dedicated_endpoint"
    assert raw["endpoint_host"].endswith(".endpoints.huggingface.cloud")
    assert raw["auth_mode"] == "dedicated_endpoint_token"
    assert "dedicated_endpoint_byo_auth" in raw["flags"]


def test_endpoint_kind_inference_provider_detected() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-70B-Instruct",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
            "headers": {"x-routing-provider": "together"},
        }
    )
    raw = action.parameters.raw
    assert raw["endpoint_kind"] == "inference_provider"
    assert raw["routing_provider"] == "together"


def test_owner_kind_unverified() -> None:
    producer = _producer()

    community_action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "random-community-user",
            "model_name": "my-finetune",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
        }
    )
    assert community_action.parameters.raw["owner_kind"] == "community"

    missing_owner_action = producer.translate(
        {
            "operation": "Models.run",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
        }
    )
    assert missing_owner_action.parameters.raw["owner_kind"] == "unverified"


def test_unpinned_model_revision_flags() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B-Instruct",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
            "base_url": "https://api-inference.huggingface.co/models/meta-llama/Llama-3-8B-Instruct",
        }
    )
    raw = action.parameters.raw
    assert raw["endpoint_kind"] == "serverless"
    assert raw["model_revision"] is None
    assert "unpinned_model_revision" in raw["flags"]


def test_cpu_on_long_text_generation_flags() -> None:
    producer = _producer(long_generation_tokens=500)

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
            "headers": {"x-compute-type": "cpu"},
        }
    )
    raw = action.parameters.raw
    # No completion_tokens in usage; falls back to generated_text_length;
    # short response so no flag.
    assert "cpu_on_long_text_generation" not in raw["flags"]

    action_long = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": {
                "choices": [{"message": {"content": "x"}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 1500, "total_tokens": 1550},
                "generated_text": "x",
            },
            "headers": {"x-compute-type": "cpu"},
        }
    )
    raw_long = action_long.parameters.raw
    assert raw_long["compute_type"] == "cpu"
    assert raw_long["completion_tokens"] == 1500
    assert "cpu_on_long_text_generation" in raw_long["flags"]


def test_cache_hit_captured() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
            "headers": {
                "x-cached": "true",
                "x-routing-provider": "fireworks-ai",
            },
        }
    )
    raw = action.parameters.raw
    assert raw["cache_hit"] is True
    assert raw["endpoint_kind"] == "inference_provider"
    assert raw["routing_provider"] == "fireworks-ai"
    assert "inference_provider_cache_hit" in raw["flags"]


def test_input_text_never_stored() -> None:
    producer = _producer()

    sensitive_prompt = "kevin.e.bauer@gmail.com please summarise the SSN 123-45-6789 case"
    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": sensitive_prompt},
            "response_body": [{"generated_text": "ok"}],
        }
    )

    raw = action.parameters.raw
    assert raw["request"]["inputs_present"] is True
    assert raw["request"]["inputs_length"] == len(sensitive_prompt)
    assert isinstance(raw["request"]["inputs_sha256"], str)
    assert len(raw["request"]["inputs_sha256"]) == 64
    serialized = json.dumps(raw)
    assert "kevin.e.bauer" not in serialized
    assert "123-45-6789" not in serialized


def test_output_text_never_stored() -> None:
    producer = _producer()

    secret_output = "INTERNAL CONFIDENTIAL output text that should never be persisted"
    action = producer.translate(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": secret_output}],
        }
    )

    raw = action.parameters.raw
    assert raw["response"]["generated_text_length"] == len(secret_output)
    serialized = json.dumps(raw)
    assert "INTERNAL CONFIDENTIAL" not in serialized
    assert "should never be persisted" not in serialized


def test_register_tools() -> None:
    producer = _producer()
    registry = ToolRegistry()

    registered = producer.register_tools(registry)

    expected = [
        "huggingface:Models.run:text-generation",
        "huggingface:Models.run:text-to-image",
        "huggingface:Models.run:text-to-speech",
        "huggingface:Models.run:speech-to-text",
        "huggingface:Models.run:image-classification",
        "huggingface:Models.run:image-to-text",
        "huggingface:Models.run:embeddings",
        "huggingface:Models.run:text-classification",
        "huggingface:Models.run:token-classification",
        "huggingface:Models.run:question-answering",
        "huggingface:Models.run:summarization",
        "huggingface:Models.run:translation",
        "huggingface:Models.run:fill-mask",
        "huggingface:Models.run:zero-shot-classification",
        "huggingface:Models.run:conversational",
        "huggingface:Models.run:unknown",
    ]
    assert registered == expected
    for name in registered:
        entry = registry.lookup(name)
        assert entry is not None
        assert entry.description_hash == producer.compute_tool_hash(name)


def test_observe_emits_evidence() -> None:
    producer = _producer()

    observation = producer.observe(
        {
            "operation": "Models.run",
            "model_owner": "meta-llama",
            "model_name": "Llama-3-8B",
            "model_revision": "v1",
            "task_type": "text-generation",
            "request_body": {"inputs": "p"},
            "response_body": [{"generated_text": "ok"}],
        }
    )

    assert observation.action.tool.name == "huggingface:Models.run:text-generation"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "huggingface:Models.run:text-generation"
    assert "huggingface Models.run" in observation.evidence.output_summary
    assert "task=text-generation" in observation.evidence.output_summary
