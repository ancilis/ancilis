from __future__ import annotations

import json

from ancilis.adapters.replicate import (
    ReplicateActionProducer,
    ReplicateInvocation,
)
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType


def _producer() -> ReplicateActionProducer:
    config = load_config(raw={"agent": {"name": "replicate-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return ReplicateActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
    )


def test_replicate_producer_satisfies_protocol_without_replicate_sdk() -> None:
    import ancilis

    producer = _producer()

    assert isinstance(producer, ActionProducer)
    assert producer.producer_type == ProducerType.FRAMEWORK
    assert ancilis.ReplicateActionProducer is ReplicateActionProducer


def test_translate_predictions_create_image() -> None:
    producer = _producer()

    action = producer.translate(
        ReplicateInvocation(
            operation="Predictions.create",
            model_owner="stability-ai",
            model_name="sdxl",
            version="abc123def456",
            request_body={
                "version": "abc123def456",
                "input": {
                    "prompt": "an extremely sensitive prompt about person X",
                    "image": "https://uploads.example/upload-1.png",
                    "width": 1024,
                    "height": 1024,
                },
            },
            response_body={
                "id": "pred_001",
                "model": "stability-ai/sdxl",
                "version": "abc123def456",
                "status": "succeeded",
                "output": [
                    "https://replicate.delivery/pbxt/abc/output-0.png",
                    "https://replicate.delivery/pbxt/abc/output-1.png",
                ],
                "metrics": {"predict_time": 4.21},
                "created_at": "2026-05-09T00:00:00Z",
                "started_at": "2026-05-09T00:00:01Z",
                "completed_at": "2026-05-09T00:00:05Z",
                "urls": {"get": "https://api.replicate.com/v1/predictions/pred_001"},
            },
            http_status=201,
            request_id="req_replicate_image",
            latency_ms=4210.0,
            headers={"Authorization": "Token r8_super_secret_token"},
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "replicate:Predictions.create"
    assert action.tool.server == "api.replicate.com"
    assert action.action_type == "api_request"
    assert raw["provider"] == "replicate"
    assert raw["operation"] == "Predictions.create"
    assert raw["model_owner"] == "stability-ai"
    assert raw["model_name"] == "sdxl"
    assert raw["model_version"] == "abc123def456"
    assert raw["model_id"] == "stability-ai/sdxl:abc123def456"
    assert raw["owner_kind"] == "first_party"
    assert raw["status"] == "succeeded"
    assert raw["captured"] is True
    assert raw["content_type"] == "image-generation"
    assert raw["predict_time"] == 4.21
    assert raw["response"]["output_url_count"] == 2
    assert raw["response"]["output_host"] == "replicate.delivery"
    assert raw["response"]["prediction_id"] == "pred_001"
    assert raw["response"]["get_url_host"] == "api.replicate.com"
    assert raw["request"]["webhook_present"] is False
    assert raw["auth_mode"] == "api_token"

    serialized = json.dumps(raw)
    assert "extremely sensitive prompt" not in serialized
    assert "r8_super_secret_token" not in serialized
    assert "output-0.png" not in serialized
    assert "output-1.png" not in serialized


def test_translate_predictions_create_text() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "meta",
            "model_name": "llama-2-70b",
            "version": "v1",
            "request_body": {
                "input": {"prompt": "Tell me a story", "max_tokens": 256}
            },
            "response_body": {
                "id": "pred_text_1",
                "status": "succeeded",
                "output": ["Once upon a time..."],
                "model": "meta/llama-2-70b",
            },
        }
    )

    raw = action.parameters.raw
    assert raw["content_type"] == "text-generation"
    assert raw["model_owner"] == "meta"
    assert raw["owner_kind"] == "first_party"
    # text outputs are still URL-counted but won't have a host since the
    # output isn't a URL.
    assert raw["response"]["output_url_count"] == 1


def test_observe_emits_evidence() -> None:
    producer = _producer()

    observation = producer.observe(
        {
            "operation": "Predictions.create",
            "model_owner": "stability-ai",
            "model_name": "sdxl",
            "request_body": {"input": {"prompt": "abc"}},
            "response_body": {"id": "p1", "status": "succeeded", "output": []},
        }
    )

    assert observation.action.tool.name == "replicate:Predictions.create"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "replicate:Predictions.create"
    assert "replicate Predictions.create" in observation.evidence.output_summary
    assert "status=succeeded" in observation.evidence.output_summary


def test_status_failed_captured() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "stability-ai",
            "model_name": "sdxl",
            "request_body": {"input": {"prompt": "x"}},
            "response_body": {
                "id": "pred_fail",
                "status": "failed",
                "error": "CUDA out of memory: detail leak that may include user data" * 20,
                "logs": "running model... ERROR: stack trace... internal text\n" * 30,
            },
        }
    )

    raw = action.parameters.raw
    assert raw["status"] == "failed"
    assert raw["captured"] is True
    err = raw["response"]["error_summary"]
    assert err is not None
    assert err["truncated"] is True
    assert len(err["preview"]) <= 200
    assert err["sha256"] and len(err["sha256"]) == 64
    logs = raw["response"]["logs_summary"]
    assert logs is not None
    assert logs["truncated"] is True
    serialized = json.dumps(raw)
    # Long error text past 200 chars should not appear verbatim
    assert "detail leak that may include user data" * 20 not in serialized


def test_status_canceled_captured() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "stability-ai",
            "model_name": "sdxl",
            "request_body": {"input": {"prompt": "x"}},
            "response_body": {"id": "pred_cancel", "status": "canceled"},
        }
    )

    raw = action.parameters.raw
    assert raw["status"] == "canceled"
    assert raw["captured"] is True


def test_content_type_heuristic_image() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "black-forest-labs",
            "model_name": "flux-schnell",
            "request_body": {
                "input": {"prompt": "a cat", "image": "https://x/y.png"}
            },
            "response_body": {"status": "succeeded", "output": []},
        }
    )
    assert action.parameters.raw["content_type"] == "image-generation"


def test_content_type_heuristic_audio() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "openai",
            "model_name": "whisper",
            "request_body": {
                "input": {"audio": "https://x/y.wav", "voice": "alice"}
            },
            "response_body": {"status": "succeeded", "output": []},
        }
    )
    assert action.parameters.raw["content_type"] == "audio-generation"


def test_content_type_heuristic_video() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "lucataco",
            "model_name": "animate-diff",
            "request_body": {
                "input": {"video": "https://x/y.mp4", "prompt": "make it shimmer"}
            },
            "response_body": {"status": "succeeded", "output": []},
        }
    )
    assert action.parameters.raw["content_type"] == "video-generation"


def test_owner_kind_first_party() -> None:
    producer = _producer()

    for owner in ("stability-ai", "black-forest-labs", "meta", "openai-gpt2-fine-tunes"):
        action = producer.translate(
            {
                "operation": "Predictions.create",
                "model_owner": owner,
                "model_name": "x",
                "request_body": {"input": {"prompt": "p"}},
                "response_body": {"status": "succeeded", "output": []},
            }
        )
        assert action.parameters.raw["owner_kind"] == "first_party", owner


def test_owner_kind_custom_unverified() -> None:
    producer = _producer()

    custom_action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "kevinbauer",
            "model_name": "my-finetune",
            "request_body": {"input": {"prompt": "p"}},
            "response_body": {"status": "succeeded", "output": []},
        }
    )
    assert custom_action.parameters.raw["owner_kind"] == "custom"

    unverified_action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "user-12345",
            "model_name": "anonymous-finetune",
            "request_body": {"input": {"prompt": "p"}},
            "response_body": {"status": "succeeded", "output": []},
        }
    )
    assert unverified_action.parameters.raw["owner_kind"] == "unverified"

    missing_owner_action = producer.translate(
        {
            "operation": "Predictions.create",
            "request_body": {"input": {"prompt": "p"}},
            "response_body": {"status": "succeeded", "output": []},
        }
    )
    assert missing_owner_action.parameters.raw["owner_kind"] == "unverified"


def test_webhook_present_captured() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "stability-ai",
            "model_name": "sdxl",
            "request_body": {
                "input": {"prompt": "p"},
                "webhook": "https://hooks.attacker.example/callback?secret=abc",
            },
            "response_body": {"status": "succeeded", "output": []},
        }
    )
    raw = action.parameters.raw
    assert raw["request"]["webhook_present"] is True
    assert raw["request"]["webhook_host"] == "hooks.attacker.example"
    serialized = json.dumps(raw)
    # Webhook URL path/query (which can contain secrets) must not be persisted
    assert "callback" not in serialized
    assert "secret=abc" not in serialized


def test_input_values_never_stored_raw() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "stability-ai",
            "model_name": "sdxl",
            "request_body": {
                "input": {
                    "prompt": "kevin.e.bauer@gmail.com please draw me",
                    "negative_prompt": "no SSN 123-45-6789",
                }
            },
            "response_body": {"status": "succeeded", "output": []},
        }
    )

    raw = action.parameters.raw
    # Only the keys + count + sha256 of joined values should be retained.
    assert "negative_prompt" in raw["request"]["input_keys"]
    assert "prompt" in raw["request"]["input_keys"]
    assert raw["request"]["input_count"] == 2
    assert isinstance(raw["request"]["input_value_hash"], str)
    assert len(raw["request"]["input_value_hash"]) == 64

    serialized = json.dumps(raw)
    assert "kevin.e.bauer" not in serialized
    assert "123-45-6789" not in serialized


def test_output_urls_redacted_to_hosts_only() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "stability-ai",
            "model_name": "sdxl",
            "request_body": {"input": {"prompt": "p"}},
            "response_body": {
                "id": "p1",
                "status": "succeeded",
                "output": [
                    "https://replicate.delivery/pbxt/secret-path-AAA/file-1.png",
                    "https://replicate.delivery/pbxt/secret-path-BBB/file-2.png",
                    "https://replicate.delivery/pbxt/secret-path-CCC/file-3.png",
                ],
            },
        }
    )

    raw = action.parameters.raw
    assert raw["response"]["output_url_count"] == 3
    assert raw["response"]["output_host"] == "replicate.delivery"

    serialized = json.dumps(raw)
    assert "secret-path-AAA" not in serialized
    assert "secret-path-BBB" not in serialized
    assert "secret-path-CCC" not in serialized
    assert "file-1.png" not in serialized


def test_register_tools() -> None:
    producer = _producer()
    registry = ToolRegistry()

    registered = producer.register_tools(registry)

    assert registered == [
        "replicate:Predictions.create",
        "replicate:Predictions.get",
        "replicate:Trainings.create",
    ]
    for name in registered:
        entry = registry.lookup(name)
        assert entry is not None
        assert entry.description_hash == producer.compute_tool_hash(name)


def test_custom_base_url_inferred() -> None:
    producer = _producer()

    action = producer.translate(
        ReplicateInvocation(
            operation="Predictions.create",
            model_owner="stability-ai",
            model_name="sdxl",
            request_body={"input": {"prompt": "p"}},
            response_body={"status": "succeeded", "output": []},
            base_url="https://replicate-proxy.internal.example/v1",
        )
    )

    raw = action.parameters.raw
    assert raw["endpoint_host"] == "replicate-proxy.internal.example"
    assert raw["custom_base_url"] is True
    assert action.tool.server == "replicate-proxy.internal.example"


def test_bearer_auth_mode_detected() -> None:
    producer = _producer()

    action = producer.translate(
        {
            "operation": "Predictions.create",
            "model_owner": "stability-ai",
            "model_name": "sdxl",
            "request_body": {"input": {"prompt": "p"}},
            "response_body": {"status": "succeeded", "output": []},
            "headers": {"Authorization": "Bearer some-bearer-secret"},
        }
    )

    raw = action.parameters.raw
    assert raw["auth_mode"] == "bearer"
    serialized = json.dumps(raw)
    assert "some-bearer-secret" not in serialized
