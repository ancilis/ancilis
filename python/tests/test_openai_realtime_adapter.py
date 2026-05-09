from __future__ import annotations

import base64
import hashlib
import json

from ancilis.adapters.openai_realtime import (
    OpenAIRealtimeActionProducer,
    OpenAIRealtimeInvocation,
)
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType


def _producer() -> OpenAIRealtimeActionProducer:
    config = load_config(raw={"agent": {"name": "openai-realtime-agent"}})
    store = EvidenceStore(config, in_memory=True)
    return OpenAIRealtimeActionProducer(
        config=config,
        engine=Engine(config),
        evidence_store=store,
    )


def _audio_b64(byte_count: int) -> str:
    return base64.b64encode(b"\x00" * byte_count).decode()


def _seconds_to_pcm16_bytes(seconds: float) -> int:
    # 16 kHz mono pcm16 = 32_000 bytes/sec
    return int(seconds * 32_000)


def _session_config(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "model": "gpt-realtime",
        "voice": "alloy",
        "modalities": ["audio", "text"],
        "turn_detection": {"type": "server_vad"},
        "input_audio_format": "pcm16",
        "output_audio_format": "pcm16",
        "input_audio_transcription": {"model": "whisper-1", "language": "en"},
        "tools": [],
    }
    base.update(overrides)
    return base


def test_translate_minimal_session() -> None:
    producer = _producer()

    events = [
        {"type": "session.created", "session": {"id": "sess_abc"}},
        {"type": "response.created"},
        {"type": "response.done"},
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            operation="Session.observe",
            session_id="sess_abc",
            session_config=_session_config(),
            events=events,
            session_started_at="2026-05-09T00:00:00Z",
            session_ended_at="2026-05-09T00:00:30Z",
            http_status=101,
            request_id="req_realtime_1",
            latency_ms=42.0,
        )
    )

    raw = action.parameters.raw
    assert action.tool.name == "openai-realtime:Session.observe"
    assert action.tool.server == "api.openai.com"
    assert action.action_type == "api_request"
    assert action.producer_type == ProducerType.FRAMEWORK.value
    assert raw["provider"] == "openai-realtime"
    assert raw["operation"] == "Session.observe"
    assert raw["model"] == "gpt-realtime"
    assert raw["voice"] == "alloy"
    assert raw["modalities"] == ["audio", "text"]
    assert raw["turn_detection_mode"] == "server_vad"
    assert raw["session_id"] == "sess_abc"
    assert raw["http_status"] == 101
    assert raw["request_id"] == "req_realtime_1"
    assert raw["latency_ms"] == 42.0
    assert raw["turn_count"] == 1
    assert raw["deployment"]["model_family"] == "gpt-realtime"
    assert raw["audit_flags"]["no_transcription_long_audio"] is False
    assert raw["audit_flags"]["undeclared_function_calls"] is False
    assert isinstance(producer, ActionProducer)


def test_observe_emits_evidence() -> None:
    producer = _producer()

    observation = producer.observe(
        {
            "operation": "Session.observe",
            "session_id": "sess_xyz",
            "session_config": _session_config(model="gpt-4o-realtime-preview"),
            "events": [
                {"type": "session.created", "session": {"id": "sess_xyz"}},
                {"type": "response.created"},
                {"type": "response.done"},
            ],
        }
    )

    assert observation.action.tool.name == "openai-realtime:Session.observe"
    assert observation.evaluation.source_type == "framework"
    assert observation.evidence.tool_name == "openai-realtime:Session.observe"
    assert "openai-realtime Session.observe gpt-4o-realtime-preview" in (
        observation.evidence.output_summary
    )
    assert "turns=1" in observation.evidence.output_summary


def test_audio_durations_aggregated_from_byte_counts() -> None:
    producer = _producer()
    # 1 second of pcm16 mono @ 16 kHz = 32_000 bytes
    in_bytes = _seconds_to_pcm16_bytes(2.5)
    out_bytes = _seconds_to_pcm16_bytes(1.25)
    events = [
        {"type": "session.created", "session": {"id": "sess_audio"}},
        {"type": "input_audio_buffer.append", "audio": _audio_b64(in_bytes // 2)},
        {"type": "input_audio_buffer.append", "audio": _audio_b64(in_bytes // 2)},
        {"type": "response.created"},
        {"type": "response.audio.delta", "delta": _audio_b64(out_bytes)},
        {"type": "response.done"},
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_audio",
            session_config=_session_config(),
            events=events,
        )
    )

    raw = action.parameters.raw
    # base64 encoding rounds slightly, allow ~1% tolerance
    assert abs(raw["audio_in_seconds"] - 2.5) < 0.05
    assert abs(raw["audio_out_seconds"] - 1.25) < 0.05
    assert raw["audio_in_bytes"] > 0
    assert raw["audio_out_bytes"] > 0


def test_function_call_arguments_never_stored() -> None:
    producer = _producer()
    secret_args = {"customer_ssn": "123-45-6789", "phone": "+1-555-VICTIM"}

    events = [
        {"type": "session.created", "session": {"id": "sess_fn"}},
        {"type": "response.created"},
        {
            "type": "response.function_call_arguments.delta",
            "call_id": "call_1",
            "delta": json.dumps(secret_args),
        },
        {
            "type": "response.function_call_arguments.done",
            "call_id": "call_1",
            "name": "lookup_customer",
            "arguments": json.dumps(secret_args),
        },
        {"type": "response.done"},
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_fn",
            session_config=_session_config(
                tools=[{"type": "function", "name": "lookup_customer"}]
            ),
            events=events,
        )
    )

    raw = action.parameters.raw
    serialized = json.dumps(raw)
    # Raw arg values must never appear anywhere in the payload.
    assert "123-45-6789" not in serialized
    assert "+1-555-VICTIM" not in serialized
    assert "customer_ssn" not in serialized
    # The arguments object/key list itself must not leak.
    assert "arguments" not in raw["function_calls"]


def test_function_call_names_count_captured() -> None:
    producer = _producer()
    events = [
        {"type": "session.created", "session": {"id": "sess_fn2"}},
        {"type": "response.created"},
        {
            "type": "response.function_call_arguments.done",
            "call_id": "call_a",
            "name": "lookup_customer",
            "arguments": "{}",
        },
        {
            "type": "response.function_call_arguments.done",
            "call_id": "call_b",
            "name": "send_email",
            "arguments": "{}",
        },
        # Duplicate call_id — must not double-count.
        {
            "type": "response.function_call_arguments.done",
            "call_id": "call_b",
            "name": "send_email",
            "arguments": "{}",
        },
        {"type": "response.done"},
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_fn2",
            session_config=_session_config(
                tools=[
                    {"type": "function", "name": "lookup_customer"},
                    {"type": "function", "name": "send_email"},
                ]
            ),
            events=events,
        )
    )

    raw = action.parameters.raw
    assert raw["function_calls"]["count"] == 2
    assert sorted(raw["function_calls"]["names"]) == ["lookup_customer", "send_email"]


def test_session_instructions_redacted() -> None:
    producer = _producer()
    secret_instructions = (
        "You are Aria, a banking voice agent. Master key: sk-INSTRUCTIONLEAK."
    )
    config = _session_config(instructions=secret_instructions)

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_instr",
            session_config=config,
            events=[{"type": "session.created", "session": {"id": "sess_instr"}}],
        )
    )

    raw = action.parameters.raw
    assert raw["instructions"]["length"] == len(secret_instructions)
    assert raw["instructions"]["sha256"] == hashlib.sha256(
        secret_instructions.encode()
    ).hexdigest()
    serialized = json.dumps(raw)
    assert secret_instructions not in serialized
    assert "sk-INSTRUCTIONLEAK" not in serialized


def test_transcript_text_redacted() -> None:
    producer = _producer()
    spoken_pii = "My social security number is 123-45-6789 and my mother's maiden name is Smith"

    events = [
        {"type": "session.created", "session": {"id": "sess_tx"}},
        {"type": "response.created"},
        {"type": "response.audio_transcript.delta", "delta": spoken_pii[:30]},
        {"type": "response.audio_transcript.delta", "delta": spoken_pii[30:]},
        {"type": "response.done"},
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_tx",
            session_config=_session_config(),
            events=events,
        )
    )

    raw = action.parameters.raw
    serialized = json.dumps(raw)
    # Transcript text must never appear in the payload.
    assert "123-45-6789" not in serialized
    assert "Smith" not in serialized
    assert raw["transcript"]["length"] == len(spoken_pii)
    assert raw["transcript"]["sha256"] == hashlib.sha256(
        spoken_pii.encode()
    ).hexdigest()


def test_no_transcription_long_audio_audit_flag_in_payload() -> None:
    producer = _producer()
    # 60 seconds of input audio, no transcription configured.
    long_audio_bytes = _seconds_to_pcm16_bytes(60)
    events = [
        {"type": "session.created", "session": {"id": "sess_long"}},
        {
            "type": "input_audio_buffer.append",
            "byte_count": long_audio_bytes,
        },
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_long",
            session_config=_session_config(input_audio_transcription=None),
            events=events,
        )
    )

    raw = action.parameters.raw
    assert raw["audio_in_seconds"] >= 30.0
    assert raw["audit_flags"]["no_transcription_long_audio"] is True
    assert raw["transcription_model"] is None
    assert "PR-05" in raw["control_surfacing"]


def test_undeclared_function_call_indicator_in_payload() -> None:
    producer = _producer()
    events = [
        {"type": "session.created", "session": {"id": "sess_undecl"}},
        {"type": "response.created"},
        {
            "type": "response.function_call_arguments.done",
            "call_id": "call_x",
            "name": "wire_transfer",
            "arguments": "{}",
        },
        {"type": "response.done"},
    ]

    # Session config has no tools registered, but a function call fires.
    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_undecl",
            session_config=_session_config(tools=[]),
            events=events,
        )
    )

    raw = action.parameters.raw
    assert raw["function_calls"]["count"] == 1
    assert raw["tool_descriptions"]["names"] == []
    assert raw["audit_flags"]["undeclared_function_calls"] is True
    assert "PR-02" in raw["control_surfacing"]


def test_manual_turn_detection_long_audio_indicator() -> None:
    producer = _producer()
    long_bytes = _seconds_to_pcm16_bytes(20)
    events = [
        {"type": "session.created", "session": {"id": "sess_manual"}},
        {"type": "input_audio_buffer.append", "byte_count": long_bytes},
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_manual",
            session_config=_session_config(turn_detection=None),
            events=events,
        )
    )

    raw = action.parameters.raw
    assert raw["turn_detection_mode"] is None
    assert raw["audio_in_seconds"] >= 10.0
    assert raw["audit_flags"]["manual_turn_detection_long_audio"] is True
    assert "PR-05" in raw["control_surfacing"]


def test_error_event_captured() -> None:
    producer = _producer()
    events = [
        {"type": "session.created", "session": {"id": "sess_err"}},
        {
            "type": "error",
            "error": {
                "type": "invalid_request_error",
                "code": "invalid_audio_format",
                "message": "raw error blob with PII xyz@example.com",
            },
        },
        {
            "type": "error",
            "error": {"type": "rate_limit_error", "message": "second one"},
        },
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_err",
            session_config=_session_config(),
            events=events,
        )
    )

    raw = action.parameters.raw
    assert raw["error_count"] == 2
    assert raw["first_error_type"] == "invalid_request_error"
    assert "DE-01" in raw["control_surfacing"]
    serialized = json.dumps(raw)
    # We capture type/count, not error message text.
    assert "xyz@example.com" not in serialized
    assert "raw error blob" not in serialized


def test_rate_limit_event_surfaced() -> None:
    producer = _producer()
    events = [
        {"type": "session.created", "session": {"id": "sess_rl"}},
        {
            "type": "rate_limits.updated",
            "rate_limits": [
                {"name": "requests", "limit": 1000, "remaining": 5},
                {"name": "tokens", "limit": 100_000, "remaining": 500},
            ],
        },
        {"type": "rate_limits.updated", "rate_limits": []},
        {"type": "response.created"},
    ]

    action = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_rl",
            session_config=_session_config(),
            events=events,
        )
    )

    raw = action.parameters.raw
    assert raw["rate_limit_events"] == 2
    assert "rate_limits.updated" in raw["events"]["types"]


def test_register_tools() -> None:
    producer = _producer()
    registry = ToolRegistry()

    registered = producer.register_tools(registry)

    assert registered == [
        "openai-realtime:Session.create",
        "openai-realtime:Session.update",
        "openai-realtime:Session.observe",
    ]
    for name in registered:
        entry = registry.lookup(name)
        assert entry is not None
        assert entry.description_hash == producer.compute_tool_hash(name)


def test_auth_mode_ephemeral_detected() -> None:
    producer = _producer()

    # Explicit ephemeral_token override.
    explicit = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_e1",
            session_config=_session_config(),
            events=[],
            auth_mode="ephemeral",
        )
    )
    assert explicit.parameters.raw["auth_mode"] == "ephemeral_token"

    # ek_-prefixed bearer token detected as ephemeral.
    detected_bearer = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_e2",
            session_config=_session_config(),
            events=[],
            headers={"authorization": "Bearer ek_session_abcdef"},
        )
    )
    assert detected_bearer.parameters.raw["auth_mode"] == "ephemeral_token"

    # Standard sk- on default endpoint = api_key.
    api_key = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_e3",
            session_config=_session_config(),
            events=[],
            headers={"x-api-key": "sk-test-1234"},
        )
    )
    assert api_key.parameters.raw["auth_mode"] == "api_key"

    # Custom base URL with sk- = bring_your_own.
    byok = producer.translate(
        OpenAIRealtimeInvocation(
            session_id="sess_e4",
            session_config=_session_config(),
            events=[],
            headers={"authorization": "Bearer sk-leak"},
            base_url="wss://realtime.example.internal/v1/realtime",
        )
    )
    raw = byok.parameters.raw
    assert raw["auth_mode"] == "bring_your_own"
    assert raw["custom_base_url"] is True
    assert raw["endpoint_host"] == "realtime.example.internal"

    # Sensitive header values must not leak into payload.
    serialized = json.dumps(raw)
    assert "sk-leak" not in serialized
