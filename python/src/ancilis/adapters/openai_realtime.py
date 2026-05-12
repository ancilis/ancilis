# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""OpenAI Realtime API adapter for voice-agent session evidence.

The Realtime API (``gpt-realtime`` / ``gpt-4o-realtime-preview``) is a
WebSocket-based, bidirectional audio + text protocol distinct from Chat
Completions and Assistants v2. A single Realtime "invocation" for
adapter purposes is one full WebSocket session: ``session.created`` →
``session.deleted``/socket close. This adapter aggregates the stream of
event dicts received over that session into a single
:class:`Action` envelope so policy controls can inspect voice-agent
activity without ever holding raw audio, transcripts, or function-call
arguments.

Key sanitization invariants:

* Audio bytes are never stored — only summed byte counts converted to
  durations (assumed 16 kHz mono pcm16 unless otherwise indicated).
* Conversation transcript text is reduced to a length + sha256 digest;
  transcripts of voice conversations are the highest-PII surface in
  the Realtime API.
* Function-call arguments carry user-spoken intent and are PII; the
  adapter records names and counts only.
* ``session.instructions`` is reduced to length + sha256.

Audit-completeness payload flags (consumed by PR-02/PR-03/PR-05) are
surfaced as plain top-level booleans / structured indicators so
controls can react without re-deriving them from event arrays.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import ParseResult, urlparse

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ProducerType
from ancilis.telemetry import record_adapter_used

PROVIDER = "openai-realtime"
PRODUCER_VERSION = "0.1.0"

DEFAULT_ENDPOINT_HOST = "api.openai.com"
DEFAULT_BASE_URL = "wss://api.openai.com/v1/realtime"

# Audio assumptions: Realtime sessions default to 16 kHz mono pcm16
# (2 bytes/sample). We allow per-session overrides via the session
# config's ``input_audio_format`` / ``output_audio_format`` fields, but
# byte-count-to-seconds conversion always uses these defaults unless the
# format is one of the recognized telephony codecs (g711_*, 8 kHz mono).
_PCM16_SAMPLE_RATE_HZ = 16_000
_PCM16_BYTES_PER_SAMPLE = 2
_G711_SAMPLE_RATE_HZ = 8_000
_G711_BYTES_PER_SAMPLE = 1

_AUDIO_INCOMPLETENESS_THRESHOLD_S = 30.0
_MANUAL_TURN_DETECTION_THRESHOLD_S = 10.0

_SAFE_AUTH_MODES = {"api_key", "bearer", "bring_your_own", "ephemeral_token"}
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "api-key",
    "api_key",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "ephemeral_key",
    "ephemeral_token",
    "oauth",
    "openai-api-key",
    "openai_api_key",
    "refresh_token",
    "secret",
    "session_token",
    "x-api-key",
)
_REGISTERED_OPERATIONS = (
    "Session.create",
    "Session.update",
    "Session.observe",
)


@dataclass
class OpenAIRealtimeInvocation:
    """Raw OpenAI Realtime session invocation before translation.

    Mirrors the surface of a Realtime SDK session so the SDK is
    importable without the ``openai`` or ``websockets`` Python packages
    being installed. ``events`` is the ordered list of event dicts
    received (and/or sent) during the session lifetime.
    """

    operation: str = "Session.observe"
    session_id: str | None = None
    session_config: Mapping[str, Any] | None = None
    events: Sequence[Mapping[str, Any]] = field(default_factory=list)
    session_started_at: str | None = None
    session_ended_at: str | None = None
    http_status: int | None = 101
    request_id: str | None = None
    latency_ms: float | None = None
    headers: Mapping[str, Any] | None = None
    response_metadata: Mapping[str, Any] | None = None
    agent_id: str | None = None
    auth_mode: str | None = None
    base_url: str | None = None


@dataclass
class OpenAIRealtimeObservation:
    """Action, evaluation, and evidence record for a Realtime session."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    session_id: str | None
    session_config: Mapping[str, Any]
    events: Sequence[Mapping[str, Any]]
    session_started_at: str | None
    session_ended_at: str | None
    http_status: int | None
    request_id: str | None
    latency_ms: float | None
    headers: Mapping[str, Any]
    response_metadata: Mapping[str, Any]
    agent_id: str
    auth_mode: str | None
    base_url: str | None


class OpenAIRealtimeActionProducer:
    """Produces Action objects from OpenAI Realtime sessions.

    The adapter accepts plain dictionaries or
    :class:`OpenAIRealtimeInvocation` objects so the SDK stays
    importable without the ``openai`` or ``websockets`` Python packages
    installed. Aggregation strategy: we walk the event stream once,
    summing audio byte counts, counting responses, collecting function
    names, and capturing rate-limit / error events, then emit one
    Action per session.
    """

    def __init__(
        self,
        config: ResolvedConfig,
        engine: Engine,
        registry: ToolRegistry | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._registry = registry or engine.registry
        self._evidence_store = (
            evidence_store if evidence_store is not None else EvidenceStore(config)
        )
        self._session_id = str(uuid.uuid4())
        record_adapter_used(PROVIDER)

    @property
    def session_id(self) -> str:
        """Unique identifier for this producer instance."""
        return self._session_id

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.FRAMEWORK

    @property
    def producer_version(self) -> str:
        return PRODUCER_VERSION

    def translate(
        self, raw_invocation: OpenAIRealtimeInvocation | Mapping[str, Any]
    ) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)

        endpoint = _endpoint(invocation.base_url)
        custom_endpoint = endpoint != DEFAULT_ENDPOINT_HOST
        auth_mode = _resolve_auth_mode(invocation, custom_endpoint)
        request_id = (
            invocation.request_id
            or _header_value(invocation.headers, "x-request-id")
            or _header_value(invocation.headers, "openai-request-id")
        )

        session_config = invocation.session_config or {}
        # Session config is also broadcast over the wire as the
        # ``session`` field of ``session.created`` / ``session.updated``
        # events. If the caller didn't pass it explicitly we recover it
        # from the event stream.
        if not session_config:
            session_config = _session_config_from_events(invocation.events) or {}

        session_id = invocation.session_id or _session_id_from_events(invocation.events)
        model = _optional_str(_mapping_value(session_config, "model"))
        model_metadata = _model_metadata(model)
        voice = _optional_str(_mapping_value(session_config, "voice"))
        modalities = _modalities(_mapping_value(session_config, "modalities"))
        turn_detection_mode = _turn_detection_mode(
            _mapping_value(session_config, "turn_detection")
        )
        input_audio_format = _optional_str(
            _mapping_value(session_config, "input_audio_format")
        )
        output_audio_format = _optional_str(
            _mapping_value(session_config, "output_audio_format")
        )
        transcription = _summarize_transcription(
            _mapping_value(session_config, "input_audio_transcription")
        )
        instructions_summary = _summarize_instructions(
            _mapping_value(session_config, "instructions")
        )
        tool_descriptions = _summarize_tool_descriptions(
            _mapping_value(session_config, "tools")
        )

        event_summary = _summarize_events(invocation.events)
        audio_in_seconds = _bytes_to_seconds(
            event_summary["audio_in_bytes"], input_audio_format
        )
        audio_out_seconds = _bytes_to_seconds(
            event_summary["audio_out_bytes"], output_audio_format
        )
        function_calls = event_summary["function_calls"]
        function_call_count = function_calls["count"]
        turn_count = event_summary["turn_count"]
        error_count = event_summary["error_count"]
        first_error_type = event_summary["first_error_type"]
        rate_limit_events = event_summary["rate_limit_events"]
        transcript_summary = event_summary["transcript"]

        no_transcription_long_audio = (
            transcription is None
            and audio_in_seconds > _AUDIO_INCOMPLETENESS_THRESHOLD_S
        )
        manual_turn_detection_long_audio = (
            turn_detection_mode is None
            and audio_in_seconds > _MANUAL_TURN_DETECTION_THRESHOLD_S
        )
        audio_modality = "audio" in modalities
        missing_voice_for_audio = audio_modality and not voice
        undeclared_function_calls = (
            function_call_count > 0 and not tool_descriptions["names"]
        )

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "model": model,
            "model_id": model,
            "endpoint_host": endpoint,
            "destination": endpoint,
            "custom_base_url": custom_endpoint,
            "http_status": invocation.http_status,
            "request_id": request_id,
            "latency_ms": invocation.latency_ms,
            "session_id": session_id,
            "session_started_at": invocation.session_started_at,
            "session_ended_at": invocation.session_ended_at,
            "model_metadata": model_metadata,
            "deployment": {
                "provider": PROVIDER,
                "endpoint_host": endpoint,
                "model": model,
                "model_family": model_metadata["family"],
            },
            "voice": voice,
            "modalities": modalities,
            "turn_detection_mode": turn_detection_mode,
            "input_audio_format": input_audio_format,
            "output_audio_format": output_audio_format,
            "audio_in_seconds": round(audio_in_seconds, 3),
            "audio_out_seconds": round(audio_out_seconds, 3),
            "audio_in_bytes": event_summary["audio_in_bytes"],
            "audio_out_bytes": event_summary["audio_out_bytes"],
            "turn_count": turn_count,
            "events": {
                "count": event_summary["count"],
                "types": event_summary["types"],
            },
            "tool_descriptions": {
                "count": tool_descriptions["count"],
                "names": tool_descriptions["names"],
                "types": tool_descriptions["types"],
            },
            "function_calls": {
                "count": function_call_count,
                "names": function_calls["names"],
            },
            "transcript": transcript_summary,
            "error_count": error_count,
            "first_error_type": first_error_type,
            "rate_limit_events": rate_limit_events,
            "audit_flags": {
                "no_transcription_long_audio": no_transcription_long_audio,
                "manual_turn_detection_long_audio": manual_turn_detection_long_audio,
                "missing_voice_for_audio_modality": missing_voice_for_audio,
                "undeclared_function_calls": undeclared_function_calls,
            },
        }

        if instructions_summary is not None:
            payload["instructions"] = instructions_summary
        if transcription is not None:
            payload["input_audio_transcription"] = transcription
            payload["transcription_model"] = transcription.get("model")
        else:
            payload["input_audio_transcription"] = None
            payload["transcription_model"] = None
        if auth_mode:
            payload["auth_mode"] = auth_mode

        # Surfacing flags — explicit, machine-readable list of control
        # indicators the engine can pivot on without re-deriving from
        # the payload structure.
        surfacing: list[str] = []
        if no_transcription_long_audio:
            surfacing.append("PR-05")
        if manual_turn_detection_long_audio:
            surfacing.append("PR-05")
        if missing_voice_for_audio:
            surfacing.append("PR-03")
        if undeclared_function_calls:
            surfacing.append("PR-02")
        if error_count > 0:
            surfacing.append("DE-01")
        if surfacing:
            payload["control_surfacing"] = sorted(set(surfacing))

        tool_name = _tool_name(invocation.operation)
        entry = self._registry.lookup(tool_name)
        param_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=repr).encode()
        ).hexdigest()

        return Action(
            action_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=invocation.agent_id,
            source_type=self.producer_type.value,
            agent_owner=self._config.agent_owner or None,
            action_type="api_request",
            tool=ToolInfo(
                name=tool_name,
                server=endpoint,
                description_hash=entry.description_hash if entry else None,
            ),
            parameters=ActionParameters(raw=payload, parameter_hash=param_hash),
            context=ActionContext(
                session_id=self._session_id,
                data_classifications=_data_classification_codes(self._config),
                active_overlays=list(self._config.active_overlays.keys()),
            ),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def observe(
        self, raw_invocation: OpenAIRealtimeInvocation | Mapping[str, Any]
    ) -> OpenAIRealtimeObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(normalized.operation)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return OpenAIRealtimeObservation(
            action=action, evaluation=evaluation, evidence=evidence
        )

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for operation in _REGISTERED_OPERATIONS:
            tool_name = _tool_name(operation)
            registry.register(
                ToolEntry(
                    name=tool_name,
                    description_hash=self.compute_tool_hash(tool_name),
                    status=ToolStatus.OBSERVED,
                )
            )
            registered.append(tool_name)
        return registered

    def _ensure_registered(self, operation: str) -> str:
        tool_name = _tool_name(operation)
        if self._registry.lookup(tool_name) is not None:
            return tool_name
        status = (
            ToolStatus.APPROVED
            if tool_name in self._config.tools_allowed
            else ToolStatus.OBSERVED
        )
        self._registry.register(
            ToolEntry(
                name=tool_name,
                description_hash=self.compute_tool_hash(tool_name),
                status=status,
                approved_by="config" if status == ToolStatus.APPROVED else None,
            )
        )
        return tool_name


OpenAIRealtimeAdapter = OpenAIRealtimeActionProducer


def _normalize_invocation(
    raw_invocation: OpenAIRealtimeInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, OpenAIRealtimeInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        events = list(raw_invocation.events or [])
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            session_id=raw_invocation.session_id,
            session_config=dict(raw_invocation.session_config or {}),
            events=events,
            session_started_at=raw_invocation.session_started_at,
            session_ended_at=raw_invocation.session_ended_at,
            http_status=raw_invocation.http_status
            or _metadata_status_code(response_metadata),
            request_id=raw_invocation.request_id
            or _metadata_request_id(response_metadata),
            latency_ms=raw_invocation.latency_ms,
            headers=dict(raw_invocation.headers or {}),
            response_metadata=response_metadata,
            agent_id=raw_invocation.agent_id or default_agent_id,
            auth_mode=raw_invocation.auth_mode,
            base_url=raw_invocation.base_url,
        )

    response = _mapping_value(raw_invocation, "response")
    response_metadata = _first_mapping(
        _mapping_value(raw_invocation, "response_metadata"),
        _mapping_value(raw_invocation, "responseMetadata"),
        _mapping_value(response, "metadata"),
    )
    headers = _first_mapping(
        _mapping_value(raw_invocation, "headers"),
        _mapping_value(raw_invocation, "request_headers"),
        _mapping_value(raw_invocation, "requestHeaders"),
    )
    session_config = _first_mapping(
        _mapping_value(raw_invocation, "session_config"),
        _mapping_value(raw_invocation, "sessionConfig"),
        _mapping_value(raw_invocation, "session"),
        _mapping_value(raw_invocation, "config"),
    )
    raw_events = _first_present(
        raw_invocation, "events", "event_log", "eventLog", "messages"
    )
    events: list[Mapping[str, Any]] = []
    if isinstance(raw_events, Iterable) and not isinstance(
        raw_events, (str, bytes, bytearray, Mapping)
    ):
        for evt in raw_events:
            if isinstance(evt, Mapping):
                events.append(evt)

    return _NormalizedInvocation(
        operation=str(
            _first_present(raw_invocation, "operation", "method", "operationName")
            or "Session.observe"
        ),
        session_id=_optional_str(
            _first_present(raw_invocation, "session_id", "sessionId")
        ),
        session_config=session_config,
        events=events,
        session_started_at=_optional_str(
            _first_present(
                raw_invocation,
                "session_started_at",
                "sessionStartedAt",
                "started_at",
                "startedAt",
            )
        ),
        session_ended_at=_optional_str(
            _first_present(
                raw_invocation,
                "session_ended_at",
                "sessionEndedAt",
                "ended_at",
                "endedAt",
            )
        ),
        http_status=_optional_int(
            _first_present(raw_invocation, "http_status", "httpStatus", "status_code")
            or _metadata_status_code(response_metadata)
            or 101
        ),
        request_id=_optional_str(
            _first_present(raw_invocation, "request_id", "requestId")
            or _metadata_request_id(response_metadata)
        ),
        latency_ms=_optional_float(
            _first_present(raw_invocation, "latency_ms", "latencyMs", "duration_ms")
        ),
        headers=headers,
        response_metadata=response_metadata,
        agent_id=str(
            _first_present(raw_invocation, "agent_id", "agent", "agent_name")
            or default_agent_id
        ),
        auth_mode=_optional_str(
            _first_present(raw_invocation, "auth_mode", "authMode")
            or _nested_auth_mode(raw_invocation)
        ),
        base_url=_optional_str(
            _first_present(
                raw_invocation,
                "base_url",
                "baseURL",
                "baseUrl",
                "endpoint",
                "host",
                "url",
            )
        ),
    )


def _tool_name(operation: str) -> str:
    return f"{PROVIDER}:{operation}"


def _endpoint(base_url: str | None) -> str:
    host = _host_from_endpoint(base_url)
    return host or DEFAULT_ENDPOINT_HOST


def _host_from_endpoint(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    parsed = urlparse(endpoint)
    host = _host_from_parsed_url(parsed)
    if host is not None:
        return host
    candidate = endpoint.split("/", 1)[0].rsplit("@", 1)[-1]
    return candidate or None


def _host_from_parsed_url(parsed: ParseResult) -> str | None:
    if parsed.hostname is None:
        return None
    if parsed.port is None:
        return parsed.hostname
    return f"{parsed.hostname}:{parsed.port}"


def _model_metadata(model: str | None) -> dict[str, Any]:
    if not model:
        return {"id": None, "provider": "openai", "family": "unknown", "resolved": False}
    family = _model_family(model)
    return {
        "id": model,
        "provider": "openai",
        "family": family,
        "resolved": True,
    }


def _model_family(model_id: str) -> str:
    reference = model_id.rsplit("/", 1)[-1].lower()
    if "realtime" in reference:
        return "gpt-realtime"
    if reference.startswith("gpt-4o"):
        return "gpt-4o"
    if reference.startswith("gpt-4"):
        return "gpt-4"
    if "-" in reference:
        return reference.split("-", 1)[0]
    return reference or "unknown"


def _modalities(value: Any) -> list[str]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return sorted({str(item) for item in value if item is not None})
    return []


def _turn_detection_mode(value: Any) -> str | None:
    """Return turn-detection mode string or ``None`` for manual.

    The Realtime API uses ``turn_detection: null`` to indicate
    client-driven (manual) turn-taking; any non-null mapping carries a
    ``type`` (typically ``server_vad``).
    """
    if not isinstance(value, Mapping):
        return None
    return _optional_str(_mapping_value(value, "type"))


def _summarize_transcription(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        "model": _optional_str(_mapping_value(value, "model")),
        "language": _optional_str(_mapping_value(value, "language")),
    }


def _summarize_instructions(value: Any) -> dict[str, Any] | None:
    """Redact instruction text — store only length + SHA-256."""
    if value is None:
        return None
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, sort_keys=True, default=repr)
    )
    return {
        "length": len(text),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


def _summarize_tool_descriptions(value: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {"count": 0, "names": [], "types": []}
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return summary
    name_set: set[str] = set()
    type_set: set[str] = set()
    for tool in value:
        if not isinstance(tool, Mapping):
            continue
        summary["count"] += 1
        tool_type = _optional_str(_mapping_value(tool, "type"))
        if tool_type:
            type_set.add(tool_type)
        name = _optional_str(_mapping_value(tool, "name"))
        if not name:
            function_def = _mapping_value(tool, "function")
            if isinstance(function_def, Mapping):
                name = _optional_str(_mapping_value(function_def, "name"))
        if name:
            name_set.add(name)
    summary["names"] = sorted(name_set)
    summary["types"] = sorted(type_set)
    return summary


def _session_config_from_events(events: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """Recover session config from session.created/session.updated events."""
    config: dict[str, Any] = {}
    for evt in events:
        if not isinstance(evt, Mapping):
            continue
        evt_type = _optional_str(_mapping_value(evt, "type"))
        if evt_type not in {"session.created", "session.updated"}:
            continue
        payload = _mapping_value(evt, "session")
        if isinstance(payload, Mapping):
            for key, value in payload.items():
                config[str(key)] = value
    return config or None


def _session_id_from_events(events: Sequence[Mapping[str, Any]]) -> str | None:
    for evt in events:
        if not isinstance(evt, Mapping):
            continue
        if _optional_str(_mapping_value(evt, "type")) != "session.created":
            continue
        session = _mapping_value(evt, "session")
        if isinstance(session, Mapping):
            sid = _optional_str(_mapping_value(session, "id"))
            if sid:
                return sid
    return None


def _summarize_events(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate per-event statistics across a Realtime session.

    A single pass collects every metric the payload needs:

    * audio_in_bytes / audio_out_bytes — summed payload byte counts.
    * function call names + count — never arguments.
    * turn_count — number of ``response.created`` events.
    * error_count + first_error_type — captured from ``error`` events.
    * rate_limit_events — count of ``rate_limits.updated`` events.
    * transcript — length + sha256 of all transcript deltas
      concatenated; raw text is never retained.
    """
    summary: dict[str, Any] = {
        "count": 0,
        "types": [],
        "audio_in_bytes": 0,
        "audio_out_bytes": 0,
        "turn_count": 0,
        "error_count": 0,
        "first_error_type": None,
        "rate_limit_events": 0,
        "function_calls": {"count": 0, "names": []},
        "transcript": {"length": 0, "sha256": None},
    }
    type_set: set[str] = set()
    function_names: list[str] = []
    seen_function_calls: set[str] = set()
    transcript_parts: list[str] = []

    for evt in events:
        if not isinstance(evt, Mapping):
            continue
        summary["count"] += 1
        evt_type = _optional_str(_mapping_value(evt, "type")) or ""
        if evt_type:
            type_set.add(evt_type)

        if evt_type == "input_audio_buffer.append":
            summary["audio_in_bytes"] += _audio_byte_count(evt)
        elif evt_type == "response.audio.delta":
            summary["audio_out_bytes"] += _audio_byte_count(evt)
        elif evt_type == "response.created":
            summary["turn_count"] += 1
        elif evt_type == "error":
            summary["error_count"] += 1
            if summary["first_error_type"] is None:
                error_payload = _mapping_value(evt, "error")
                if isinstance(error_payload, Mapping):
                    summary["first_error_type"] = _optional_str(
                        _mapping_value(error_payload, "type")
                        or _mapping_value(error_payload, "code")
                    )
        elif evt_type == "rate_limits.updated":
            summary["rate_limit_events"] += 1
        elif evt_type == "response.function_call_arguments.done":
            # Track unique calls by call_id so we don't double-count
            # multi-delta streamed arguments (which have the same id as
            # the final ``.done`` event).
            call_id = _optional_str(_mapping_value(evt, "call_id"))
            name = _optional_str(_mapping_value(evt, "name"))
            key = call_id or f"_anon_{len(seen_function_calls)}"
            if key not in seen_function_calls:
                seen_function_calls.add(key)
                if name:
                    function_names.append(name)
                summary["function_calls"]["count"] += 1
        elif evt_type in {
            "response.audio_transcript.delta",
            "response.text.delta",
            "conversation.item.input_audio_transcription.completed",
        }:
            text = _transcript_text(evt)
            if text:
                transcript_parts.append(text)

    summary["types"] = sorted(type_set)
    summary["function_calls"]["names"] = sorted(set(function_names))
    if transcript_parts:
        joined = "".join(transcript_parts)
        summary["transcript"] = {
            "length": len(joined),
            "sha256": hashlib.sha256(joined.encode()).hexdigest(),
        }
    return summary


def _audio_byte_count(evt: Mapping[str, Any]) -> int:
    """Compute payload byte count for an audio event.

    Realtime transports audio as base64-encoded ``audio`` strings on
    ``input_audio_buffer.append`` and ``delta`` strings on
    ``response.audio.delta``. We accept either (a) an explicit
    ``byte_count`` if present, (b) the length of the base64 payload
    converted to bytes (3 bytes per 4 base64 chars), or (c) the length
    of a raw ``bytes`` payload directly.
    """
    explicit = _optional_int(
        _mapping_value(evt, "byte_count")
        or _mapping_value(evt, "byteCount")
        or _mapping_value(evt, "bytes")
    )
    if explicit is not None:
        return max(0, explicit)
    payload = _mapping_value(evt, "audio")
    if payload is None:
        payload = _mapping_value(evt, "delta")
    if isinstance(payload, (bytes, bytearray)):
        return len(payload)
    if isinstance(payload, str):
        # base64 — every 4 chars = 3 bytes (minus padding)
        stripped = payload.rstrip("=")
        return (len(stripped) * 3) // 4
    return 0


def _transcript_text(evt: Mapping[str, Any]) -> str | None:
    text = _mapping_value(evt, "delta")
    if text is None:
        text = _mapping_value(evt, "transcript")
    if text is None:
        text = _mapping_value(evt, "text")
    if isinstance(text, str):
        return text
    return None


def _bytes_to_seconds(byte_count: int, audio_format: str | None) -> float:
    if byte_count <= 0:
        return 0.0
    fmt = (audio_format or "pcm16").lower()
    if fmt.startswith("g711"):
        return byte_count / (_G711_SAMPLE_RATE_HZ * _G711_BYTES_PER_SAMPLE)
    return byte_count / (_PCM16_SAMPLE_RATE_HZ * _PCM16_BYTES_PER_SAMPLE)


def _resolve_auth_mode(
    invocation: _NormalizedInvocation, custom_endpoint: bool
) -> str | None:
    if invocation.auth_mode:
        explicit = _safe_auth_mode(invocation.auth_mode)
        if explicit is not None:
            return explicit
    api_key_header = _header_value(invocation.headers, "x-api-key") or _header_value(
        invocation.headers, "openai-api-key"
    )
    authorization = _header_value(invocation.headers, "authorization")
    ephemeral = _header_value(
        invocation.headers, "openai-ephemeral-key"
    ) or _header_value(invocation.headers, "x-openai-ephemeral-key")
    if ephemeral:
        return "ephemeral_token"
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if token.startswith("ek_") or token.startswith("eph_"):
            return "ephemeral_token"
        if token.startswith("sk-"):
            return "bring_your_own" if custom_endpoint else "api_key"
        return "bring_your_own" if custom_endpoint else "bearer"
    if api_key_header and api_key_header.startswith("sk-"):
        return "bring_your_own" if custom_endpoint else "api_key"
    if api_key_header:
        return "bring_your_own" if custom_endpoint else "api_key"
    if custom_endpoint:
        return "bring_your_own"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("-", "_")
    if mode in {"apikey", "api"}:
        mode = "api_key"
    if mode in {"byok", "bring_your_own_key"}:
        mode = "bring_your_own"
    if mode in {"ephemeral", "ephemeralkey", "ephemeral_key", "session_token"}:
        mode = "ephemeral_token"
    return mode if mode in _SAFE_AUTH_MODES else None


def _nested_auth_mode(raw: Mapping[str, Any]) -> str | None:
    auth = _mapping_value(raw, "auth")
    if isinstance(auth, Mapping):
        return _optional_str(_first_present(auth, "mode", "auth_mode", "authMode"))
    return None


def _metadata_status_code(metadata: Mapping[str, Any]) -> int | None:
    return _optional_int(
        _first_present(
            metadata,
            "HTTPStatusCode",
            "http_status",
            "httpStatus",
            "status_code",
            "statusCode",
        )
    )


def _metadata_request_id(metadata: Mapping[str, Any]) -> str | None:
    return _optional_str(
        _first_present(metadata, "RequestId", "request_id", "requestId")
    )


def _header_value(headers: Mapping[str, Any], key: str) -> str | None:
    for header_key, value in headers.items():
        if str(header_key).lower() == key.lower():
            return str(value)
    return None


def _mapping_value(data: Any, key: str) -> Any:
    if not isinstance(data, Mapping):
        return None
    for candidate_key, value in data.items():
        if str(candidate_key) == key:
            return value
    return None


def _first_present(data: Any, *keys: str) -> Any:
    if not isinstance(data, Mapping):
        return None
    for key in keys:
        if key in data:
            return data[key]
    return None


def _first_mapping(*values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, Mapping):
            return {str(key): item for key, item in value.items()}
    return {}


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part.replace("-", "_") in lowered for part in _SENSITIVE_KEY_PARTS)


def _data_classification_codes(config: ResolvedConfig) -> list[str]:
    codes: list[str] = []
    for values in config.data_classifications.values():
        for code in values:
            if code not in codes:
                codes.append(code)
    return codes


def _output_summary(action: Action) -> str:
    raw = action.parameters.raw
    operation = raw["operation"]
    model = raw.get("model") or "unknown-model"
    turns = raw.get("turn_count") or 0
    audio_in = raw.get("audio_in_seconds") or 0
    audio_out = raw.get("audio_out_seconds") or 0
    return (
        f"{raw['provider']} {operation} {model} "
        f"turns={turns} audio_in_s={audio_in} audio_out_s={audio_out}"
    )
