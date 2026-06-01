"""Tests for the OpenTelemetry GenAI semantic-convention importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ancilis.importers import OtelGenAIImporter
from ancilis.importers.otel_genai import (
    _decode_any_value,
    _decode_attributes,
    _is_gen_ai_span,
    _map_operation_to_control,
)


# ---------------------------------------------------------------------------
# Fixture builders — keep tests self-contained so we never need the
# opentelemetry SDK to be installed.
# ---------------------------------------------------------------------------


def _attr(key: str, value: Any) -> dict[str, Any]:
    """Build an OTLP attribute entry, picking the right oneof for *value*."""
    if isinstance(value, bool):
        wrapped: dict[str, Any] = {"boolValue": value}
    elif isinstance(value, int):
        # OTLP encodes int64s as strings on the wire — exercise that path.
        wrapped = {"intValue": str(value)}
    elif isinstance(value, float):
        wrapped = {"doubleValue": value}
    elif isinstance(value, list):
        wrapped = {"arrayValue": {"values": [_attr("_", v)["value"] for v in value]}}
    else:
        wrapped = {"stringValue": str(value)}
    return {"key": key, "value": wrapped}


def _span(
    *,
    name: str = "chat openai",
    span_id: str = "0102030405060708",
    trace_id: str = "00112233445566778899aabbccddeeff",
    parent_span_id: str = "",
    attributes: list[dict[str, Any]] | None = None,
    status_code: str = "STATUS_CODE_OK",
    start_ns: int = 1_700_000_000_000_000_000,
    end_ns: int = 1_700_000_000_500_000_000,
) -> dict[str, Any]:
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "name": name,
        "kind": 3,
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(end_ns),
        "attributes": attributes or [],
        "status": {"code": status_code},
    }


def _otlp(*spans: dict[str, Any], scope_name: str = "ancilis.test", scope_version: str = "0.1.0") -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [_attr("service.name", "test-agent")],
                },
                "scopeSpans": [
                    {
                        "scope": {"name": scope_name, "version": scope_version},
                        "spans": list(spans),
                    }
                ],
            }
        ]
    }


def _chat_span(**overrides: Any) -> dict[str, Any]:
    return _span(
        name="chat openai",
        attributes=[
            _attr("gen_ai.system", "openai"),
            _attr("gen_ai.operation.name", "chat"),
            _attr("gen_ai.request.model", "gpt-4o-mini"),
            _attr("gen_ai.response.model", "gpt-4o-mini-2024-07-18"),
            _attr("gen_ai.request.temperature", 0.7),
            _attr("gen_ai.request.max_tokens", 256),
            _attr("gen_ai.usage.input_tokens", 42),
            _attr("gen_ai.usage.output_tokens", 17),
            _attr("gen_ai.response.finish_reasons", ["stop"]),
        ],
        **overrides,
    )


# ---------------------------------------------------------------------------
# Decoder unit tests
# ---------------------------------------------------------------------------


def test_attribute_decoder_handles_int_string_bool() -> None:
    """The OTLP value oneof must unwrap int/string/bool consistently."""
    attrs_list = [
        _attr("a.string", "hello"),
        _attr("a.int", 99),
        _attr("a.bool", True),
        _attr("a.array", ["x", "y"]),
    ]
    decoded = _decode_attributes(attrs_list)
    assert decoded["a.string"] == "hello"
    assert decoded["a.int"] == 99 and isinstance(decoded["a.int"], int)
    assert decoded["a.bool"] is True
    assert decoded["a.array"] == ["x", "y"]

    # Direct AnyValue decoder — covers double, kvlist, and pre-unwrapped values.
    assert _decode_any_value({"doubleValue": 1.25}) == 1.25
    assert _decode_any_value({"kvlistValue": {"values": [{"key": "k", "value": {"stringValue": "v"}}]}}) == {"k": "v"}
    assert _decode_any_value("already-flat") == "already-flat"
    assert _decode_any_value(None) is None


def test_is_gen_ai_span_predicate() -> None:
    assert _is_gen_ai_span({"gen_ai.system": "openai"}) is True
    assert _is_gen_ai_span({"http.method": "GET"}) is False
    assert _is_gen_ai_span({}) is False


def test_operation_to_control_mapping() -> None:
    importer = OtelGenAIImporter()
    assert _map_operation_to_control("chat", importer._mappings) == "PR-01"
    assert _map_operation_to_control("text_completion", importer._mappings) == "PR-01"
    assert _map_operation_to_control("embeddings", importer._mappings) == "PR-04"
    assert _map_operation_to_control("execute_tool", importer._mappings) == "PR-02"
    assert _map_operation_to_control("unknown_op", importer._mappings) == "PR-03"


# ---------------------------------------------------------------------------
# parse_string / span-level behaviour
# ---------------------------------------------------------------------------


def test_parse_chat_span() -> None:
    importer = OtelGenAIImporter(agent_id="agent-1", mode="audit")
    payload = _otlp(_chat_span())
    results = importer.parse_string(json.dumps(payload))

    assert len(results) == 1
    er = results[0]
    assert er.source_type == "otel_genai_import"
    assert er.agent_id == "agent-1"
    assert er.decision == "ALLOW"
    assert er.session_id == "00112233445566778899aabbccddeeff"

    assert len(er.control_results) == 1
    cr = er.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"

    ev = cr.evidence_data
    assert ev["operation"] == "chat"
    assert ev["system"] == "openai"
    assert ev["request_model"] == "gpt-4o-mini"
    assert ev["trace_id"] == "00112233445566778899aabbccddeeff"
    assert ev["span_id"] == "0102030405060708"
    assert ev["finish_reasons"] == ["stop"]
    assert ev["request_params"]["temperature"] == 0.7
    assert ev["request_params"]["max_tokens"] == 256


def test_parse_tool_span_maps_to_pr_02() -> None:
    span = _span(
        name="execute_tool query_db",
        attributes=[
            _attr("gen_ai.system", "anthropic"),
            _attr("gen_ai.operation.name", "execute_tool"),
            _attr("gen_ai.tool.name", "query_db"),
            _attr("gen_ai.tool.call.id", "tool_call_42"),
        ],
    )
    importer = OtelGenAIImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    assert len(results) == 1
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert cr.evidence_data["tool_name"] == "query_db"
    assert cr.evidence_data["tool_call_id"] == "tool_call_42"
    assert cr.evidence_data["system"] == "anthropic"


def test_parse_embeddings_span_maps_to_pr_04() -> None:
    span = _span(
        name="embeddings cohere",
        attributes=[
            _attr("gen_ai.system", "cohere"),
            _attr("gen_ai.operation.name", "embeddings"),
            _attr("gen_ai.request.model", "embed-english-v3.0"),
            _attr("gen_ai.usage.input_tokens", 128),
        ],
    )
    importer = OtelGenAIImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    assert len(results) == 1
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["operation"] == "embeddings"


def test_error_span_marks_fail() -> None:
    span = _span(
        name="chat anthropic",
        attributes=[
            _attr("gen_ai.system", "anthropic"),
            _attr("gen_ai.operation.name", "chat"),
            _attr("gen_ai.request.model", "claude-3-5-sonnet"),
            _attr("error.type", "RateLimitError"),
        ],
        status_code="STATUS_CODE_ERROR",
    )
    importer = OtelGenAIImporter(mode="audit")
    results = importer.parse_string(json.dumps(_otlp(span)))

    assert len(results) == 1
    er = results[0]
    cr = er.control_results[0]
    assert cr.result == "FAIL"
    assert cr.evidence_data["error_type"] == "RateLimitError"
    assert cr.evidence_data["status_code"] == "STATUS_CODE_ERROR"
    # In audit mode an error becomes FLAG (not BLOCK).
    assert er.decision == "FLAG"


def test_enforce_mode_blocks_on_error() -> None:
    span = _span(
        attributes=[
            _attr("gen_ai.system", "openai"),
            _attr("gen_ai.operation.name", "chat"),
            _attr("error.type", "InternalServerError"),
        ],
        status_code="STATUS_CODE_ERROR",
    )
    importer = OtelGenAIImporter(mode="enforce")
    results = importer.parse_string(json.dumps(_otlp(span)))
    assert results[0].decision == "BLOCK"


def test_token_usage_extracted() -> None:
    span = _chat_span()
    importer = OtelGenAIImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    usage = results[0].control_results[0].evidence_data["usage"]
    assert usage["input_tokens"] == 42
    assert usage["output_tokens"] == 17
    # total_tokens not on the wire — should come back None, not blow up.
    assert usage["total_tokens"] is None


def test_non_gen_ai_spans_filtered_out() -> None:
    http_span = _span(
        name="GET /v1/users",
        span_id="aaaaaaaaaaaaaaaa",
        attributes=[_attr("http.method", "GET"), _attr("http.status_code", 200)],
    )
    chat = _chat_span(span_id="bbbbbbbbbbbbbbbb")
    importer = OtelGenAIImporter()
    results = importer.parse_string(json.dumps(_otlp(http_span, chat)))

    assert len(results) == 1
    assert results[0].action_id == "bbbbbbbbbbbbbbbb"


def test_jsonl_stream_supported() -> None:
    """JSONL: one ResourceSpans (or full doc) per line, blank/comment lines tolerated."""
    chat = _chat_span(span_id="1111111111111111", trace_id="11" * 16)
    embed = _span(
        span_id="2222222222222222",
        trace_id="22" * 16,
        attributes=[
            _attr("gen_ai.system", "vertex_ai"),
            _attr("gen_ai.operation.name", "embeddings"),
        ],
    )
    line1 = json.dumps(_otlp(chat))
    line2 = json.dumps(_otlp(embed))
    content = "\n".join(["# leading comment", "", line1, line2, ""])

    importer = OtelGenAIImporter()
    results = importer.parse_string(content)

    assert len(results) == 2
    controls = sorted(cr.control_id for r in results for cr in r.control_results)
    assert controls == ["PR-01", "PR-04"]


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    payload = _otlp(_chat_span())
    raw = json.dumps(payload).encode("utf-8")
    expected_hash = hashlib.sha256(raw).hexdigest()

    file_path = tmp_path / "spans.json"
    file_path.write_bytes(raw)

    importer = OtelGenAIImporter()
    results = importer.parse(file_path)

    assert len(results) == 1
    provenance = results[0].control_results[0].evidence_data["source_provenance"]
    assert provenance["source_format"] == "otel-genai"
    assert provenance["original_file_sha256"] == expected_hash
    assert provenance["scope_name"] == "ancilis.test"
    assert provenance["scope_version"] == "0.1.0"


# ---------------------------------------------------------------------------
# Robustness — malformed inputs should never raise.
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_list() -> None:
    importer = OtelGenAIImporter()
    assert importer.parse_string("") == []
    assert importer.parse_string("   \n  ") == []


def test_resource_spans_snake_case_supported() -> None:
    payload = {
        "resource_spans": [
            {
                "resource": {"attributes": []},
                "scope_spans": [
                    {"scope": {"name": "snake"}, "spans": [_chat_span()]},
                ],
            }
        ]
    }
    importer = OtelGenAIImporter()
    results = importer.parse_string(json.dumps(payload))
    assert len(results) == 1


def test_numeric_status_code_supported() -> None:
    span = _chat_span()
    span["status"] = {"code": 2}  # numeric 2 == STATUS_CODE_ERROR
    importer = OtelGenAIImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))
    assert results[0].control_results[0].result == "FAIL"
