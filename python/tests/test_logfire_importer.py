"""Tests for the Pydantic Logfire OTLP/JSON span importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers import LogfireImporter
from ancilis.importers.logfire import (
    _decode_any_value,
    _decode_attributes,
    _strip_url_query,
    _truncate_with_hash,
)


# ---------------------------------------------------------------------------
# Fixture builders — raw OTLP/JSON dicts so the SDK never needs `logfire`
# or `pydantic` installed.
# ---------------------------------------------------------------------------


def _attr(key: str, value: Any) -> dict[str, Any]:
    """Build an OTLP attribute entry, picking the right oneof for *value*."""
    if isinstance(value, bool):
        wrapped: dict[str, Any] = {"boolValue": value}
    elif isinstance(value, int):
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
    name: str = "logfire-span",
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


def _otlp(
    *spans: dict[str, Any],
    scope_name: str = "logfire",
    scope_version: str = "0.50.0",
) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _attr("service.name", "test-agent"),
                        _attr("logfire.environment", "test"),
                    ],
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


# ---------------------------------------------------------------------------
# Pure Logfire (no gen_ai) span tests
# ---------------------------------------------------------------------------


def test_parse_pure_logfire_span_no_gen_ai() -> None:
    """A bare Logfire info-level span produces a PR-05 PASS audit-trail record."""
    span = _span(
        name="processing batch",
        attributes=[
            _attr("logfire.level_name", "info"),
            _attr("logfire.msg", "Processing batch of 100 items"),
            _attr("logfire.tags", ["batch", "ingest"]),
            _attr("code.filepath", "/app/worker.py"),
            _attr("code.function", "process_batch"),
            _attr("code.lineno", 42),
        ],
    )
    importer = LogfireImporter(agent_id="agent-1", mode="audit")
    results = importer.parse_string(json.dumps(_otlp(span)))

    assert len(results) == 1
    er = results[0]
    assert er.source_type == "logfire_import"
    assert er.decision == "ALLOW"
    cr = er.control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["logfire"]["level_name"] == "info"
    assert cr.evidence_data["code"]["filepath"] == "/app/worker.py"
    assert cr.evidence_data["code"]["function"] == "process_batch"
    assert cr.evidence_data["code"]["lineno"] == 42
    # No gen_ai block since no gen_ai.* attrs are present.
    assert "gen_ai" not in cr.evidence_data


def test_parse_logfire_with_gen_ai_layered() -> None:
    """gen_ai.operation=chat → PR-01; logfire info level keeps it PASS."""
    span = _span(
        name="chat openai",
        attributes=[
            _attr("logfire.level_name", "info"),
            _attr("logfire.msg", "model call"),
            _attr("gen_ai.system", "openai"),
            _attr("gen_ai.operation.name", "chat"),
            _attr("gen_ai.request.model", "gpt-4o-mini"),
            _attr("gen_ai.usage.input_tokens", 50),
            _attr("gen_ai.usage.output_tokens", 20),
            _attr("pydantic_ai.agent_name", "support-agent"),
            _attr("pydantic_ai.run_id", "run-123"),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    assert len(results) == 1
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"
    assert cr.evidence_data["gen_ai"]["system"] == "openai"
    assert cr.evidence_data["gen_ai"]["operation"] == "chat"
    assert cr.evidence_data["gen_ai"]["request_model"] == "gpt-4o-mini"
    assert cr.evidence_data["gen_ai"]["usage"]["input_tokens"] == 50
    assert cr.evidence_data["pydantic_ai"]["agent_name"] == "support-agent"
    assert cr.evidence_data["pydantic_ai"]["run_id"] == "run-123"


# ---------------------------------------------------------------------------
# Level-driven results
# ---------------------------------------------------------------------------


def test_fatal_level_marks_fail() -> None:
    span = _span(
        name="explosion",
        attributes=[
            _attr("logfire.level_name", "fatal"),
            _attr("logfire.msg", "ran out of memory"),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    assert len(results) == 1
    cr = results[0].control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert results[0].decision == "FLAG"  # audit mode


def test_warn_level_flags() -> None:
    span = _span(
        name="rate-limit-hit",
        attributes=[
            _attr("logfire.level_name", "warn"),
            _attr("logfire.msg", "soft rate limit reached"),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    cr = results[0].control_results[0]
    assert cr.result == "FLAG"
    assert results[0].decision == "FLAG"


# ---------------------------------------------------------------------------
# Pydantic-specific signals
# ---------------------------------------------------------------------------


def test_pydantic_validation_errors_fails() -> None:
    """A span with pydantic.validation.errors > 0 routes to PR-03 FAIL."""
    span = _span(
        name="validate input",
        attributes=[
            _attr("logfire.level_name", "info"),
            _attr("pydantic.validation.errors", 3),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert cr.evidence_data["pydantic"]["validation_errors"] == 3


def test_pydantic_ai_tool_name_maps_pr_02() -> None:
    """A pydantic_ai.tool_name attribute (no gen_ai.*) maps to PR-02."""
    span = _span(
        name="tool: search_db",
        attributes=[
            _attr("logfire.level_name", "info"),
            _attr("pydantic_ai.tool_name", "search_db"),
            _attr("pydantic_ai.agent_name", "support-agent"),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    cr = results[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert cr.evidence_data["pydantic_ai"]["tool_name"] == "search_db"


# ---------------------------------------------------------------------------
# HTTP semantics
# ---------------------------------------------------------------------------


def test_http_5xx_fails() -> None:
    span = _span(
        name="POST /v1/agents",
        attributes=[
            _attr("http.method", "POST"),
            _attr("http.status_code", 503),
            _attr("http.url", "https://api.example.com/v1/agents?token=secret"),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    cr = results[0].control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    # Query string should be stripped from the stored URL.
    assert cr.evidence_data["http"]["url"] == "https://api.example.com/v1/agents"
    assert cr.evidence_data["http"]["status_code"] == 503
    assert cr.evidence_data["http"]["method"] == "POST"


def test_http_4xx_flags() -> None:
    span = _span(
        name="GET /v1/users",
        attributes=[
            _attr("http.method", "GET"),
            _attr("http.status_code", 429),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    cr = results[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


def test_exception_type_fails() -> None:
    span = _span(
        name="risky op",
        attributes=[
            _attr("logfire.level_name", "error"),
            _attr("logfire.exception_type", "ValueError"),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    cr = results[0].control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["logfire"]["exception_type"] == "ValueError"


# ---------------------------------------------------------------------------
# Decoder + redaction unit tests
# ---------------------------------------------------------------------------


def test_anyvalue_decoder_handles_int_string_bool() -> None:
    """The OTLP value oneof must unwrap int/string/bool/double/array/kvlist."""
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

    assert _decode_any_value({"doubleValue": 1.25}) == 1.25
    assert _decode_any_value(
        {"kvlistValue": {"values": [{"key": "k", "value": {"stringValue": "v"}}]}}
    ) == {"k": "v"}
    assert _decode_any_value("already-flat") == "already-flat"
    assert _decode_any_value(None) is None


def test_db_statement_never_stored() -> None:
    """db.statement attribute must never reach evidence_data."""
    span = _span(
        name="SELECT users",
        attributes=[
            _attr("logfire.level_name", "info"),
            _attr("db.system", "postgresql"),
            _attr(
                "db.statement",
                "SELECT * FROM users WHERE password = 'super-secret'",
            ),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    cr = results[0].control_results[0]
    serialized = json.dumps(cr.evidence_data)
    assert "super-secret" not in serialized
    assert "db.statement" not in serialized
    # We still record that a DB call happened, just not the statement.
    assert cr.evidence_data["db"]["system"] == "postgresql"
    assert cr.evidence_data["db"]["statement_redacted"] is True


def test_logfire_msg_truncated_with_sha256() -> None:
    """logfire.msg is stored as first 80 chars + sha256 of the full text."""
    long_msg = "a" * 200
    span = _span(
        name="big-log",
        attributes=[
            _attr("logfire.level_name", "info"),
            _attr("logfire.msg", long_msg),
        ],
    )
    importer = LogfireImporter()
    results = importer.parse_string(json.dumps(_otlp(span)))

    msg = results[0].control_results[0].evidence_data["logfire"]["msg"]
    assert msg["preview"] == "a" * 80
    assert msg["sha256"] == hashlib.sha256(long_msg.encode("utf-8")).hexdigest()
    assert msg["truncated"] is True
    assert msg["length"] == 200

    # Round-trip: short messages are not truncated but still carry a hash.
    short = _truncate_with_hash("hello")
    assert short["truncated"] is False
    assert short["preview"] == "hello"
    assert short["sha256"] == hashlib.sha256(b"hello").hexdigest()


# ---------------------------------------------------------------------------
# Stream + provenance
# ---------------------------------------------------------------------------


def test_jsonl_stream() -> None:
    """JSONL: blank lines and `# ...` comment lines are tolerated."""
    span_a = _span(
        span_id="1111111111111111",
        trace_id="11" * 16,
        attributes=[
            _attr("logfire.level_name", "info"),
            _attr("logfire.msg", "step a"),
        ],
    )
    span_b = _span(
        span_id="2222222222222222",
        trace_id="22" * 16,
        attributes=[
            _attr("logfire.level_name", "error"),
            _attr("logfire.exception_type", "RuntimeError"),
        ],
    )
    line1 = json.dumps(_otlp(span_a))
    line2 = json.dumps(_otlp(span_b))
    content = "\n".join(["# leading comment", "", line1, line2, ""])

    importer = LogfireImporter()
    results = importer.parse_string(content)

    assert len(results) == 2
    by_span = {r.action_id: r for r in results}
    assert by_span["1111111111111111"].control_results[0].result == "PASS"
    assert by_span["2222222222222222"].control_results[0].result == "FAIL"


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    span = _span(
        name="hello",
        attributes=[_attr("logfire.level_name", "info")],
    )
    payload = _otlp(span)
    raw = json.dumps(payload).encode("utf-8")
    expected_hash = hashlib.sha256(raw).hexdigest()

    file_path = tmp_path / "logfire-spans.json"
    file_path.write_bytes(raw)

    importer = LogfireImporter()
    results = importer.parse(file_path)

    assert len(results) == 1
    provenance = results[0].control_results[0].evidence_data["source_provenance"]
    assert provenance["source_format"] == "logfire"
    assert provenance["original_file_sha256"] == expected_hash
    assert provenance["vendor"] == "pydantic"
    assert provenance["scope_name"] == "logfire"
    assert provenance["scope_version"] == "0.50.0"


# ---------------------------------------------------------------------------
# Bonus: helper function direct tests
# ---------------------------------------------------------------------------


def test_strip_url_query_drops_query_and_fragment() -> None:
    assert (
        _strip_url_query("https://api.example.com/x?token=abc#frag")
        == "https://api.example.com/x"
    )
    assert _strip_url_query("") == ""
