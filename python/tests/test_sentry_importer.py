"""Tests for the Sentry event importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers import SentryImporter
from ancilis.importers.sentry import (
    _mask_user_id,
    _redact_email,
    _redact_value,
    _safe_frames,
    _truncate_with_hash,
)

# ---------------------------------------------------------------------------
# Fixture builders — inline Sentry events (no sentry-sdk needed)
# ---------------------------------------------------------------------------

SECRET_TITLE = (
    "ValueError in /api/agent/run: " + ("X" * 500)  # > 200 chars to force truncation
)
SECRET_EXCEPTION_VALUE = "DO_NOT_LEAK_user_input_PII_555-12-9876"
SECRET_SOURCE_LINE = "auth_token = 'secret_value_DO_NOT_LEAK'"


def _event(
    *,
    event_id: str = "abcdef0123456789",
    group_id: str = "1234567890",
    type_: str = "error",
    level: str = "error",
    platform: str = "python",
    title: str = "ValueError: bad input",
    transaction: str = "/api/agent/run",
    culprit: str = "agent.run in agent.py",
    tags: list[dict[str, str]] | None = None,
    contexts: dict[str, Any] | None = None,
    exception: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
    fingerprint: list[str] | None = None,
    release: str = "v1.2.3",
    environment: str = "production",
    is_unhandled: bool = True,
    is_resolved: bool = False,
    user_count: int = 1,
    event_count: int = 1,
    timestamp: str = "2026-05-09T12:34:56Z",
) -> dict[str, Any]:
    if tags is None:
        tags = [
            {"key": "environment", "value": environment},
            {"key": "agent.framework", "value": "langchain"},
        ]
    if contexts is None:
        contexts = {
            "trace": {"trace_id": "trace-1", "span_id": "span-1"},
            "user": {"id": "user-1234567890xyz4", "email": "alice@example.com"},
            "runtime": {"name": "python", "version": "3.11"},
        }
    if exception is None:
        exception = {
            "values": [
                {
                    "type": "ValueError",
                    "value": SECRET_EXCEPTION_VALUE,
                    "module": "builtins",
                    "stacktrace": {
                        "frames": [
                            {
                                "filename": "agent.py",
                                "function": "run",
                                "lineno": 42,
                                "in_app": True,
                                "context_line": SECRET_SOURCE_LINE,
                                "pre_context": [SECRET_SOURCE_LINE],
                                "post_context": [SECRET_SOURCE_LINE],
                            }
                        ]
                    },
                }
            ]
        }
    return {
        "id": event_id,
        "eventID": event_id,
        "groupID": group_id,
        "type": type_,
        "level": level,
        "platform": platform,
        "timestamp": timestamp,
        "title": title,
        "transaction": transaction,
        "culprit": culprit,
        "tags": tags,
        "contexts": contexts,
        "exception": exception,
        "extra": extra or {"prompt_token_count": 100, "user_input": "do not leak"},
        "fingerprint": fingerprint or ["{{ default }}"],
        "release": release,
        "environment": environment,
        "user_count": user_count,
        "event_count": event_count,
        "is_unhandled": is_unhandled,
        "is_resolved": is_resolved,
        "received": "2026-05-09T12:34:56Z",
    }


def _envelope(events: list[dict[str, Any]]) -> str:
    return json.dumps({"data": events})


def _find_control(results: list[Any], control_id: str, signal: str | None = None):
    for r in results:
        for cr in r.control_results:
            if cr.control_id == control_id and (
                signal is None or cr.evidence_data.get("signal") == signal
            ):
                return cr
    return None


# ---------------------------------------------------------------------------
# 1. Unhandled error → DE-01 FAIL
# ---------------------------------------------------------------------------

def test_parse_unhandled_error_fails() -> None:
    importer = SentryImporter()
    payload = _envelope([_event(level="error", is_unhandled=True)])
    results = importer.parse_string(payload)

    assert len(results) == 1
    de01 = _find_control(results, "DE-01", signal="type_error_unhandled")
    assert de01 is not None
    assert de01.result == "FAIL"
    # decision should reflect FAIL severity (FLAG in audit, BLOCK in enforce)
    assert results[0].decision in ("BLOCK", "FLAG")


def test_parse_unhandled_fatal_fails() -> None:
    importer = SentryImporter()
    payload = _envelope([_event(level="fatal", is_unhandled=True)])
    results = importer.parse_string(payload)
    de01 = _find_control(results, "DE-01", signal="type_error_fatal")
    assert de01 is not None
    assert de01.result == "FAIL"


# ---------------------------------------------------------------------------
# 2. Handled error → PR-05 FLAG
# ---------------------------------------------------------------------------

def test_handled_error_flags() -> None:
    importer = SentryImporter()
    payload = _envelope([_event(level="error", is_unhandled=False)])
    results = importer.parse_string(payload)

    pr05 = _find_control(results, "PR-05", signal="type_error_handled")
    assert pr05 is not None
    assert pr05.result == "FLAG"
    # No DE-01 from baseline — handled errors are surfaced not failed.
    assert _find_control(results, "DE-01", signal="type_error_handled") is None


# ---------------------------------------------------------------------------
# 3. Warning level → PR-05 FLAG
# ---------------------------------------------------------------------------

def test_warning_flags() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [_event(level="warning", is_unhandled=False, exception=None)]
    )
    results = importer.parse_string(payload)
    pr05 = _find_control(results, "PR-05", signal="type_warning")
    assert pr05 is not None
    assert pr05.result == "FLAG"


# ---------------------------------------------------------------------------
# 4. Transaction → PR-05 PASS audit-trail
# ---------------------------------------------------------------------------

def test_transaction_passes_audit() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [
            _event(
                type_="transaction",
                level="info",
                exception=None,
                contexts={
                    "trace": {"trace_id": "trace-2", "span_id": "span-2"},
                    "ai": {
                        "model": "gpt-4o",
                        "operation": "agent_run",
                        "input_tokens": 100,
                        "output_tokens": 50,
                        "total_tokens": 150,
                        "response_quality_score": 0.95,
                    },
                },
                is_unhandled=False,
            )
        ]
    )
    results = importer.parse_string(payload)
    pr05 = _find_control(results, "PR-05", signal="type_transaction")
    assert pr05 is not None
    assert pr05.result == "PASS"
    assert results[0].decision == "ALLOW"


# ---------------------------------------------------------------------------
# 5. Low quality score → PR-03 FLAG
# ---------------------------------------------------------------------------

def test_low_quality_score_flags_degradation() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [
            _event(
                type_="transaction",
                level="info",
                exception=None,
                contexts={
                    "trace": {"trace_id": "trace-3", "span_id": "span-3"},
                    "ai": {
                        "model": "gpt-4o",
                        "operation": "agent_run",
                        "response_quality_score": 0.1,
                    },
                },
                is_unhandled=False,
            )
        ]
    )
    results = importer.parse_string(payload)
    pr03 = _find_control(results, "PR-03", signal="low_quality_score")
    assert pr03 is not None
    assert pr03.result == "FLAG"


# ---------------------------------------------------------------------------
# 6. AI chat operation → PR-01 captured
# ---------------------------------------------------------------------------

def test_ai_chat_operation_captured() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [
            _event(
                type_="transaction",
                level="info",
                exception=None,
                contexts={
                    "trace": {"trace_id": "trace-4", "span_id": "span-4"},
                    "ai": {
                        "model": "gpt-4o",
                        "operation": "chat",
                        "input_tokens": 100,
                        "output_tokens": 50,
                        "total_tokens": 150,
                    },
                },
                is_unhandled=False,
            )
        ]
    )
    results = importer.parse_string(payload)
    pr01 = _find_control(results, "PR-01", signal="operation_chat")
    assert pr01 is not None
    assert pr01.evidence_data["ai"]["model"] == "gpt-4o"
    assert pr01.evidence_data["ai"]["total_tokens"] == 150


# ---------------------------------------------------------------------------
# 7. AI tool_call operation → PR-02 captured
# ---------------------------------------------------------------------------

def test_ai_tool_call_operation_captured() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [
            _event(
                type_="transaction",
                level="info",
                exception=None,
                contexts={
                    "trace": {"trace_id": "trace-5", "span_id": "span-5"},
                    "ai": {
                        "model": "gpt-4o",
                        "operation": "tool_call",
                        "tool_name": "fetch_weather",
                    },
                },
                is_unhandled=False,
            )
        ]
    )
    results = importer.parse_string(payload)
    pr02 = _find_control(results, "PR-02", signal="operation_tool_call")
    assert pr02 is not None
    assert pr02.evidence_data["ai"]["tool_name"] == "fetch_weather"


# ---------------------------------------------------------------------------
# 8. Security keyword in exception → PR-01 FLAG
# ---------------------------------------------------------------------------

def test_security_keyword_in_exception_flags() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [
            _event(
                level="error",
                is_unhandled=True,
                exception={
                    "values": [
                        {
                            "type": "AuthenticationFailed",
                            "value": "Invalid API key — secret rotated",
                            "module": "auth",
                            "stacktrace": {"frames": []},
                        }
                    ]
                },
            )
        ]
    )
    results = importer.parse_string(payload)
    pr01 = _find_control(results, "PR-01", signal="security_keyword")
    assert pr01 is not None
    assert pr01.result == "FLAG"
    # Stored matched_pattern should be one of the configured keyword patterns.
    assert pr01.evidence_data.get("matched_pattern", "").startswith("*")


# ---------------------------------------------------------------------------
# 9. Widespread group-level error → PR-04 FLAG
# ---------------------------------------------------------------------------

def test_widespread_error_group_flags() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [
            _event(
                level="error",
                is_unhandled=True,
                event_count=5000,
                user_count=500,
            )
        ]
    )
    results = importer.parse_string(payload)
    pr04 = _find_control(results, "PR-04", signal="widespread_error")
    assert pr04 is not None
    assert pr04.result == "FLAG"
    assert pr04.evidence_data["event_count"] == 5000
    assert pr04.evidence_data["user_count"] == 500


# ---------------------------------------------------------------------------
# 10. Exception value redacted (length + sha256, never raw)
# ---------------------------------------------------------------------------

def test_exception_value_redacted() -> None:
    importer = SentryImporter()
    payload = _envelope([_event()])
    results = importer.parse_string(payload)
    serialized = json.dumps(
        [r.__dict__ for r in results],
        default=lambda o: getattr(o, "__dict__", str(o)),
    )
    assert SECRET_EXCEPTION_VALUE not in serialized

    # Exception summary should record sha256 + length, not the raw value.
    de01 = _find_control(results, "DE-01")
    assert de01 is not None
    exc_summary = de01.evidence_data["exception"]
    first = exc_summary["values"][0]
    assert "value_redacted" in first
    redacted = first["value_redacted"]
    assert redacted["present"] is True
    assert redacted["sha256"] == hashlib.sha256(
        SECRET_EXCEPTION_VALUE.encode("utf-8")
    ).hexdigest()
    assert redacted["byte_length"] == len(SECRET_EXCEPTION_VALUE.encode("utf-8"))


# ---------------------------------------------------------------------------
# 11. User email — only domain stored, local part dropped
# ---------------------------------------------------------------------------

def test_user_email_only_domain_stored() -> None:
    importer = SentryImporter()
    payload = _envelope([_event()])
    results = importer.parse_string(payload)
    serialized = json.dumps(
        [r.__dict__ for r in results],
        default=lambda o: getattr(o, "__dict__", str(o)),
    )
    assert "alice@example.com" not in serialized
    assert "alice" not in serialized.replace("alice...", "")  # also no bare local-part

    de01 = _find_control(results, "DE-01")
    assert de01 is not None
    user = de01.evidence_data["user"]
    assert user["email_domain"] == "@example.com"
    # User id should be masked too.
    assert user["id_masked"] is not None
    assert user["id_masked"] != "user-1234567890xyz4"
    assert "..." in user["id_masked"]


# ---------------------------------------------------------------------------
# 12. Stacktrace source-line content NEVER stored
# ---------------------------------------------------------------------------

def test_stacktrace_source_lines_never_stored() -> None:
    importer = SentryImporter()
    payload = _envelope([_event()])
    results = importer.parse_string(payload)
    serialized = json.dumps(
        [r.__dict__ for r in results],
        default=lambda o: getattr(o, "__dict__", str(o)),
    )
    assert SECRET_SOURCE_LINE not in serialized
    assert "context_line" not in serialized
    assert "pre_context" not in serialized
    assert "post_context" not in serialized

    de01 = _find_control(results, "DE-01")
    assert de01 is not None
    frames = de01.evidence_data["exception"]["values"][0]["frames"]
    assert frames == [
        {
            "filename": "agent.py",
            "function": "run",
            "lineno": 42,
            "module": None,
            "in_app": True,
        }
    ]


# ---------------------------------------------------------------------------
# 13. Title truncated with sha256
# ---------------------------------------------------------------------------

def test_title_truncated_with_sha256() -> None:
    importer = SentryImporter()
    payload = _envelope([_event(title=SECRET_TITLE)])
    results = importer.parse_string(payload)

    serialized = json.dumps(
        [r.__dict__ for r in results],
        default=lambda o: getattr(o, "__dict__", str(o)),
    )
    # Full title (with the long X-run) must not appear verbatim.
    assert SECRET_TITLE not in serialized

    de01 = _find_control(results, "DE-01")
    assert de01 is not None
    title = de01.evidence_data["title_redacted"]
    assert title["truncated"] is True
    assert title["length"] == len(SECRET_TITLE)
    assert len(title["preview"]) <= 200
    assert title["sha256"] == hashlib.sha256(
        SECRET_TITLE.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# 14. JSONL stream
# ---------------------------------------------------------------------------

def test_jsonl_stream() -> None:
    importer = SentryImporter()
    e1 = _event(event_id="aaaa1111", level="error", is_unhandled=True)
    e2 = _event(
        event_id="bbbb2222",
        type_="transaction",
        level="info",
        exception=None,
        contexts={
            "trace": {"trace_id": "t-2", "span_id": "s-2"},
            "ai": {
                "model": "gpt-4o",
                "operation": "chat",
                "response_quality_score": 0.9,
            },
        },
        is_unhandled=False,
    )
    e3 = _event(
        event_id="cccc3333",
        level="warning",
        exception=None,
        is_unhandled=False,
    )
    jsonl = "\n".join(json.dumps(e) for e in (e1, e2, e3))
    results = importer.parse_string(jsonl)
    assert len(results) == 3
    assert _find_control([results[0]], "DE-01") is not None
    assert _find_control([results[1]], "PR-01", signal="operation_chat") is not None
    assert _find_control([results[2]], "PR-05", signal="type_warning") is not None


# ---------------------------------------------------------------------------
# 15. Source provenance includes file hash
# ---------------------------------------------------------------------------

def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    importer = SentryImporter()
    payload = _envelope([_event(level="error", is_unhandled=True)])
    file_path = tmp_path / "sentry-events.json"
    file_path.write_text(payload, encoding="utf-8")

    expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    results = importer.parse(file_path)

    assert len(results) == 1
    de01 = _find_control(results, "DE-01")
    assert de01 is not None
    provenance = de01.evidence_data["source_provenance"]
    assert provenance["source_format"] == "sentry"
    assert provenance["source_tool_name"] == "sentry"
    assert provenance["original_file_sha256"] == expected_hash


# ---------------------------------------------------------------------------
# 16. Helper sanity checks (small, fast)
# ---------------------------------------------------------------------------

def test_redact_email_helper() -> None:
    assert _redact_email("alice@example.com") == "@example.com"
    assert _redact_email(None) is None
    assert _redact_email("no-at-sign") is None


def test_mask_user_id_helper() -> None:
    masked = _mask_user_id("user-1234567890xyz4")
    assert masked is not None
    assert masked.startswith("user")
    assert masked.endswith("xyz4")
    assert "..." in masked
    assert _mask_user_id(None) is None


def test_redact_value_helper() -> None:
    redacted = _redact_value("hello secret")
    assert redacted["present"] is True
    assert redacted["byte_length"] == len("hello secret".encode("utf-8"))
    assert redacted["sha256"] == hashlib.sha256(b"hello secret").hexdigest()
    assert _redact_value(None) == {"present": False}


def test_safe_frames_strips_source_lines() -> None:
    frames = _safe_frames(
        [
            {
                "filename": "x.py",
                "function": "f",
                "lineno": 1,
                "context_line": "secret",
                "pre_context": ["s1"],
                "post_context": ["s2"],
            }
        ]
    )
    assert frames == [
        {"filename": "x.py", "function": "f", "lineno": 1, "module": None, "in_app": None}
    ]


def test_truncate_with_hash_short_string() -> None:
    out = _truncate_with_hash("hello")
    assert out["preview"] == "hello"
    assert out["truncated"] is False
    assert out["length"] == 5


# ---------------------------------------------------------------------------
# Single-event (no envelope) shape support
# ---------------------------------------------------------------------------

def test_parse_single_event_shape() -> None:
    importer = SentryImporter()
    payload = json.dumps(_event(level="error", is_unhandled=True))
    results = importer.parse_string(payload)
    assert len(results) == 1
    assert _find_control(results, "DE-01") is not None


def test_empty_payload_emits_audit_pass() -> None:
    importer = SentryImporter()
    results = importer.parse_string("")
    assert len(results) == 1
    assert results[0].decision == "ALLOW"
    assert results[0].control_results[0].control_id == "PR-05"


def test_priority_high_for_production_error() -> None:
    importer = SentryImporter()
    payload = _envelope(
        [_event(level="error", is_unhandled=True, environment="production")]
    )
    results = importer.parse_string(payload)
    de01 = _find_control(results, "DE-01")
    assert de01 is not None
    assert de01.evidence_data["priority"] == "high"


def test_extra_dict_only_keys_stored() -> None:
    importer = SentryImporter()
    secret_extra_value = "DO_NOT_LEAK_extra_value"
    payload = _envelope(
        [
            _event(
                level="error",
                is_unhandled=True,
                extra={"prompt_token_count": 100, "user_input": secret_extra_value},
            )
        ]
    )
    results = importer.parse_string(payload)
    serialized = json.dumps(
        [r.__dict__ for r in results],
        default=lambda o: getattr(o, "__dict__", str(o)),
    )
    assert secret_extra_value not in serialized

    de01 = _find_control(results, "DE-01")
    assert de01 is not None
    extra_summary = de01.evidence_data["extra_summary"]
    assert extra_summary["present"] is True
    assert sorted(extra_summary["keys"]) == ["prompt_token_count", "user_input"]
