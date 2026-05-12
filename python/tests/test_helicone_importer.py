"""Tests for the Helicone request/log evidence importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers.helicone import HeliconeImporter, _sanitize_body


# ---------------------------------------------------------------------------
# Fixtures — inline Helicone export documents (no helicone package required)
# ---------------------------------------------------------------------------

def _entry(
    *,
    id: str = "req-1",
    status: int = 200,
    cost_usd: float = 0.001,
    feedback: dict | None = None,
    node_id: str | None = "thread-1",
    request_body: dict | None = None,
    response_body: dict | None = None,
    properties: dict | None = None,
) -> dict:
    return {
        "id": id,
        "request_created_at": "2026-04-01T12:00:00Z",
        "response_created_at": "2026-04-01T12:00:01Z",
        "user_id": "user-42",
        "model": "gpt-4o",
        "provider": "OPENAI",
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "cost_usd": cost_usd,
        "status": status,
        "latency_ms": 1234,
        "request_body": request_body if request_body is not None else {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "secret prompt"}],
        },
        "response_body": response_body if response_body is not None else {
            "id": "chatcmpl-xyz",
            "choices": [{"message": {"content": "sensitive response"}}],
        },
        "properties": properties or {"env": "prod"},
        "feedback": feedback if feedback is not None else {},
        "node_id": node_id,
    }


def _export(*entries: dict) -> str:
    return json.dumps({"data": list(entries)})


HELICONE_CLEAN = _export(_entry())
HELICONE_400 = _export(_entry(id="req-400", status=401))
HELICONE_500 = _export(_entry(id="req-500", status=502))
HELICONE_NEG_FEEDBACK = _export(
    _entry(id="req-neg", status=200, feedback={"rating": "negative"})
)
HELICONE_HIGH_COST = _export(_entry(id="req-pricey", status=200, cost_usd=2.5))
HELICONE_MIXED = _export(
    _entry(id="req-a", status=200),
    _entry(id="req-b", status=403),
    _entry(id="req-c", status=503),
    _entry(id="req-d", status=200, feedback={"rating": "negative"}),
    _entry(id="req-e", status=200, cost_usd=5.0),
)


# ---------------------------------------------------------------------------
# Importer behaviour tests
# ---------------------------------------------------------------------------

class TestHeliconeImporter:
    def test_parse_export(self):
        """Importer reads {data: [...]} envelope and returns one result per entry."""
        imp = HeliconeImporter(agent_id="ci")
        results = imp.parse_string(HELICONE_MIXED)

        assert len(results) == 5
        for ev in results:
            assert ev.source_type == "helicone_import"
            assert ev.agent_id == "ci"
            assert ev.evaluation_id  # uuid populated
            assert ev.timestamp
            assert isinstance(ev.control_results, list)
            assert len(ev.control_results) >= 1

    def test_status_200_passes(self):
        imp = HeliconeImporter()
        results = imp.parse_string(HELICONE_CLEAN)

        assert len(results) == 1
        ev = results[0]
        assert ev.decision == "ALLOW"
        # Exactly one control result for a clean 200 entry
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-01"
        assert cr.evidence_data["signal"] == "status_2xx"
        assert cr.evidence_data["provider"] == "OPENAI"
        assert cr.evidence_data["model"] == "gpt-4o"
        assert cr.evidence_data["total_tokens"] == 150

    def test_status_4xx_flags(self):
        imp = HeliconeImporter()
        ev = imp.parse_string(HELICONE_400)[0]

        assert ev.decision == "FLAG"
        cr = ev.control_results[0]
        assert cr.result == "FLAG"
        assert cr.control_id == "PR-02"
        assert cr.evidence_data["signal"] == "status_4xx"
        assert cr.evidence_data["status"] == 401

    def test_status_5xx_flags(self):
        imp = HeliconeImporter()
        ev = imp.parse_string(HELICONE_500)[0]

        assert ev.decision == "FLAG"
        cr = ev.control_results[0]
        assert cr.result == "FLAG"
        assert cr.control_id == "DE-01"
        assert cr.evidence_data["signal"] == "status_5xx"
        assert cr.evidence_data["status"] == 502

    def test_negative_feedback_flags(self):
        imp = HeliconeImporter()
        ev = imp.parse_string(HELICONE_NEG_FEEDBACK)[0]

        # Even though status is 200, negative feedback should produce a FLAG.
        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "status_2xx" in signals
        assert "negative_feedback" in signals

        neg = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "negative_feedback"
        )
        assert neg.result == "FLAG"
        assert neg.control_id == "PR-05"

    def test_cost_threshold_flag(self):
        # Default threshold is $1; entry costs $2.5
        imp_default = HeliconeImporter()
        ev = imp_default.parse_string(HELICONE_HIGH_COST)[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "cost_threshold_exceeded" in signals
        cost_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "cost_threshold_exceeded"
        )
        assert cost_cr.result == "FLAG"
        assert cost_cr.control_id == "PR-04"
        assert cost_cr.evidence_data["cost_usd"] == 2.5
        assert cost_cr.evidence_data["cost_threshold_usd"] == 1.0

        # Custom higher threshold should suppress the flag.
        imp_lenient = HeliconeImporter(cost_threshold_usd=10.0)
        ev2 = imp_lenient.parse_string(HELICONE_HIGH_COST)[0]
        assert ev2.decision == "ALLOW"
        signals2 = {cr.evidence_data.get("signal") for cr in ev2.control_results}
        assert "cost_threshold_exceeded" not in signals2

    def test_request_body_not_stored_raw(self):
        """Sensitive prompt/response text must never appear in evidence_data."""
        secret_prompt = "DO NOT LEAK: super-secret-customer-data"
        secret_response = "DO NOT LEAK: confidential-answer"
        export = _export(_entry(
            id="req-priv",
            status=200,
            request_body={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": secret_prompt}],
            },
            response_body={
                "choices": [{"message": {"content": secret_response}}],
            },
        ))

        imp = HeliconeImporter()
        ev = imp.parse_string(export)[0]
        cr = ev.control_results[0]

        # Serialize the entire EvaluationResult and confirm secret content is absent.
        serialized = json.dumps({
            "decision": ev.decision,
            "decision_reason": ev.decision_reason,
            "control_results": [
                {
                    "control_id": c.control_id,
                    "detail": c.detail,
                    "evidence_data": c.evidence_data,
                }
                for c in ev.control_results
            ],
        }, default=str)
        assert secret_prompt not in serialized
        assert secret_response not in serialized

        # Body summary must include keys + sha256, but no raw content.
        req_summary = cr.evidence_data["request_body_summary"]
        assert req_summary["present"] is True
        assert "body_keys" in req_summary
        assert "messages" in req_summary["body_keys"]
        assert "sha256" in req_summary
        assert "byte_length" in req_summary
        # Crucially: no field carrying raw content
        assert "messages" not in req_summary or req_summary.get("kind") == "object"
        for forbidden in ("content", "messages_raw", "prompt", "text"):
            # body_keys may legitimately list "messages" — that's metadata, not raw.
            assert forbidden not in req_summary or forbidden == "content" and req_summary.get(forbidden) in (None,)

        resp_summary = cr.evidence_data["response_body_summary"]
        assert resp_summary["present"] is True
        assert "sha256" in resp_summary

    def test_clean_export_yields_pass(self):
        """An export of only successful, low-cost, no-feedback requests → all ALLOW."""
        export = _export(
            _entry(id="r1", status=200, cost_usd=0.001),
            _entry(id="r2", status=201, cost_usd=0.002),
            _entry(id="r3", status=200, cost_usd=0.003),
        )
        imp = HeliconeImporter()
        results = imp.parse_string(export)

        assert len(results) == 3
        assert all(ev.decision == "ALLOW" for ev in results)
        for ev in results:
            assert len(ev.control_results) == 1
            assert ev.control_results[0].result == "PASS"
            assert ev.control_results[0].control_id == "PR-01"


# ---------------------------------------------------------------------------
# File-based parse + provenance hash
# ---------------------------------------------------------------------------

class TestHeliconeFileProvenance:
    def test_parse_file_captures_hash(self, tmp_path: Path):
        fixture = tmp_path / "helicone-export.json"
        fixture.write_text(HELICONE_CLEAN, encoding="utf-8")
        expected = hashlib.sha256(HELICONE_CLEAN.encode("utf-8")).hexdigest()

        imp = HeliconeImporter(agent_id="pipeline")
        ev = imp.parse(fixture)[0]
        provenance = ev.control_results[0].evidence_data["source_provenance"]

        assert provenance["source_format"] == "helicone"
        assert provenance["original_file_sha256"] == expected


# ---------------------------------------------------------------------------
# Sanitization helper
# ---------------------------------------------------------------------------

class TestSanitizeBody:
    def test_none_body_marked_absent(self):
        s = _sanitize_body(None)
        assert s == {"present": False}

    def test_object_body_keeps_keys_only(self):
        body = {"messages": [{"role": "user", "content": "hi"}], "model": "gpt-4o"}
        s = _sanitize_body(body)
        assert s["present"] is True
        assert s["kind"] == "object"
        assert sorted(s["body_keys"]) == ["messages", "model"]
        assert "sha256" in s
        assert "byte_length" in s
        # No raw content fields leak
        assert "content" not in s
        assert "hi" not in json.dumps(s)

    def test_primitive_body_recorded_with_sha(self):
        s = _sanitize_body("hello world")
        assert s["present"] is True
        assert s["kind"] == "str"
        assert "sha256" in s
        # Raw value must not appear in summary.
        assert "hello world" not in json.dumps(s)
