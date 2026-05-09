"""Tests for the LiteLLM gateway log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.litellm import (
    LiteLLMImporter,
    _detect_guardrail_violation,
    _sanitize_messages,
)


# ---------------------------------------------------------------------------
# Fixture builders — inline LiteLLM callback log entries.
# ---------------------------------------------------------------------------

def _completion_entry(
    *,
    id: str = "req-1",
    model: str = "gpt-4o",
    provider: str = "openai",
    status: str = "success",
    response_cost: float = 0.001,
    messages: list | None = None,
    response: dict | None = None,
    metadata: dict | None = None,
    exception: str | None = None,
) -> dict:
    return {
        "id": id,
        "call_type": "completion",
        "model": model,
        "messages": messages if messages is not None else [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "secret prompt"},
        ],
        "response": response if response is not None else {
            "id": "chatcmpl-xyz",
            "choices": [{"message": {"content": "sensitive response"}}],
        },
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        "response_cost": response_cost,
        "start_time": "2026-04-01T12:00:00Z",
        "end_time": "2026-04-01T12:00:01Z",
        "status": status,
        "metadata": metadata if metadata is not None else {
            "user_id": "user-42",
            "trace_id": "trace-abc",
            "tags": ["prod"],
        },
        "litellm_params": {
            "api_base": "https://api.openai.com/v1",
            "custom_llm_provider": provider,
        },
        **({"exception": exception} if exception else {}),
    }


def _embedding_entry(**overrides) -> dict:
    base = {
        "id": "emb-1",
        "call_type": "embeddings",
        "model": "text-embedding-3-small",
        "input": ["chunk-a", "chunk-b"],
        "response": {"data": [{"embedding": [0.1, 0.2]}, {"embedding": [0.3, 0.4]}]},
        "usage": {"prompt_tokens": 8, "total_tokens": 8},
        "response_cost": 0.00002,
        "start_time": "2026-04-01T12:01:00Z",
        "end_time": "2026-04-01T12:01:00.500Z",
        "status": "success",
        "metadata": {"user_id": "user-7"},
        "litellm_params": {"custom_llm_provider": "openai"},
    }
    base.update(overrides)
    return base


def _image_entry(**overrides) -> dict:
    base = {
        "id": "img-1",
        "call_type": "image_generation",
        "model": "dall-e-3",
        "input": "a photo of a cat",
        "response": {"data": [{"url": "https://example/img.png"}]},
        "usage": {},
        "response_cost": 0.04,
        "start_time": "2026-04-01T12:02:00Z",
        "end_time": "2026-04-01T12:02:03Z",
        "status": "success",
        "metadata": {},
        "litellm_params": {"custom_llm_provider": "openai"},
    }
    base.update(overrides)
    return base


def _moderation_entry(**overrides) -> dict:
    base = {
        "id": "mod-1",
        "call_type": "moderation",
        "model": "text-moderation-latest",
        "input": "user submitted text",
        "response": {"results": [{"flagged": False}]},
        "usage": {},
        "response_cost": 0.0,
        "start_time": "2026-04-01T12:03:00Z",
        "end_time": "2026-04-01T12:03:00.100Z",
        "status": "success",
        "metadata": {},
        "litellm_params": {"custom_llm_provider": "openai"},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Importer behaviour tests
# ---------------------------------------------------------------------------

class TestLiteLLMImporter:
    def test_parse_completion_success(self):
        imp = LiteLLMImporter(agent_id="ci")
        export = json.dumps([_completion_entry()])
        results = imp.parse_string(export)

        assert len(results) == 1
        ev = results[0]
        assert ev.source_type == "litellm_import"
        assert ev.agent_id == "ci"
        assert ev.decision == "ALLOW"
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-01"
        assert cr.evidence_data["call_type"] == "completion"
        assert cr.evidence_data["signal"] == "completion_success"
        assert cr.evidence_data["total_tokens"] == 150
        # Duration computed from start/end.
        assert ev.total_duration_ms == 1000.0

    def test_parse_embeddings(self):
        imp = LiteLLMImporter()
        export = json.dumps([_embedding_entry()])
        ev = imp.parse_string(export)[0]

        assert ev.decision == "ALLOW"
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-04"
        assert cr.evidence_data["call_type"] == "embeddings"
        assert cr.evidence_data["signal"] == "embeddings_success"
        # Input summary captures item count + sha256 (no raw text).
        inp = cr.evidence_data["input_summary"]
        assert inp["present"] is True
        assert inp["item_count"] == 2
        assert "sha256" in inp

    def test_parse_image_generation(self):
        imp = LiteLLMImporter()
        export = json.dumps([_image_entry()])
        ev = imp.parse_string(export)[0]

        assert ev.decision == "ALLOW"
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-04"
        assert cr.evidence_data["call_type"] == "image_generation"
        assert cr.evidence_data["signal"] == "image_generation_success"

    def test_parse_moderation(self):
        imp = LiteLLMImporter()
        export = json.dumps([_moderation_entry()])
        ev = imp.parse_string(export)[0]

        assert ev.decision == "ALLOW"
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-04"
        assert cr.evidence_data["call_type"] == "moderation"
        assert cr.evidence_data["signal"] == "moderation_success"

    def test_failure_marks_fail(self):
        imp = LiteLLMImporter()
        entry = _completion_entry(
            id="req-fail",
            status="failure",
            exception="openai.RateLimitError: 429",
        )
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "BLOCK"
        # Exactly one control_result for a failure (no PASS added).
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "status_failure" in signals
        assert "completion_success" not in signals
        fail_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "status_failure"
        )
        assert fail_cr.result == "FAIL"
        assert fail_cr.control_id == "DE-01"
        assert "RateLimitError" in fail_cr.evidence_data["exception"]

    def test_cost_threshold_flag(self):
        # Default threshold is $1; use $2.50 to trigger.
        imp = LiteLLMImporter()
        entry = _completion_entry(id="req-pricey", response_cost=2.5)
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "completion_success" in signals
        assert "cost_threshold_exceeded" in signals
        cost_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "cost_threshold_exceeded"
        )
        assert cost_cr.result == "FLAG"
        assert cost_cr.control_id == "PR-04"
        assert cost_cr.evidence_data["cost_threshold_usd"] == 1.0

        # Custom higher threshold suppresses the FLAG.
        lenient = LiteLLMImporter(cost_threshold_usd=10.0)
        ev2 = lenient.parse_string(json.dumps([entry]))[0]
        assert ev2.decision == "ALLOW"
        signals2 = {cr.evidence_data.get("signal") for cr in ev2.control_results}
        assert "cost_threshold_exceeded" not in signals2

    def test_guardrail_violation_marks_fail(self):
        imp = LiteLLMImporter()
        entry = _completion_entry(
            id="req-blocked",
            metadata={
                "user_id": "user-9",
                "guardrail_violation": True,
                "guardrail_reason": "pii_detected",
            },
        )
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "BLOCK"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "guardrail_violation" in signals
        guard_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "guardrail_violation"
        )
        assert guard_cr.result == "FAIL"
        assert guard_cr.control_id == "PR-02"
        assert guard_cr.evidence_data["guardrail_matches"]

    def test_messages_sanitized_no_raw_text(self):
        """Prompt and response text must never appear in evidence_data."""
        secret_prompt = "DO NOT LEAK: super-secret-customer-data"
        secret_response = "DO NOT LEAK: confidential-answer"
        entry = _completion_entry(
            id="req-priv",
            messages=[
                {"role": "system", "content": "be helpful"},
                {"role": "user", "content": secret_prompt},
            ],
            response={"choices": [{"message": {"content": secret_response}}]},
        )
        imp = LiteLLMImporter()
        ev = imp.parse_string(json.dumps([entry]))[0]

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

        cr = ev.control_results[0]
        msg_summary = cr.evidence_data["messages_summary"]
        assert msg_summary["present"] is True
        assert msg_summary["message_count"] == 2
        assert msg_summary["role_distribution"] == {"system": 1, "user": 1}
        assert "sha256" in msg_summary
        assert "byte_length" in msg_summary
        # No raw content fields leak into the summary.
        for forbidden in ("content", "messages_raw", "prompt", "text"):
            assert forbidden not in msg_summary

        resp_summary = cr.evidence_data["response_summary"]
        assert resp_summary["present"] is True
        assert "sha256" in resp_summary

    def test_jsonl_stream(self):
        """JSONL: one JSON object per line, blank lines tolerated."""
        lines = [
            json.dumps(_completion_entry(id="req-1")),
            "",
            json.dumps(_embedding_entry(id="emb-9")),
            json.dumps(_image_entry(id="img-7")),
        ]
        content = "\n".join(lines) + "\n"

        imp = LiteLLMImporter()
        results = imp.parse_string(content)
        assert len(results) == 3
        call_types = [
            ev.control_results[0].evidence_data["call_type"]
            for ev in results
        ]
        assert call_types == ["completion", "embeddings", "image_generation"]
        assert all(ev.decision == "ALLOW" for ev in results)

    def test_spend_log_format_data_array(self):
        """Spend-log envelope ``{"data": [...]}`` is supported."""
        envelope = {
            "data": [
                _completion_entry(id="r1"),
                _completion_entry(id="r2", response_cost=0.05),
                _embedding_entry(id="e1"),
            ]
        }
        imp = LiteLLMImporter()
        results = imp.parse_string(json.dumps(envelope))
        assert len(results) == 3
        for ev in results:
            assert ev.source_type == "litellm_import"
            assert ev.decision == "ALLOW"

    def test_provider_routing_captured(self):
        """custom_llm_provider must surface as evidence_data.provider_routed_to."""
        imp = LiteLLMImporter()
        entry_anthropic = _completion_entry(
            id="req-anthropic",
            model="claude-3-5-sonnet-20241022",
            provider="anthropic",
        )
        entry_vertex = _completion_entry(
            id="req-vertex",
            model="vertex_ai/gemini-1.5-pro",
            provider="vertex_ai",
        )
        export = json.dumps([entry_anthropic, entry_vertex])
        results = imp.parse_string(export)

        assert len(results) == 2
        providers = [
            ev.control_results[0].evidence_data["provider_routed_to"]
            for ev in results
        ]
        assert providers == ["anthropic", "vertex_ai"]
        # api_base is also captured for forensic provenance.
        for ev in results:
            assert "api_base" in ev.control_results[0].evidence_data

    def test_clean_export_yields_pass(self):
        """All-success, low-cost, no-guardrail → every entry ALLOW with single PASS."""
        export = json.dumps([
            _completion_entry(id="r1", response_cost=0.001),
            _embedding_entry(id="e1", response_cost=0.0001),
            _moderation_entry(id="m1"),
            _image_entry(id="i1", response_cost=0.04),
        ])
        imp = LiteLLMImporter()
        results = imp.parse_string(export)

        assert len(results) == 4
        assert all(ev.decision == "ALLOW" for ev in results)
        for ev in results:
            assert len(ev.control_results) == 1
            assert ev.control_results[0].result == "PASS"

    def test_source_provenance_includes_file_hash(self, tmp_path: Path):
        """parse(path) must include sha256 of the source file in source_provenance."""
        export = json.dumps([_completion_entry()])
        fixture = tmp_path / "litellm-callbacks.json"
        fixture.write_text(export, encoding="utf-8")
        expected = hashlib.sha256(export.encode("utf-8")).hexdigest()

        imp = LiteLLMImporter(agent_id="pipeline")
        ev = imp.parse(fixture)[0]
        provenance = ev.control_results[0].evidence_data["source_provenance"]

        assert provenance["source_format"] == "litellm"
        assert provenance["source_tool_name"] == "litellm"
        assert provenance["original_file_sha256"] == expected
        # parse_string (no path) does NOT have the file hash.
        ev_str = imp.parse_string(export)[0]
        prov_str = ev_str.control_results[0].evidence_data["source_provenance"]
        assert "original_file_sha256" not in prov_str

    def test_blocked_metadata_string_marks_fail(self):
        """A string value containing 'blocked' in metadata is treated as a guardrail hit."""
        entry = _completion_entry(
            id="req-blockstr",
            metadata={"reason": "request was blocked by content policy"},
        )
        imp = LiteLLMImporter()
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "BLOCK"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "guardrail_violation" in signals


# ---------------------------------------------------------------------------
# Sanitization helper
# ---------------------------------------------------------------------------

class TestSanitizeMessages:
    def test_none_messages_marked_absent(self):
        s = _sanitize_messages(None)
        assert s == {"present": False, "message_count": 0}

    def test_messages_summary_keeps_no_raw_content(self):
        secret = "this is highly sensitive"
        s = _sanitize_messages([
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": secret},
            {"role": "assistant", "content": "ok"},
        ])
        assert s["present"] is True
        assert s["message_count"] == 3
        assert s["role_distribution"] == {"system": 1, "user": 1, "assistant": 1}
        assert "sha256" in s
        assert "byte_length" in s
        assert secret not in json.dumps(s)


class TestDetectGuardrail:
    def test_clean_metadata_returns_empty(self):
        assert _detect_guardrail_violation({"user_id": "u", "tags": ["prod"]}) == []

    def test_truthy_guardrail_key_is_hit(self):
        hits = _detect_guardrail_violation({"guardrail_violation": True})
        assert hits

    def test_falsy_guardrail_key_is_not_hit(self):
        # An explicit False value should NOT be treated as a violation.
        assert _detect_guardrail_violation({"guardrail_violation": False}) == []
