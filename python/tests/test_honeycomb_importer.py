"""Tests for the Honeycomb event importer.

Honeycomb for LLMs ingests OTel GenAI spans and adds derivative computed fields
plus trigger annotations. The importer maps these signals to AKSI controls and
sanitizes user-input-bearing fields (``exception.message`` and span ``name``).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.honeycomb import HoneycombImporter


# ---------------------------------------------------------------------------
# Fixture builders — inline Honeycomb canonical envelopes
# ---------------------------------------------------------------------------


def _payload(**overrides) -> dict:
    """Default Honeycomb event payload (under the canonical ``data`` wrap)."""
    base = {
        "trace.trace_id": "trace-1",
        "trace.span_id": "span-1",
        "trace.parent_id": None,
        "name": "openai.chat.completion",
        "service.name": "agent-svc",
        "duration_ms": 1234,
        "error": False,
        "status_code": "OK",
        "gen_ai.system": "openai",
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": "gpt-4o",
        "gen_ai.response.model": "gpt-4o-2024-11-20",
        "gen_ai.usage.input_tokens": 100,
        "gen_ai.usage.output_tokens": 50,
        "gen_ai.request.temperature": 0.7,
        "honeycomb.cost_usd": 0.0015,
        "agent.framework": "langchain",
        "agent.tenant_id": "tenant-a",
        "prompt.template_id": "agent-001",
        "prompt.version": "v3",
    }
    base.update(overrides)
    return base


def _envelope(*payloads: dict) -> str:
    """Wrap payloads in Honeycomb's canonical ``{"data":[{"Timestamp","data":...}]}``."""
    items = [
        {"Timestamp": "2026-04-01T12:00:00Z", "data": p}
        for p in payloads
    ]
    return json.dumps({"data": items})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHoneycombImporter:
    def test_parse_chat_span(self) -> None:
        content = _envelope(_payload())
        results = HoneycombImporter().parse_string(content)
        assert len(results) == 1
        er = results[0]
        # gen_ai.operation=chat → PR-01 PASS baseline. Framework attribution
        # is present and template is versioned, so no extra FLAGs fire.
        controls = [(c.control_id, c.result) for c in er.control_results]
        assert ("PR-01", "PASS") in controls
        assert er.decision == "ALLOW"
        # No DE-01 FAIL, no PR-05 FLAGs.
        assert not any(r == "FAIL" for _, r in controls)
        assert not any(r == "FLAG" for _, r in controls)

    def test_parse_tool_span(self) -> None:
        payload = _payload(
            **{
                "name": "execute_tool.lookup",
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.request.model": "",
                "gen_ai.response.model": "",
            }
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        assert len(results) == 1
        controls = [(c.control_id, c.result) for c in results[0].control_results]
        assert ("PR-02", "PASS") in controls

    def test_error_status_fails(self) -> None:
        payload = _payload(
            **{
                "error": True,
                "status_code": "ERROR",
                "exception.type": "RateLimitError",
                "exception.message": "leaky user prompt: SECRET-XYZ",
            }
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        de01 = [c for c in er.control_results if c.control_id == "DE-01"]
        assert de01, "expected DE-01 FAIL on error span"
        assert de01[0].result == "FAIL"
        assert de01[0].evidence_data.get("error_type") == "RateLimitError"
        # No baseline operation PASS for an error span.
        assert not any(c.result == "PASS" and c.control_id == "PR-01" for c in er.control_results)
        assert er.decision == "FLAG"  # default mode=audit downgrades BLOCK→FLAG

    def test_alert_trigger_critical_fails(self) -> None:
        payload = _payload(
            **{
                "honeycomb.trigger.type": "alert",
                "honeycomb.trigger.severity": "critical",
            }
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        de01 = [c for c in er.control_results if c.control_id == "DE-01"]
        assert de01 and de01[0].result == "FAIL"
        assert de01[0].evidence_data.get("signal") == "trigger_alert_critical"

    def test_slo_burn_critical_fails(self) -> None:
        payload = _payload(
            **{
                "honeycomb.trigger.type": "slo_burn",
                "honeycomb.trigger.severity": "critical",
            }
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        pr05_fails = [
            c for c in er.control_results
            if c.control_id == "PR-05" and c.result == "FAIL"
        ]
        assert pr05_fails, "SLO burn critical should produce PR-05 FAIL"
        assert pr05_fails[0].evidence_data.get("signal") == "trigger_slo_burn_critical"

    def test_anomaly_detection_flags(self) -> None:
        payload = _payload(
            **{
                "honeycomb.trigger.type": "anomaly_detection",
                "honeycomb.bubbleup.dimensions": ["model", "tenant_id"],
            }
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        flags = [
            c for c in er.control_results
            if c.control_id == "PR-05" and c.result == "FLAG"
            and c.evidence_data.get("signal") == "trigger_anomaly_detection"
        ]
        assert flags, "anomaly_detection should produce PR-05 FLAG"
        assert flags[0].evidence_data.get("bubbleup_dimensions") == ["model", "tenant_id"]

    def test_high_error_rate_flags(self) -> None:
        payload = _payload(
            **{"honeycomb.derivative.error_rate_24h": 0.15}
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        flags = [
            c for c in er.control_results
            if c.evidence_data.get("signal") == "derivative_high_error_rate_24h"
        ]
        assert flags
        assert flags[0].control_id == "PR-03"
        assert flags[0].result == "FLAG"
        assert flags[0].evidence_data["error_rate_24h"] == 0.15

    def test_high_tenant_cost_flags(self) -> None:
        payload = _payload(
            **{"honeycomb.derivative.cost_per_tenant_usd_24h": 250.0}
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        flags = [
            c for c in er.control_results
            if c.evidence_data.get("signal") == "derivative_high_tenant_cost_24h"
        ]
        assert flags
        assert flags[0].control_id == "PR-04"
        assert flags[0].result == "FLAG"
        assert flags[0].evidence_data["cost_per_tenant_usd_24h"] == 250.0

    def test_high_latency_p95_flags(self) -> None:
        payload = _payload(
            **{"honeycomb.derivative.latency_p95_ms_24h": 45000}
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        flags = [
            c for c in er.control_results
            if c.evidence_data.get("signal") == "derivative_high_latency_p95_24h"
        ]
        assert flags
        assert flags[0].control_id == "PR-03"
        assert flags[0].result == "FLAG"
        assert flags[0].evidence_data["latency_p95_ms_24h"] == 45000.0
        # Default threshold check.
        assert flags[0].evidence_data["latency_p95_threshold_ms"] == 30000.0

    def test_unversioned_prompt_template_flags(self) -> None:
        payload = _payload(
            **{
                "prompt.template_id": "agent-007",
                "prompt.version": None,
            }
        )
        # Need to actually drop the key, not set it to None — the importer
        # treats falsy as absent already, which is what we want.
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        flags = [
            c for c in er.control_results
            if c.evidence_data.get("signal") == "prompt_unversioned"
        ]
        assert flags, "un-versioned prompt should FLAG PR-05"
        assert flags[0].control_id == "PR-05"
        assert flags[0].result == "FLAG"
        assert flags[0].evidence_data["prompt_template_id"] == "agent-007"

    def test_no_framework_attribution_flags(self) -> None:
        payload = _payload(**{"agent.framework": None})
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        flags = [
            c for c in er.control_results
            if c.evidence_data.get("signal") == "framework_missing"
        ]
        assert flags, "missing agent.framework should FLAG PR-05"
        assert flags[0].control_id == "PR-05"
        assert flags[0].result == "FLAG"

    def test_exception_message_redacted(self) -> None:
        leaky_message = "user query failed: SSN=123-45-6789, password=hunter2"
        payload = _payload(
            **{
                "error": True,
                "status_code": "ERROR",
                "exception.type": "RuntimeError",
                "exception.message": leaky_message,
                # Span name can also carry interpolated user input — verify
                # the importer truncates to 80 chars.
                "name": "x" * 200,
            }
        )
        content = _envelope(payload)
        results = HoneycombImporter().parse_string(content)
        er = results[0]
        # Verify the raw exception message never appears anywhere in evidence.
        for cr in er.control_results:
            ev_dump = json.dumps(cr.evidence_data, default=str)
            assert leaky_message not in ev_dump
            assert "SSN=" not in ev_dump
            assert "hunter2" not in ev_dump
            # name field truncated to 80.
            captured_name = cr.evidence_data.get("name", "")
            assert len(captured_name) <= 80
        # The redacted summary records length+sha256, not text.
        de01 = [c for c in er.control_results if c.control_id == "DE-01"][0]
        summary = de01.evidence_data.get("exception_message_summary")
        assert summary["present"] is True
        expected_sha = hashlib.sha256(leaky_message.encode("utf-8")).hexdigest()
        assert summary["sha256"] == expected_sha
        assert summary["byte_length"] == len(leaky_message.encode("utf-8"))

    def test_jsonl_stream(self) -> None:
        # JSONL of bare event payloads (no canonical envelope).
        line1 = json.dumps(_payload(**{"trace.span_id": "span-A"}))
        line2 = json.dumps(_payload(**{"trace.span_id": "span-B"}))
        line3 = json.dumps(
            _payload(
                **{
                    "trace.span_id": "span-C",
                    "error": True,
                    "status_code": "ERROR",
                    "exception.type": "TimeoutError",
                }
            )
        )
        content = "\n".join([line1, line2, line3])
        results = HoneycombImporter().parse_string(content)
        assert len(results) == 3
        # Span IDs flow through to action_id / session_id territory.
        span_ids = {er.session_id for er in results}
        # session_id is set from trace.trace_id (all "trace-1" here), so
        # check span_id via control evidence.
        ev_span_ids = {
            cr.evidence_data.get("span_id")
            for er in results for cr in er.control_results
            if cr.evidence_data.get("span_id")
        }
        assert ev_span_ids == {"span-A", "span-B", "span-C"}
        assert span_ids == {"trace-1"}
        # Last span errored → DE-01 FAIL present.
        third = results[2]
        assert any(
            c.control_id == "DE-01" and c.result == "FAIL"
            for c in third.control_results
        )

    def test_honeycomb_canonical_envelope(self) -> None:
        # Two events under canonical wrap.
        content = _envelope(
            _payload(**{"trace.span_id": "span-1"}),
            _payload(
                **{
                    "trace.span_id": "span-2",
                    "honeycomb.trigger.type": "alert",
                    "honeycomb.trigger.severity": "critical",
                }
            ),
        )
        results = HoneycombImporter().parse_string(content)
        assert len(results) == 2
        # Second event → DE-01 FAIL via alert+critical trigger.
        second = results[1]
        de01 = [c for c in second.control_results if c.control_id == "DE-01"]
        assert de01 and de01[0].result == "FAIL"
        # First event → PR-01 PASS baseline.
        first = results[0]
        assert any(
            c.control_id == "PR-01" and c.result == "PASS"
            for c in first.control_results
        )

    def test_source_provenance_includes_file_hash(self, tmp_path: Path) -> None:
        content = _envelope(_payload())
        f = tmp_path / "honeycomb.json"
        f.write_text(content)
        expected_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()

        results = HoneycombImporter().parse(f)
        assert len(results) == 1
        for cr in results[0].control_results:
            prov = cr.evidence_data.get("source_provenance")
            assert isinstance(prov, dict)
            assert prov["source_format"] == "honeycomb"
            assert prov["source_tool_name"] == "honeycomb"
            assert prov["original_file_sha256"] == expected_sha
