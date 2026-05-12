"""Tests for the Datadog LLM Observability span importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers import DatadogLLMImporter
from ancilis.importers.datadog_llm import (
    _summarize_io,
    _summarize_messages,
)


# ---------------------------------------------------------------------------
# Fixture builders — inline Datadog LLM-Obs span events (no datadog SDK needed)
# ---------------------------------------------------------------------------

SECRET_USER_TEXT = "DO_NOT_LEAK_user_prompt_PII_555-12-9876"
SECRET_ASSISTANT_TEXT = "DO_NOT_LEAK_assistant_response_secret_token_abcdef"


def _span(
    *,
    span_id: str = "span-1",
    trace_id: str = "trace-1",
    parent_span_id: str | None = None,
    kind: str = "llm",
    status: str = "ok",
    name: str = "openai.chat.completion",
    service: str = "agent-svc",
    session_id: str = "session-abc",
    ml_app: str = "production-rag",
    duration_ns: int = 1_500_000,  # 1.5 ms
    start_ns: int = 1_700_000_000_000_000_000,
    error: dict[str, Any] | None = None,
    meta_input: dict[str, Any] | None = None,
    meta_output: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    model_name: str = "gpt-4o",
    model_provider: str = "openai",
    metrics: dict[str, Any] | None = None,
    annotations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if meta_input is None:
        meta_input = {
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": SECRET_USER_TEXT},
            ]
        }
    if meta_output is None:
        meta_output = {
            "messages": [
                {"role": "assistant", "content": SECRET_ASSISTANT_TEXT}
            ]
        }
    attrs: dict[str, Any] = {
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "service": service,
        "session_id": session_id,
        "ml_app": ml_app,
        "name": name,
        "kind": kind,
        "start_ns": start_ns,
        "duration": duration_ns,
        "status": status,
        "meta": {
            "input": meta_input,
            "output": meta_output,
            "metadata": metadata or {"temperature": 0.7, "max_tokens": 256},
            "tags": tags if tags is not None else ["env:prod", "team:agents"],
            "model_name": model_name,
            "model_provider": model_provider,
        },
        "metrics": metrics
        if metrics is not None
        else {
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 150,
            "input_cost": 0.001,
            "output_cost": 0.0005,
            "total_cost": 0.0015,
        },
        "annotations": annotations or [],
    }
    if error is not None:
        attrs["error"] = error
    return {
        "id": f"event-{span_id}",
        "type": "trace.search.events",
        "attributes": attrs,
    }


def _envelope(*spans: dict[str, Any]) -> str:
    return json.dumps({"data": list(spans)})


# ---------------------------------------------------------------------------
# Per-span behaviour
# ---------------------------------------------------------------------------


class TestKindMapping:
    def test_parse_llm_span(self):
        imp = DatadogLLMImporter(agent_id="ci")
        ev = imp.parse_string(_envelope(_span(span_id="s-llm", kind="llm")))[0]
        assert ev.source_type == "datadog_llm_import"
        assert ev.agent_id == "ci"
        assert ev.decision == "ALLOW"
        # Exactly one baseline PASS for a clean llm span.
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-01"
        assert cr.evidence_data["signal"] == "kind_llm"
        assert cr.evidence_data["model_name"] == "gpt-4o"
        assert cr.evidence_data["model_provider"] == "openai"
        assert cr.evidence_data["ml_app"] == "production-rag"
        assert cr.evidence_data["span_id"] == "s-llm"
        assert cr.evidence_data["trace_id"] == "trace-1"
        assert cr.evidence_data["session_id"] == "session-abc"
        assert cr.evidence_data["total_tokens"] == 150
        assert cr.evidence_data["duration_ms"] == 1.5

    def test_parse_tool_span(self):
        imp = DatadogLLMImporter()
        ev = imp.parse_string(
            _envelope(_span(span_id="s-tool", kind="tool", name="github.create_issue"))
        )[0]
        cr = ev.control_results[0]
        assert cr.control_id == "PR-02"
        assert cr.result == "PASS"
        assert cr.evidence_data["signal"] == "kind_tool"
        assert ev.decision == "ALLOW"

    def test_parse_embedding_span(self):
        imp = DatadogLLMImporter()
        ev = imp.parse_string(
            _envelope(_span(span_id="s-emb", kind="embedding", name="openai.embedding"))
        )[0]
        cr = ev.control_results[0]
        assert cr.control_id == "PR-04"
        assert cr.evidence_data["signal"] == "kind_embedding"
        assert ev.decision == "ALLOW"

    def test_parse_retrieval_and_task_kinds(self):
        imp = DatadogLLMImporter()
        evs = imp.parse_string(
            _envelope(
                _span(span_id="s-ret", kind="retrieval"),
                _span(span_id="s-task", kind="task"),
                _span(span_id="s-agent", kind="agent"),
                _span(span_id="s-flow", kind="workflow"),
            )
        )
        assert len(evs) == 4
        kind_to_control = {
            ev.control_results[0].evidence_data["kind"]: ev.control_results[0].control_id
            for ev in evs
        }
        assert kind_to_control == {
            "retrieval": "PR-04",
            "task": "PR-05",
            "agent": "PR-05",
            "workflow": "PR-01",
        }


class TestStatusError:
    def test_status_error_marks_fail(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-err",
            kind="llm",
            status="error",
            error={
                "type": "openai.RateLimitError",
                "message": "Rate limit exceeded",
                "stack": "Traceback...",
            },
        )
        ev = imp.parse_string(_envelope(span))[0]
        assert ev.decision == "BLOCK"
        # FAIL control result for the error.
        fail_crs = [cr for cr in ev.control_results if cr.result == "FAIL"]
        assert len(fail_crs) == 1
        fail = fail_crs[0]
        assert fail.control_id == "DE-01"
        assert fail.evidence_data["signal"] == "status_error"
        assert fail.evidence_data["error_type"] == "openai.RateLimitError"
        assert "Rate limit exceeded" in fail.evidence_data["error_message"]
        # No baseline PASS should be emitted on error spans (avoids understating severity).
        assert all(cr.result != "PASS" for cr in ev.control_results)


class TestAnnotations:
    def test_pii_annotation_flags(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-pii",
            kind="llm",
            annotations=[
                {"label": "pii_detected", "score": True, "type": "boolean"}
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "pii_detected" in signals
        pii_cr = next(
            cr for cr in ev.control_results if cr.evidence_data.get("signal") == "pii_detected"
        )
        assert pii_cr.result == "FLAG"
        assert pii_cr.control_id == "PR-04"

    def test_prompt_injection_annotation_fails(self):
        """Top-priority security signal: prompt_injection must FAIL (block)."""
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-inj",
            kind="llm",
            annotations=[
                {"label": "prompt_injection", "score": True, "type": "boolean"}
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        # prompt_injection must escalate the decision to BLOCK.
        assert ev.decision == "BLOCK"
        inj_crs = [
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "prompt_injection"
        ]
        assert len(inj_crs) == 1
        inj = inj_crs[0]
        assert inj.result == "FAIL"
        assert inj.control_id == "PR-01"
        # Annotation label/score preserved in evidence_data.
        assert inj.evidence_data["annotation_label"] == "prompt_injection"
        assert inj.evidence_data["annotation_score"] is True

    def test_prompt_injection_false_does_not_fail(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-clean",
            kind="llm",
            annotations=[
                {"label": "prompt_injection", "score": False, "type": "boolean"}
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        # No FAIL when score=False.
        assert ev.decision == "ALLOW"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "prompt_injection" not in signals

    def test_hallucination_annotation_flags(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-hal",
            kind="llm",
            annotations=[
                {"label": "hallucination", "score": "yes", "type": "categorical"}
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        assert ev.decision == "FLAG"
        hal = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "hallucination"
        )
        assert hal.result == "FLAG"
        assert hal.control_id == "PR-03"

    def test_hallucination_numerical_above_threshold_flags(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-hal-num",
            kind="llm",
            annotations=[
                {"label": "hallucination", "score": 0.92, "type": "numerical"}
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "hallucination" in signals

    def test_low_faithfulness_score_flags(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-faith",
            kind="llm",
            annotations=[
                {"label": "faithfulness", "score": 0.5, "type": "numerical"}
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        assert ev.decision == "FLAG"
        cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "low_faithfulness"
        )
        assert cr.result == "FLAG"
        assert cr.control_id == "PR-03"
        assert cr.evidence_data["annotation_score"] == 0.5
        assert cr.evidence_data["faithfulness_threshold"] == 0.8

    def test_high_faithfulness_score_does_not_flag(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-faith-ok",
            kind="llm",
            annotations=[
                {"label": "faithfulness", "score": 0.95, "type": "numerical"}
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        assert ev.decision == "ALLOW"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "low_faithfulness" not in signals

    def test_annotation_labels_captured_in_evidence(self):
        """Custom / unknown annotation labels are captured in evidence_data without rule."""
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-custom",
            kind="llm",
            annotations=[
                {"label": "custom_metric", "score": 0.42, "type": "numerical"},
                {"label": "team_review", "score": "approved", "type": "categorical"},
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        # Unknown labels emit no extra ControlResult.
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        # But the annotations summary is in evidence_data.
        ann_summary = cr.evidence_data["annotations"]
        labels = {a["label"] for a in ann_summary}
        assert "custom_metric" in labels
        assert "team_review" in labels
        scores = {a["label"]: a["score"] for a in ann_summary}
        assert scores["custom_metric"] == 0.42
        assert scores["team_review"] == "approved"


class TestCostThreshold:
    def test_cost_above_threshold_flags(self):
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-pricey",
            kind="llm",
            metrics={
                "input_tokens": 10000,
                "output_tokens": 5000,
                "total_tokens": 15000,
                "input_cost": 1.0,
                "output_cost": 1.5,
                "total_cost": 2.5,
            },
        )
        ev = imp.parse_string(_envelope(span))[0]
        assert ev.decision == "FLAG"
        cost_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "cost_threshold_exceeded"
        )
        assert cost_cr.result == "FLAG"
        assert cost_cr.control_id == "PR-04"
        assert cost_cr.evidence_data["total_cost"] == 2.5
        assert cost_cr.evidence_data["cost_threshold_usd"] == 1.0

    def test_cost_threshold_override(self):
        imp = DatadogLLMImporter(cost_threshold_usd=10.0)
        span = _span(
            span_id="s-pricey",
            kind="llm",
            metrics={"total_cost": 2.5, "total_tokens": 100},
        )
        ev = imp.parse_string(_envelope(span))[0]
        assert ev.decision == "ALLOW"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "cost_threshold_exceeded" not in signals


# ---------------------------------------------------------------------------
# Per-trace mode
# ---------------------------------------------------------------------------


class TestPerTraceMode:
    def test_per_trace_mode_aggregates(self):
        imp = DatadogLLMImporter(per_trace=True)
        spans = [
            _span(span_id="s-1", trace_id="trace-A", kind="llm"),
            _span(span_id="s-2", trace_id="trace-A", kind="tool"),
            _span(span_id="s-3", trace_id="trace-A", kind="task"),
            _span(span_id="s-4", trace_id="trace-B", kind="llm"),
        ]
        evs = imp.parse_string(_envelope(*spans))
        assert len(evs) == 2
        trace_a = next(ev for ev in evs if "trace-A" in ev.action_id)
        trace_b = next(ev for ev in evs if "trace-B" in ev.action_id)

        # trace-A aggregates 3 baseline PASS control results (one per span).
        assert len(trace_a.control_results) == 3
        signals = [cr.evidence_data.get("signal") for cr in trace_a.control_results]
        assert sorted(signals) == ["kind_llm", "kind_task", "kind_tool"]
        assert trace_a.decision == "ALLOW"

        # trace-B has a single span.
        assert len(trace_b.control_results) == 1
        assert trace_b.decision == "ALLOW"

        # Per-trace decision escalates if any span has a security signal.
        spans_with_pii = [
            _span(span_id="s-x", trace_id="trace-C", kind="llm"),
            _span(
                span_id="s-y",
                trace_id="trace-C",
                kind="llm",
                annotations=[
                    {"label": "pii_detected", "score": True, "type": "boolean"}
                ],
            ),
        ]
        evs2 = imp.parse_string(_envelope(*spans_with_pii))
        assert len(evs2) == 1
        assert evs2[0].decision == "FLAG"

    def test_per_trace_action_id_uses_trace_id(self):
        imp = DatadogLLMImporter(per_trace=True)
        ev = imp.parse_string(
            _envelope(_span(span_id="s-1", trace_id="abcdef0123456789", kind="llm"))
        )[0]
        assert ev.action_id.startswith("datadog-llm-trace-")
        assert "abcdef0123456789" in ev.action_id


# ---------------------------------------------------------------------------
# Sanitization — message text must NEVER appear in evidence
# ---------------------------------------------------------------------------


class TestSanitization:
    def test_messages_text_never_stored(self):
        """Prompt/response text must never appear anywhere in EvaluationResult."""
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-priv",
            kind="llm",
            meta_input={
                "messages": [
                    {"role": "system", "content": "system text"},
                    {"role": "user", "content": SECRET_USER_TEXT},
                ],
                "value": SECRET_USER_TEXT,
            },
            meta_output={
                "messages": [{"role": "assistant", "content": SECRET_ASSISTANT_TEXT}],
                "value": SECRET_ASSISTANT_TEXT,
            },
        )
        ev = imp.parse_string(_envelope(span))[0]
        serialized = json.dumps(
            {
                "decision": ev.decision,
                "decision_reason": ev.decision_reason,
                "control_results": [
                    {
                        "control_id": c.control_id,
                        "control_name": c.control_name,
                        "detail": c.detail,
                        "evidence_data": c.evidence_data,
                    }
                    for c in ev.control_results
                ],
            },
            default=str,
        )
        assert SECRET_USER_TEXT not in serialized
        assert SECRET_ASSISTANT_TEXT not in serialized

        cr = ev.control_results[0]
        input_summary = cr.evidence_data["input_summary"]
        assert input_summary["present"] is True
        assert input_summary["kind"] == "object"
        assert "messages_summary" in input_summary
        msgs_sum = input_summary["messages_summary"]
        assert msgs_sum["count"] == 2
        assert msgs_sum["role_counts"] == {"system": 1, "user": 1}
        assert "sha256" in msgs_sum
        assert "byte_length" in msgs_sum
        # value summary should also strip text and keep only sha+length.
        assert "value_summary" in input_summary
        vs = input_summary["value_summary"]
        assert "sha256" in vs
        assert "byte_length" in vs
        assert "value" not in vs  # raw value never copied

        output_summary = cr.evidence_data["output_summary"]
        assert output_summary["present"] is True
        assert output_summary["messages_summary"]["count"] == 1
        assert output_summary["messages_summary"]["role_counts"] == {"assistant": 1}

    def test_summarize_messages_helper(self):
        msgs = [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
        ]
        s = _summarize_messages(msgs)
        assert s["present"] is True
        assert s["count"] == 2
        assert s["role_counts"] == {"user": 1, "assistant": 1}
        # No raw content text.
        assert "hi" not in json.dumps(s)
        assert "hello" not in json.dumps(s)

    def test_summarize_io_handles_none(self):
        assert _summarize_io(None) == {"present": False}


# ---------------------------------------------------------------------------
# JSON formats: envelope, JSONL, single event
# ---------------------------------------------------------------------------


class TestFormats:
    def test_jsonl_stream(self):
        spans = [
            _span(span_id=f"s-{i}", kind="llm")
            for i in range(3)
        ]
        # JSONL: one event per line.
        jsonl = "\n".join(json.dumps(s) for s in spans)
        imp = DatadogLLMImporter()
        evs = imp.parse_string(jsonl)
        assert len(evs) == 3
        for ev in evs:
            assert ev.source_type == "datadog_llm_import"
            assert len(ev.control_results) >= 1

    def test_single_data_object(self):
        """Accepts {"data": <single event>} shape."""
        single = json.dumps({"data": _span(span_id="s-solo", kind="llm")})
        imp = DatadogLLMImporter()
        evs = imp.parse_string(single)
        assert len(evs) == 1
        assert evs[0].control_results[0].evidence_data["span_id"] == "s-solo"

    def test_bare_event(self):
        """Accepts a bare event-shaped object."""
        bare = json.dumps(_span(span_id="s-bare", kind="llm"))
        imp = DatadogLLMImporter()
        evs = imp.parse_string(bare)
        assert len(evs) == 1

    def test_empty_export_yields_clean_pass(self):
        imp = DatadogLLMImporter()
        evs = imp.parse_string('{"data": []}')
        assert len(evs) == 1
        assert evs[0].decision == "ALLOW"
        assert evs[0].control_results[0].evidence_data["span_count"] == 0


# ---------------------------------------------------------------------------
# Source provenance
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_source_provenance_includes_file_hash(self, tmp_path: Path):
        content = _envelope(_span(span_id="s-prov", kind="llm"))
        fixture = tmp_path / "datadog-spans.json"
        fixture.write_text(content, encoding="utf-8")
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()

        imp = DatadogLLMImporter(agent_id="pipeline")
        ev = imp.parse(fixture)[0]
        provenance = ev.control_results[0].evidence_data["source_provenance"]
        assert provenance["source_format"] == "datadog_llm"
        assert provenance["source_tool_name"] == "datadog_llm_observability"
        assert provenance["original_file_sha256"] == expected

    def test_parse_string_omits_file_hash(self):
        imp = DatadogLLMImporter()
        ev = imp.parse_string(_envelope(_span(span_id="s", kind="llm")))[0]
        provenance = ev.control_results[0].evidence_data["source_provenance"]
        assert "original_file_sha256" not in provenance


# ---------------------------------------------------------------------------
# Mixed signals on a single span
# ---------------------------------------------------------------------------


class TestMixedSignals:
    def test_prompt_injection_plus_high_cost(self):
        """Multiple security signals on one span produce multiple control results."""
        imp = DatadogLLMImporter()
        span = _span(
            span_id="s-multi",
            kind="llm",
            metrics={"total_cost": 5.0, "total_tokens": 1000},
            annotations=[
                {"label": "prompt_injection", "score": True, "type": "boolean"},
                {"label": "pii_detected", "score": True, "type": "boolean"},
            ],
        )
        ev = imp.parse_string(_envelope(span))[0]
        # FAIL (prompt_injection) dominates → BLOCK.
        assert ev.decision == "BLOCK"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "prompt_injection" in signals
        assert "pii_detected" in signals
        assert "cost_threshold_exceeded" in signals
        assert "kind_llm" in signals  # baseline still emitted (status != error)
