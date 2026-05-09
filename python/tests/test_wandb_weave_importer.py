"""Tests for the W&B Weave call importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers import WandbWeaveImporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _call(
    *,
    call_id: str = "call-001",
    trace_id: str = "trace-001",
    op_name: str = "openai.ChatCompletion.create",
    started_at: str = "2026-04-01T10:00:00Z",
    ended_at: str = "2026-04-01T10:00:01Z",
    exception: str | None = None,
    inputs: dict | None = None,
    output: dict | str | None = None,
    scores: dict | None = None,
    feedback: list | None = None,
    usage: dict | None = None,
    trace_name: str = "agent-run",
    latency_ms: float = 1234.0,
    wb_run_id: str = "wbr-abc",
    wb_user_id: str = "wbu-xyz",
    feedback_count: int = 0,
    tags: list | None = None,
    attributes: dict | None = None,
    parent_id: str = "",
) -> dict:
    summary: dict = {
        "weave": {"trace_name": trace_name, "latency_ms": latency_ms},
    }
    if usage is not None:
        summary["usage"] = usage
    else:
        summary["usage"] = {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
        }
    if scores is not None:
        summary["scores"] = scores
    if feedback is not None:
        summary["feedback"] = feedback

    call: dict = {
        "id": call_id,
        "trace_id": trace_id,
        "parent_id": parent_id,
        "op_name": op_name,
        "started_at": started_at,
        "ended_at": ended_at,
        "attributes": attributes or {"model": "gpt-4o", "temperature": 0.7},
        "inputs": inputs or {"messages": [{"role": "user", "content": "hi"}]},
        "output": output if output is not None else {"choices": [{"text": "hello"}]},
        "summary": summary,
        "wb_run_id": wb_run_id,
        "wb_user_id": wb_user_id,
        "feedback_count": feedback_count,
        "tags": tags or [],
    }
    if exception is not None:
        call["exception"] = exception
    return call


def _envelope(calls: list[dict]) -> dict:
    return {"calls": calls}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_chat_completion_call():
    """A simple ChatCompletion call yields one EvaluationResult mapped to PR-01."""
    payload = _envelope([_call(op_name="openai.ChatCompletion.create")])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    assert res.source_type == "wandb_weave_import"
    assert res.action_id.startswith("weave-call-")
    assert res.session_id == "trace-001"
    assert res.decision == "ALLOW"
    op_crs = [
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "op_name"
    ]
    assert len(op_crs) == 1
    assert op_crs[0].control_id == "PR-01"
    assert op_crs[0].evidence_data["op_name"] == "openai.ChatCompletion.create"
    # Token usage captured.
    assert op_crs[0].evidence_data["token_usage"]["prompt_tokens"] == 100
    assert op_crs[0].evidence_data["wb_run_id"] == "wbr-abc"
    assert op_crs[0].evidence_data["wb_user_id"] == "wbu-xyz"


def test_parse_evaluation_op():
    """A weave.Evaluation.* op maps to PR-03 (provenance)."""
    payload = _envelope([_call(op_name="weave.Evaluation.summarize")])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    op_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "op_name"
    )
    assert op_cr.control_id == "PR-03"


def test_parse_tool_op():
    """A tool.* op maps to PR-02 (scope)."""
    payload = _envelope([_call(op_name="tool.search_database")])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    op_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "op_name"
    )
    assert op_cr.control_id == "PR-02"


def test_exception_marks_fail():
    """A call with `exception` populated emits a DE-01 FAIL ControlResult."""
    payload = _envelope([
        _call(
            op_name="openai.ChatCompletion.create",
            exception="RateLimitError: tokens per minute exceeded",
        )
    ])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    exc_crs = [
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "exception"
    ]
    assert len(exc_crs) == 1
    assert exc_crs[0].control_id == "DE-01"
    assert exc_crs[0].result == "FAIL"
    assert "RateLimitError" in exc_crs[0].evidence_data["exception"]
    assert res.decision == "BLOCK"


def test_high_faithfulness_score_passes():
    """A faithfulness score >= 0.9 buckets to PASS on PR-03."""
    payload = _envelope([
        _call(scores={"faithfulness": {"mean": 0.95, "stderr": 0.01}})
    ])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "score"
        and cr.evidence_data["score_name"] == "faithfulness"
    )
    assert score_cr.control_id == "PR-03"
    assert score_cr.result == "PASS"
    assert res.decision == "ALLOW"


def test_low_faithfulness_score_fails():
    """A faithfulness score < 0.7 buckets to FAIL."""
    payload = _envelope([_call(scores={"faithfulness": {"mean": 0.55}})])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "faithfulness"
    )
    assert score_cr.result == "FAIL"
    assert res.decision == "BLOCK"


def test_inverted_hallucination_high_fails():
    """A high hallucination score fails the inverted band (lower is better)."""
    payload = _envelope([_call(scores={"hallucination": {"mean": 0.45}})])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "hallucination"
    )
    assert score_cr.result == "FAIL"
    assert score_cr.evidence_data["inverted"] is True
    assert score_cr.control_id == "PR-03"
    assert res.decision == "BLOCK"


def test_inverted_hallucination_low_passes():
    """A low hallucination score passes the inverted band."""
    payload = _envelope([_call(scores={"hallucination": {"mean": 0.02}})])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "hallucination"
    )
    assert score_cr.result == "PASS"
    assert score_cr.evidence_data["inverted"] is True


def test_score_dict_with_mean_handled():
    """A dict score record (Weave aggregate shape) is handled — mean is extracted."""
    payload = _envelope([
        _call(scores={"faithfulness": {"mean": 0.95, "stderr": 0.01, "count": 10}})
    ])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "faithfulness"
    )
    assert score_cr.evidence_data["score_value"] == 0.95
    assert score_cr.evidence_data["score_stderr"] == 0.01
    assert score_cr.evidence_data["score_shape"] == "dict_with_mean"


def test_score_scalar_handled():
    """A scalar float score record is handled identically to dict-with-mean."""
    payload = _envelope([_call(scores={"faithfulness": 0.95})])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "faithfulness"
    )
    assert score_cr.evidence_data["score_value"] == 0.95
    assert score_cr.evidence_data["score_stderr"] is None
    assert score_cr.evidence_data["score_shape"] == "scalar"
    assert score_cr.result == "PASS"


def test_thumbs_down_feedback_flags():
    """A thumbs_down feedback entry emits a PR-05 FLAG ControlResult."""
    payload = _envelope([
        _call(
            feedback=[
                {
                    "feedback_type": "thumbs_down",
                    "creator": "user-42",
                    "payload": {"reason": "wrong answer"},
                }
            ],
        )
    ])
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps(payload))

    feedback_crs = [
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "feedback"
    ]
    assert len(feedback_crs) == 1
    assert feedback_crs[0].control_id == "PR-05"
    assert feedback_crs[0].result == "FLAG"
    assert feedback_crs[0].evidence_data["creator"] == "user-42"
    assert res.decision == "FLAG"


def test_per_trace_mode():
    """per_trace=True groups calls by trace_id and emits one result per trace."""
    calls = [
        _call(call_id="c1", trace_id="trace-A", scores={"faithfulness": 0.96}),
        _call(call_id="c2", trace_id="trace-A", scores={"faithfulness": 0.94}),
        _call(call_id="c3", trace_id="trace-B", scores={"faithfulness": 0.55}),
    ]
    payload = _envelope(calls)
    importer = WandbWeaveImporter(per_trace=True)
    results = importer.parse_string(json.dumps(payload))

    assert len(results) == 2
    by_trace = {r.session_id: r for r in results}
    # trace-A: mean(0.96, 0.94) = 0.95 → PASS.
    a_score = next(
        cr for cr in by_trace["trace-A"].control_results
        if cr.evidence_data.get("score_name") == "faithfulness"
    )
    assert a_score.result == "PASS"
    assert a_score.evidence_data["score_count"] == 2
    assert a_score.evidence_data["aggregation"] == "per_trace_mean"
    # trace-B: 0.55 → FAIL → BLOCK.
    assert by_trace["trace-B"].decision == "BLOCK"
    # Aggregate metrics record exists.
    metrics_crs = [
        cr for cr in by_trace["trace-A"].control_results
        if cr.control_id == "PR-04"
        and cr.evidence_data.get("call_count") == 2
    ]
    assert metrics_crs


def test_inputs_output_text_never_stored():
    """No raw inputs/output text leaks into evidence — only summaries + sha256."""
    secret_input = "SECRET_PROMPT_DO_NOT_LEAK_token-xyz-42"
    secret_output = "ULTRA_PRIVATE_RESPONSE_payload-99"
    payload = _envelope([
        _call(
            inputs={"messages": [{"role": "user", "content": secret_input}]},
            output={"choices": [{"text": secret_output}]},
            scores={"faithfulness": 0.95},
        )
    ])
    importer = WandbWeaveImporter()
    results = importer.parse_string(json.dumps(payload))
    serialized = json.dumps(
        [
            {
                "evidence": [cr.evidence_data for cr in r.control_results],
                "decision_reason": r.decision_reason,
                "details": [cr.detail for cr in r.control_results],
            }
            for r in results
        ],
        default=str,
    )
    assert secret_input not in serialized
    assert secret_output not in serialized

    # The structural summary should record sha256 + byte_length.
    res = results[0]
    op_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "op_name"
    )
    assert op_cr.evidence_data["inputs_summary"]["present"] is True
    assert "sha256" in op_cr.evidence_data["inputs_summary"]
    assert op_cr.evidence_data["output_summary"]["present"] is True
    assert "sha256" in op_cr.evidence_data["output_summary"]


def test_source_provenance_includes_file_hash(tmp_path: Path):
    """Parsing from a file records the SHA-256 hash in source_provenance."""
    payload = _envelope([_call()])
    raw = json.dumps(payload).encode("utf-8")
    expected_hash = hashlib.sha256(raw).hexdigest()
    p = tmp_path / "weave-export.json"
    p.write_bytes(raw)

    importer = WandbWeaveImporter()
    [res] = importer.parse(p)
    cr = res.control_results[0]
    prov = cr.evidence_data["source_provenance"]
    assert prov["original_file_sha256"] == expected_hash
    assert prov["source_format"] == "wandb_weave"
    assert prov["call_id"] == "call-001"
    assert prov["trace_id"] == "trace-001"


# ---------------------------------------------------------------------------
# Bonus sanity tests
# ---------------------------------------------------------------------------


def test_jsonl_input_accepted():
    """JSONL input is parsed identically to a {calls: [...]} envelope."""
    calls = [_call(call_id="c1"), _call(call_id="c2", trace_id="trace-002")]
    content = "\n".join(json.dumps(c) for c in calls) + "\n"
    importer = WandbWeaveImporter()
    results = importer.parse_string(content)
    assert len(results) == 2


def test_data_envelope_accepted():
    """{data: [...]} envelope is parsed identically to {calls: [...]}."""
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(json.dumps({"data": [_call()]}))
    assert res.session_id == "trace-001"


def test_anthropic_messages_op_maps_to_pr01():
    """An Anthropic Messages op routes via *.Messages.* → PR-01."""
    importer = WandbWeaveImporter()
    [res] = importer.parse_string(
        json.dumps(_envelope([_call(op_name="anthropic.Messages.create")]))
    )
    op_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "op_name"
    )
    assert op_cr.control_id == "PR-01"
