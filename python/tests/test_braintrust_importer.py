"""Tests for the Braintrust eval scorecard importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers import BraintrustImporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _experiment(
    *,
    exp_id: str = "exp-001",
    name: str = "rag-quality-2026-q2",
    git_commit: str = "abc1234",
) -> dict:
    return {
        "id": exp_id,
        "name": name,
        "project_id": "proj-rag",
        "created": "2026-04-01T10:00:00Z",
        "dataset_id": "ds-001",
        "git_commit": git_commit,
        "model_metadata": {"model": "gpt-4o", "temperature": 0.7},
    }


def _event(
    *,
    event_id: str = "evt-1",
    scores: dict[str, float] | None = None,
    input_text: str = "What is the capital of France?",
    output_text: str = "The capital of France is Paris.",
    expected: str | None = "Paris",
    metrics: dict | None = None,
    tags: list[str] | None = None,
) -> dict:
    return {
        "id": event_id,
        "input": input_text,
        "output": output_text,
        "expected": expected,
        "scores": scores or {"faithfulness": 0.95, "factuality": 0.93},
        "metadata": {"prompt_version": "v3"},
        "metrics": metrics or {"latency_ms": 1234, "tokens_in": 100, "tokens_out": 50},
        "tags": tags or ["regression-suite"],
    }


def _bundle(events: list[dict], **exp_kwargs) -> dict:
    return {"experiment": _experiment(**exp_kwargs), "events": events}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_single_experiment():
    """A single {experiment, events} bundle yields exactly one EvaluationResult."""
    payload = _bundle([
        _event(event_id="e1", scores={"faithfulness": 0.95, "factuality": 0.93}),
        _event(event_id="e2", scores={"faithfulness": 0.91, "factuality": 0.92}),
    ])
    importer = BraintrustImporter()
    results = importer.parse_string(json.dumps(payload))

    assert len(results) == 1
    res = results[0]
    assert res.source_type == "braintrust_import"
    assert res.action_id.startswith("braintrust-import-")
    assert res.session_id == "exp-001"
    # All scores are >= 0.9 → ALLOW.
    assert res.decision == "ALLOW"
    # Two scorers in this experiment → at least 2 ControlResults plus the PR-04 metrics record.
    score_crs = [cr for cr in res.control_results if cr.evidence_data.get("score_name")]
    assert len(score_crs) == 2
    score_names = {cr.evidence_data["score_name"] for cr in score_crs}
    assert score_names == {"faithfulness", "factuality"}


def test_parse_multiple_experiments():
    """{experiments: [...]} envelope yields one result per experiment."""
    payload = {
        "experiments": [
            _bundle([_event(event_id="a")], exp_id="exp-A", name="quality-A"),
            _bundle([_event(event_id="b")], exp_id="exp-B", name="quality-B"),
        ]
    }
    importer = BraintrustImporter()
    results = importer.parse_string(json.dumps(payload))

    assert len(results) == 2
    session_ids = {r.session_id for r in results}
    assert session_ids == {"exp-A", "exp-B"}


def test_jsonl_event_stream():
    """A JSONL stream of events is grouped under a synthetic experiment."""
    events = [
        _event(event_id="e1"),
        _event(event_id="e2", scores={"faithfulness": 0.99, "factuality": 0.95}),
        _event(event_id="e3", scores={"faithfulness": 0.92, "factuality": 0.91}),
    ]
    content = "\n".join(json.dumps(e) for e in events) + "\n"

    importer = BraintrustImporter()
    results = importer.parse_string(content)
    assert len(results) == 1
    res = results[0]
    # The aggregated metrics record reports all 3 events.
    metrics_crs = [
        cr for cr in res.control_results
        if cr.control_id == "PR-04" and cr.evidence_data.get("event_count")
    ]
    assert metrics_crs and metrics_crs[0].evidence_data["event_count"] == 3


def test_high_score_passes():
    """A score >= 0.9 buckets to PASS in normal mode."""
    payload = _bundle([_event(event_id="e1", scores={"faithfulness": 0.95})])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "faithfulness"
    )
    assert score_cr.result == "PASS"
    assert score_cr.control_id == "PR-03"
    assert res.decision == "ALLOW"


def test_mid_score_flags():
    """A score in [0.7, 0.9) buckets to FLAG."""
    payload = _bundle([_event(event_id="e1", scores={"faithfulness": 0.8})])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "faithfulness"
    )
    assert score_cr.result == "FLAG"
    assert res.decision == "FLAG"


def test_low_score_fails():
    """A score < 0.7 buckets to FAIL."""
    payload = _bundle([_event(event_id="e1", scores={"factuality": 0.55})])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "factuality"
    )
    assert score_cr.result == "FAIL"
    assert res.decision == "BLOCK"


def test_inverted_score_hallucination_high_fails():
    """A high hallucination_rate fails the inverted band (lower is better)."""
    payload = _bundle([_event(event_id="e1", scores={"hallucination_rate": 0.45})])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "hallucination_rate"
    )
    assert score_cr.result == "FAIL"
    assert score_cr.evidence_data["inverted"] is True
    assert score_cr.control_id == "PR-03"
    assert res.decision == "BLOCK"


def test_inverted_score_toxicity_low_passes():
    """A low toxicity score passes the inverted band."""
    payload = _bundle([_event(event_id="e1", scores={"toxicity": 0.02})])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "toxicity"
    )
    assert score_cr.result == "PASS"
    assert score_cr.evidence_data["inverted"] is True
    assert score_cr.control_id == "DE-01"


def test_per_event_mode():
    """per_event=True emits one EvaluationResult per event, not aggregated."""
    payload = _bundle([
        _event(event_id="e1", scores={"faithfulness": 0.95}),
        _event(event_id="e2", scores={"faithfulness": 0.55}),  # FAIL
        _event(event_id="e3", scores={"faithfulness": 0.91}),
    ])
    importer = BraintrustImporter(per_event=True)
    results = importer.parse_string(json.dumps(payload))

    assert len(results) == 3
    decisions = [r.decision for r in results]
    assert decisions == ["ALLOW", "BLOCK", "ALLOW"]
    # Each result has aggregation marker per_event.
    for r in results:
        score_crs = [
            cr for cr in r.control_results
            if cr.evidence_data.get("aggregation") == "per_event"
        ]
        assert score_crs


def test_per_experiment_aggregates_mean():
    """Default per-experiment mode averages score values across events."""
    # Faithfulness mean = (0.99 + 0.81) / 2 = 0.90 → PASS (>= 0.9 inclusive).
    # Factuality mean = (0.6 + 0.6) / 2 = 0.6 → FAIL.
    payload = _bundle([
        _event(event_id="e1", scores={"faithfulness": 0.99, "factuality": 0.60}),
        _event(event_id="e2", scores={"faithfulness": 0.81, "factuality": 0.60}),
    ])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    faithfulness_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "faithfulness"
    )
    factuality_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "factuality"
    )
    assert faithfulness_cr.evidence_data["score_mean"] == pytest.approx(0.90)
    assert faithfulness_cr.result == "PASS"
    assert faithfulness_cr.evidence_data["score_count"] == 2
    assert factuality_cr.evidence_data["score_mean"] == pytest.approx(0.60)
    assert factuality_cr.result == "FAIL"
    # Worst result drives decision.
    assert res.decision == "BLOCK"


def test_git_commit_in_provenance():
    """The git_commit and model metadata are surfaced in source_provenance for code-link."""
    payload = _bundle(
        [_event(event_id="e1")],
        git_commit="deadbeefcafe1234",
    )
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    cr = next(cr for cr in res.control_results if cr.evidence_data.get("score_name"))
    prov = cr.evidence_data["source_provenance"]
    assert prov["git_commit"] == "deadbeefcafe1234"
    assert prov["model"] == "gpt-4o"
    assert prov["model_metadata"] == {"model": "gpt-4o", "temperature": 0.7}
    assert prov["experiment_id"] == "exp-001"
    assert prov["dataset_id"] == "ds-001"


def test_input_output_text_never_stored():
    """No raw input/output/expected text leaks into evidence — only summaries + sha256."""
    secret_input = "SECRET_PROMPT_DO_NOT_LEAK_token-xyz-42"
    secret_output = "ULTRA_PRIVATE_RESPONSE_payload-99"
    secret_expected = "GROUND_TRUTH_LABEL_classified-001"
    payload = _bundle([
        _event(
            event_id="e1",
            input_text=secret_input,
            output_text=secret_output,
            expected=secret_expected,
            scores={"faithfulness": 0.95},
        )
    ])
    importer = BraintrustImporter()
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
    assert secret_expected not in serialized

    # Per-event summary captures sha256 + byte_length but no text.
    res = results[0]
    metrics_cr = next(
        cr for cr in res.control_results
        if cr.control_id == "PR-04" and cr.evidence_data.get("event_summaries")
    )
    summary = metrics_cr.evidence_data["event_summaries"][0]
    assert summary["input_summary"]["present"] is True
    assert "sha256" in summary["input_summary"]
    assert summary["input_summary"]["sha256"] == hashlib.sha256(
        secret_input.encode("utf-8")
    ).hexdigest()
    # Aggregate joined-input hash also computed.
    assert "joined_input_sha256" in metrics_cr.evidence_data


def test_unknown_score_falls_back_to_pr_03():
    """An unmapped scorer name falls back to the default PR-03 control."""
    payload = _bundle([_event(event_id="e1", scores={"some_custom_metric": 0.95})])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    score_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("score_name") == "some_custom_metric"
    )
    assert score_cr.control_id == "PR-03"
    assert score_cr.result == "PASS"


def test_source_provenance_includes_file_hash(tmp_path: Path):
    """Parsing from a file records the SHA-256 hash in source_provenance."""
    payload = _bundle([_event(event_id="e1")])
    raw = json.dumps(payload).encode("utf-8")
    expected_hash = hashlib.sha256(raw).hexdigest()
    p = tmp_path / "braintrust-export.json"
    p.write_bytes(raw)

    importer = BraintrustImporter()
    [res] = importer.parse(p)
    cr = res.control_results[0]
    prov = cr.evidence_data["source_provenance"]
    assert prov["original_file_sha256"] == expected_hash
    assert prov["source_format"] == "braintrust"
    assert prov["experiment_id"] == "exp-001"


# ---------------------------------------------------------------------------
# Bonus: sanity tests
# ---------------------------------------------------------------------------


def test_safety_score_maps_to_de01():
    """safety / toxicity / bias all map to DE-01 (harm prevention)."""
    payload = _bundle([
        _event(event_id="e1", scores={"safety": 1.0, "toxicity": 0.0, "bias": 0.01})
    ])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    de01_scorers = {
        cr.evidence_data["score_name"]
        for cr in res.control_results
        if cr.control_id == "DE-01" and cr.evidence_data.get("score_name")
    }
    assert {"safety", "toxicity", "bias"} <= de01_scorers


def test_metrics_p95_latency_aggregation():
    """latency_ms across events is aggregated as p95."""
    payload = _bundle([
        _event(event_id=f"e{i}", metrics={"latency_ms": v, "tokens_in": 10, "tokens_out": 5})
        for i, v in enumerate([100, 200, 300, 400, 1000])
    ])
    importer = BraintrustImporter()
    [res] = importer.parse_string(json.dumps(payload))

    metrics_cr = next(
        cr for cr in res.control_results
        if cr.control_id == "PR-04" and cr.evidence_data.get("metrics", {}).get("event_count")
    )
    p95 = metrics_cr.evidence_data["metrics"]["latency_ms_p95"]
    # p95 of [100,200,300,400,1000] → between 400 and 1000, weighted toward 1000.
    assert 700 <= p95 <= 1000
    # Tokens summed.
    assert metrics_cr.evidence_data["metrics"]["tokens_in"] == 50
    assert metrics_cr.evidence_data["metrics"]["tokens_out"] == 25
