"""Tests for the LangSmith trace importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers.langsmith import (
    LangSmithImporter,
    _load_mappings,
    _map_run_to_control,
)


# ---------------------------------------------------------------------------
# Fixtures — minimal inline LangSmith run exports
# ---------------------------------------------------------------------------

CLEAN_TRACE = {
    "runs": [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "ChatOpenAI",
            "run_type": "llm",
            "inputs": {"messages": [{"role": "user", "content": "hello"}]},
            "outputs": {"generations": [[{"text": "hi"}]]},
            "error": None,
            "start_time": "2026-01-01T00:00:00.000Z",
            "end_time": "2026-01-01T00:00:00.500Z",
            "extra": {
                "metadata": {
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 5,
                        "total_tokens": 15,
                    }
                },
                "tags": ["chat", "openai"],
            },
            "trace_id": "trace-aaaa",
            "parent_run_id": None,
            "session_id": "session-1",
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "name": "search_docs",
            "run_type": "tool",
            "inputs": {"query": "ancilis"},
            "outputs": {"docs": ["doc1", "doc2"]},
            "error": None,
            "start_time": "2026-01-01T00:00:00.500Z",
            "end_time": "2026-01-01T00:00:00.700Z",
            "extra": {"metadata": {}},
            "trace_id": "trace-aaaa",
            "parent_run_id": "11111111-1111-1111-1111-111111111111",
        },
    ]
}

ERROR_RUN = {
    "runs": [
        {
            "id": "33333333-3333-3333-3333-333333333333",
            "name": "ChatOpenAI",
            "run_type": "llm",
            "inputs": {"messages": [{"role": "user", "content": "boom"}]},
            "outputs": None,
            "error": {"detail": "RateLimitError: too many requests"},
            "start_time": "2026-01-01T01:00:00.000Z",
            "end_time": "2026-01-01T01:00:00.100Z",
            "trace_id": "trace-bbbb",
        }
    ]
}

UNKNOWN_TYPE = {
    "runs": [
        {
            "id": "44444444-4444-4444-4444-444444444444",
            "name": "MysteryStep",
            "run_type": "embedding",
            "inputs": {"text": "ancilis"},
            "outputs": {"vector": [0.1, 0.2]},
            "error": None,
            "start_time": "2026-01-01T02:00:00.000Z",
            "end_time": "2026-01-01T02:00:00.050Z",
            "trace_id": "trace-cccc",
        }
    ]
}

PII_TRACE = {
    "runs": [
        {
            "id": "55555555-5555-5555-5555-555555555555",
            "name": "ChatOpenAI",
            "run_type": "llm",
            "inputs": {"messages": [{"role": "user", "content": "email me at alice@example.com"}]},
            "outputs": {"generations": [[{"text": "ok"}]]},
            "error": None,
            "start_time": "2026-01-01T03:00:00.000Z",
            "end_time": "2026-01-01T03:00:00.200Z",
            "trace_id": "trace-dddd",
        }
    ]
}

JSONL_STREAM = "\n".join(
    [
        json.dumps(
            {
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "name": "ChatOpenAI",
                "run_type": "llm",
                "inputs": {"messages": []},
                "outputs": {"generations": []},
                "error": None,
                "start_time": "2026-01-01T04:00:00.000Z",
                "end_time": "2026-01-01T04:00:00.300Z",
                "trace_id": "trace-jsonl-1",
            }
        ),
        "",  # blank line — must be tolerated
        json.dumps(
            {
                "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "name": "search",
                "run_type": "tool",
                "inputs": {"q": "x"},
                "outputs": {"hits": []},
                "error": None,
                "start_time": "2026-01-01T04:00:00.300Z",
                "end_time": "2026-01-01T04:00:00.400Z",
                "trace_id": "trace-jsonl-2",
            }
        ),
    ]
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_json_export():
    imp = LangSmithImporter(agent_id="ls-agent")
    results = imp.parse_string(json.dumps(CLEAN_TRACE))

    assert len(results) == 1  # both runs share trace_id "trace-aaaa"
    ev = results[0]
    assert ev.source_type == "langsmith_import"
    assert ev.agent_id == "ls-agent"
    assert ev.decision == "ALLOW"
    assert len(ev.control_results) == 2
    # Run types covered: llm → PR-01, tool → PR-02
    control_ids = {cr.control_id for cr in ev.control_results}
    assert control_ids == {"PR-01", "PR-02"}
    assert ev.session_id == "session-1"


def test_parse_jsonl_stream():
    imp = LangSmithImporter()
    results = imp.parse_string(JSONL_STREAM)

    # Two distinct trace_ids → two evaluations.
    assert len(results) == 2
    decisions = {ev.decision for ev in results}
    assert decisions == {"ALLOW"}
    types = sorted({cr.control_id for ev in results for cr in ev.control_results})
    assert types == ["PR-01", "PR-02"]


def test_run_with_error_marks_fail():
    imp = LangSmithImporter()
    results = imp.parse_string(json.dumps(ERROR_RUN))

    assert len(results) == 1
    ev = results[0]
    assert ev.decision == "BLOCK"
    cr = ev.control_results[0]
    assert cr.result == "FAIL"
    # llm.error → DE-01 per shared mapping
    assert cr.control_id == "DE-01"
    assert "RateLimitError" in cr.detail
    assert "RateLimitError" in cr.evidence_data["error"]


def test_token_usage_extracted():
    imp = LangSmithImporter()
    results = imp.parse_string(json.dumps(CLEAN_TRACE))
    ev = results[0]
    llm_cr = next(cr for cr in ev.control_results if cr.control_id == "PR-01")
    usage = llm_cr.evidence_data["token_usage"]
    assert usage["prompt_tokens"] == 10
    assert usage["completion_tokens"] == 5
    assert usage["total_tokens"] == 15
    # Latency derived from start/end timestamps (500ms).
    assert llm_cr.evidence_data["latency_ms"] == pytest.approx(500.0, rel=1e-3)


def test_unknown_run_type_falls_back():
    imp = LangSmithImporter()
    results = imp.parse_string(json.dumps(UNKNOWN_TYPE))

    assert len(results) == 1
    ev = results[0]
    assert ev.decision == "ALLOW"
    cr = ev.control_results[0]
    # 'embedding' is unmapped → falls back to the 'unknown' control (PR-05).
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_source_provenance_includes_file_hash(tmp_path: Path):
    fixture = tmp_path / "trace.json"
    payload = json.dumps(CLEAN_TRACE)
    fixture.write_text(payload, encoding="utf-8")
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    imp = LangSmithImporter(agent_id="ci")
    ev = imp.parse(fixture)[0]
    provenance = ev.control_results[0].evidence_data["source_provenance"]
    assert provenance["source_format"] == "langsmith"
    assert provenance["source_tool_name"] == "langsmith"
    assert provenance["original_file_sha256"] == expected
    assert provenance["run_count"] == 2
    assert provenance["run_types"] == ["llm", "tool"]


def test_clean_export_yields_pass_evaluation():
    imp = LangSmithImporter()
    results = imp.parse_string(json.dumps(CLEAN_TRACE))
    ev = results[0]
    assert ev.decision == "ALLOW"
    assert all(cr.result == "PASS" for cr in ev.control_results)


# ---------------------------------------------------------------------------
# Extra coverage — useful but not in the explicit deliverable list
# ---------------------------------------------------------------------------


def test_pii_marker_flags_llm_input():
    imp = LangSmithImporter()
    ev = imp.parse_string(json.dumps(PII_TRACE))[0]
    assert ev.decision == "FLAG"
    cr = ev.control_results[0]
    assert cr.result == "FLAG"
    assert "email" in cr.evidence_data["pii_markers"]


def test_per_run_mode_emits_one_per_run():
    imp = LangSmithImporter(per_run=True)
    results = imp.parse_string(json.dumps(CLEAN_TRACE))
    assert len(results) == 2
    assert {ev.decision for ev in results} == {"ALLOW"}


def test_empty_export_is_handled_gracefully():
    imp = LangSmithImporter()
    results = imp.parse_string(json.dumps({"runs": []}))
    assert len(results) == 1
    ev = results[0]
    assert ev.decision == "ALLOW"
    assert ev.control_results[0].result == "PASS"
    assert ev.control_results[0].evidence_data["run_count"] == 0


def test_malformed_run_does_not_crash():
    # Mix of valid + malformed entries; importer should ignore non-dicts.
    payload = json.dumps({"runs": [None, "junk", {"id": "x", "run_type": "llm",
                                                     "trace_id": "trace-z"}]})
    imp = LangSmithImporter()
    results = imp.parse_string(payload)
    # Only the valid run produces a trace.
    assert len(results) == 1
    assert results[0].control_results[0].control_id == "PR-01"


def test_mapping_table_loads():
    m = _load_mappings()
    assert isinstance(m, dict)
    assert m.get("llm") == "PR-01"
    assert m.get("tool") == "PR-02"
    assert m.get("retriever") == "PR-04"


def test_map_run_with_error_prefers_error_variant():
    mappings = {"llm": "PR-01", "llm.error": "DE-01"}
    assert _map_run_to_control("llm", has_error=False, mappings=mappings) == "PR-01"
    assert _map_run_to_control("llm", has_error=True, mappings=mappings) == "DE-01"


def test_evaluation_fields_valid_for_store():
    imp = LangSmithImporter(agent_id="ls-pipeline")
    ev = imp.parse_string(json.dumps(CLEAN_TRACE))[0]
    # Mirrors the SARIF/CycloneDX integration assertions.
    assert ev.evaluation_id
    assert ev.timestamp
    assert ev.agent_id == "ls-pipeline"
    assert ev.source_type == "langsmith_import"
    assert ev.mode in ("audit", "enforce")
    assert isinstance(ev.control_results, list) and ev.control_results
    assert ev.decision in ("ALLOW", "FLAG", "BLOCK")
