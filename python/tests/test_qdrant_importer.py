"""Tests for the Qdrant audit-event importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers import QdrantImporter


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _event(**overrides: object) -> dict[str, object]:
    """Build a Qdrant audit event with sensible defaults."""
    base: dict[str, object] = {
        "id": "evt-default-1",
        "operation": "search",
        "collection": "documents",
        "shard_key": "tenant-1234",
        "timestamp": "2026-05-01T12:00:00Z",
        "actor": "user-alice",
        "api_key_hint": "qdr_abcd****",
        "limit": 50,
        "with_payload": True,
        "with_vectors": False,
        "filter_keys": ["category", "tenant_id"],
        "score_threshold": 0.7,
        "exact": False,
        "consistency": "majority",
        "result_count": 12,
        "status": "ok",
        "duration_ms": 45,
        "request_id": "req-abc",
    }
    base.update(overrides)
    return base


def _envelope(events: list[dict[str, object]]) -> str:
    return json.dumps({"events": events})


def _control_ids(result) -> list[str]:
    return [cr.control_id for cr in result.control_results]


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# Per-operation tests
# ---------------------------------------------------------------------------

def test_parse_search_success() -> None:
    """A clean search with filter, default limit, no vectors → single PR-04 PASS."""
    importer = QdrantImporter()
    results = importer.parse_string(_envelope([_event()]))

    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    assert len(res.control_results) == 1
    cr = res.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_search_success"
    assert cr.evidence_data["collection"] == "documents"
    assert cr.evidence_data["shard_key"] == "tenant-1234"
    assert cr.evidence_data["result_count"] == 12
    assert cr.evidence_data["with_payload"] is True
    assert cr.evidence_data["score_threshold"] == 0.7
    assert cr.evidence_data["duration_ms"] == 45.0
    assert res.source_type == "qdrant_import"
    assert res.action_id.startswith("qdrant-")


def test_parse_upsert() -> None:
    """upsert success → PR-03 PASS (provenance / write integrity)."""
    importer = QdrantImporter()
    ev = _event(
        id="evt-upsert-1",
        operation="upsert",
        filter_keys=None,
        result_count=None,
        with_vectors=None,
    )
    results = importer.parse_string(_envelope([ev]))

    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    cr = res.control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_upsert_success"


def test_delete_marks_audit() -> None:
    """delete success → PR-05 PASS (audit-trail control)."""
    importer = QdrantImporter()
    ev = _event(id="evt-del", operation="delete", filter_keys=None)
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    cr = res.control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_delete_success"
    # Successful delete with no other risk signals → ALLOW.
    assert res.decision == "ALLOW"


def test_collection_lifecycle_flags() -> None:
    """create_collection / delete_collection → PR-05 FLAG (privileged schema change)."""
    importer = QdrantImporter()
    events = [
        _event(id="evt-create", operation="create_collection", filter_keys=None,
               result_count=None),
        _event(id="evt-drop", operation="delete_collection", filter_keys=None,
               result_count=None),
    ]
    results = importer.parse_string(_envelope(events))
    # 2 events, 0 cross-collection synthetic since one actor across two collection
    # *names* would normally trigger — but both events use the same default
    # collection. Use distinct collections to make the test deterministic about
    # the per-event flags.
    # Override to ensure same collection for these events:
    events = [
        _event(id="evt-create", operation="create_collection",
               collection="docs", filter_keys=None, result_count=None),
        _event(id="evt-drop", operation="delete_collection",
               collection="docs", filter_keys=None, result_count=None),
    ]
    results = importer.parse_string(_envelope(events))

    assert len(results) == 2  # no cross-collection synthetic (one collection)
    for res, expected_signal in zip(
        results, ["operation_create_collection", "operation_delete_collection"]
    ):
        cr = res.control_results[0]
        assert cr.control_id == "PR-05"
        assert cr.result == "FLAG"
        assert cr.evidence_data["signal"] == expected_signal
        assert res.decision == "FLAG"


def test_snapshot_flags_privileged() -> None:
    """snapshot_create / snapshot_recover → PR-05 FLAG (privileged backup ops)."""
    importer = QdrantImporter()
    events = [
        _event(id="evt-snap", operation="snapshot_create",
               collection="docs", filter_keys=None, result_count=None),
        _event(id="evt-recover", operation="snapshot_recover",
               collection="docs", filter_keys=None, result_count=None),
    ]
    results = importer.parse_string(_envelope(events))

    assert len(results) == 2
    for res, expected in zip(
        results, ["operation_snapshot_create", "operation_snapshot_recover"]
    ):
        cr = res.control_results[0]
        assert cr.control_id == "PR-05"
        assert cr.result == "FLAG"
        assert cr.evidence_data["signal"] == expected
        assert res.decision == "FLAG"


# ---------------------------------------------------------------------------
# Error-path tests
# ---------------------------------------------------------------------------

def test_forbidden_marks_fail() -> None:
    """status=error & error_status=Forbidden → PR-02 FAIL → BLOCK."""
    importer = QdrantImporter()
    ev = _event(
        id="evt-forbidden",
        status="error",
        error_status="Forbidden",
    )
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "error_status_forbidden"


def test_bad_request_flags_input_validation() -> None:
    """status=error & error_status=BadRequest → PR-03 FLAG."""
    importer = QdrantImporter()
    ev = _event(
        id="evt-bad",
        status="error",
        error_status="BadRequest",
    )
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    assert res.decision == "FLAG"
    cr = res.control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "error_status_bad_request"


def test_internal_error_marks_de01_fail() -> None:
    """status=error & error_status=Internal → DE-01 FAIL → BLOCK."""
    importer = QdrantImporter()
    ev = _event(
        id="evt-internal",
        status="error",
        error_status="Internal",
    )
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "error_status_internal"


# ---------------------------------------------------------------------------
# Search-quality flag tests
# ---------------------------------------------------------------------------

def test_with_vectors_flags() -> None:
    """search with with_vectors=true → PR-04 FLAG (raw vectors leaked)."""
    importer = QdrantImporter()
    ev = _event(id="evt-vec", with_vectors=True)
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    signals = _signals(res)
    assert "operation_search_success" in signals
    assert "search_with_vectors" in signals
    assert res.decision == "FLAG"
    vec_cr = next(c for c in res.control_results if c.evidence_data["signal"] == "search_with_vectors")
    assert vec_cr.control_id == "PR-04"
    assert vec_cr.result == "FLAG"


def test_unscoped_search_flags() -> None:
    """search with no filter_keys → PR-04 FLAG (un-scoped)."""
    importer = QdrantImporter()
    ev = _event(id="evt-noscope", filter_keys=[])
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    assert "search_no_filter" in _signals(res)
    assert res.decision == "FLAG"
    no_filter_cr = next(c for c in res.control_results if c.evidence_data["signal"] == "search_no_filter")
    assert no_filter_cr.control_id == "PR-04"


def test_limit_above_threshold_flags() -> None:
    """search with limit > threshold → PR-04 FLAG (over-fetch)."""
    importer = QdrantImporter(limit_threshold=100)
    ev = _event(id="evt-overfetch", limit=2500)
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    assert "search_limit_exceeded" in _signals(res)
    assert res.decision == "FLAG"
    over_cr = next(c for c in res.control_results if c.evidence_data["signal"] == "search_limit_exceeded")
    assert over_cr.control_id == "PR-04"
    assert over_cr.evidence_data["limit_threshold"] == 100
    assert over_cr.evidence_data["limit"] == 2500


def test_exact_flag_flags() -> None:
    """search with exact=true → PR-04 FLAG (full-scan; expensive + leaks distribution)."""
    importer = QdrantImporter()
    ev = _event(id="evt-exact", exact=True)
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    assert "search_exact_scan" in _signals(res)
    assert res.decision == "FLAG"
    exact_cr = next(c for c in res.control_results if c.evidence_data["signal"] == "search_exact_scan")
    assert exact_cr.control_id == "PR-04"
    assert exact_cr.result == "FLAG"
    # Default-limit + exact=true should produce both an op-success PASS and the
    # exact-scan FLAG (and *not* an over-fetch FLAG, distinguishing the signals).
    signals = _signals(res)
    assert "search_limit_exceeded" not in signals


# ---------------------------------------------------------------------------
# Cross-collection synthetic finding
# ---------------------------------------------------------------------------

def test_cross_collection_pattern_synthetic_finding() -> None:
    """Same actor across multiple collections → synthetic PR-02 FLAG record."""
    importer = QdrantImporter()
    events = [
        _event(id="e1", actor="user-mallory", collection="customers"),
        _event(id="e2", actor="user-mallory", collection="invoices"),
        _event(id="e3", actor="user-mallory", collection="employees"),
        # A second actor stays scoped to one collection — should not trigger.
        _event(id="e4", actor="user-bob", collection="public_docs"),
    ]
    results = importer.parse_string(_envelope(events))

    # 4 per-event + 1 synthetic = 5
    assert len(results) == 5
    synthetic = results[-1]
    assert synthetic.action_id.startswith("qdrant-synthetic-")
    cr = synthetic.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cross_collection_pattern"
    assert cr.evidence_data["actor"] == "user-mallory"
    touched = cr.evidence_data["collections_touched"]
    assert sorted(touched) == ["customers", "employees", "invoices"]
    assert cr.evidence_data["collection_count"] == 3
    assert cr.evidence_data["event_count"] == 3
    # user-bob was scoped — must not appear among crossing actors.
    crossing = cr.evidence_data["all_crossing_actors"]
    assert "user-bob" not in crossing
    assert "user-mallory" in crossing


def test_cross_collection_disabled_returns_no_synthetic() -> None:
    """detect_cross_collection=False suppresses the synthetic record."""
    importer = QdrantImporter(detect_cross_collection=False)
    events = [
        _event(id="e1", actor="user-mallory", collection="customers"),
        _event(id="e2", actor="user-mallory", collection="invoices"),
    ]
    results = importer.parse_string(_envelope(events))

    assert len(results) == 2
    assert all(not r.action_id.startswith("qdrant-synthetic-") for r in results)


# ---------------------------------------------------------------------------
# Sanitization & provenance
# ---------------------------------------------------------------------------

def test_filter_values_never_stored() -> None:
    """Filter *values* — even when supplied as a dict — must never appear in evidence."""
    importer = QdrantImporter()
    secret_value = "alice@example.com"
    secret_value_2 = "S3CRET-PII-VALUE"
    # Two shapes: list-of-keys and dict-of-keys-with-values. Only key *names*
    # should survive.
    ev_list = _event(id="evt-list", filter_keys=["email", "tenant_id"])
    ev_dict = _event(
        id="evt-dict",
        filter_keys={
            "email": secret_value,
            "ssn": secret_value_2,
        },
    )
    results = importer.parse_string(_envelope([ev_list, ev_dict]))

    blob = json.dumps(
        [
            {
                "decision_reason": r.decision_reason,
                "control_results": [
                    {
                        "detail": cr.detail,
                        "evidence_data": cr.evidence_data,
                    }
                    for cr in r.control_results
                ],
            }
            for r in results
        ],
        default=str,
    )
    assert secret_value not in blob
    assert secret_value_2 not in blob

    # Affirmatively: the *names* should appear in filter_keys.
    list_cr = results[0].control_results[0]
    dict_cr = results[1].control_results[0]
    assert list_cr.evidence_data["filter_keys"] == ["email", "tenant_id"]
    assert dict_cr.evidence_data["filter_keys"] == ["email", "ssn"]


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) populates source_provenance.original_file_sha256 with sha256 of file."""
    payload = _envelope([_event(id="evt-prov")])
    f = tmp_path / "qdrant_audit.json"
    f.write_text(payload, encoding="utf-8")
    expected_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    importer = QdrantImporter()
    results = importer.parse(f)

    assert len(results) == 1
    prov = results[0].control_results[0].evidence_data["source_provenance"]
    assert prov["source_format"] == "qdrant"
    assert prov["original_file_sha256"] == expected_sha

    # parse_string() should NOT include a hash (no file).
    string_results = importer.parse_string(payload)
    string_prov = string_results[0].control_results[0].evidence_data["source_provenance"]
    assert "original_file_sha256" not in string_prov


# ---------------------------------------------------------------------------
# Format flexibility
# ---------------------------------------------------------------------------

def test_parses_data_envelope_and_jsonl_and_single_object() -> None:
    """Importer accepts {events:[]}, {data:[]}, JSONL, and a bare single object."""
    importer = QdrantImporter()
    e1 = _event(id="e1")
    e2 = _event(id="e2")

    # data envelope
    data_doc = json.dumps({"data": [e1, e2]})
    assert len(importer.parse_string(data_doc)) == 2

    # JSONL
    jsonl_doc = "\n".join(json.dumps(e) for e in [e1, e2])
    assert len(importer.parse_string(jsonl_doc)) == 2

    # single object (no envelope)
    single = importer.parse_string(json.dumps(e1))
    assert len(single) == 1
    assert single[0].control_results[0].evidence_data["qdrant_event_id"] == "e1"


# ---------------------------------------------------------------------------
# Smoke: SDK importable without optional deps
# ---------------------------------------------------------------------------

def test_importable_without_qdrant_client() -> None:
    """The importer module must not require the optional qdrant-client package."""
    # Importing inside the test ensures we exercise the import surface.
    import importlib

    mod = importlib.import_module("ancilis.importers.qdrant")
    assert hasattr(mod, "QdrantImporter")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
