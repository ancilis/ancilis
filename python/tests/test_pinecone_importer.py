"""Tests for the Pinecone vector store operation log evidence importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.pinecone import (
    PineconeImporter,
    _sanitize_filter_keys,
    _sanitize_score_distribution,
)


# ---------------------------------------------------------------------------
# Fixtures — inline Pinecone operation log documents (no pinecone-client needed)
# ---------------------------------------------------------------------------

def _op(
    *,
    id: str = "op-1",
    operation: str = "query",
    index: str = "production-rag",
    namespace: str = "tenant-1234",
    status: str = "success",
    top_k: int | None = 10,
    filter_keys: list[str] | None = None,
    include_metadata: bool = True,
    include_values: bool = False,
    vector_count: int = 50,
    latency_ms: float = 45.0,
    request_units: float = 1.5,
    score_distribution: dict | None = None,
    user_id: str = "user-42",
    api_key_id: str = "key-A",
    trace_id: str | None = "trace-1",
    error_code: str | None = None,
    timestamp: str = "2026-04-01T12:00:00Z",
) -> dict:
    op = {
        "id": id,
        "operation": operation,
        "index": index,
        "namespace": namespace,
        "timestamp": timestamp,
        "user_id": user_id,
        "api_key_id": api_key_id,
        "vector_count": vector_count,
        "include_metadata": include_metadata,
        "include_values": include_values,
        "latency_ms": latency_ms,
        "status": status,
        "request_units": request_units,
    }
    if top_k is not None:
        op["top_k"] = top_k
    if filter_keys is not None:
        op["filter_keys"] = filter_keys
    if score_distribution is not None:
        op["score_distribution"] = score_distribution
    if trace_id is not None:
        op["trace_id"] = trace_id
    if error_code is not None:
        op["error_code"] = error_code
    return op


def _export(*ops: dict, envelope: str = "operations") -> str:
    return json.dumps({envelope: list(ops)})


SECRET_USER_ID_VALUE = "user@example.com"
SECRET_VECTOR_PAYLOAD = "VECTOR-DATA-MUST-NEVER-LEAK-12345"


# ---------------------------------------------------------------------------
# Importer behaviour tests
# ---------------------------------------------------------------------------

class TestPineconeImporter:
    def test_parse_query_success(self):
        export = _export(
            _op(
                id="q-1",
                operation="query",
                top_k=10,
                filter_keys=["userId", "category"],
                score_distribution={"min": 0.32, "max": 0.91, "median": 0.78},
            )
        )
        imp = PineconeImporter(agent_id="ci")
        results = imp.parse_string(export)

        assert len(results) == 1
        ev = results[0]
        assert ev.source_type == "pinecone_import"
        assert ev.agent_id == "ci"
        assert ev.decision == "ALLOW"
        # Exactly one control result for a clean filtered query within top_k.
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-04"
        assert cr.evidence_data["signal"] == "operation_query_success"
        assert cr.evidence_data["operation"] == "query"
        assert cr.evidence_data["index"] == "production-rag"
        assert cr.evidence_data["namespace"] == "tenant-1234"
        assert cr.evidence_data["top_k"] == 10
        assert cr.evidence_data["filter_keys"] == ["category", "userId"]
        assert cr.evidence_data["score_distribution"] == {
            "min": 0.32,
            "max": 0.91,
            "median": 0.78,
        }

    def test_parse_upsert(self):
        export = _export(
            _op(id="u-1", operation="upsert", top_k=None, vector_count=200)
        )
        imp = PineconeImporter()
        ev = imp.parse_string(export)[0]

        assert ev.decision == "ALLOW"
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-03"
        assert cr.evidence_data["signal"] == "operation_upsert_success"
        assert cr.evidence_data["vector_count"] == 200

    def test_parse_delete_marks_audit(self):
        export = _export(
            _op(id="d-1", operation="delete", top_k=None, vector_count=5)
        )
        imp = PineconeImporter()
        ev = imp.parse_string(export)[0]

        assert ev.decision == "ALLOW"
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-05"  # audit-trail bucket
        assert cr.evidence_data["signal"] == "operation_delete_success"

    def test_fetch_with_include_values_flags(self):
        export = _export(
            _op(
                id="f-1",
                operation="fetch",
                top_k=None,
                filter_keys=["id"],
                include_values=True,
            )
        )
        imp = PineconeImporter()
        ev = imp.parse_string(export)[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "operation_fetch_success" in signals
        assert "fetch_include_values" in signals

        flag_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "fetch_include_values"
        )
        assert flag_cr.result == "FLAG"
        assert flag_cr.control_id == "PR-04"

    def test_query_top_k_above_threshold_flags(self):
        # Default threshold is 100; top_k=500 should flag.
        export = _export(
            _op(
                id="q-big",
                operation="query",
                top_k=500,
                filter_keys=["userId"],
            )
        )
        imp = PineconeImporter()
        ev = imp.parse_string(export)[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "query_top_k_exceeded" in signals

        flag_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "query_top_k_exceeded"
        )
        assert flag_cr.result == "FLAG"
        assert flag_cr.control_id == "PR-04"
        assert flag_cr.evidence_data["top_k"] == 500
        assert flag_cr.evidence_data["top_k_threshold"] == 100

        # Custom higher threshold suppresses the flag.
        imp2 = PineconeImporter(top_k_threshold=1000)
        ev2 = imp2.parse_string(export)[0]
        signals2 = {cr.evidence_data.get("signal") for cr in ev2.control_results}
        assert "query_top_k_exceeded" not in signals2

    def test_query_without_filter_flags(self):
        export = _export(
            _op(
                id="q-noscope",
                operation="query",
                top_k=10,
                filter_keys=[],
            )
        )
        imp = PineconeImporter()
        ev = imp.parse_string(export)[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "query_no_filter" in signals

        flag_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "query_no_filter"
        )
        assert flag_cr.result == "FLAG"
        assert flag_cr.control_id == "PR-04"

        # Filter completely missing from the operation should also flag.
        export2 = json.dumps({"operations": [{
            "id": "q-noscope2",
            "operation": "query",
            "index": "production-rag",
            "namespace": "tenant-1234",
            "top_k": 10,
            "status": "success",
            "timestamp": "2026-04-01T12:00:00Z",
        }]})
        ev2 = imp.parse_string(export2)[0]
        signals2 = {cr.evidence_data.get("signal") for cr in ev2.control_results}
        assert "query_no_filter" in signals2

    def test_failure_marks_fail(self):
        export = _export(
            _op(
                id="q-err",
                operation="query",
                top_k=10,
                filter_keys=["userId"],
                status="failure",
                error_code="UNAUTHORIZED",
            )
        )
        imp = PineconeImporter()
        ev = imp.parse_string(export)[0]

        assert ev.decision == "BLOCK"
        # Failure short-circuits the success branch — only the FAIL ControlResult
        # should be present (no operation_*_success flag for failures).
        assert any(cr.result == "FAIL" for cr in ev.control_results)
        fail_cr = next(cr for cr in ev.control_results if cr.result == "FAIL")
        assert fail_cr.control_id == "DE-01"
        assert fail_cr.evidence_data["signal"] == "status_failure"
        assert fail_cr.evidence_data["error_code"] == "UNAUTHORIZED"
        # No success signal should fire for a failed op.
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "operation_query_success" not in signals

    def test_cross_namespace_pattern_flags_scope(self):
        """Same trace_id touching multiple namespaces → PR-02 FLAG on every op in the bucket."""
        export = _export(
            _op(
                id="q-a", operation="query", namespace="tenant-1234",
                top_k=10, filter_keys=["userId"], trace_id="trace-multi",
                api_key_id="key-X",
            ),
            _op(
                id="q-b", operation="query", namespace="tenant-9999",
                top_k=10, filter_keys=["userId"], trace_id="trace-multi",
                api_key_id="key-X",
            ),
            # Different trace, different namespace — not flagged.
            _op(
                id="q-c", operation="query", namespace="tenant-isolated",
                top_k=10, filter_keys=["userId"], trace_id="trace-solo",
                api_key_id="key-Y",
            ),
        )
        imp = PineconeImporter()
        results = imp.parse_string(export)

        # The two ops sharing trace-multi should both be flagged.
        flagged = [
            ev for ev in results
            if any(
                cr.evidence_data.get("signal") == "cross_namespace_pattern"
                for cr in ev.control_results
            )
        ]
        assert len(flagged) == 2

        for ev in flagged:
            cross_cr = next(
                cr for cr in ev.control_results
                if cr.evidence_data.get("signal") == "cross_namespace_pattern"
            )
            assert cross_cr.result == "FLAG"
            assert cross_cr.control_id == "PR-02"
            assert cross_cr.evidence_data["namespace_count_in_bucket"] == 2
            assert sorted(cross_cr.evidence_data["namespaces_in_bucket"]) == [
                "tenant-1234",
                "tenant-9999",
            ]
            assert ev.decision == "FLAG"

        # The isolated op should pass cleanly.
        isolated = next(ev for ev in results if ev.action_id == "pinecone-q-c")
        signals = {cr.evidence_data.get("signal") for cr in isolated.control_results}
        assert "cross_namespace_pattern" not in signals
        assert isolated.decision == "ALLOW"

        # Disabling cross-namespace detection suppresses the flag entirely.
        imp_off = PineconeImporter(detect_cross_namespace=False)
        results_off = imp_off.parse_string(export)
        for ev in results_off:
            signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
            assert "cross_namespace_pattern" not in signals

    def test_filter_values_never_stored(self):
        """Filter VALUES, vector data, and metadata must never appear in evidence_data."""
        # Even if a buggy export leaks values into the filter object, the
        # importer must keep only the keys.
        export = json.dumps({
            "operations": [
                {
                    "id": "q-secret",
                    "operation": "query",
                    "index": "production-rag",
                    "namespace": "tenant-1234",
                    "timestamp": "2026-04-01T12:00:00Z",
                    "user_id": SECRET_USER_ID_VALUE,
                    "api_key_id": "key-A",
                    "trace_id": "trace-secret",
                    "top_k": 10,
                    "filter_keys": {
                        "userId": SECRET_USER_ID_VALUE,
                        "vector_payload": SECRET_VECTOR_PAYLOAD,
                    },
                    "include_metadata": True,
                    "include_values": False,
                    "vector_count": 1,
                    "latency_ms": 30,
                    "request_units": 0.1,
                    "status": "success",
                    # Buggy/aggressive exporter shape — should be discarded.
                    "vectors": [{"values": SECRET_VECTOR_PAYLOAD}],
                    "metadata": {"raw": SECRET_VECTOR_PAYLOAD},
                }
            ]
        })

        imp = PineconeImporter()
        ev = imp.parse_string(export)[0]

        # filter_keys must be just the keys, no values.
        cr = ev.control_results[0]
        fk = cr.evidence_data["filter_keys"]
        assert fk == ["userId", "vector_payload"]

        # Serialize the entire EvaluationResult and confirm secret payload is absent.
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
        assert SECRET_VECTOR_PAYLOAD not in serialized
        # The user_id is captured (as a contextual identifier), but it should
        # only appear via the user_id field — never via filter values. Confirm
        # there's no leakage of the value INTO any filter or metadata field.
        for cr in ev.control_results:
            for forbidden_field in ("vectors", "metadata", "filter", "filter_values"):
                assert forbidden_field not in cr.evidence_data

    def test_jsonl_stream(self):
        op_a = _op(id="op-a", operation="query", top_k=10, filter_keys=["x"])
        op_b = _op(id="op-b", operation="upsert", top_k=None, vector_count=10)
        op_c = _op(id="op-c", operation="delete", top_k=None, vector_count=2)
        jsonl = "\n".join(json.dumps(o) for o in (op_a, op_b, op_c)) + "\n"

        imp = PineconeImporter()
        results = imp.parse_string(jsonl)

        assert len(results) == 3
        op_ids = [
            cr.evidence_data["pinecone_operation_id"]
            for ev in results
            for cr in ev.control_results
            if cr.result == "PASS"
        ]
        assert "op-a" in op_ids
        assert "op-b" in op_ids
        assert "op-c" in op_ids

    def test_clean_export_yields_pass(self):
        """An export of only well-formed, scoped, in-budget ops yields all ALLOW."""
        export = _export(
            _op(id="q1", operation="query", top_k=10, filter_keys=["userId"],
                trace_id="t1"),
            _op(id="q2", operation="query", top_k=20, filter_keys=["category"],
                trace_id="t2"),
            _op(id="u1", operation="upsert", top_k=None, vector_count=5,
                trace_id="t3"),
            _op(id="d1", operation="delete", top_k=None, vector_count=1,
                trace_id="t4"),
        )
        imp = PineconeImporter()
        results = imp.parse_string(export)

        assert len(results) == 4
        assert all(ev.decision == "ALLOW" for ev in results)
        for ev in results:
            assert len(ev.control_results) == 1
            assert ev.control_results[0].result == "PASS"

    def test_source_provenance_includes_file_hash(self, tmp_path: Path):
        export = _export(
            _op(id="q-1", operation="query", top_k=10, filter_keys=["userId"])
        )
        fixture = tmp_path / "pinecone-export.json"
        fixture.write_text(export, encoding="utf-8")
        expected = hashlib.sha256(export.encode("utf-8")).hexdigest()

        imp = PineconeImporter(agent_id="pipeline")
        ev = imp.parse(fixture)[0]
        provenance = ev.control_results[0].evidence_data["source_provenance"]

        assert provenance["source_format"] == "pinecone"
        assert provenance["source_tool_name"] == "pinecone"
        assert provenance["original_file_sha256"] == expected


# ---------------------------------------------------------------------------
# Envelope / shape tolerance
# ---------------------------------------------------------------------------

class TestPineconeEnvelopes:
    def test_data_envelope_accepted(self):
        export = _export(
            _op(id="q-1", operation="query", top_k=10, filter_keys=["userId"]),
            envelope="data",
        )
        imp = PineconeImporter()
        results = imp.parse_string(export)
        assert len(results) == 1

    def test_single_object_accepted(self):
        single = json.dumps(
            _op(id="q-1", operation="query", top_k=10, filter_keys=["userId"])
        )
        imp = PineconeImporter()
        results = imp.parse_string(single)
        assert len(results) == 1
        assert results[0].decision == "ALLOW"

    def test_bare_list_accepted(self):
        bare = json.dumps([
            _op(id="q-1", operation="query", top_k=10, filter_keys=["userId"]),
            _op(id="q-2", operation="query", top_k=10, filter_keys=["category"]),
        ])
        imp = PineconeImporter()
        results = imp.parse_string(bare)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

class TestSanitizers:
    def test_sanitize_filter_keys_from_list(self):
        assert _sanitize_filter_keys(["b", "a"]) == ["a", "b"]

    def test_sanitize_filter_keys_from_dict_drops_values(self):
        result = _sanitize_filter_keys({"userId": "secret-value", "tier": "gold"})
        assert result == ["tier", "userId"]
        # Confirm the SECRET value is not present.
        assert "secret-value" not in json.dumps(result)

    def test_sanitize_filter_keys_handles_none(self):
        assert _sanitize_filter_keys(None) == []

    def test_sanitize_score_distribution_keeps_numeric_only(self):
        dist = {
            "min": 0.1, "max": 0.9, "median": 0.5,
            "raw_scores": [0.1, 0.2, 0.3, 0.9],  # must be dropped
        }
        out = _sanitize_score_distribution(dist)
        assert out == {"min": 0.1, "max": 0.9, "median": 0.5}
        assert "raw_scores" not in out
