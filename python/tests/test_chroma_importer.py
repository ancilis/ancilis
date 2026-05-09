"""Tests for the Chroma vector store operation log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers import ChromaImporter


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _operation(**overrides: object) -> dict[str, object]:
    """Build a Chroma operation record with sensible defaults."""
    base: dict[str, object] = {
        "id": "op-default-1",
        "operation": "query",
        "collection_name": "documents",
        "tenant": "tenant-acme",
        "database": "prod-rag",
        "timestamp": "2026-05-01T12:00:00Z",
        "user_id": "user-alice",
        "embedding_function": "openai_ada_002",
        "n_results": 10,
        "where_keys": ["metadata.category"],
        "where_document_keys": [],
        "include": ["metadatas", "distances"],
        "result_count": 8,
        "documents_count": 0,
        "duration_ms": 32,
        "status": "ok",
        "request_size_bytes": 4096,
        "response_size_bytes": 16384,
    }
    base.update(overrides)
    return base


def _envelope(operations: list[dict[str, object]]) -> str:
    return json.dumps({"operations": operations})


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# Per-operation tests
# ---------------------------------------------------------------------------

def test_parse_query_success() -> None:
    """A clean query with where filter, default n_results, no embeddings → PR-04 PASS."""
    importer = ChromaImporter()
    results = importer.parse_string(_envelope([_operation()]))

    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    assert len(res.control_results) == 1
    cr = res.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_query_success"
    assert cr.evidence_data["collection_name"] == "documents"
    assert cr.evidence_data["tenant"] == "tenant-acme"
    assert cr.evidence_data["database"] == "prod-rag"
    assert cr.evidence_data["embedding_function"] == "openai_ada_002"
    assert cr.evidence_data["n_results"] == 10
    assert cr.evidence_data["result_count"] == 8
    assert cr.evidence_data["duration_ms"] == 32.0
    assert cr.evidence_data["request_size_bytes"] == 4096
    assert cr.evidence_data["response_size_bytes"] == 16384
    assert res.source_type == "chroma_import"
    assert res.action_id.startswith("chroma-")


def test_parse_add() -> None:
    """add success → PR-03 PASS (input validation context)."""
    importer = ChromaImporter()
    op = _operation(
        id="op-add-1",
        operation="add",
        n_results=None,
        result_count=None,
        documents_count=5,
        where_keys=[],
        include=[],
    )
    results = importer.parse_string(_envelope([op]))

    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    cr = res.control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_add_success"


def test_delete_marks_audit() -> None:
    """delete success → PR-05 PASS (audit-trail control)."""
    importer = ChromaImporter()
    op = _operation(
        id="op-del",
        operation="delete",
        n_results=None,
        where_keys=["metadata.id"],
        include=[],
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    cr = res.control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_delete_success"
    assert res.decision == "ALLOW"


def test_create_collection_flags() -> None:
    """create_collection / delete_collection / modify → PR-05 FLAG (schema-change governance)."""
    importer = ChromaImporter()
    operations = [
        _operation(
            id="op-create",
            operation="create_collection",
            collection_name="docs",
            n_results=None,
            where_keys=[],
            include=[],
        ),
        _operation(
            id="op-drop",
            operation="delete_collection",
            collection_name="docs",
            n_results=None,
            where_keys=[],
            include=[],
        ),
        _operation(
            id="op-mod",
            operation="modify",
            collection_name="docs",
            n_results=None,
            where_keys=[],
            include=[],
        ),
    ]
    results = importer.parse_string(_envelope(operations))

    # No cross-collection synthetic since one collection is touched.
    assert len(results) == 3
    expected = [
        "operation_create_collection",
        "operation_delete_collection",
        "operation_modify",
    ]
    for res, expected_signal in zip(results, expected, strict=True):
        cr = res.control_results[0]
        assert cr.control_id == "PR-05"
        assert cr.result == "FLAG"
        assert cr.evidence_data["signal"] == expected_signal
        assert res.decision == "FLAG"


# ---------------------------------------------------------------------------
# Error-path tests
# ---------------------------------------------------------------------------

def test_authorization_error_fails_scope() -> None:
    """status=error & error_type=AuthorizationError → PR-02 FAIL → BLOCK."""
    importer = ChromaImporter()
    op = _operation(
        id="op-authz",
        status="error",
        error_type="AuthorizationError",
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "error_status_authorization"


def test_dimension_mismatch_flags_validation() -> None:
    """status=error & error_type=DimensionMismatch → PR-03 FLAG."""
    importer = ChromaImporter()
    op = _operation(
        id="op-dim",
        operation="add",
        status="error",
        error_type="DimensionMismatch",
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    assert res.decision == "FLAG"
    cr = res.control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "error_status_dimension_mismatch"


def test_internal_error_fails() -> None:
    """status=error & error_type=InternalError → DE-01 FAIL → BLOCK."""
    importer = ChromaImporter()
    op = _operation(
        id="op-internal",
        status="error",
        error_type="InternalError",
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "error_status_internal"


# ---------------------------------------------------------------------------
# Query-quality flag tests
# ---------------------------------------------------------------------------

def test_include_embeddings_flags() -> None:
    """include containing 'embeddings' → PR-04 FLAG (raw vectors in response)."""
    importer = ChromaImporter()
    op = _operation(
        id="op-emb",
        include=["metadatas", "documents", "embeddings", "distances"],
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    signals = _signals(res)
    assert "operation_query_success" in signals
    assert "include_embeddings" in signals
    assert res.decision == "FLAG"
    emb_cr = next(c for c in res.control_results if c.evidence_data["signal"] == "include_embeddings")
    assert emb_cr.control_id == "PR-04"
    assert emb_cr.result == "FLAG"


def test_unscoped_document_fetch_flags() -> None:
    """include containing 'documents' with no where filters → PR-04 FLAG (un-scoped fetch)."""
    importer = ChromaImporter()
    op = _operation(
        id="op-unscoped",
        operation="get",
        include=["documents", "metadatas"],
        where_keys=[],
        where_document_keys=[],
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    signals = _signals(res)
    assert "include_documents_unscoped" in signals
    assert res.decision == "FLAG"
    cr = next(c for c in res.control_results if c.evidence_data["signal"] == "include_documents_unscoped")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"

    # With a where filter present, the un-scoped flag must NOT fire.
    op_scoped = _operation(
        id="op-scoped",
        operation="get",
        include=["documents", "metadatas"],
        where_keys=["metadata.tenant_id"],
        where_document_keys=[],
    )
    results_scoped = importer.parse_string(_envelope([op_scoped]))
    assert "include_documents_unscoped" not in _signals(results_scoped[0])


def test_n_results_above_threshold_flags() -> None:
    """n_results > threshold → PR-04 FLAG (over-fetch)."""
    importer = ChromaImporter(n_results_threshold=100)
    op = _operation(id="op-overfetch", n_results=2500)
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    assert "n_results_exceeded" in _signals(res)
    assert res.decision == "FLAG"
    cr = next(c for c in res.control_results if c.evidence_data["signal"] == "n_results_exceeded")
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["n_results_threshold"] == 100
    assert cr.evidence_data["n_results"] == 2500


# ---------------------------------------------------------------------------
# Deployment-shape flag tests
# ---------------------------------------------------------------------------

def test_default_tenant_database_flag() -> None:
    """tenant=default_tenant + database=default_database + user_id present → PR-02 FLAG."""
    importer = ChromaImporter()
    op = _operation(
        id="op-default",
        tenant="default_tenant",
        database="default_database",
        user_id="user-alice",
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    signals = _signals(res)
    assert "default_tenant_database" in signals
    assert res.decision == "FLAG"
    cr = next(c for c in res.control_results if c.evidence_data["signal"] == "default_tenant_database")
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"

    # No user_id → no flag (legitimate single-user local dev).
    op_no_user = _operation(
        id="op-default-nouser",
        tenant="default_tenant",
        database="default_database",
        user_id=None,
    )
    results_nouser = importer.parse_string(_envelope([op_no_user]))
    assert "default_tenant_database" not in _signals(results_nouser[0])

    # Non-default tenant → no flag.
    op_real_tenant = _operation(
        id="op-real",
        tenant="tenant-acme",
        database="default_database",
        user_id="user-alice",
    )
    results_real = importer.parse_string(_envelope([op_real_tenant]))
    assert "default_tenant_database" not in _signals(results_real[0])


def test_default_embedding_function_on_prod_flags() -> None:
    """embedding_function=default on production-looking collection → PR-03 FLAG."""
    importer = ChromaImporter()
    op = _operation(
        id="op-default-ef",
        operation="add",
        collection_name="customer_documents",
        embedding_function="default",
        where_keys=[],
        include=[],
        n_results=None,
    )
    results = importer.parse_string(_envelope([op]))

    res = results[0]
    signals = _signals(res)
    assert "default_embedding_function" in signals
    assert res.decision == "FLAG"
    cr = next(c for c in res.control_results if c.evidence_data["signal"] == "default_embedding_function")
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"

    # Test/dev/local-named collections must NOT trigger.
    for non_prod_name in ("test_collection", "dev-rag", "local_index", "demo_docs"):
        op_np = _operation(
            id=f"op-{non_prod_name}",
            operation="add",
            collection_name=non_prod_name,
            embedding_function="default",
            where_keys=[],
            include=[],
            n_results=None,
        )
        results_np = importer.parse_string(_envelope([op_np]))
        assert "default_embedding_function" not in _signals(results_np[0]), (
            f"non-prod collection {non_prod_name} should not flag"
        )

    # Explicit embedding_function on prod collection → no flag.
    op_explicit = _operation(
        id="op-explicit",
        operation="add",
        collection_name="customer_documents",
        embedding_function="openai_ada_002",
        where_keys=[],
        include=[],
        n_results=None,
    )
    results_explicit = importer.parse_string(_envelope([op_explicit]))
    assert "default_embedding_function" not in _signals(results_explicit[0])


# ---------------------------------------------------------------------------
# Cross-collection synthetic finding
# ---------------------------------------------------------------------------

def test_cross_collection_pattern_synthetic_finding() -> None:
    """Same user_id touching ≥3 collections → synthetic PR-02 FLAG record."""
    importer = ChromaImporter()
    operations = [
        _operation(id="o1", user_id="user-mallory", collection_name="customers"),
        _operation(id="o2", user_id="user-mallory", collection_name="invoices"),
        _operation(id="o3", user_id="user-mallory", collection_name="employees"),
        # Second user stays scoped to one collection — should NOT trigger.
        _operation(id="o4", user_id="user-bob", collection_name="public_docs"),
        # Third user touches only 2 collections — under default threshold of 3.
        _operation(id="o5", user_id="user-carol", collection_name="alpha"),
        _operation(id="o6", user_id="user-carol", collection_name="beta"),
    ]
    results = importer.parse_string(_envelope(operations))

    # 6 per-event + 1 synthetic = 7
    assert len(results) == 7
    synthetic = results[-1]
    assert synthetic.action_id.startswith("chroma-synthetic-")
    assert synthetic.source_type == "chroma_import_synthetic"
    cr = synthetic.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cross_collection_pattern"
    assert cr.evidence_data["user_id"] == "user-mallory"
    touched = cr.evidence_data["collections_touched"]
    assert sorted(touched) == ["customers", "employees", "invoices"]
    assert cr.evidence_data["collection_count"] == 3
    assert cr.evidence_data["operation_count"] == 3
    # carol only touched 2 collections (under threshold of 3) — not a crossing user.
    crossing = cr.evidence_data["all_crossing_users"]
    assert "user-carol" not in crossing
    assert "user-bob" not in crossing
    assert "user-mallory" in crossing


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------

def test_filter_values_never_stored() -> None:
    """Filter VALUES, document content, embedding vectors, and query text must never appear."""
    importer = ChromaImporter()
    secret_email = "alice@example.com"
    secret_pii = "S3CRET-PII-VALUE"
    secret_query = "DELETE PROD DATA NOW"
    secret_doc = "This document contains a confidential trade secret."
    secret_vector_marker = "0.999888777666"
    # The importer must look ONLY at the structural keys (where_keys,
    # where_document_keys, include) and never at any of the value fields.
    op = _operation(
        id="op-sanitize",
        # Mix list-of-keys and dict-of-keys-with-values shapes.
        where_keys={
            "metadata.email": secret_email,
            "metadata.ssn": secret_pii,
        },
        where_document_keys=["$contains"],
        include=["metadatas", "documents", "embeddings", "distances"],
        # These extra fields, even if Chroma ever exports them, must NEVER reach evidence.
        query_text=secret_query,
        documents=[secret_doc],
        embeddings=[[float(secret_vector_marker), 0.1, 0.2]],
        where={"metadata.email": secret_email},
        where_document={"$contains": secret_query},
    )
    results = importer.parse_string(_envelope([op]))

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
    for forbidden in (
        secret_email,
        secret_pii,
        secret_query,
        secret_doc,
        secret_vector_marker,
    ):
        assert forbidden not in blob, f"sanitization leak: {forbidden!r} reached evidence_data"

    # Affirmatively: the structural KEYS should appear.
    cr = results[0].control_results[0]
    assert "metadata.email" in cr.evidence_data["where_keys"]
    assert "metadata.ssn" in cr.evidence_data["where_keys"]
    assert cr.evidence_data["where_document_keys"] == ["$contains"]
    assert "embeddings" in cr.evidence_data["include"]


# ---------------------------------------------------------------------------
# Provenance & format flexibility
# ---------------------------------------------------------------------------

def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) populates source_provenance.original_file_sha256 with sha256 of file."""
    payload = _envelope([_operation(id="op-prov")])
    f = tmp_path / "chroma_audit.json"
    f.write_text(payload, encoding="utf-8")
    expected_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    importer = ChromaImporter()
    results = importer.parse(f)

    assert len(results) == 1
    prov = results[0].control_results[0].evidence_data["source_provenance"]
    assert prov["source_format"] == "chroma"
    assert prov["original_file_sha256"] == expected_sha

    # parse_string() should NOT include a hash (no file).
    string_results = importer.parse_string(payload)
    string_prov = string_results[0].control_results[0].evidence_data["source_provenance"]
    assert "original_file_sha256" not in string_prov


def test_parses_data_envelope_jsonl_and_single_object() -> None:
    """Importer accepts {operations:[]}, {data:[]}, JSONL, and a bare single object."""
    importer = ChromaImporter()
    op1 = _operation(id="o1")
    op2 = _operation(id="o2")

    # data envelope
    data_doc = json.dumps({"data": [op1, op2]})
    assert len(importer.parse_string(data_doc)) == 2

    # JSONL
    jsonl_doc = "\n".join(json.dumps(o) for o in [op1, op2])
    assert len(importer.parse_string(jsonl_doc)) == 2

    # single object (no envelope)
    single = importer.parse_string(json.dumps(op1))
    assert len(single) == 1
    assert single[0].control_results[0].evidence_data["chroma_operation_id"] == "o1"


def test_importable_without_chroma_client() -> None:
    """The importer module must not require the optional chromadb package."""
    import importlib

    mod = importlib.import_module("ancilis.importers.chroma")
    assert hasattr(mod, "ChromaImporter")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
