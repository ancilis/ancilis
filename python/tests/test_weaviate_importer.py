"""Tests for the Weaviate vector search audit log evidence importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers.weaviate import WeaviateImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Weaviate audit-log entries (no weaviate-client dependency)
# ---------------------------------------------------------------------------


def _entry(
    *,
    id: str = "log-1",
    operation: str = "Get",
    class_name: str = "Document",
    tenant: str | None = None,
    vectorizer: str = "text2vec-openai",
    user: str = "alice",
    timestamp: str = "2026-04-15T12:00:00Z",
    limit: int = 50,
    where_filter_path: list[str] | None = None,
    near_vector_present: bool = False,
    near_text_present: bool = False,
    hybrid_alpha: float | None = None,
    results_count: int = 12,
    consistency_level: str = "QUORUM",
    status_code: int = 200,
    error_message: str = "",
    duration_ms: float = 45.0,
    rbac_role: str = "viewer",
    graphql_query: str | None = None,
    operation_name: str | None = None,
    variables_keys: list[str] | None = None,
) -> dict:
    out: dict = {
        "id": id,
        "operation": operation,
        "class_name": class_name,
        "vectorizer": vectorizer,
        "user": user,
        "timestamp": timestamp,
        "limit": limit,
        "near_vector_present": near_vector_present,
        "near_text_present": near_text_present,
        "results_count": results_count,
        "consistency_level": consistency_level,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "rbac_role": rbac_role,
    }
    if tenant is not None:
        out["tenant"] = tenant
    if where_filter_path is not None:
        out["where_filter_path"] = where_filter_path
    if hybrid_alpha is not None:
        out["hybrid_alpha"] = hybrid_alpha
    if error_message:
        out["error_message"] = error_message
    if graphql_query is not None:
        out["graphql_query"] = graphql_query
    if operation_name is not None:
        out["operation_name"] = operation_name
    if variables_keys is not None:
        out["variables_keys"] = variables_keys
    return out


def _doc(*entries) -> str:
    return json.dumps({"logs": list(entries)})


# ---------------------------------------------------------------------------
# Shape parsing
# ---------------------------------------------------------------------------


def test_parse_get_success() -> None:
    """Successful Get → PR-04 PASS, decision ALLOW."""
    doc = _doc(_entry(operation="Get", where_filter_path=["category", "==", "x"]))
    results = WeaviateImporter().parse_string(doc)
    assert len(results) == 1
    er = results[0]
    assert er.source_type == "weaviate_import"
    assert er.action_id == "weaviate-log-1"
    assert er.decision == "ALLOW"
    assert len(er.control_results) == 1
    cr = er.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_get"
    # Filter path KEYS captured (operator and value are stripped).
    assert cr.evidence_data["where_filter_path_keys"] == ["category"]
    assert cr.evidence_data["where_filter_operator"] == "=="
    assert cr.evidence_data["where_filter_present"] is True


def test_parse_create_marks_pass() -> None:
    """Create → PR-03 PASS."""
    doc = _doc(_entry(operation="Create", class_name="Article", id="log-c"))
    results = WeaviateImporter().parse_string(doc)
    assert len(results) == 1
    cr_list = results[0].control_results
    assert any(cr.control_id == "PR-03" and cr.result == "PASS" for cr in cr_list)
    assert results[0].decision == "ALLOW"


def test_parse_update_marks_pass() -> None:
    """Update → PR-03 PASS."""
    doc = _doc(_entry(operation="Update", id="log-u"))
    results = WeaviateImporter().parse_string(doc)
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "PASS"


def test_delete_marks_audit() -> None:
    """Delete → PR-05 PASS (audit trail)."""
    doc = _doc(_entry(operation="Delete", id="log-d"))
    results = WeaviateImporter().parse_string(doc)
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_delete"


def test_backup_flags_privileged() -> None:
    """Backup → PR-05 FLAG (privileged op)."""
    doc = _doc(_entry(operation="Backup", id="log-b", class_name=""))
    results = WeaviateImporter().parse_string(doc)
    cr_list = results[0].control_results
    assert any(cr.control_id == "PR-05" and cr.result == "FLAG" for cr in cr_list)
    assert results[0].decision == "FLAG"


def test_restore_flags_privileged() -> None:
    """Restore → PR-05 FLAG (privileged op)."""
    doc = _doc(_entry(operation="Restore", id="log-r", class_name=""))
    results = WeaviateImporter().parse_string(doc)
    cr_list = results[0].control_results
    assert any(cr.control_id == "PR-05" and cr.result == "FLAG" for cr in cr_list)


def test_4xx_flags() -> None:
    """status_code 4xx → PR-02 FLAG, decision FLAG."""
    doc = _doc(_entry(operation="Get", status_code=403, id="log-4"))
    results = WeaviateImporter().parse_string(doc)
    er = results[0]
    assert er.decision == "FLAG"
    assert any(
        cr.control_id == "PR-02" and cr.result == "FLAG"
        and cr.evidence_data["signal"] == "status_4xx"
        for cr in er.control_results
    )


def test_5xx_fails() -> None:
    """status_code 5xx → DE-01 FAIL, decision BLOCK."""
    doc = _doc(
        _entry(
            operation="Create",
            status_code=503,
            id="log-5",
            error_message="upstream unavailable",
        )
    )
    results = WeaviateImporter().parse_string(doc)
    er = results[0]
    assert er.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01" and cr.result == "FAIL"
        for cr in er.control_results
    )


def test_limit_above_threshold_flags() -> None:
    """limit > 1000 default → PR-04 FLAG."""
    doc = _doc(
        _entry(
            operation="Get",
            limit=5000,
            tenant="acme",
            where_filter_path=["category"],
            id="log-big",
        )
    )
    results = WeaviateImporter().parse_string(doc)
    er = results[0]
    assert er.decision == "FLAG"
    assert any(
        cr.evidence_data.get("signal") == "limit_above_threshold"
        and cr.control_id == "PR-04"
        and cr.result == "FLAG"
        for cr in er.control_results
    )
    # Custom threshold via constructor.
    results2 = WeaviateImporter(limit_threshold=10).parse_string(
        _doc(_entry(operation="Get", limit=50, tenant="acme", where_filter_path=["x"]))
    )
    assert any(
        cr.evidence_data.get("signal") == "limit_above_threshold"
        for cr in results2[0].control_results
    )


def test_unscoped_query_flags() -> None:
    """Get with no where filter and no tenant → PR-04 FLAG (unscoped)."""
    doc = _doc(
        _entry(
            operation="Get",
            tenant=None,
            where_filter_path=None,
            id="log-uns",
        )
    )
    results = WeaviateImporter().parse_string(doc)
    er = results[0]
    assert er.decision == "FLAG"
    assert any(
        cr.evidence_data.get("signal") == "unscoped_query"
        and cr.control_id == "PR-04"
        for cr in er.control_results
    )
    # And: presence of either tenant OR filter path suppresses the flag.
    doc2 = _doc(
        _entry(
            operation="Get",
            tenant="t1",
            where_filter_path=None,
            id="log-scoped",
        )
    )
    results2 = WeaviateImporter().parse_string(doc2)
    assert not any(
        cr.evidence_data.get("signal") == "unscoped_query"
        for cr in results2[0].control_results
    )


def test_admin_on_read_op_flags() -> None:
    """rbac_role=admin on a read-only op → PR-02 FLAG (over-privileged)."""
    doc = _doc(
        _entry(
            operation="Get",
            rbac_role="admin",
            tenant="t1",
            where_filter_path=["x"],
            id="log-adm",
        )
    )
    results = WeaviateImporter().parse_string(doc)
    er = results[0]
    assert er.decision == "FLAG"
    assert any(
        cr.evidence_data.get("signal") == "admin_on_read_op"
        and cr.control_id == "PR-02"
        for cr in er.control_results
    )
    # Admin on a write should NOT trigger admin_on_read_op.
    doc2 = _doc(
        _entry(operation="Create", rbac_role="admin", id="log-adm-w")
    )
    results2 = WeaviateImporter().parse_string(doc2)
    assert not any(
        cr.evidence_data.get("signal") == "admin_on_read_op"
        for cr in results2[0].control_results
    )


def test_consistency_one_on_write_flags() -> None:
    """consistency_level=ONE on Create/Update → PR-03 FLAG (weak)."""
    doc = _doc(
        _entry(operation="Create", consistency_level="ONE", id="log-w1")
    )
    results = WeaviateImporter().parse_string(doc)
    assert results[0].decision == "FLAG"
    assert any(
        cr.evidence_data.get("signal") == "consistency_one_on_write"
        and cr.control_id == "PR-03"
        for cr in results[0].control_results
    )
    # ONE on Get should NOT flag.
    doc2 = _doc(
        _entry(
            operation="Get",
            consistency_level="ONE",
            tenant="t1",
            where_filter_path=["x"],
            id="log-w2",
        )
    )
    results2 = WeaviateImporter().parse_string(doc2)
    assert not any(
        cr.evidence_data.get("signal") == "consistency_one_on_write"
        for cr in results2[0].control_results
    )


def test_cross_tenant_pattern_synthetic_finding() -> None:
    """Same user touching multiple tenants → synthetic PR-02 FLAG finding."""
    doc = _doc(
        _entry(user="alice", tenant="t1", id="log-x1", where_filter_path=["x"]),
        _entry(user="alice", tenant="t2", id="log-x2", where_filter_path=["x"]),
        _entry(user="bob", tenant="t1", id="log-x3", where_filter_path=["x"]),
    )
    results = WeaviateImporter().parse_string(doc)
    # 3 per-entry results + 1 synthetic for alice (bob only touched 1 tenant).
    synthetic = [r for r in results if r.source_type == "weaviate_import_synthetic"]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    assert syn.action_id == "weaviate-cross-tenant-alice"
    assert len(syn.control_results) == 1
    cr = syn.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cross_tenant_access"
    assert cr.evidence_data["user"] == "alice"
    assert sorted(cr.evidence_data["tenants_touched"]) == ["t1", "t2"]
    assert cr.evidence_data["tenant_count"] == 2


def test_query_bodies_never_stored() -> None:
    """graphql_query bodies, where filter values, and near_vector contents must NEVER appear in evidence_data."""
    secret_query = "{ Get { Document(where: {path:[\"ssn\"], valueText:\"123-45-6789\"}) { _additional { id } } } }"
    secret_filter_value = "kevin@example.com SUPER SECRET"
    doc = _doc(
        _entry(
            operation="Get",
            tenant="t1",
            where_filter_path=["email", "==", secret_filter_value],
            graphql_query=secret_query,
            operation_name="GetByEmail",
            variables_keys=["email", "limit"],
            id="log-sec",
        )
    )
    results = WeaviateImporter().parse_string(doc)
    er = results[0]
    # Render the entire result to JSON and assert the secrets do not appear anywhere.
    blob = json.dumps(
        {
            "decision": er.decision,
            "decision_reason": er.decision_reason,
            "control_results": [
                {
                    "control_id": cr.control_id,
                    "detail": cr.detail,
                    "evidence_data": cr.evidence_data,
                }
                for cr in er.control_results
            ],
        },
        default=str,
    )
    assert secret_query not in blob
    assert "ssn" not in blob  # value-side filter token
    assert "123-45-6789" not in blob
    assert "kevin@example.com" not in blob
    # Structural metadata IS captured.
    cr = er.control_results[0]
    assert cr.evidence_data["graphql_query_present"] is True
    assert cr.evidence_data["graphql_operation_name"] == "GetByEmail"
    assert cr.evidence_data["graphql_variable_keys"] == ["email", "limit"]


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) records sha256 of the original file in source_provenance."""
    payload = _doc(_entry(operation="Get", tenant="t1", where_filter_path=["x"]))
    f = tmp_path / "weaviate.json"
    f.write_text(payload)
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    results = WeaviateImporter().parse(f)
    assert len(results) >= 1
    cr = results[0].control_results[0]
    prov = cr.evidence_data["source_provenance"]
    assert prov["original_file_sha256"] == expected
    assert prov["source_format"] == "weaviate"
    assert prov["source_tool_name"] == "weaviate"
    # parse_string omits file hash.
    results2 = WeaviateImporter().parse_string(payload)
    prov2 = results2[0].control_results[0].evidence_data["source_provenance"]
    assert "original_file_sha256" not in prov2


def test_jsonl_and_data_envelope_shapes() -> None:
    """Importer accepts {logs: [...]}, {data: [...]}, and JSONL."""
    e1 = _entry(id="log-jsonl-1", tenant="t1", where_filter_path=["x"])
    e2 = _entry(id="log-jsonl-2", tenant="t1", where_filter_path=["x"])
    # JSONL
    jsonl = "\n".join([json.dumps(e1), json.dumps(e2)])
    r1 = WeaviateImporter().parse_string(jsonl)
    assert len(r1) == 2
    assert {r.action_id for r in r1} == {"weaviate-log-jsonl-1", "weaviate-log-jsonl-2"}
    # {"data": [...]}
    r2 = WeaviateImporter().parse_string(json.dumps({"data": [e1, e2]}))
    assert len(r2) == 2
    # Bare list
    r3 = WeaviateImporter().parse_string(json.dumps([e1, e2]))
    assert len(r3) == 2


def test_missing_mapping_file_uses_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importer remains functional even if mapping JSON cannot be loaded."""
    # Force the loader to return an empty mapping.
    from ancilis.importers import weaviate as wmod

    monkeypatch.setattr(wmod, "_load_mapping_table", lambda: {})
    importer = wmod.WeaviateImporter()
    doc = _doc(_entry(operation="Get", tenant="t1", where_filter_path=["x"]))
    results = importer.parse_string(doc)
    assert results[0].control_results[0].control_id == "PR-04"
    assert importer.limit_threshold == 1000
