"""Tests for the Milvus distributed vector database access-log importer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ancilis.importers import MilvusImporter


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _event(**overrides: object) -> dict[str, object]:
    """Build a Milvus access-log event with sensible defaults."""
    base: dict[str, object] = {
        "id": "evt-default-1",
        "timestamp": "2026-05-01T12:00:00Z",
        "user": "agent-svc",
        "role": "db_rw",
        "operation": "Search",
        "collection_name": "documents",
        "partition_names": ["partition_2026"],
        "consistency_level": "Bounded",
        "limit": 10,
        "expr_present": True,
        "search_params": {"metric_type": "L2", "params": {"nprobe": 10}},
        "topk": 10,
        "output_fields_count": 3,
        "with_payload": False,
        "result_count": 8,
        "request_id": "req-1",
        "duration_ms": 12,
        "status": {"code": 0, "reason": ""},
        "client_ip": "10.0.0.1",
        "user_agent": "milvus-py/2.5.0",
        "trace_id": "trace-1",
        "rbac_action": None,
        "is_admin": False,
        "is_root": False,
    }
    base.update(overrides)
    return base


def _envelope(events: list[dict[str, object]]) -> str:
    return json.dumps({"events": events})


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# Per-operation tests
# ---------------------------------------------------------------------------


def test_search_success() -> None:
    """Clean Search with filter, default limit, payload off → PR-04 PASS."""
    importer = MilvusImporter()
    results = importer.parse_string(_envelope([_event()]))

    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    assert len(res.control_results) == 1
    cr = res.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_search_success"
    assert cr.evidence_data["collection_name"] == "documents"
    assert cr.evidence_data["topk"] == 10
    assert cr.evidence_data["output_fields_count"] == 3
    assert cr.evidence_data["result_count"] == 8
    assert cr.evidence_data["search_params"]["metric_type"] == "L2"
    assert res.source_type == "milvus_import"
    assert res.action_id.startswith("milvus-")


def test_insert_success() -> None:
    """Insert success → PR-03 PASS (provenance)."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-insert",
        operation="Insert",
        consistency_level="Strong",
        limit=None,
        expr_present=None,
        with_payload=None,
        topk=None,
    )
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    assert res.decision == "ALLOW"
    cr = res.control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_insert_success"


def test_delete_audit() -> None:
    """Delete success → PR-05 PASS (audit-trail control)."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-del",
        operation="Delete",
        limit=None,
        expr_present=True,
        with_payload=None,
    )
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    cr = res.control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "operation_delete_success"
    assert res.decision == "ALLOW"


def test_collection_lifecycle_flags() -> None:
    """Schema-lifecycle ops → PR-05 FLAG."""
    importer = MilvusImporter()
    events = [
        _event(
            id="evt-create",
            operation="CreateCollection",
            collection_name="docs",
            limit=None,
            expr_present=None,
            with_payload=None,
        ),
        _event(
            id="evt-drop",
            operation="DropCollection",
            collection_name="docs",
            limit=None,
            expr_present=None,
            with_payload=None,
        ),
        _event(
            id="evt-alter",
            operation="AlterCollection",
            collection_name="docs",
            limit=None,
            expr_present=None,
            with_payload=None,
        ),
        _event(
            id="evt-cidx",
            operation="CreateIndex",
            collection_name="docs",
            limit=None,
            expr_present=None,
            with_payload=None,
        ),
        _event(
            id="evt-didx",
            operation="DropIndex",
            collection_name="docs",
            limit=None,
            expr_present=None,
            with_payload=None,
        ),
    ]
    results = importer.parse_string(_envelope(events))
    expected = [
        "operation_create_collection",
        "operation_drop_collection",
        "operation_alter_collection",
        "operation_create_index",
        "operation_drop_index",
    ]
    # Five events, no synthetic finding (one collection only).
    assert len(results) == 5
    for res, expected_signal in zip(results, expected, strict=True):
        cr = res.control_results[0]
        assert cr.control_id == "PR-05"
        assert cr.result == "FLAG"
        assert cr.evidence_data["signal"] == expected_signal
        assert res.decision == "FLAG"


def test_rbac_change_flags() -> None:
    """Routine RBAC change → PR-02 FLAG (not FAIL)."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-rbac",
        operation="CreateRole",
        target_role="db_ro",
        limit=None,
        expr_present=None,
        with_payload=None,
    )
    results = importer.parse_string(_envelope([ev]))

    res = results[0]
    cr = res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "rbac_change"
    assert res.decision == "FLAG"


def test_admin_grant_fails() -> None:
    """GrantPrivilege targeting admin/root role → PR-02 FAIL → BLOCK."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-grant-admin",
        operation="GrantPrivilege",
        user="security-admin",
        target_user="some-svc",
        target_role="db_admin",
        limit=None,
        expr_present=None,
        with_payload=None,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "admin_grant"


def test_admin_drop_fails() -> None:
    """DropUser whose target had admin role → PR-02 FAIL."""
    importer = MilvusImporter()
    events = [
        # First event establishes that admin-user has db_admin role.
        _event(
            id="evt-admin-action",
            operation="Search",
            user="admin-user",
            role="db_admin",
            is_admin=True,
        ),
        # Second event drops that admin user.
        _event(
            id="evt-drop-admin",
            operation="DropUser",
            user="security-svc",
            target_user="admin-user",
            limit=None,
            expr_present=None,
            with_payload=None,
        ),
    ]
    results = importer.parse_string(_envelope(events))
    drop_res = results[1]
    assert drop_res.decision == "BLOCK"
    cr = drop_res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "admin_drop"


def test_permission_denied_fails() -> None:
    """status.code=2 → PR-02 FAIL."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-denied",
        operation="Search",
        status={"code": 2, "reason": "permission denied"},
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "permission_denied"


def test_unauthenticated_fails() -> None:
    """status.code=1 → PR-01 FAIL."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-unauth",
        operation="Search",
        status={"code": 1, "reason": "missing credentials"},
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.evidence_data["signal"] == "unauthenticated"


def test_root_usage_fails() -> None:
    """is_root=true on routine ops → PR-01 FAIL → BLOCK."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-root-search",
        operation="Search",
        user="root",
        role="root",
        is_admin=True,
        is_root=True,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "BLOCK"
    signals = _signals(res)
    assert "root_user_routine_op" in signals
    fails = [cr for cr in res.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "PR-01"
        and cr.evidence_data["signal"] == "root_user_routine_op"
        for cr in fails
    )


def test_admin_on_read_op_flags() -> None:
    """is_admin=true on Search → PR-02 FLAG (over-privileged)."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-admin-read",
        operation="Search",
        user="admin-svc",
        role="db_admin",
        is_admin=True,
        is_root=False,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "FLAG"
    signals = _signals(res)
    assert "admin_on_read_op" in signals


def test_search_overfetch_flags() -> None:
    """Search limit > threshold → PR-04 FLAG."""
    importer = MilvusImporter(over_fetch_threshold=100)
    ev = _event(
        id="evt-overfetch",
        operation="Search",
        limit=10_000,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "FLAG"
    signals = _signals(res)
    assert "search_overfetch" in signals
    flag_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data["signal"] == "search_overfetch"
    )
    assert flag_cr.evidence_data["over_fetch_threshold"] == 100


def test_unscoped_search_flags() -> None:
    """Search with expr_present=false → PR-04 FLAG."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-unscoped",
        operation="Search",
        expr_present=False,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "FLAG"
    assert "search_unscoped" in _signals(res)


def test_with_payload_search_flags() -> None:
    """Search with with_payload=true → PR-04 FLAG (payload retrieval)."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-payload",
        operation="Search",
        with_payload=True,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "FLAG"
    assert "search_with_payload" in _signals(res)


def test_eventually_consistency_on_insert_flags() -> None:
    """Insert with consistency_level=Eventually → PR-03 FLAG."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-eventually",
        operation="Insert",
        consistency_level="Eventually",
        limit=None,
        expr_present=None,
        with_payload=None,
        topk=None,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    assert res.decision == "FLAG"
    signals = _signals(res)
    assert "insert_eventual_consistency" in signals
    consistency_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data["signal"] == "insert_eventual_consistency"
    )
    assert consistency_cr.control_id == "PR-03"


def test_cross_collection_pattern_synthetic() -> None:
    """User touching > N distinct collections → synthetic PR-02 FLAG."""
    importer = MilvusImporter(cross_collection_threshold=3)
    events: list[dict[str, object]] = []
    for i, name in enumerate(["c1", "c2", "c3", "c4", "c5"]):
        events.append(
            _event(
                id=f"evt-{i}",
                operation="Search",
                user="busy-agent",
                collection_name=name,
            )
        )
    results = importer.parse_string(_envelope(events))
    # 5 per-event + 1 synthetic.
    assert len(results) == 6
    synthetic = results[-1]
    assert synthetic.source_type == "milvus_import_synthetic"
    cr = synthetic.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cross_collection_pattern"
    assert cr.evidence_data["collection_count"] == 5
    assert cr.evidence_data["user"] == "busy-agent"


def test_privilege_grant_burst_synthetic() -> None:
    """> N GrantPrivilege ops within window → synthetic PR-02 FLAG."""
    importer = MilvusImporter(
        privilege_grant_burst_threshold=3,
        privilege_grant_burst_window_seconds=3600,
    )
    base = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    events: list[dict[str, object]] = []
    for i in range(5):
        ts = (base + timedelta(minutes=i * 5)).isoformat()
        events.append(
            _event(
                id=f"evt-grant-{i}",
                operation="GrantPrivilege",
                timestamp=ts,
                user="rotator-bot",
                target_role="db_ro",
                target_user=f"svc-{i}",
                limit=None,
                expr_present=None,
                with_payload=None,
            )
        )
    results = importer.parse_string(_envelope(events))
    # 5 per-event + 1 synthetic.
    assert len(results) == 6
    synthetic = results[-1]
    assert synthetic.source_type == "milvus_import_synthetic"
    cr = synthetic.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["signal"] == "privilege_grant_burst"
    assert cr.evidence_data["burst_count"] == 5
    assert "rotator-bot" in cr.evidence_data["actors_in_window"]


# ---------------------------------------------------------------------------
# Sanitization tests — these are non-negotiable.
# ---------------------------------------------------------------------------


def test_partition_names_count_only_stored() -> None:
    """Partition names raw must NEVER be persisted — only the count is captured."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-tenant",
        operation="Search",
        # Names that look tenant-encoded — must not survive into evidence.
        partition_names=[
            "tenant_acme_corp",
            "tenant_globex",
            "tenant_initech",
        ],
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    cr = res.control_results[0]
    evidence = cr.evidence_data
    assert evidence["partition_names_count"] == 3
    # Raw names must not appear under any key.
    serialized = json.dumps(evidence)
    assert "tenant_acme_corp" not in serialized
    assert "tenant_globex" not in serialized
    assert "tenant_initech" not in serialized
    assert "partition_names" not in evidence


def test_output_fields_count_only_stored() -> None:
    """Output field NAMES must never be written; only output_fields_count is captured."""
    importer = MilvusImporter()
    ev = _event(
        id="evt-fields",
        operation="Search",
        # Even if a Milvus exporter foolishly includes names, we must not emit them.
        output_fields=["ssn_embedding", "passport_doc", "card_number"],
        output_fields_count=3,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    cr = res.control_results[0]
    serialized = json.dumps(cr.evidence_data)
    assert cr.evidence_data["output_fields_count"] == 3
    # No semantically loaded field names anywhere in the evidence blob.
    assert "ssn_embedding" not in serialized
    assert "passport_doc" not in serialized
    assert "card_number" not in serialized


def test_expr_value_never_stored() -> None:
    """Even if an exporter mis-emits the expression body, we must drop it."""
    importer = MilvusImporter()
    secret_expr = "user_id == 'kevin@example.com' && ssn == '123-45-6789'"
    ev = _event(
        id="evt-expr",
        operation="Search",
        expr=secret_expr,  # We never read this — only expr_present.
        expr_present=True,
    )
    results = importer.parse_string(_envelope([ev]))
    res = results[0]
    serialized = json.dumps(res.control_results[0].evidence_data)
    assert "kevin@example.com" not in serialized
    assert "123-45-6789" not in serialized
    assert "ssn" not in serialized
    # But the boolean flag IS captured.
    assert res.control_results[0].evidence_data["expr_present"] is True


# ---------------------------------------------------------------------------
# Sanitization tests — IP and user_agent.
# ---------------------------------------------------------------------------


def test_client_ip_masked_to_slash_16() -> None:
    """IPv4 client_ip must be masked to /16."""
    importer = MilvusImporter()
    ev = _event(operation="Search", client_ip="10.20.30.40")
    results = importer.parse_string(_envelope([ev]))
    masked = results[0].control_results[0].evidence_data["client_ip_masked"]
    assert masked == "10.20.0.0"


def test_user_agent_capsule_truncated_and_hashed() -> None:
    """User-Agent must be retained as first-80-chars + sha256, never raw verbatim."""
    importer = MilvusImporter()
    long_ua = "milvus-py/2.5.0 (" + "x" * 200 + ")"
    ev = _event(operation="Search", user_agent=long_ua)
    results = importer.parse_string(_envelope([ev]))
    capsule = results[0].control_results[0].evidence_data["user_agent"]
    assert capsule is not None
    assert len(capsule["prefix"]) == 80
    assert capsule["sha256"] == hashlib.sha256(long_ua.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Format-shape & file-hash tests
# ---------------------------------------------------------------------------


def test_jsonl_shape() -> None:
    importer = MilvusImporter()
    payload = "\n".join(
        json.dumps(_event(id=f"evt-{i}", operation="Search"))
        for i in range(3)
    )
    results = importer.parse_string(payload)
    assert len(results) == 3
    for res in results:
        assert res.source_type == "milvus_import"


def test_data_envelope_shape() -> None:
    importer = MilvusImporter()
    payload = json.dumps({"data": [_event(id="evt-data-1")]})
    results = importer.parse_string(payload)
    assert len(results) == 1


def test_single_event_shape() -> None:
    importer = MilvusImporter()
    payload = json.dumps(_event(id="evt-single"))
    results = importer.parse_string(payload)
    assert len(results) == 1


def test_file_sha256_is_recorded(tmp_path: Path) -> None:
    """parse() must record the file's sha256 in source_provenance."""
    importer = MilvusImporter()
    payload = _envelope([_event(id="evt-file")])
    file_path = tmp_path / "milvus.json"
    file_path.write_text(payload)
    expected_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    results = importer.parse(file_path)
    assert len(results) == 1
    provenance = results[0].control_results[0].evidence_data["source_provenance"]
    assert provenance["original_file_sha256"] == expected_sha
    assert provenance["source_format"] == "milvus"


def test_search_params_only_structural_shape() -> None:
    """search_params.params values must not survive — only metric_type + key names."""
    importer = MilvusImporter()
    ev = _event(
        operation="Search",
        # Tunable values can hint at index / data shape — drop them.
        search_params={
            "metric_type": "COSINE",
            "params": {"nprobe": 4242, "ef": 8888, "secret_seed": "leakme"},
        },
    )
    results = importer.parse_string(_envelope([ev]))
    sp = results[0].control_results[0].evidence_data["search_params"]
    assert sp["metric_type"] == "COSINE"
    assert sorted(sp["param_keys"]) == ["ef", "nprobe", "secret_seed"]
    assert sp["param_key_count"] == 3
    serialized = json.dumps(sp)
    assert "4242" not in serialized
    assert "8888" not in serialized
    assert "leakme" not in serialized


def test_importer_works_without_pymilvus_installed() -> None:
    """The importer must be importable with no optional client deps present."""
    with pytest.MonkeyPatch.context() as mp:
        # Simulate pymilvus not being installed by removing it from sys.modules
        # (it is not in the SDK deps anyway, but assert defensively).
        import sys
        mp.delitem(sys.modules, "pymilvus", raising=False)
        from ancilis.importers import MilvusImporter as _Reimport
        assert _Reimport is MilvusImporter
