"""Tests for the MongoDB Atlas audit-event importer."""

from __future__ import annotations

import json

from ancilis.importers.mongodb_atlas import MongoDBAtlasImporter


# ---------------------------------------------------------------------------
# Fixture builder
# ---------------------------------------------------------------------------


def _event(
    *,
    atype: str = "find",
    ts: str = "2026-04-01T12:00:00+00:00",
    result: int = 0,
    ns: str = "prod_app.transactions",
    command: str | None = None,
    filter_keys: list[str] | None = None,
    doc_count: int = 0,
    users: list[dict] | None = None,
    roles: list[dict] | None = None,
    roles_granted: list[dict] | None = None,
    roles_revoked: list[dict] | None = None,
    privileges: list[dict] | None = None,
    local_ip: str = "10.0.0.1",
    remote_ip: str = "203.0.113.50",
    session_id: str = "abcdef0123456789sessabc",
    tls_used: bool = True,
    tls_protocol: str = "TLSv1.3",
    is_atlas_admin_action: bool = False,
    cluster_name: str = "prod-cluster",
    project_id: str = "proj-1",
    org_id: str = "org-1",
    version: str = "7.0",
    is_replica_set: bool = True,
    is_sharded: bool = False,
) -> dict:
    param: dict = {"ns": ns}
    if command is not None:
        param["command"] = command
    if filter_keys is not None:
        param["filter_keys"] = filter_keys
    if doc_count:
        param["doc_count"] = doc_count
    if roles_granted is not None:
        param["rolesGranted"] = roles_granted
    if roles_revoked is not None:
        param["rolesRevoked"] = roles_revoked
    if privileges is not None:
        param["privileges"] = privileges
    return {
        "atype": atype,
        "ts": ts,
        "local": {"ip": local_ip, "port": 27017},
        "remote": {"ip": remote_ip, "port": 50000},
        "users": users if users is not None else [
            {"user": "agent_svc", "db": "prod_app"}
        ],
        "roles": roles if roles is not None else [
            {"role": "readWrite", "db": "prod_app"}
        ],
        "param": param,
        "result": result,
        "atlas_event_data": {
            "cluster_name": cluster_name,
            "project_id": project_id,
            "org_id": org_id,
            "version": version,
            "is_replica_set": is_replica_set,
            "is_sharded": is_sharded,
        },
        "tls_used": tls_used,
        "tls_protocol": tls_protocol,
        "session_id": session_id,
        "is_atlas_admin_action": is_atlas_admin_action,
    }


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# 1. find on a non-sensitive ns → PR-04 PASS
# ---------------------------------------------------------------------------


def test_find_passes() -> None:
    doc = json.dumps({"events": [_event(atype="find", ns="prod_app.orders")]})
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "ns_read" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "ns_read")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 2. find on sensitive namespace + filter_keys → PR-04 FLAG
# ---------------------------------------------------------------------------


def test_sensitive_namespace_find_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="find",
                    ns="prod_app.customers",
                    filter_keys=["customer_id"],
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "ns_read_sensitive" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "ns_read_sensitive"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"
    # Full ns must NOT appear — only redacted bucket.
    assert cr.evidence_data["ns_redacted"] == "ns_sensitivity:high"


# ---------------------------------------------------------------------------
# 3. find on sensitive namespace WITHOUT filter_keys → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_unscoped_sensitive_find_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="find",
                    ns="prod_app.embeddings",
                    filter_keys=[],  # un-scoped full-collection scan
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "ns_read_unscoped_sensitive" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "ns_read_unscoped_sensitive"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 4. remove with doc_count > threshold → PR-02 FLAG
# ---------------------------------------------------------------------------


def test_mass_remove_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="remove",
                    ns="prod_app.events",
                    doc_count=5000,
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "ns_delete_mass" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "ns_delete_mass"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["doc_count"] == 5000


# ---------------------------------------------------------------------------
# 5. remove on sensitive namespace → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_sensitive_remove_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(atype="remove", ns="prod_app.users", doc_count=1)
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "ns_delete_sensitive" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "ns_delete_sensitive"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 6. dropCollection → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_drop_collection_fails() -> None:
    doc = json.dumps(
        {"events": [_event(atype="dropCollection", ns="prod_app.legacy")]}
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "schema_destruction" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "schema_destruction"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 7. grantRolesToUser with admin role → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_grant_admin_role_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="grantRolesToUser",
                    ns="admin.$cmd",
                    roles_granted=[{"role": "userAdminAnyDatabase", "db": "admin"}],
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "role_grant_admin" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "role_grant_admin"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"
    assert "userAdminAnyDatabase" in cr.evidence_data["granted_roles"]


# ---------------------------------------------------------------------------
# 8. dropAllUsersFromDatabase → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_drop_all_users_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(atype="dropAllUsersFromDatabase", ns="prod_app.$cmd")
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "mass_user_removal" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "mass_user_removal"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 9. createRole / updateRole over-broad → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_overbroad_role_creation_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="createRole",
                    ns="admin.$cmd",
                    privileges=[
                        {
                            "resource": {"anyResource": True},
                            "actions": ["find", "insert"],
                        }
                    ],
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "role_overbroad" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "role_overbroad"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 10. command param.command=eval → PR-03 FAIL (server-side eval)
# ---------------------------------------------------------------------------


def test_eval_command_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="command",
                    ns="prod_app.$cmd",
                    command="eval",
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "command_eval" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "command_eval"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-03"


# ---------------------------------------------------------------------------
# 11. tls_used=false → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_unencrypted_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="find",
                    ns="prod_app.orders",
                    tls_used=False,
                    tls_protocol="",
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "tls_disabled" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "tls_disabled"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 12. admin db user reading non-admin namespace → PR-02 FLAG
# ---------------------------------------------------------------------------


def test_admin_user_on_app_data_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="find",
                    ns="prod_app.orders",
                    users=[{"user": "root_user", "db": "admin"}],
                    filter_keys=["order_id"],
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "admin_user_on_app_data" in _signals(r)
    cr = next(
        c for c in r.control_results
        if c.evidence_data.get("signal") == "admin_user_on_app_data"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 13. Failed-auth burst synthetic finding
# ---------------------------------------------------------------------------


def test_failed_auth_burst_synthetic() -> None:
    events = []
    for i in range(12):
        events.append(
            _event(
                atype="authenticate",
                result=18,
                remote_ip="8.8.4.4",
                ts=f"2026-04-01T12:{i:02d}:00+00:00",
                users=[{"user": "attacker", "db": "admin"}],
                ns="admin.$cmd",
            )
        )
    doc = json.dumps({"events": events})
    results = MongoDBAtlasImporter().parse_string(doc)
    synthetics = [
        r for r in results
        if any(
            cr.evidence_data.get("signal") == "failed_auth_burst"
            for cr in r.control_results
        )
    ]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-01"
    assert cr.evidence_data["failed_auth_count"] >= 12
    # Source IP must be masked, not raw.
    assert cr.evidence_data["remote_ip_masked"] == "8.8.0.0/16"


# ---------------------------------------------------------------------------
# 14. Mass-sensitive-read synthetic finding
# ---------------------------------------------------------------------------


def test_mass_sensitive_read_synthetic() -> None:
    # Use small thresholds for the test.
    importer = MongoDBAtlasImporter(
        high_volume_sensitive_read_threshold=3,
        high_volume_sensitive_read_window_seconds=3600,
    )
    events = []
    for i in range(6):
        events.append(
            _event(
                atype="find",
                ns="prod_app.customers",
                filter_keys=["customer_id"],
                ts=f"2026-04-01T12:{i:02d}:00+00:00",
                users=[{"user": "agent_svc", "db": "prod_app"}],
            )
        )
    doc = json.dumps({"events": events})
    results = importer.parse_string(doc)
    synthetics = [
        r for r in results
        if r.action_id.startswith("mongodb-atlas-mass-sensitive-read-")
    ]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["high_volume_count"] >= 6


# ---------------------------------------------------------------------------
# 15. Privacy: param.args is NEVER stored in evidence
# ---------------------------------------------------------------------------


def test_query_args_never_stored() -> None:
    raw_event = _event(
        atype="find",
        ns="prod_app.customers",
        filter_keys=["customer_id"],
    )
    raw_event["param"]["args"] = {
        "filter": {"email": "leaky@example.com", "ssn": "123-45-6789"},
        "projection": {"_id": 1},
    }
    doc = json.dumps({"events": [raw_event]})
    [r] = MongoDBAtlasImporter().parse_string(doc)
    # Recursively check no evidence_data carries 'args' or any of the leak markers.
    for cr in r.control_results:
        blob = json.dumps(cr.evidence_data)
        assert "args" not in cr.evidence_data
        assert "leaky@example.com" not in blob
        assert "123-45-6789" not in blob


# ---------------------------------------------------------------------------
# 16. Privacy: IPs are masked, not raw
# ---------------------------------------------------------------------------


def test_ip_redacted() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    atype="find",
                    ns="prod_app.orders",
                    remote_ip="8.8.8.8",
                    local_ip="1.1.1.1",
                )
            ]
        }
    )
    [r] = MongoDBAtlasImporter().parse_string(doc)
    cr = r.control_results[0]
    assert cr.evidence_data["remote_ip_masked"] == "8.8.0.0/16"
    assert cr.evidence_data["local_ip_masked"] == "1.1.0.0/16"
    blob = json.dumps(cr.evidence_data)
    # Raw octets must not leak.
    assert "8.8.8.8" not in blob
    assert "1.1.1.1" not in blob
