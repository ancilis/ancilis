"""Tests for DuckDB tenant scoping in the Python SDK evidence store (ANC-212)."""

from __future__ import annotations

import os
import tempfile
import uuid

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config() -> ResolvedConfig:
    return load_config(raw={"agent": {"name": "test-agent"}})


def make_evaluation(
    decision: str = "ALLOW",
    session_id: str | None = None,
    timestamp: str = "2025-01-15T10:00:00Z",
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        action_id="action-001",
        timestamp=timestamp,
        agent_id="test-agent",
        mode="audit",
        session_id=session_id,
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="ok",
                evidence_data={},
                duration_ms=1.0,
            )
        ],
        decision=decision,
        decision_reason="ok",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=2.0,
    )


def make_temp_db() -> str:
    """Create a temp path for DuckDB (file must not exist — DuckDB creates it)."""
    fd, path = tempfile.mkstemp(suffix=".duckdb")
    os.close(fd)
    os.unlink(path)
    return path


# ---------------------------------------------------------------------------
# 1. Tenant scoped store — cross-tenant isolation
# ---------------------------------------------------------------------------


class TestTenantScopedStore:
    def test_tenant_a_records_not_visible_to_tenant_b(self):
        config = make_config()
        db = make_temp_db()
        try:
            sa = EvidenceStore(config, db_path=db, tenant_id="tenant-a")
            sb = EvidenceStore(config, db_path=db, tenant_id="tenant-b")

            for _ in range(3):
                sa.store(make_evaluation(decision="ALLOW"), tool_name="tool-a")
            for _ in range(2):
                sb.store(make_evaluation(decision="BLOCK"), tool_name="tool-b")

            assert sa.count() == 3
            assert sb.count() == 2

            records_a = sa.get_records()
            records_b = sb.get_records()

            assert all(r.tool_name == "tool-a" for r in records_a)
            assert all(r.tool_name == "tool-b" for r in records_b)

            sa.close()
            sb.close()
        finally:
            if os.path.exists(db):
                os.unlink(db)

    def test_no_tenant_sees_all_records(self):
        config = make_config()
        db = make_temp_db()
        try:
            sa = EvidenceStore(config, db_path=db, tenant_id="tenant-a")
            sb = EvidenceStore(config, db_path=db, tenant_id="tenant-b")
            s_all = EvidenceStore(config, db_path=db)  # no tenant filter

            sa.store(make_evaluation(), tool_name="tool-a")
            sb.store(make_evaluation(), tool_name="tool-b")

            # no-tenant store sees both
            assert s_all.count() == 2
            assert sa.count() == 1
            assert sb.count() == 1

            sa.close()
            sb.close()
            s_all.close()
        finally:
            if os.path.exists(db):
                os.unlink(db)

    def test_tenant_id_stored_in_record(self):
        config = make_config()
        db = make_temp_db()
        try:
            store = EvidenceStore(config, db_path=db, tenant_id="acme-corp")
            store.store(make_evaluation(), tool_name="tool")

            records = store.get_records()
            assert len(records) == 1
            assert records[0].tenant_id == "acme-corp"

            store.close()
        finally:
            if os.path.exists(db):
                os.unlink(db)


# ---------------------------------------------------------------------------
# 2. Hash chain independence per tenant
# ---------------------------------------------------------------------------


class TestTenantHashChainIndependent:
    def test_hash_chains_valid_independently(self):
        config = make_config()
        db = make_temp_db()
        try:
            sa = EvidenceStore(config, db_path=db, tenant_id="tenant-a")
            sb = EvidenceStore(config, db_path=db, tenant_id="tenant-b")

            for _ in range(5):
                sa.store(make_evaluation(), tool_name="tool")
            for _ in range(3):
                sb.store(make_evaluation(), tool_name="tool")

            valid_a, errors_a = sa.verify_chain()
            valid_b, errors_b = sb.verify_chain()

            assert valid_a, f"Tenant A chain invalid: {errors_a}"
            assert valid_b, f"Tenant B chain invalid: {errors_b}"

            sa.close()
            sb.close()
        finally:
            if os.path.exists(db):
                os.unlink(db)

    def test_tenant_hash_differs_from_no_tenant_hash(self):
        """Records with different tenant_ids produce different hashes."""
        config = make_config()
        db_a = make_temp_db()
        db_b = make_temp_db()
        try:
            # same evaluation stored in two stores: one tenanted, one not
            evaluation = make_evaluation()
            store_tenanted = EvidenceStore(config, db_path=db_a, tenant_id="corp-x")
            store_plain = EvidenceStore(config, db_path=db_b)

            store_tenanted.store(evaluation, tool_name="tool")
            store_plain.store(evaluation, tool_name="tool")

            rec_tenanted = store_tenanted.get_records()[0]
            rec_plain = store_plain.get_records()[0]

            # hash inputs differ because tenant_id is included
            assert rec_tenanted.record_hash != rec_plain.record_hash

            store_tenanted.close()
            store_plain.close()
        finally:
            for p in (db_a, db_b):
                if os.path.exists(p):
                    os.unlink(p)


# ---------------------------------------------------------------------------
# 3. Backward compatibility — no tenant_id = original behavior
# ---------------------------------------------------------------------------


class TestNoTenantBackwardCompatible:
    def test_no_tenant_store_and_query_unchanged(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        for _ in range(4):
            store.store(make_evaluation(decision="ALLOW"), tool_name="tool")

        assert store.count() == 4
        summary = store.get_summary()
        assert summary["total_evaluations"] == 4
        assert summary["decisions"]["ALLOW"] == 4

        valid, errors = store.verify_chain()
        assert valid, f"Chain invalid: {errors}"

        store.close()

    def test_schema_migration_adds_tenant_column(self):
        """Opening an existing store without tenant_id column triggers migration."""
        import duckdb
        config = make_config()
        db = make_temp_db()
        try:
            # Create table without tenant_id column (pre-migration schema)
            conn = duckdb.connect(db)
            conn.execute("CREATE SEQUENCE IF NOT EXISTS evidence_seq START 1")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_records (
                    seq_id BIGINT DEFAULT nextval('evidence_seq'),
                    record_id VARCHAR NOT NULL,
                    evaluation_id VARCHAR NOT NULL,
                    timestamp VARCHAR NOT NULL,
                    agent_id VARCHAR NOT NULL,
                    tool_name VARCHAR,
                    source_type VARCHAR NOT NULL,
                    action_id VARCHAR,
                    mode VARCHAR NOT NULL,
                    session_id VARCHAR,
                    decision VARCHAR NOT NULL,
                    decision_reason VARCHAR,
                    active_overlays VARCHAR,
                    data_classifications VARCHAR,
                    active_certifications VARCHAR,
                    control_results VARCHAR,
                    record_hash VARCHAR NOT NULL,
                    previous_hash VARCHAR NOT NULL,
                    total_duration_ms FLOAT,
                    output_summary VARCHAR
                )
            """)
            conn.close()

            # Opening with EvidenceStore should trigger migration
            store = EvidenceStore(config, db_path=db)
            store.store(make_evaluation(), tool_name="tool")

            records = store.get_records()
            assert len(records) == 1
            # tenant_id defaults to None on migrated schema
            assert records[0].tenant_id is None

            store.close()
        finally:
            if os.path.exists(db):
                os.unlink(db)
