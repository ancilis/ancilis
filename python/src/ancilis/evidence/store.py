"""DuckDB-backed evidence store with hash chain integrity."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import duckdb

if TYPE_CHECKING:
    from ancilis.baselines.models import DriftReport

from ancilis.aksi.version import AKSI_FRAMEWORK_VERSION
from ancilis.config import ResolvedConfig
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.adapter import EvidenceAdapter, EvidenceAdapterPayload
from ancilis.evidence.chain import (
    CHAIN_FORMAT_V1,
    CHAIN_FORMAT_V2,
    GENESIS_SEED,
    canonical_payload,
    compute_hash,
    compute_keyed_hash,
    resolve_chain_key,
)
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.sync_state import (
    SYNC_STATUS_FAILED,
    SYNC_STATUS_PENDING,
    SYNC_STATUS_SYNCED,
    EvidenceSyncState,
    EvidenceSyncSummary,
)

logger = logging.getLogger("ancilis.evidence")

DEFAULT_DB_DIR = Path.home() / ".ancilis"
DEFAULT_DB_NAME = "evidence.duckdb"

_UNSET = object()


@dataclass
class ChainVerificationReport:
    """Structured result of an evidence-chain verification.

    ``valid`` is True only when no tampering, broken links, or missing-key
    conditions were found. Legacy (v1, pre-keyed) records that are structurally
    intact are reported as ``legacy_unverified_count`` — never silently counted
    as cryptographically verified, and never treated as a failure that would
    invalidate retained data. ``status`` summarizes the chain:
    verified | legacy-unverified | mixed | broken | empty | reset-or-purged.
    """

    valid: bool
    errors: list[str]
    verified_count: int
    legacy_unverified_count: int
    reset_events: int
    purge_events: int
    status: str


def _normalize_decision_key(decision: str) -> str:
    """Normalize persisted decision values for reporting compatibility."""
    return decision.strip().upper()


def _chain_event_canonical(
    event_id: str,
    event_type: str,
    created_at: str,
    hwm_seq: int,
    hwm_hash: str,
    record_count: int,
    boundary_hash: str = "",
) -> str:
    """Deterministic canonical string for a reset/purge/migration checkpoint signature."""
    return json.dumps(
        {
            "boundary_hash": boundary_hash,
            "created_at": created_at,
            "event_id": event_id,
            "event_type": event_type,
            "hwm_hash": hwm_hash,
            "hwm_seq": int(hwm_seq),
            "record_count": int(record_count),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _agent_db_path(agent_name: str) -> Path:
    """Derive a per-agent, per-project evidence DB path.

    Path: ~/.ancilis/{agent_name}-{cwd_hash[:8]}/evidence.duckdb

    The cwd hash disambiguates agents with the same name in different
    projects or environments (e.g. two repos both using 'my-agent').
    """
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_name)
    cwd_hash = hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]
    agent_dir = DEFAULT_DB_DIR / f"{safe_name}-{cwd_hash}"
    agent_dir.mkdir(parents=True, exist_ok=True)
    return agent_dir / DEFAULT_DB_NAME

CREATE_TABLE_SQL = """
CREATE SEQUENCE IF NOT EXISTS evidence_seq START 1;
CREATE TABLE IF NOT EXISTS evidence_records (
    seq_id BIGINT DEFAULT nextval('evidence_seq'),
    record_id VARCHAR PRIMARY KEY,
    evaluation_id VARCHAR NOT NULL,
    timestamp VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    session_id VARCHAR,
    source_type VARCHAR NOT NULL DEFAULT 'agent',
    tool_name VARCHAR NOT NULL,
    decision VARCHAR NOT NULL,
    mode VARCHAR NOT NULL,
    control_results JSON NOT NULL,
    active_overlays JSON NOT NULL,
    data_classifications JSON NOT NULL,
    active_certifications JSON NOT NULL,
    record_hash VARCHAR NOT NULL,
    previous_hash VARCHAR NOT NULL,
    total_duration_ms DOUBLE NOT NULL,
    output_summary VARCHAR,
    tenant_id VARCHAR,
    detected_data_types JSON NOT NULL DEFAULT '[]',
    sdk_version VARCHAR,
    classification_context JSON NOT NULL DEFAULT '{}',
    framework_version VARCHAR,
    chain_format_version INTEGER NOT NULL DEFAULT 1
);
"""

# Signed audit log of reset/purge events. A wipe cannot pass verification as a
# pristine empty chain: a high-water-mark checkpoint (last seq/hash + count) is
# recorded and signed here before any deletion, so verify_chain reports that a
# reset/purge occurred instead of returning a silently-clean empty chain.
CREATE_CHAIN_EVENTS_SQL = """
CREATE TABLE IF NOT EXISTS evidence_chain_events (
    event_id VARCHAR PRIMARY KEY,
    event_type VARCHAR NOT NULL,
    created_at VARCHAR NOT NULL,
    hwm_seq BIGINT NOT NULL,
    hwm_hash VARCHAR NOT NULL,
    record_count BIGINT NOT NULL,
    keyed BOOLEAN NOT NULL DEFAULT FALSE,
    boundary_hash VARCHAR NOT NULL DEFAULT '',
    signature VARCHAR NOT NULL
);
"""

INSERT_SQL = """
INSERT INTO evidence_records (
    record_id, evaluation_id, timestamp, agent_id, session_id, source_type, tool_name,
    decision, mode, control_results, active_overlays,
    data_classifications, active_certifications,
    record_hash, previous_hash, total_duration_ms, output_summary, tenant_id,
    detected_data_types, sdk_version, classification_context, framework_version,
    chain_format_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

SELECT_COLUMNS = """
seq_id, record_id, evaluation_id, timestamp, agent_id, session_id, source_type, tool_name,
decision, mode, control_results, active_overlays, data_classifications,
active_certifications, record_hash, previous_hash, total_duration_ms, output_summary,
tenant_id, detected_data_types, sdk_version, classification_context, framework_version,
chain_format_version
"""

SYNC_SELECT_COLUMNS = """
er.seq_id, er.record_id, er.evaluation_id, er.timestamp, er.agent_id,
er.session_id, er.source_type, er.tool_name, er.decision, er.mode,
er.control_results, er.active_overlays, er.data_classifications,
er.active_certifications, er.record_hash, er.previous_hash, er.total_duration_ms,
er.output_summary, er.tenant_id, er.detected_data_types, er.sdk_version,
er.classification_context, er.framework_version, er.chain_format_version
"""

CREATE_SYNC_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS evidence_sync_state (
    record_id VARCHAR PRIMARY KEY,
    status VARCHAR NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at VARCHAR,
    last_synced_at VARCHAR,
    last_error VARCHAR,
    next_retry_at VARCHAR,
    remote_status_code INTEGER,
    remote_evidence_id VARCHAR
);
CREATE TABLE IF NOT EXISTS evidence_sync_meta (
    key VARCHAR PRIMARY KEY,
    value VARCHAR
);
"""


class EvidenceStore:
    """Persists evidence records in DuckDB with cryptographic hash chaining.

    Lazy initialization: no filesystem side effects at construction time.
    The DuckDB file is created on first write (store/query/verify).
    """

    def __init__(
        self,
        config: ResolvedConfig,
        db_path: str | Path | None = None,
        in_memory: bool = False,
        tenant_id: str | None = None,
        on_drift: Callable[[DriftReport], None] | None = None,
        evidence_adapter: EvidenceAdapter | None = None,
        evidence_adapter_name: str | None = None,
        evidence_adapter_metadata: Mapping[str, Any] | None = None,
        chain_key: bytes | str | None = None,
    ) -> None:
        self._config = config
        self._certifications: list[str] = list(
            getattr(config, "active_certifications", []) or []
        )
        self._in_memory = in_memory
        self._conn: duckdb.DuckDBPyConnection | None = None
        self._tenant_id = tenant_id
        self._on_drift = on_drift
        self._evidence_adapter = evidence_adapter
        self._evidence_adapter_name = evidence_adapter_name
        self._evidence_adapter_metadata = dict(evidence_adapter_metadata or {})
        # Evidence-chain HMAC key, resolved lazily from (explicit arg > env >
        # OS keyring) and NEVER stored in the DB. _UNSET means "not resolved".
        self._chain_key_arg = chain_key
        self._chain_key_cache: bytes | None | object = _UNSET
        self._warned_unkeyed = False
        self._migration_checked = False

        if in_memory:
            self._db_path = ":memory:"
        elif db_path is not None:
            self._db_path = str(db_path)
        else:
            # Derive path but don't create anything yet
            agent_name = getattr(config, "agent_name", "") or "default"
            safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_name)
            cwd_hash = hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]
            self._db_path = str(DEFAULT_DB_DIR / f"{safe_name}-{cwd_hash}" / DEFAULT_DB_NAME)

    def _ensure_initialized(self) -> None:
        """Lazy init: create DB directory and connection on first use."""
        if self._conn is not None:
            return

        if self._in_memory:
            self._conn = duckdb.connect(":memory:")
        else:
            db_dir = os.path.dirname(self._db_path)
            os.makedirs(db_dir, exist_ok=True)
            self._conn = duckdb.connect(self._db_path)
            logger.info("Evidence store: %s", self._db_path)

        self._connection.execute(CREATE_TABLE_SQL)
        self._connection.execute(CREATE_SYNC_TABLES_SQL)
        self._connection.execute(CREATE_CHAIN_EVENTS_SQL)
        event_columns = {
            row[1]
            for row in self._connection.execute("PRAGMA table_info('evidence_chain_events')").fetchall()
        }
        if "boundary_hash" not in event_columns:
            self._connection.execute(
                "ALTER TABLE evidence_chain_events ADD COLUMN boundary_hash VARCHAR DEFAULT ''"
            )
        columns = {row[1] for row in self._connection.execute("PRAGMA table_info('evidence_records')").fetchall()}
        if "chain_format_version" not in columns:
            # Migration: pre-existing rows predate keyed chaining → mark them v1
            # (legacy). verify_chain reports v1 records as "legacy-unverified".
            # DuckDB ALTER cannot add NOT NULL columns; DEFAULT 1 backfills
            # existing (legacy) rows to v1, which is the intended migration.
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN chain_format_version INTEGER DEFAULT 1"
            )
        if "session_id" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN session_id VARCHAR"
            )
        if "source_type" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN source_type VARCHAR DEFAULT 'agent'"
            )
        if "output_summary" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN output_summary VARCHAR"
            )
        if "tenant_id" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN tenant_id VARCHAR"
            )
        if "detected_data_types" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN detected_data_types JSON DEFAULT '[]'"
            )
        if "sdk_version" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN sdk_version VARCHAR"
            )
        if "classification_context" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN classification_context JSON DEFAULT '{}'"
            )
        if "framework_version" not in columns:
            self._connection.execute(
                "ALTER TABLE evidence_records ADD COLUMN framework_version VARCHAR"
            )
        self._backfill_missing_sync_state_rows()

    @property
    def db_path(self) -> str:
        return self._db_path

    @property
    def _connection(self) -> duckdb.DuckDBPyConnection:
        """Get the DuckDB connection, ensuring it's initialized."""
        self._ensure_initialized()
        assert self._conn is not None
        return self._conn

    def close(self) -> None:
        """Flush and close the DuckDB connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> EvidenceStore:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _chain_key(self) -> bytes | None:
        """Resolve the chain HMAC key once (explicit arg > env > OS keyring)."""
        if self._chain_key_cache is _UNSET:
            self._chain_key_cache = resolve_chain_key(self._chain_key_arg)
        return self._chain_key_cache  # type: ignore[return-value]

    def _max_seq_id(self) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(MAX(seq_id), 0) FROM evidence_records"
        ).fetchone()
        return int(row[0]) if row else 0

    def _ensure_migration_checkpoint(self, boundary_seq: int) -> None:
        """Record a signed migration boundary on the first keyed (v2) write.

        After this boundary, any record still marked v1 is a downgrade attempt.
        Recorded once; the boundary seq is the highest seq that existed before the
        first v2 record (legacy records at or below it may legitimately be v1).
        """
        if self._migration_checked:
            return
        self._migration_checked = True
        existing = self._connection.execute(
            "SELECT 1 FROM evidence_chain_events WHERE event_type = 'migration' LIMIT 1"
        ).fetchone()
        if existing is not None:
            return
        self._record_chain_event("migration", boundary_seq_override=boundary_seq)

    def _warn_unkeyed_once(self) -> None:
        if not self._warned_unkeyed:
            self._warned_unkeyed = True
            logger.warning(
                "ANCILIS_CHAIN_KEY is not set: evidence is written with the legacy "
                "unkeyed SHA-256 chain (v1). Without a protected key, an attacker "
                "with database write access can forge records and re-chain them. "
                "Set ANCILIS_CHAIN_KEY (or an OS keyring entry) to enable keyed "
                "HMAC chaining (v2)."
            )

    def _get_last_hash(self) -> str:
        """Get the hash of the most recent record, or GENESIS_SEED if empty.

        When tenant_id is set, only considers records for that tenant (independent chains).
        """
        self._ensure_initialized()
        if self._tenant_id is not None:
            row = self._connection.execute(
                "SELECT record_hash FROM evidence_records WHERE tenant_id = ? ORDER BY seq_id DESC LIMIT 1",
                [self._tenant_id],
            ).fetchone()
        else:
            row = self._connection.execute(
                "SELECT record_hash FROM evidence_records ORDER BY seq_id DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else GENESIS_SEED

    def store(
        self,
        evaluation: EvaluationResult,
        tool_name: str,
        output_summary: str | None = None,
    ) -> EvidenceRecord:
        """Convert an EvaluationResult into an evidence record and persist it."""
        self._ensure_initialized()
        record_id = str(uuid.uuid4())
        previous_hash = self._get_last_hash()
        previous_max_seq = self._max_seq_id()
        session_id = getattr(evaluation, "session_id", None)
        agent_id = getattr(self._config, "agent_id", None) or evaluation.agent_id

        control_results_data = [
            {
                "control_id": cr.control_id,
                "control_name": cr.control_name,
                "result": cr.result,
                "detail": cr.detail,
                "evidence_data": cr.evidence_data,
                "duration_ms": cr.duration_ms,
            }
            for cr in evaluation.control_results
        ]

        detected_data_types = list(getattr(evaluation, "detected_data_types", None) or [])
        framework_version = (
            getattr(evaluation, "framework_version", None) or AKSI_FRAMEWORK_VERSION
        )

        _sdk_ver: str | None
        try:
            from ancilis import __version__ as _sdk_ver
        except Exception:  # noqa: BLE001 — best-effort, never breaks evidence writes
            _sdk_ver = None

        classification_context: dict[str, Any] = {}
        llm_provider = getattr(self._config, "llm_provider", None)
        if llm_provider:
            classification_context["llm_provider"] = llm_provider

        canon = canonical_payload(
            evaluation_id=evaluation.evaluation_id,
            timestamp=evaluation.timestamp,
            agent_id=agent_id,
            source_type=evaluation.source_type,
            tool_name=tool_name,
            decision=evaluation.decision,
            mode=evaluation.mode,
            control_results=control_results_data,
            active_overlays=evaluation.active_overlays,
            data_classifications=evaluation.data_classifications,
            active_certifications=self._certifications,
            total_duration_ms=evaluation.total_duration_ms,
            previous_hash=previous_hash,
            output_summary=output_summary,
            session_id=session_id,
            tenant_id=self._tenant_id,
            detected_data_types=detected_data_types,
            sdk_version=_sdk_ver,
            framework_version=framework_version,
            classification_context=classification_context,
        )
        # Keyed (v2) chaining when a chain key is available; otherwise legacy
        # unkeyed v1 (with a one-time warning). The version is persisted and,
        # for v2, bound into the HMAC so it cannot be silently downgraded.
        key = self._chain_key()
        if key is not None:
            chain_format_version = CHAIN_FORMAT_V2
            record_hash = compute_keyed_hash(canon, key, version=CHAIN_FORMAT_V2)
        else:
            chain_format_version = CHAIN_FORMAT_V1
            record_hash = compute_hash(canon)
            self._warn_unkeyed_once()

        record = EvidenceRecord(
            record_id=record_id,
            evaluation_id=evaluation.evaluation_id,
            timestamp=evaluation.timestamp,
            agent_id=agent_id,
            source_type=evaluation.source_type,
            tool_name=tool_name,
            decision=_normalize_decision_key(evaluation.decision),
            mode=evaluation.mode,
            control_results=control_results_data,
            active_overlays=evaluation.active_overlays,
            data_classifications=evaluation.data_classifications,
            active_certifications=self._certifications,
            record_hash=record_hash,
            previous_hash=previous_hash,
            total_duration_ms=evaluation.total_duration_ms,
            output_summary=output_summary,
            session_id=session_id,
            tenant_id=self._tenant_id,
            detected_data_types=detected_data_types,
            sdk_version=_sdk_ver,
            framework_version=framework_version,
            classification_context=classification_context,
            chain_format_version=chain_format_version,
        )

        # On the first keyed (v2) write, record a signed migration boundary so a
        # later downgrade of a v2 record to v1 (by editing the column) is caught.
        if chain_format_version == CHAIN_FORMAT_V2:
            self._ensure_migration_checkpoint(previous_max_seq)

        self._connection.execute(INSERT_SQL, [
            record.record_id,
            record.evaluation_id,
            record.timestamp,
            record.agent_id,
            record.session_id,
            record.source_type,
            record.tool_name,
            record.decision,
            record.mode,
            json.dumps(record.control_results),
            json.dumps(record.active_overlays),
            json.dumps(record.data_classifications),
            json.dumps(record.active_certifications),
            record.record_hash,
            record.previous_hash,
            record.total_duration_ms,
            record.output_summary,
            record.tenant_id,
            json.dumps(record.detected_data_types),
            record.sdk_version,
            json.dumps(record.classification_context),
            record.framework_version,
            chain_format_version,
        ])
        self._create_sync_state_row(record.record_id)

        self._maybe_trigger_drift_check()
        self._forward_to_evidence_adapter(record)
        return record

    def _create_sync_state_row(self, record_id: str) -> None:
        row = self._connection.execute(
            "SELECT record_id FROM evidence_sync_state WHERE record_id = ?",
            [record_id],
        ).fetchone()
        if row is not None:
            return
        self._connection.execute(
            "INSERT INTO evidence_sync_state (record_id, status, attempt_count) "
            "VALUES (?, ?, 0)",
            [record_id, SYNC_STATUS_PENDING],
        )

    def _backfill_missing_sync_state_rows(self) -> None:
        self._connection.execute(
            "INSERT INTO evidence_sync_state (record_id, status, attempt_count) "
            "SELECT er.record_id, ?, 0 FROM evidence_records er "
            "WHERE NOT EXISTS ("
            "SELECT 1 FROM evidence_sync_state ss WHERE ss.record_id = er.record_id"
            ")",
            [SYNC_STATUS_PENDING],
        )

    def _require_sync_state(self, record_id: str) -> None:
        row = self._connection.execute(
            "SELECT record_id FROM evidence_sync_state WHERE record_id = ?",
            [record_id],
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown evidence record_id: {record_id}")

    @staticmethod
    def _sync_state_from_row(row: tuple[Any, ...]) -> EvidenceSyncState:
        return EvidenceSyncState(
            record_id=row[0],
            status=row[1],
            attempt_count=row[2],
            last_attempt_at=row[3],
            last_synced_at=row[4],
            last_error=row[5],
            next_retry_at=row[6],
            remote_status_code=row[7],
            remote_evidence_id=row[8],
        )

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def get_sync_state(self, record_id: str) -> EvidenceSyncState | None:
        """Return mutable sync metadata for an evidence record."""
        self._ensure_initialized()
        row = self._connection.execute(
            "SELECT record_id, status, attempt_count, last_attempt_at, "
            "last_synced_at, last_error, next_retry_at, remote_status_code, "
            "remote_evidence_id FROM evidence_sync_state WHERE record_id = ?",
            [record_id],
        ).fetchone()
        return self._sync_state_from_row(row) if row else None

    def get_pending_sync_records(self, now: str | None = None) -> list[EvidenceRecord]:
        """Return records eligible for sync, ordered by immutable evidence sequence."""
        self._ensure_initialized()
        effective_now = now or self._now_iso()
        conditions = [
            "(ss.status = ? OR (ss.status = ? AND ss.next_retry_at IS NOT NULL AND ss.next_retry_at <= ?))",
        ]
        params: list[Any] = [SYNC_STATUS_PENDING, SYNC_STATUS_FAILED, effective_now]
        if self._tenant_id is not None:
            conditions.append("er.tenant_id = ?")
            params.append(self._tenant_id)
        params.append(getattr(self._config, "sync_max_queue_size", 10000))
        query = (
            "SELECT "
            + SYNC_SELECT_COLUMNS
            + " FROM evidence_records er "
            "JOIN evidence_sync_state ss ON ss.record_id = er.record_id "
            "WHERE "
            + " AND ".join(conditions)
            + " ORDER BY er.seq_id ASC LIMIT ?"
        )
        rows = self._connection.execute(query, params).fetchall()  # nosemgrep
        return [self._row_to_record(row) for row in rows]

    def mark_sync_synced(
        self,
        record_id: str,
        *,
        synced_at: str | None = None,
        remote_status_code: int | None = None,
        remote_evidence_id: str | None = None,
    ) -> None:
        """Mark an evidence record as successfully synced."""
        self._ensure_initialized()
        self._require_sync_state(record_id)
        self._connection.execute(
            "UPDATE evidence_sync_state SET status = ?, last_synced_at = ?, "
            "last_error = NULL, next_retry_at = NULL, remote_status_code = ?, "
            "remote_evidence_id = ? WHERE record_id = ?",
            [
                SYNC_STATUS_SYNCED,
                synced_at or self._now_iso(),
                remote_status_code,
                remote_evidence_id,
                record_id,
            ],
        )

    def mark_sync_failed(
        self,
        record_id: str,
        *,
        error: str,
        attempted_at: str | None = None,
        next_retry_at: str | None = None,
        remote_status_code: int | None = None,
    ) -> None:
        """Record a failed sync attempt and optional retry time."""
        self._ensure_initialized()
        self._require_sync_state(record_id)
        self._connection.execute(
            "UPDATE evidence_sync_state SET status = ?, "
            "attempt_count = attempt_count + 1, last_attempt_at = ?, "
            "last_error = ?, next_retry_at = ?, remote_status_code = ? "
            "WHERE record_id = ?",
            [
                SYNC_STATUS_FAILED,
                attempted_at or self._now_iso(),
                error,
                next_retry_at,
                remote_status_code,
                record_id,
            ],
        )

    def get_sync_summary(self) -> EvidenceSyncSummary:
        """Return aggregate sync metadata without contacting any platform service."""
        if self._conn is None and not self._in_memory and not Path(self._db_path).exists():
            return EvidenceSyncSummary(pending_count=0, failed_count=0)
        self._ensure_initialized()
        if self._tenant_id is not None:
            join = " JOIN evidence_records er ON er.record_id = ss.record_id"
            params: list[Any] = [self._tenant_id]
            tenant_conditions = ["er.tenant_id = ?"]
        else:
            join = ""
            params = []
            tenant_conditions = []
        base_from = " FROM evidence_sync_state ss" + join
        status_where = (
            " WHERE " + " AND ".join(tenant_conditions)
            if tenant_conditions
            else ""
        )
        counts = dict(
            self._connection.execute(  # nosemgrep
                "SELECT ss.status, COUNT(*)"
                + base_from
                + status_where
                + " GROUP BY ss.status",
                params,
            ).fetchall()
        )
        last_sync = self._connection.execute(  # nosemgrep
            "SELECT MAX(ss.last_synced_at)" + base_from + status_where,
            params,
        ).fetchone()
        last_error_conditions = [*tenant_conditions, "ss.last_error IS NOT NULL"]
        last_error_where = " WHERE " + " AND ".join(last_error_conditions)
        last_error = self._connection.execute(  # nosemgrep
            "SELECT ss.last_error"
            + base_from
            + last_error_where
            + " ORDER BY ss.last_attempt_at DESC NULLS LAST LIMIT 1",
            params,
        ).fetchone()
        next_retry_conditions = [*tenant_conditions, "ss.next_retry_at IS NOT NULL"]
        next_retry_where = " WHERE " + " AND ".join(next_retry_conditions)
        next_retry = self._connection.execute(  # nosemgrep
            "SELECT MIN(ss.next_retry_at)" + base_from + next_retry_where,
            params,
        ).fetchone()
        return EvidenceSyncSummary(
            pending_count=counts.get(SYNC_STATUS_PENDING, 0),
            failed_count=counts.get(SYNC_STATUS_FAILED, 0),
            last_sync_at=last_sync[0] if last_sync else None,
            last_error=last_error[0] if last_error else None,
            next_retry_at=next_retry[0] if next_retry else None,
        )

    def _forward_to_evidence_adapter(self, record: EvidenceRecord) -> None:
        if self._evidence_adapter is None:
            return
        payload = EvidenceAdapterPayload(
            record=copy.deepcopy(record),
            adapter_metadata=dict(self._evidence_adapter_metadata),
        )
        try:
            self._evidence_adapter.store(payload)
        except Exception as exc:  # noqa: BLE001 — plugin hooks must not break DuckDB evidence
            adapter_name = self._evidence_adapter_name or self._evidence_adapter.__class__.__name__
            logger.warning("plugin evidence adapter %r store hook failed: %s", adapter_name, exc)

    def _maybe_trigger_drift_check(self) -> None:
        """Fire the on_drift callback if configured and an active baseline exists."""
        if self._on_drift is None:
            return
        try:
            from ancilis.baselines.manager import BaselineManager  # lazy — avoids circular import
            mgr = BaselineManager(self, self._config)
            report = mgr.check_drift()
            self._on_drift(report)
        except KeyError:
            # No active baseline — nothing to check
            pass
        except Exception as exc:
            logger.warning("on_drift callback error: %s", exc)

    def get_records(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        tool_name: str | None = None,
        decision: str | None = None,
        since: str | None = None,
        limit: int | None = 100,
    ) -> list[EvidenceRecord]:
        """Query evidence records with optional filters."""
        self._ensure_initialized()
        conditions: list[str] = []
        params: list[Any] = []

        if self._tenant_id is not None:
            conditions.append("tenant_id = ?")
            params.append(self._tenant_id)
        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if session_id is not None:
            conditions.append("session_id = ?")
            params.append(session_id)
        if tool_name is not None:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if decision is not None:
            conditions.append("decision = ?")
            params.append(_normalize_decision_key(decision))
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)

        # Build query with parameterized WHERE conditions
        base_query = "SELECT " + SELECT_COLUMNS + " FROM evidence_records"
        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)
            query = base_query + where_clause + " ORDER BY seq_id ASC"
        else:
            query = base_query + " ORDER BY seq_id ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        # nosemgrep: all parameters properly bound, where_clause from internal conditions only
        rows = self._connection.execute(query, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def count(self, session_id: str | None = None) -> int:
        """Return total number of evidence records, optionally scoped to a session."""
        self._ensure_initialized()
        conditions: list[str] = []
        params: list[Any] = []
        if self._tenant_id is not None:
            conditions.append("tenant_id = ?")
            params.append(self._tenant_id)
        if session_id is not None:
            conditions.append("session_id = ?")
            params.append(session_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        # where is built from internal conditions only, safe to concatenate
        row = self._connection.execute(  # nosemgrep
            "SELECT COUNT(*) FROM evidence_records" + where, params  # nosemgrep
        ).fetchone()
        return row[0] if row else 0

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return known sessions with record counts and time ranges."""
        self._ensure_initialized()
        if self._tenant_id is not None:
            rows = self._connection.execute(
                "SELECT session_id, COUNT(*) as count, "
                "MIN(timestamp) as first_seen, MAX(timestamp) as last_seen "
                "FROM evidence_records "
                "WHERE session_id IS NOT NULL AND tenant_id = ? "
                "GROUP BY session_id ORDER BY last_seen DESC",
                [self._tenant_id],
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT session_id, COUNT(*) as count, "
                "MIN(timestamp) as first_seen, MAX(timestamp) as last_seen "
                "FROM evidence_records "
                "WHERE session_id IS NOT NULL "
                "GROUP BY session_id ORDER BY last_seen DESC"
            ).fetchall()
        return [
            {"session_id": r[0], "count": r[1], "first_seen": r[2], "last_seen": r[3]}
            for r in rows
        ]

    def latest_session_id(self) -> str | None:
        """Return the session_id of the most recent evidence record that has one, or None if empty.

        Records with session_id=NULL (e.g. from the dependency scanner) are skipped
        so they do not poison the latest-session lookup and inflate subsequent scan results.
        """
        self._ensure_initialized()
        if self._tenant_id is not None:
            result = self._connection.execute(
                "SELECT session_id FROM evidence_records "
                "WHERE session_id IS NOT NULL AND tenant_id = ? ORDER BY timestamp DESC LIMIT 1",
                [self._tenant_id],
            ).fetchone()
        else:
            result = self._connection.execute(
                "SELECT session_id FROM evidence_records "
                "WHERE session_id IS NOT NULL ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
        return result[0] if result else None

    def reset(self) -> int:
        """Delete ALL evidence records and return count deleted.

        This is a full reset — the hash chain restarts from GENESIS_SEED.
        For session-scoped views, use session_id filters on queries instead.
        """
        self._ensure_initialized()
        n = self.count()
        # Record a signed reset checkpoint BEFORE deleting, so the wipe is
        # auditable and cannot pass verification as a pristine empty chain.
        self._record_chain_event("reset")
        self._connection.execute("DELETE FROM evidence_sync_state")
        self._connection.execute("DELETE FROM evidence_sync_meta")
        self._connection.execute("DELETE FROM evidence_records")
        return n

    def _record_chain_event(
        self,
        event_type: str,
        *,
        boundary_hash: str = "",
        boundary_seq_override: int | None = None,
    ) -> None:
        """Append a signed checkpoint (reset / purge / migration).

        Captures the current max seq_id, last record hash, and record count, and
        signs the checkpoint with the chain key (HMAC) when available, falling
        back to SHA-256 otherwise. ``boundary_hash`` records a purge's resume
        point (the surviving chain's predecessor hash). ``boundary_seq_override``
        sets the migration boundary seq. verify_chain reports these events so a
        wiped/migrated chain is never silently "clean" and a v2->v1 downgrade is
        caught.
        """
        row = self._connection.execute(
            "SELECT COALESCE(MAX(seq_id), 0), COUNT(*) FROM evidence_records"
        ).fetchone()
        hwm_seq = boundary_seq_override if boundary_seq_override is not None else (int(row[0]) if row else 0)
        record_count = int(row[1]) if row else 0
        last = self._connection.execute(
            "SELECT record_hash FROM evidence_records ORDER BY seq_id DESC LIMIT 1"
        ).fetchone()
        hwm_hash = last[0] if last else GENESIS_SEED
        event_id = str(uuid.uuid4())
        created_at = self._now_iso()
        canonical = _chain_event_canonical(
            event_id, event_type, created_at, hwm_seq, hwm_hash, record_count, boundary_hash
        )
        key = self._chain_key()
        if key is not None:
            keyed = True
            signature = compute_keyed_hash(canonical, key)
        else:
            keyed = False
            signature = compute_hash(canonical)
        self._connection.execute(
            "INSERT INTO evidence_chain_events "
            "(event_id, event_type, created_at, hwm_seq, hwm_hash, record_count, keyed, boundary_hash, signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [event_id, event_type, created_at, hwm_seq, hwm_hash, record_count, keyed, boundary_hash, signature],
        )

    def _full_canonical(self, record: EvidenceRecord) -> str:
        """Canonical payload over the full (expanded) field set for a record."""
        return canonical_payload(
            evaluation_id=record.evaluation_id,
            timestamp=record.timestamp,
            agent_id=record.agent_id,
            source_type=record.source_type,
            tool_name=record.tool_name,
            decision=record.decision,
            mode=record.mode,
            control_results=record.control_results,
            active_overlays=record.active_overlays,
            data_classifications=record.data_classifications,
            active_certifications=record.active_certifications,
            total_duration_ms=record.total_duration_ms,
            previous_hash=record.previous_hash,
            output_summary=record.output_summary,
            session_id=record.session_id,
            tenant_id=record.tenant_id,
            detected_data_types=record.detected_data_types,
            sdk_version=record.sdk_version,
            framework_version=record.framework_version,
            classification_context=record.classification_context,
        )

    def _matches_legacy_v1(self, record: EvidenceRecord) -> bool:
        """ANC-922 compatibility for GENUINE pre-expansion v1 records only.

        Older v1 records were hashed over narrower canonical payloads (before the
        framework_version / expanded-metadata additions). This is consulted ONLY
        for v1 records, never for v2, so a keyed record can never be forged by
        stripping the expanded fields.
        """
        pre_framework = canonical_payload(
            evaluation_id=record.evaluation_id,
            timestamp=record.timestamp,
            agent_id=record.agent_id,
            source_type=record.source_type,
            tool_name=record.tool_name,
            decision=record.decision,
            mode=record.mode,
            control_results=record.control_results,
            active_overlays=record.active_overlays,
            data_classifications=record.data_classifications,
            active_certifications=record.active_certifications,
            total_duration_ms=record.total_duration_ms,
            previous_hash=record.previous_hash,
            output_summary=record.output_summary,
            session_id=record.session_id,
            tenant_id=record.tenant_id,
            detected_data_types=record.detected_data_types,
            sdk_version=record.sdk_version,
            classification_context=record.classification_context,
        )
        if record.record_hash == compute_hash(pre_framework):
            return True
        legacy = canonical_payload(
            evaluation_id=record.evaluation_id,
            timestamp=record.timestamp,
            agent_id=record.agent_id,
            source_type=record.source_type,
            tool_name=record.tool_name,
            decision=record.decision,
            mode=record.mode,
            control_results=record.control_results,
            active_overlays=record.active_overlays,
            data_classifications=record.data_classifications,
            active_certifications=record.active_certifications,
            total_duration_ms=record.total_duration_ms,
            previous_hash=record.previous_hash,
            output_summary=record.output_summary,
            session_id=record.session_id,
            tenant_id=record.tenant_id,
        )
        return record.record_hash == compute_hash(legacy)

    def verify_chain(
        self, session_id: str | None = None, *, key: bytes | str | None = None
    ) -> tuple[bool, list[str]]:
        """Verify the hash chain. Returns (valid, errors).

        Backward-compatible facade over verify_chain_report. ``valid`` is False
        on tampering, broken links, or a v2 record that cannot be verified
        because no chain key is available. Intact legacy (v1) records are NOT
        failures; call verify_chain_report() to surface their explicit
        "legacy-unverified" status.
        """
        report = self.verify_chain_report(session_id=session_id, key=key)
        return report.valid, report.errors

    def verify_chain_report(
        self, session_id: str | None = None, *, key: bytes | str | None = None
    ) -> ChainVerificationReport:
        """Verify records and reset/purge/migration checkpoints; return a report.

        v2 records are verified with HMAC and REQUIRE the chain key. v1 records
        are checked structurally and reported as legacy-unverified -- never
        silently passed nor failed. A signed migration boundary catches a
        v2->v1 downgrade; signed purge checkpoints authorize the surviving
        chain's resume point so a legitimate prune does not read as broken;
        reset/purge on an emptied store is reported as reset-or-purged, not as a
        pristine empty chain.
        """
        self._ensure_initialized()
        resolved_key = resolve_chain_key(key) if key is not None else self._chain_key()

        if self._tenant_id is not None:
            query = "SELECT " + SELECT_COLUMNS + " FROM evidence_records WHERE tenant_id = ? ORDER BY seq_id ASC"  # nosemgrep
            rows = self._connection.execute(query, [self._tenant_id]).fetchall()  # nosemgrep
        else:
            query = "SELECT " + SELECT_COLUMNS + " FROM evidence_records ORDER BY seq_id ASC"  # nosemgrep
            rows = self._connection.execute(query).fetchall()  # nosemgrep

        events = self._connection.execute(
            "SELECT event_id, event_type, created_at, hwm_seq, hwm_hash, record_count, keyed, boundary_hash, signature "
            "FROM evidence_chain_events ORDER BY created_at ASC"
        ).fetchall()
        reset_events = sum(1 for e in events if e[1] == "reset")
        purge_events = sum(1 for e in events if e[1] == "purge")

        errors: list[str] = []
        authorized_resume_hashes: set[str] = set()
        migration_boundary: int | None = None
        has_keyed_migration = False

        # Verify checkpoint signatures, and collect the purge resume points and
        # migration boundary from cryptographically valid checkpoints only. A
        # keyed checkpoint cannot be verified without the key (an error, like a
        # keyed record).
        for e in events:
            event_id, event_type = e[0], e[1]
            boundary_hash = e[7]
            signature = e[8]
            canonical = _chain_event_canonical(e[0], e[1], e[2], e[3], e[4], e[5], boundary_hash)
            keyed = bool(e[6])
            sig_ok = False
            if keyed:
                if resolved_key is None:
                    errors.append(
                        f"Chain event {event_id} ({event_type}): chain key required to "
                        f"verify keyed checkpoint - set ANCILIS_CHAIN_KEY."
                    )
                elif signature != compute_keyed_hash(canonical, resolved_key):
                    errors.append(f"Chain event {event_id} ({event_type}): signature invalid - audit log tampered.")
                else:
                    sig_ok = True
            elif signature != compute_hash(canonical):
                errors.append(f"Chain event {event_id} ({event_type}): signature invalid - audit log tampered.")
            else:
                sig_ok = True
            if not sig_ok:
                continue
            # Trust model: when a key is present, only KEYED checkpoints may
            # authorize a downgrade boundary or a purge gap — an unkeyed
            # checkpoint is forgeable by a DB writer without the key, so it must
            # not authorize anything in a keyed chain. When no key is present the
            # chain is legacy-unverified regardless, so unkeyed checkpoints may
            # authorize legacy purge gaps (they cannot grant "verified").
            trusted = keyed if resolved_key is not None else not keyed
            if not trusted:
                continue
            if event_type == "purge" and boundary_hash:
                authorized_resume_hashes.add(boundary_hash)
            elif event_type == "migration":
                boundary = int(e[3])
                migration_boundary = boundary if migration_boundary is None else max(migration_boundary, boundary)
                if keyed:
                    has_keyed_migration = True

        if not rows:
            status = "reset-or-purged" if (reset_events or purge_events) else "empty"
            return ChainVerificationReport(
                valid=len(errors) == 0,
                errors=errors,
                verified_count=0,
                legacy_unverified_count=0,
                reset_events=reset_events,
                purge_events=purge_events,
                status=status,
            )

        verified_count = 0
        legacy_unverified_count = 0
        has_v2 = False
        expected_previous = GENESIS_SEED

        for row in rows:
            record = self._row_to_record(row)
            seq_id = int(row[0])
            version = record.chain_format_version
            in_scope = session_id is None or record.session_id == session_id

            # Linkage: accept the expected predecessor, or a signed purge resume
            # point (an authorized gap left by a legitimate prune).
            if (
                in_scope
                and record.previous_hash != expected_previous
                and record.previous_hash not in authorized_resume_hashes
            ):
                errors.append(
                    f"Record {record.record_id}: previous_hash mismatch. "
                    f"Expected {expected_previous[:16]}..., got {record.previous_hash[:16]}..."
                )

            # Downgrade guard: past a signed migration boundary, a v1 record is a
            # chain-format downgrade attempt (an HMAC bypass via the version column).
            if (
                in_scope
                and migration_boundary is not None
                and seq_id > migration_boundary
                and version != CHAIN_FORMAT_V2
            ):
                errors.append(
                    f"Record {record.record_id}: chain-format downgrade - record after the "
                    f"keyed migration boundary is not v2 (possible HMAC bypass)."
                )
                expected_previous = record.record_hash
                continue

            canon = self._full_canonical(record)

            if version == CHAIN_FORMAT_V2:
                has_v2 = True
                if resolved_key is None:
                    if in_scope:
                        errors.append(
                            f"Record {record.record_id}: chain key required to verify "
                            f"keyed (v2) record - set ANCILIS_CHAIN_KEY."
                        )
                else:
                    expected_hash = compute_keyed_hash(canon, resolved_key, version=CHAIN_FORMAT_V2)
                    if record.record_hash != expected_hash:
                        if in_scope:
                            errors.append(
                                f"Record {record.record_id}: HMAC mismatch - record "
                                f"tampered or signed with a different key."
                            )
                    elif in_scope:
                        verified_count += 1
                # No narrower-payload fallback for v2 (ANC-922 loophole closed).
            else:
                # Legacy v1: structural check only - not cryptographically attestable.
                ok = record.record_hash == compute_hash(canon) or self._matches_legacy_v1(record)
                if in_scope:
                    if ok:
                        legacy_unverified_count += 1
                    else:
                        errors.append(
                            f"Record {record.record_id}: legacy (v1) hash mismatch - record altered."
                        )

            expected_previous = record.record_hash

        # A keyed chain (any v2 record) MUST carry a signed keyed migration
        # checkpoint. Its absence means the audit log was tampered — e.g. the
        # checkpoint was deleted to try to re-interpret v2 records under the
        # weaker v1 rules.
        if resolved_key is not None and has_v2 and not has_keyed_migration:
            errors.append(
                "v2 (keyed) records are present but no signed keyed migration "
                "checkpoint exists - audit log incomplete or tampered."
            )

        if errors:
            status = "broken"
        elif verified_count and legacy_unverified_count:
            status = "mixed"
        elif legacy_unverified_count:
            status = "legacy-unverified"
        else:
            status = "verified"

        return ChainVerificationReport(
            valid=len(errors) == 0,
            errors=errors,
            verified_count=verified_count,
            legacy_unverified_count=legacy_unverified_count,
            reset_events=reset_events,
            purge_events=purge_events,
            status=status,
        )

    def get_summary(
        self,
        since: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate a summary for posture reports.

        Args:
            since: Optional ISO timestamp. When provided, only evidence records
                   with timestamp >= since are included in counts and stats.
            session_id: Optional session identifier. When provided, only
                   evidence records from that session are included in counts
                   and stats.
                   Chain verification always runs against the full store.

        Returns empty results if no evidence has been recorded yet (without
        forcing DB creation for persistent stores).
        """
        if self._conn is None and not self._in_memory and not Path(self._db_path).exists():
            # No evidence recorded yet — return empty without creating DB
            return {
                "total_evaluations": 0,
                "decisions": {},
                "tools_evaluated": [],
                "chain_valid": True,
                "chain_errors": [],
                "control_pass_rates": {},
                "pattern_detections": {},
            }

        self._ensure_initialized()
        conditions: list[str] = []
        params: list[str] = []
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)
        if session_id is not None:
            conditions.append("session_id = ?")
            params.append(session_id)
        where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        # Total evaluations (period-filtered)
        # where_clause is built from internal logic (constant or " WHERE timestamp >= ?"), safe to concatenate
        count_query = "SELECT COUNT(*) FROM evidence_records" + where_clause  # nosemgrep
        count_row = self._connection.execute(count_query, params).fetchone()  # nosemgrep
        total = count_row[0] if count_row else 0

        if total == 0 and since is None:
            return {
                "total_evaluations": 0,
                "decisions": {},
                "tools_evaluated": [],
                "chain_valid": True,
                "chain_errors": [],
                "control_pass_rates": {},
                "pattern_detections": {},
            }

        # Decision counts (period-filtered)
        # where_clause is built from internal logic, safe to concatenate
        decision_query = "SELECT decision, COUNT(*) FROM evidence_records" + where_clause + " GROUP BY decision"  # nosemgrep
        decision_rows = self._connection.execute(decision_query, params).fetchall()  # nosemgrep
        decisions: dict[str, int] = {}
        for raw_decision, count in decision_rows:
            decision = _normalize_decision_key(raw_decision)
            decisions[decision] = decisions.get(decision, 0) + count

        # Unique tools (period-filtered)
        # where_clause is built from internal logic, safe to concatenate
        tool_query = "SELECT DISTINCT tool_name FROM evidence_records" + where_clause + " ORDER BY tool_name"  # nosemgrep
        tool_rows = self._connection.execute(tool_query, params).fetchall()  # nosemgrep
        tools = [row[0] for row in tool_rows]

        # Chain integrity (always full store — verified end-to-end)
        chain_report = self.verify_chain_report()
        chain_valid = chain_report.valid
        chain_errors = chain_report.errors

        # Control pass rates (period-filtered)
        # where_clause is built from internal logic, safe to concatenate
        control_query = "SELECT control_results FROM evidence_records" + where_clause  # nosemgrep
        control_rows = self._connection.execute(control_query, params).fetchall()  # nosemgrep
        control_stats: dict[str, dict[str, int]] = {}
        pattern_detections: dict[str, int] = {}
        for (cr_json,) in control_rows:
            results = json.loads(cr_json) if isinstance(cr_json, str) else cr_json
            for cr in results:
                cid = cr["control_id"]
                if cid not in control_stats:
                    control_stats[cid] = {"PASS": 0, "FAIL": 0, "FLAG": 0, "SKIP": 0, "ERROR": 0}
                result = cr.get("result", "SKIP")
                if result in control_stats[cid]:
                    control_stats[cid][result] += 1
                for pattern in cr.get("evidence_data", {}).get("patterns_detected", []):
                    pattern_type = pattern.get("type")
                    count = pattern.get("count", 0)
                    if isinstance(pattern_type, str) and isinstance(count, int):
                        pattern_detections[pattern_type] = pattern_detections.get(pattern_type, 0) + count

        return {
            "total_evaluations": total,
            "decisions": decisions,
            "tools_evaluated": tools,
            "control_pass_rates": control_stats,
            "pattern_detections": pattern_detections,
            "chain_valid": chain_valid,
            "chain_errors": chain_errors,
            "chain_status": chain_report.status,
            "chain_verified": chain_report.verified_count,
            "chain_legacy_unverified": chain_report.legacy_unverified_count,
            "chain_reset_events": chain_report.reset_events,
            "chain_purge_events": chain_report.purge_events,
        }

    def purge_before(self, before_timestamp: str) -> int:
        """Remove records older than the given ISO timestamp. Returns count removed.

        Records a signed purge checkpoint before deletion so the purge is
        auditable and an emptied chain cannot pass verification as pristine.
        """
        self._ensure_initialized()
        row = self._connection.execute(
            "SELECT COUNT(*) FROM evidence_records WHERE timestamp < ?",
            [before_timestamp],
        ).fetchone()
        count = row[0] if row else 0

        if count > 0:
            # Capture the surviving chain's resume point (the previous_hash of
            # the oldest record that will survive). The signed purge checkpoint
            # authorizes verify_chain to accept that link instead of reporting
            # the pruned prefix as a broken chain (which would invalidate
            # retained data — forbidden by the hard constraint).
            survivor = self._connection.execute(
                "SELECT previous_hash FROM evidence_records WHERE timestamp >= ? "
                "ORDER BY seq_id ASC LIMIT 1",
                [before_timestamp],
            ).fetchone()
            resume_hash = survivor[0] if survivor else ""
            self._record_chain_event("purge", boundary_hash=resume_hash)
            self._connection.execute(
                "DELETE FROM evidence_sync_state WHERE record_id IN ("
                "SELECT record_id FROM evidence_records WHERE timestamp < ?"
                ")",
                [before_timestamp],
            )
            self._connection.execute(
                "DELETE FROM evidence_records WHERE timestamp < ?",
                [before_timestamp],
            )

        return count

    @staticmethod
    def _row_to_record(row: tuple[Any, ...]) -> EvidenceRecord:
        """Convert a DuckDB row tuple to an EvidenceRecord.

        Column order: seq_id, record_id, evaluation_id, timestamp, agent_id,
        session_id, source_type, tool_name, decision, mode, control_results,
        active_overlays, data_classifications, active_certifications,
        record_hash, previous_hash, total_duration_ms, output_summary,
        tenant_id, detected_data_types, sdk_version, classification_context,
        framework_version
        """
        raw_detected = row[19] if len(row) > 19 else None
        detected_data_types: list[str] = (
            json.loads(raw_detected) if isinstance(raw_detected, str) else (raw_detected or [])
        )
        raw_ctx = row[21] if len(row) > 21 else None
        classification_context: dict[str, Any] = (
            json.loads(raw_ctx) if isinstance(raw_ctx, str) else (raw_ctx or {})
        )
        return EvidenceRecord(
            record_id=row[1],
            evaluation_id=row[2],
            timestamp=row[3],
            agent_id=row[4],
            source_type=row[6],
            tool_name=row[7],
            decision=row[8],
            mode=row[9],
            control_results=json.loads(row[10]) if isinstance(row[10], str) else row[10],
            active_overlays=json.loads(row[11]) if isinstance(row[11], str) else row[11],
            data_classifications=json.loads(row[12]) if isinstance(row[12], str) else row[12],
            active_certifications=json.loads(row[13]) if isinstance(row[13], str) else row[13],
            record_hash=row[14],
            previous_hash=row[15],
            total_duration_ms=row[16],
            output_summary=row[17] if len(row) > 17 else None,
            session_id=row[5] if len(row) > 5 else None,
            tenant_id=row[18] if len(row) > 18 else None,
            detected_data_types=detected_data_types,
            sdk_version=row[20] if len(row) > 20 else None,
            classification_context=classification_context,
            framework_version=row[22] if len(row) > 22 else None,
            chain_format_version=int(row[23]) if len(row) > 23 and row[23] is not None else CHAIN_FORMAT_V1,
        )
