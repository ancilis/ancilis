"""DuckDB-backed evidence store with hash chain integrity."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import duckdb

if TYPE_CHECKING:
    from ancilis.baselines.models import DriftReport

from ancilis.config import ResolvedConfig
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.chain import GENESIS_SEED, canonical_payload, compute_hash
from ancilis.evidence.record import EvidenceRecord

logger = logging.getLogger("ancilis.evidence")

DEFAULT_DB_DIR = Path.home() / ".ancilis"
DEFAULT_DB_NAME = "evidence.duckdb"


def _normalize_decision_key(decision: str) -> str:
    """Normalize persisted decision values for reporting compatibility."""
    return decision.strip().upper()


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
    tenant_id VARCHAR
);
"""

INSERT_SQL = """
INSERT INTO evidence_records (
    record_id, evaluation_id, timestamp, agent_id, session_id, source_type, tool_name,
    decision, mode, control_results, active_overlays,
    data_classifications, active_certifications,
    record_hash, previous_hash, total_duration_ms, output_summary, tenant_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

SELECT_COLUMNS = """
seq_id, record_id, evaluation_id, timestamp, agent_id, session_id, source_type, tool_name,
decision, mode, control_results, active_overlays, data_classifications,
active_certifications, record_hash, previous_hash, total_duration_ms, output_summary,
tenant_id
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
    ) -> None:
        self._config = config
        self._certifications: list[str] = list(
            getattr(config, "active_certifications", []) or []
        )
        self._in_memory = in_memory
        self._conn: duckdb.DuckDBPyConnection | None = None
        self._tenant_id = tenant_id
        self._on_drift = on_drift

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
        columns = {row[1] for row in self._connection.execute("PRAGMA table_info('evidence_records')").fetchall()}
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
        session_id = getattr(evaluation, "session_id", None)

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

        canon = canonical_payload(
            evaluation_id=evaluation.evaluation_id,
            timestamp=evaluation.timestamp,
            agent_id=evaluation.agent_id,
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
        )
        record_hash = compute_hash(canon)

        record = EvidenceRecord(
            record_id=record_id,
            evaluation_id=evaluation.evaluation_id,
            timestamp=evaluation.timestamp,
            agent_id=evaluation.agent_id,
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
        )

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
        ])

        self._maybe_trigger_drift_check()
        return record

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
        """Return the session_id of the most recent evidence record, or None if empty."""
        self._ensure_initialized()
        if self._tenant_id is not None:
            result = self._connection.execute(
                "SELECT session_id FROM evidence_records "
                "WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 1",
                [self._tenant_id],
            ).fetchone()
        else:
            result = self._connection.execute(
                "SELECT session_id FROM evidence_records ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
        return result[0] if result else None

    def reset(self) -> int:
        """Delete ALL evidence records and return count deleted.

        This is a full reset — the hash chain restarts from GENESIS_SEED.
        For session-scoped views, use session_id filters on queries instead.
        """
        self._ensure_initialized()
        n = self.count()
        self._connection.execute("DELETE FROM evidence_records")
        return n

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the hash chain integrity. Returns (valid, errors)."""
        self._ensure_initialized()
        # SELECT_COLUMNS is a constant defined at module level, safe to concatenate
        if self._tenant_id is not None:
            query = "SELECT " + SELECT_COLUMNS + " FROM evidence_records WHERE tenant_id = ? ORDER BY seq_id ASC"  # nosemgrep
            rows = self._connection.execute(query, [self._tenant_id]).fetchall()  # nosemgrep
        else:
            query = "SELECT " + SELECT_COLUMNS + " FROM evidence_records ORDER BY seq_id ASC"  # nosemgrep
            rows = self._connection.execute(query).fetchall()  # nosemgrep

        if not rows:
            return True, []

        errors: list[str] = []
        expected_previous = GENESIS_SEED

        for row in rows:
            record = self._row_to_record(row)

            # Check previous_hash links correctly
            if record.previous_hash != expected_previous:
                errors.append(
                    f"Record {record.record_id}: previous_hash mismatch. "
                    f"Expected {expected_previous[:16]}..., got {record.previous_hash[:16]}..."
                )

            # Recompute hash
            canon = canonical_payload(
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
            expected_hash = compute_hash(canon)

            if record.record_hash != expected_hash:
                errors.append(
                    f"Record {record.record_id}: hash mismatch. "
                    f"Expected {expected_hash[:16]}..., got {record.record_hash[:16]}..."
                )

            expected_previous = record.record_hash

        return len(errors) == 0, errors

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

        # Chain integrity (always full store — chain must be verified end-to-end)
        chain_valid, chain_errors = self.verify_chain()

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
        }

    def purge_before(self, before_timestamp: str) -> int:
        """Remove records older than the given ISO timestamp. Returns count removed."""
        self._ensure_initialized()
        row = self._connection.execute(
            "SELECT COUNT(*) FROM evidence_records WHERE timestamp < ?",
            [before_timestamp],
        ).fetchone()
        count = row[0] if row else 0

        if count > 0:
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
        record_hash, previous_hash, total_duration_ms, output_summary, tenant_id
        """
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
        )
