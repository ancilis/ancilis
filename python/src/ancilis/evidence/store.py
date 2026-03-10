"""DuckDB-backed evidence store with hash chain integrity."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

from ancilis.config import ResolvedConfig
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.chain import GENESIS_SEED, canonical_payload, compute_hash
from ancilis.evidence.record import EvidenceRecord

CREATE_TABLE_SQL = """
CREATE SEQUENCE IF NOT EXISTS evidence_seq START 1;
CREATE TABLE IF NOT EXISTS evidence_records (
    seq_id BIGINT DEFAULT nextval('evidence_seq'),
    record_id VARCHAR PRIMARY KEY,
    evaluation_id VARCHAR NOT NULL,
    timestamp VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    tool_name VARCHAR NOT NULL,
    decision VARCHAR NOT NULL,
    mode VARCHAR NOT NULL,
    control_results JSON NOT NULL,
    active_overlays JSON NOT NULL,
    data_classifications JSON NOT NULL,
    active_certifications JSON NOT NULL,
    record_hash VARCHAR NOT NULL,
    previous_hash VARCHAR NOT NULL,
    total_duration_ms DOUBLE NOT NULL
);
"""

INSERT_SQL = """
INSERT INTO evidence_records (
    record_id, evaluation_id, timestamp, agent_id, tool_name,
    decision, mode, control_results, active_overlays,
    data_classifications, active_certifications,
    record_hash, previous_hash, total_duration_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""


class EvidenceStore:
    """Persists evidence records in DuckDB with cryptographic hash chaining."""

    def __init__(
        self,
        config: ResolvedConfig,
        db_path: str | Path | None = None,
    ) -> None:
        self._config = config
        self._certifications: list[str] = list(
            getattr(config, "active_certifications", []) or []
        )

        if db_path is None:
            self._db_path = ":memory:"
        else:
            self._db_path = str(db_path)

        self._conn = duckdb.connect(self._db_path)
        self._conn.execute(CREATE_TABLE_SQL)

    @property
    def db_path(self) -> str:
        return self._db_path

    def close(self) -> None:
        self._conn.close()

    def _get_last_hash(self) -> str:
        """Get the hash of the most recent record, or GENESIS_SEED if empty."""
        row = self._conn.execute(
            "SELECT record_hash FROM evidence_records ORDER BY seq_id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_SEED

    def store(
        self,
        evaluation: EvaluationResult,
        tool_name: str,
    ) -> EvidenceRecord:
        """Convert an EvaluationResult into an evidence record and persist it."""
        record_id = str(uuid.uuid4())
        previous_hash = self._get_last_hash()

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
            tool_name=tool_name,
            decision=evaluation.decision,
            mode=evaluation.mode,
            control_results=control_results_data,
            active_overlays=evaluation.active_overlays,
            data_classifications=evaluation.data_classifications,
            active_certifications=self._certifications,
            total_duration_ms=evaluation.total_duration_ms,
            previous_hash=previous_hash,
        )
        record_hash = compute_hash(canon)

        record = EvidenceRecord(
            record_id=record_id,
            evaluation_id=evaluation.evaluation_id,
            timestamp=evaluation.timestamp,
            agent_id=evaluation.agent_id,
            tool_name=tool_name,
            decision=evaluation.decision,
            mode=evaluation.mode,
            control_results=control_results_data,
            active_overlays=evaluation.active_overlays,
            data_classifications=evaluation.data_classifications,
            active_certifications=self._certifications,
            record_hash=record_hash,
            previous_hash=previous_hash,
            total_duration_ms=evaluation.total_duration_ms,
        )

        self._conn.execute(INSERT_SQL, [
            record.record_id,
            record.evaluation_id,
            record.timestamp,
            record.agent_id,
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
        ])

        return record

    def get_records(
        self,
        agent_id: str | None = None,
        tool_name: str | None = None,
        decision: str | None = None,
        limit: int = 100,
    ) -> list[EvidenceRecord]:
        """Query evidence records with optional filters."""
        conditions: list[str] = []
        params: list[Any] = []

        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if tool_name is not None:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if decision is not None:
            conditions.append("decision = ?")
            params.append(decision)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM evidence_records{where} ORDER BY seq_id ASC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def count(self) -> int:
        """Return total number of evidence records."""
        row = self._conn.execute("SELECT COUNT(*) FROM evidence_records").fetchone()
        return row[0] if row else 0

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the hash chain integrity. Returns (valid, errors)."""
        rows = self._conn.execute(
            "SELECT * FROM evidence_records ORDER BY seq_id ASC"
        ).fetchall()

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
                tool_name=record.tool_name,
                decision=record.decision,
                mode=record.mode,
                control_results=record.control_results,
                active_overlays=record.active_overlays,
                data_classifications=record.data_classifications,
                active_certifications=record.active_certifications,
                total_duration_ms=record.total_duration_ms,
                previous_hash=record.previous_hash,
            )
            expected_hash = compute_hash(canon)

            if record.record_hash != expected_hash:
                errors.append(
                    f"Record {record.record_id}: hash mismatch. "
                    f"Expected {expected_hash[:16]}..., got {record.record_hash[:16]}..."
                )

            expected_previous = record.record_hash

        return len(errors) == 0, errors

    def get_summary(self) -> dict[str, Any]:
        """Generate a summary for posture reports (Unit 6)."""
        total = self.count()
        if total == 0:
            return {
                "total_evaluations": 0,
                "decisions": {},
                "tools_evaluated": [],
                "chain_valid": True,
                "chain_errors": [],
            }

        # Decision counts
        decision_rows = self._conn.execute(
            "SELECT decision, COUNT(*) FROM evidence_records GROUP BY decision"
        ).fetchall()
        decisions = {row[0]: row[1] for row in decision_rows}

        # Unique tools
        tool_rows = self._conn.execute(
            "SELECT DISTINCT tool_name FROM evidence_records ORDER BY tool_name"
        ).fetchall()
        tools = [row[0] for row in tool_rows]

        # Chain integrity
        chain_valid, chain_errors = self.verify_chain()

        # Control pass rates
        control_rows = self._conn.execute(
            "SELECT control_results FROM evidence_records"
        ).fetchall()
        control_stats: dict[str, dict[str, int]] = {}
        for (cr_json,) in control_rows:
            results = json.loads(cr_json) if isinstance(cr_json, str) else cr_json
            for cr in results:
                cid = cr["control_id"]
                if cid not in control_stats:
                    control_stats[cid] = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
                result = cr.get("result", "SKIP")
                if result in control_stats[cid]:
                    control_stats[cid][result] += 1

        return {
            "total_evaluations": total,
            "decisions": decisions,
            "tools_evaluated": tools,
            "control_pass_rates": control_stats,
            "chain_valid": chain_valid,
            "chain_errors": chain_errors,
        }

    def purge_before(self, before_timestamp: str) -> int:
        """Remove records older than the given ISO timestamp. Returns count removed."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM evidence_records WHERE timestamp < ?",
            [before_timestamp],
        ).fetchone()
        count = row[0] if row else 0

        if count > 0:
            self._conn.execute(
                "DELETE FROM evidence_records WHERE timestamp < ?",
                [before_timestamp],
            )

        return count

    @staticmethod
    def _row_to_record(row: tuple) -> EvidenceRecord:
        """Convert a DuckDB row tuple to an EvidenceRecord.

        Column order: seq_id, record_id, evaluation_id, timestamp, agent_id,
        tool_name, decision, mode, control_results, active_overlays,
        data_classifications, active_certifications, record_hash,
        previous_hash, total_duration_ms
        """
        return EvidenceRecord(
            record_id=row[1],
            evaluation_id=row[2],
            timestamp=row[3],
            agent_id=row[4],
            tool_name=row[5],
            decision=row[6],
            mode=row[7],
            control_results=json.loads(row[8]) if isinstance(row[8], str) else row[8],
            active_overlays=json.loads(row[9]) if isinstance(row[9], str) else row[9],
            data_classifications=json.loads(row[10]) if isinstance(row[10], str) else row[10],
            active_certifications=json.loads(row[11]) if isinstance(row[11], str) else row[11],
            record_hash=row[12],
            previous_hash=row[13],
            total_duration_ms=row[14],
        )
