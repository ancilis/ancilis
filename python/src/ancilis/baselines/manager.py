from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from ancilis.baselines.drift import DriftDetector, _compute_control_stats, _dominant_result, _pass_rate
from ancilis.baselines.models import Baseline, ControlSnapshot, DriftReport

if TYPE_CHECKING:
    from ancilis.config import ResolvedConfig
    from ancilis.evidence.store import EvidenceStore

CREATE_BASELINES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS baselines (
    baseline_id VARCHAR PRIMARY KEY,
    created_at VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    overlay_id VARCHAR,
    label VARCHAR NOT NULL,
    control_snapshots JSON NOT NULL,
    metadata JSON,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
"""


class BaselineManager:
    """Manages baseline snapshots and drift detection against the evidence store."""

    def __init__(self, evidence_store: EvidenceStore, config: ResolvedConfig) -> None:
        self._store = evidence_store
        self._config = config
        self._detector = DriftDetector()
        self._ensure_table()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_table(self) -> None:
        self._store._connection.execute(CREATE_BASELINES_TABLE_SQL)

    def _conn(self):  # type: ignore[return]
        return self._store._connection

    def _agent_id(self) -> str:
        return getattr(self._config, "agent_name", "") or "default"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(
        self,
        label: str,
        overlay_id: str | None = None,
        evidence_window_hours: int = 168,
        metadata: dict[str, Any] | None = None,
    ) -> Baseline:
        """Snapshot current posture from the evidence window into a new baseline.

        Deactivates any existing active baseline for the same agent+overlay pair.
        """
        agent_id = self._agent_id()
        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(hours=evidence_window_hours)).isoformat()
        window_end = now.isoformat()

        # Fetch evidence in the window
        conditions = ["timestamp >= ?"]
        params: list[Any] = [window_start]
        if overlay_id is not None:
            # Filter by overlay presence in active_overlays JSON array
            conditions.append("active_overlays LIKE ?")
            params.append(f"%{overlay_id}%")

        where = " WHERE " + " AND ".join(conditions)
        rows = self._conn().execute(
            "SELECT control_results FROM evidence_records" + where,
            params,
        ).fetchall()

        stats = _compute_control_stats(rows)

        snapshots = [
            ControlSnapshot(
                control_id=cid,
                result=_dominant_result(s),
                pass_rate=_pass_rate(s),
                total_evaluations=s["total"],
                evidence_window_start=window_start,
                evidence_window_end=window_end,
            )
            for cid, s in stats.items()
        ]

        # Deactivate existing active baseline for same agent+overlay
        if overlay_id is not None:
            self._conn().execute(
                "UPDATE baselines SET is_active = FALSE "
                "WHERE agent_id = ? AND overlay_id = ? AND is_active = TRUE",
                [agent_id, overlay_id],
            )
        else:
            self._conn().execute(
                "UPDATE baselines SET is_active = FALSE "
                "WHERE agent_id = ? AND overlay_id IS NULL AND is_active = TRUE",
                [agent_id],
            )

        baseline_id = str(uuid.uuid4())
        baseline = Baseline(
            baseline_id=baseline_id,
            created_at=now.isoformat(),
            agent_id=agent_id,
            overlay_id=overlay_id,
            label=label,
            control_snapshots=snapshots,
            metadata=metadata,
            is_active=True,
        )

        self._conn().execute(
            "INSERT INTO baselines "
            "(baseline_id, created_at, agent_id, overlay_id, label, "
            "control_snapshots, metadata, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                baseline.baseline_id,
                baseline.created_at,
                baseline.agent_id,
                baseline.overlay_id,
                baseline.label,
                json.dumps([s.__dict__ for s in baseline.control_snapshots]),
                json.dumps(baseline.metadata) if baseline.metadata else None,
                baseline.is_active,
            ],
        )

        return baseline

    def list_baselines(self, overlay_id: str | None = None) -> list[Baseline]:
        """Return baselines for this agent, optionally filtered by overlay."""
        agent_id = self._agent_id()
        if overlay_id is not None:
            rows = self._conn().execute(
                "SELECT baseline_id, created_at, agent_id, overlay_id, label, "
                "control_snapshots, metadata, is_active FROM baselines "
                "WHERE agent_id = ? AND overlay_id = ? ORDER BY created_at DESC",
                [agent_id, overlay_id],
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT baseline_id, created_at, agent_id, overlay_id, label, "
                "control_snapshots, metadata, is_active FROM baselines "
                "WHERE agent_id = ? ORDER BY created_at DESC",
                [agent_id],
            ).fetchall()
        return [self._row_to_baseline(r) for r in rows]

    def get_baseline(self, baseline_id: str) -> Baseline:
        """Fetch a single baseline by ID. Raises KeyError if not found."""
        row = self._conn().execute(
            "SELECT baseline_id, created_at, agent_id, overlay_id, label, "
            "control_snapshots, metadata, is_active FROM baselines "
            "WHERE baseline_id = ?",
            [baseline_id],
        ).fetchone()
        if row is None:
            raise KeyError(f"Baseline not found: {baseline_id}")
        return self._row_to_baseline(row)

    def check_drift(
        self,
        baseline_id: str | None = None,
        overlay_id: str | None = None,
    ) -> DriftReport:
        """Run drift detection against the most recent (or specified) baseline.

        If baseline_id is None, uses the most recent active baseline for the
        agent (optionally scoped to overlay_id).
        """
        agent_id = self._agent_id()

        if baseline_id is not None:
            baseline = self.get_baseline(baseline_id)
        else:
            # Find most recent active baseline
            if overlay_id is not None:
                row = self._conn().execute(
                    "SELECT baseline_id, created_at, agent_id, overlay_id, label, "
                    "control_snapshots, metadata, is_active FROM baselines "
                    "WHERE agent_id = ? AND overlay_id = ? AND is_active = TRUE "
                    "ORDER BY created_at DESC LIMIT 1",
                    [agent_id, overlay_id],
                ).fetchone()
            else:
                row = self._conn().execute(
                    "SELECT baseline_id, created_at, agent_id, overlay_id, label, "
                    "control_snapshots, metadata, is_active FROM baselines "
                    "WHERE agent_id = ? AND is_active = TRUE "
                    "ORDER BY created_at DESC LIMIT 1",
                    [agent_id],
                ).fetchone()
            if row is None:
                raise KeyError("No active baseline found. Run 'ancilis baseline create' first.")
            baseline = self._row_to_baseline(row)

        # Fetch evidence since baseline was created
        since = baseline.created_at
        conditions = ["timestamp >= ?"]
        params: list[Any] = [since]
        if baseline.overlay_id is not None:
            conditions.append("active_overlays LIKE ?")
            params.append(f"%{baseline.overlay_id}%")

        where = " WHERE " + " AND ".join(conditions)
        rows = self._conn().execute(
            "SELECT control_results FROM evidence_records" + where,
            params,
        ).fetchall()

        current_stats = _compute_control_stats(rows)

        # Collect first failure timestamps per control
        first_failures: dict[str, str | None] = {}
        for cid in current_stats:
            fail_row = self._conn().execute(
                "SELECT MIN(timestamp) FROM evidence_records "
                "WHERE timestamp >= ? AND control_results LIKE ?",
                [since, f'%"control_id": "{cid}"%'],
            ).fetchone()
            first_failures[cid] = fail_row[0] if fail_row and fail_row[0] else None

        return self._detector.detect(baseline, current_stats, first_failures)

    def deactivate(self, baseline_id: str) -> None:
        """Mark a baseline as inactive."""
        self._conn().execute(
            "UPDATE baselines SET is_active = FALSE WHERE baseline_id = ?",
            [baseline_id],
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_baseline(row: tuple[Any, ...]) -> Baseline:
        snapshots_raw = json.loads(row[5]) if isinstance(row[5], str) else row[5]
        snapshots = [ControlSnapshot(**s) for s in snapshots_raw]
        metadata_raw = row[6]
        metadata = json.loads(metadata_raw) if isinstance(metadata_raw, str) else metadata_raw
        return Baseline(
            baseline_id=row[0],
            created_at=row[1],
            agent_id=row[2],
            overlay_id=row[3],
            label=row[4],
            control_snapshots=snapshots,
            metadata=metadata,
            is_active=bool(row[7]),
        )
