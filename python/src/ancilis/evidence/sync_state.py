"""Evidence sync metadata models."""

from __future__ import annotations

from dataclasses import dataclass


SYNC_STATUS_PENDING = "pending_sync"
SYNC_STATUS_SYNCED = "synced"
SYNC_STATUS_FAILED = "sync_failed"


@dataclass(frozen=True)
class EvidenceSyncState:
    record_id: str
    status: str
    attempt_count: int
    last_attempt_at: str | None = None
    last_synced_at: str | None = None
    last_error: str | None = None
    next_retry_at: str | None = None
    remote_status_code: int | None = None
    remote_evidence_id: str | None = None


@dataclass(frozen=True)
class EvidenceSyncSummary:
    pending_count: int
    failed_count: int
    last_sync_at: str | None = None
    last_error: str | None = None
    next_retry_at: str | None = None
