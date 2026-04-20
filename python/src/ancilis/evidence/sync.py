"""Manual evidence sync engine."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from ancilis.config import ResolvedConfig
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.platform.client import (
    PlatformBatchResponse,
    PlatformClient,
    PlatformConnectionError,
    PlatformHTTPError,
)


class EvidenceBatchClient(Protocol):
    def post_evidence_batch(self, records: list[dict[str, Any]]) -> PlatformBatchResponse:
        """Post one evidence batch and return per-record results."""


@dataclass
class SyncResult:
    status: str
    offline_mode: str
    pending: int = 0
    attempted: int = 0
    synced: int = 0
    failed: int = 0
    batches: int = 0
    would_send: int = 0
    message: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SyncEngine:
    """Synchronize local DuckDB evidence to the platform on demand."""

    def __init__(
        self,
        config: ResolvedConfig,
        store: EvidenceStore,
        *,
        client: EvidenceBatchClient | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._client = client
        self._now = now or (lambda: datetime.now(timezone.utc))

    def sync_once(self, *, limit: int | None = None, dry_run: bool = False) -> SyncResult:
        pending_records = self._store.get_pending_sync_records(now=self._now_iso())
        selected_records = pending_records[:limit] if limit is not None else pending_records
        result = SyncResult(
            status="noop",
            offline_mode=self._config.sync_offline_mode,
            pending=len(pending_records),
            would_send=len(selected_records) if dry_run else 0,
        )

        if self._config.sync_offline_mode == "always_offline":
            result.message = "sync skipped because sync.offline_mode is always_offline"
            return result
        if dry_run:
            result.status = "dry_run"
            result.message = "dry run only; no evidence sync state was changed"
            return result
        if not selected_records:
            result.message = "no pending evidence records to sync"
            return result

        client = self._client or self._build_client()
        if client is None:
            result.status = "failed" if self._config.sync_offline_mode == "always_online" else "pending"
            result.message = "platform sync is not configured; pending evidence remains local"
            result.errors.append(result.message)
            return result

        for batch in _chunks(selected_records, self._batch_size()):
            serialized = [serialize_evidence_record(record) for record in batch]
            result.attempted += len(batch)
            result.batches += 1
            try:
                response = client.post_evidence_batch(serialized)
            except PlatformConnectionError as exc:
                self._mark_batch_failed(batch, str(exc), result, transient=True)
                continue
            except PlatformHTTPError as exc:
                self._mark_batch_failed(
                    batch,
                    exc.message,
                    result,
                    transient=_is_transient_status(exc.status_code),
                    status_code=exc.status_code,
                )
                continue

            self._apply_item_results(batch, response, result)

        if result.failed:
            result.status = (
                "failed"
                if self._config.sync_offline_mode == "always_online"
                else "pending"
            )
            result.message = "sync completed with failures; evidence remains local"
        elif result.synced:
            result.status = "synced"
            result.message = f"synced {result.synced} evidence record(s)"
        return result

    def _build_client(self) -> PlatformClient | None:
        if not self._config.platform_url:
            return None
        api_key = os.environ.get(self._config.platform_api_key_env)
        if not api_key:
            return None
        return PlatformClient(self._config.platform_url, api_key)

    def _batch_size(self) -> int:
        return max(1, min(int(self._config.sync_batch_size), 100))

    def _apply_item_results(
        self,
        batch: list[EvidenceRecord],
        response: PlatformBatchResponse,
        result: SyncResult,
    ) -> None:
        by_record_id = {item.record_id: item for item in response.results}
        for record in batch:
            item = by_record_id.get(record.record_id)
            if item is None:
                self._mark_record_failed(
                    record,
                    "platform response omitted record result",
                    result,
                    transient=True,
                )
                continue
            if _is_success_status(item.status_code) or item.status_code == 409:
                self._store.mark_sync_synced(
                    record.record_id,
                    synced_at=self._now_iso(),
                    remote_status_code=item.status_code,
                    remote_evidence_id=item.remote_evidence_id,
                )
                result.synced += 1
            elif _is_transient_status(item.status_code):
                self._mark_record_failed(
                    record,
                    item.error or f"platform returned HTTP {item.status_code}",
                    result,
                    transient=True,
                    status_code=item.status_code,
                )
            else:
                self._mark_record_failed(
                    record,
                    item.error or f"platform returned HTTP {item.status_code}",
                    result,
                    transient=False,
                    status_code=item.status_code,
                )

    def _mark_batch_failed(
        self,
        batch: list[EvidenceRecord],
        error: str,
        result: SyncResult,
        *,
        transient: bool,
        status_code: int | None = None,
    ) -> None:
        for record in batch:
            self._mark_record_failed(
                record,
                error,
                result,
                transient=transient,
                status_code=status_code,
            )

    def _mark_record_failed(
        self,
        record: EvidenceRecord,
        error: str,
        result: SyncResult,
        *,
        transient: bool,
        status_code: int | None = None,
    ) -> None:
        self._store.mark_sync_failed(
            record.record_id,
            error=error,
            attempted_at=self._now_iso(),
            next_retry_at=self._next_retry_at(record) if transient else None,
            remote_status_code=status_code,
        )
        result.failed += 1
        prefix = "transient" if transient else "permanent"
        result.errors.append(f"{prefix}: {error}")

    def _next_retry_at(self, record: EvidenceRecord) -> str | None:
        state = self._store.get_sync_state(record.record_id)
        attempt_count = state.attempt_count if state else 0
        if attempt_count >= self._config.sync_max_retries:
            return None
        delay = self._config.sync_backoff_base_seconds * (2**attempt_count)
        return _format_iso(self._now() + timedelta(seconds=delay))

    def _now_iso(self) -> str:
        return _format_iso(self._now())


def serialize_evidence_record(record: EvidenceRecord) -> dict[str, Any]:
    return {
        "record_id": record.record_id,
        "evaluation_id": record.evaluation_id,
        "record_hash": record.record_hash,
        "previous_hash": record.previous_hash,
        "agent_id": record.agent_id,
        "source_type": record.source_type,
        "tool_name": record.tool_name,
        "decision": record.decision,
        "mode": record.mode,
        "timestamp": record.timestamp,
        "controls": record.control_results,
        "overlays": record.active_overlays,
        "classifications": record.data_classifications,
        "certifications": record.active_certifications,
        "session": record.session_id,
        "tenant": record.tenant_id,
        "sdk_version": record.sdk_version,
        "classification_context": record.classification_context,
        "detected_data_types": record.detected_data_types,
        "total_duration_ms": record.total_duration_ms,
        "output_summary": record.output_summary,
    }


def _chunks(records: list[EvidenceRecord], size: int) -> list[list[EvidenceRecord]]:
    return [records[index : index + size] for index in range(0, len(records), size)]


def _is_success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def _is_transient_status(status_code: int) -> bool:
    return status_code in {408, 429} or status_code >= 500


def _format_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00",
        "Z",
    )
