"""ancilis sync - manual evidence sync command."""

from __future__ import annotations

import json
from pathlib import Path

import click

from ancilis.cli.status import _load_config_safe
from ancilis.evidence.store import EvidenceStore
from ancilis.evidence.sync import SyncEngine, SyncResult


@click.command()
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--limit", type=click.IntRange(min=1), default=None, help="Maximum records to sync")
@click.option("--dry-run", is_flag=True, help="Show what would sync without mutating state")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON")
def sync(
    config_path: str | None,
    db_path: str | None,
    limit: int | None,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Manually sync pending local evidence to the Ancilis platform."""
    config = _load_config_safe(config_path)
    if config is None:
        raise SystemExit(1)

    store = EvidenceStore(config, db_path=Path(db_path) if db_path else None)
    try:
        result = SyncEngine(config, store).sync_once(limit=limit, dry_run=dry_run)
    finally:
        store.close()

    if json_output:
        click.echo(json.dumps(result.to_dict(), sort_keys=True))
    else:
        click.echo(_format_sync_result(result))

    if config.sync_offline_mode == "always_online" and result.status == "failed":
        raise SystemExit(1)


def _format_sync_result(result: SyncResult) -> str:
    if result.status == "dry_run":
        return (
            f"Would sync {result.would_send} pending evidence "
            f"{_record_word(result.would_send)} ({result.pending} pending locally)."
        )
    if result.status == "noop":
        return f"Sync skipped: {result.message}"
    if result.status == "synced":
        return (
            f"Sync complete: {result.synced} evidence {_record_word(result.synced)} "
            f"synced in {result.batches} {_batch_word(result.batches)}."
        )
    if result.status == "pending":
        return (
            f"Sync pending: {result.failed} evidence {_record_word(result.failed)} "
            f"failed transiently and remain local."
        )
    if result.status == "failed":
        if result.failed == 0 and result.message:
            return f"Sync failed: {result.message}"
        return (
            f"Sync failed: {result.failed} evidence {_record_word(result.failed)} "
            "could not be synced. Evidence remains local."
        )
    return result.message or "Sync finished."


def _record_word(count: int) -> str:
    return "record" if count == 1 else "records"


def _batch_word(count: int) -> str:
    return "batch" if count == 1 else "batches"
