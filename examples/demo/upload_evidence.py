#!/usr/bin/env python3
"""Upload evidence records from a local DuckDB store to the Ancilis Platform API.

Bridges the gap between the local demo flow (DuckDB on disk) and Railway
deployments that have no local filesystem access.  Reads every record from
the evidence store and POST-s them in batches to ``POST /v1/evidence/ingest``.

Usage::

    python examples/demo/upload_evidence.py \\
        --db-path ~/.ancilis/finance-demo-agent-<hash>/evidence.duckdb \\
        --api-url https://app.ancilis.ai \\
        --auth-token <bearer-token> [--source-id <uuid>] [--batch-size 50]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

# Allow running directly from repo root without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python" / "src"))

from ancilis.config import ResolvedConfig
from ancilis.evidence.store import EvidenceStore

_DEFAULT_BATCH_SIZE = 50


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Upload Ancilis evidence records to the Platform API."
    )
    p.add_argument("--db-path", required=True, help="Path to evidence.duckdb")
    p.add_argument(
        "--api-url",
        required=True,
        help="Platform API base URL, e.g. https://app.ancilis.ai",
    )
    p.add_argument("--auth-token", required=True, help="Bearer auth token")
    p.add_argument(
        "--source-id",
        default=None,
        help=(
            "Integration UUID sent as source_id in every batch. "
            "Defaults to a UUID5 derived from the DB path so the same store "
            "always maps to the same source."
        ),
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=_DEFAULT_BATCH_SIZE,
        help=f"Records per HTTP request (default {_DEFAULT_BATCH_SIZE})",
    )
    return p.parse_args()


def _record_to_dict(rec) -> dict:  # type: ignore[type-arg]
    return {
        "record_id": rec.record_id,
        "evaluation_id": rec.evaluation_id,
        "timestamp": rec.timestamp,
        "agent_id": rec.agent_id,
        "session_id": rec.session_id,
        "source_type": rec.source_type,
        "tool_name": rec.tool_name,
        "decision": rec.decision,
        "mode": rec.mode,
        "control_results": rec.control_results,
        "active_overlays": rec.active_overlays,
        "data_classifications": rec.data_classifications,
        "active_certifications": rec.active_certifications,
        "output_summary": rec.output_summary,
        "record_hash": rec.record_hash,
        "previous_hash": rec.previous_hash,
        "total_duration_ms": rec.total_duration_ms,
    }


def _post_batch(api_url: str, token: str, source_id: str, records: list[dict]) -> dict:  # type: ignore[type-arg]
    payload = json.dumps({"source_id": source_id, "records": records}).encode()
    req = urllib.request.Request(
        api_url.rstrip("/") + "/v1/evidence/ingest",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())  # type: ignore[return-value]


def main() -> int:
    args = _parse_args()

    db_path = Path(args.db_path).expanduser().resolve()
    if not db_path.exists():
        print(f"error: DB not found: {db_path}", file=sys.stderr)
        return 1

    source_id = args.source_id or str(uuid.uuid5(uuid.NAMESPACE_DNS, str(db_path)))

    cfg = ResolvedConfig()
    store = EvidenceStore(cfg, db_path=db_path)
    records = store.get_records(limit=None)

    if not records:
        print("No evidence records found — nothing to upload.")
        return 0

    total = len(records)
    print(f"Found {total} record(s) in {db_path}")
    print(f"Uploading to {args.api_url}  (source_id={source_id})")

    batches = [
        records[i : i + args.batch_size] for i in range(0, total, args.batch_size)
    ]
    n_batches = len(batches)

    ingested = 0
    deduped = 0
    failed = 0

    for idx, batch in enumerate(batches, 1):
        dicts = [_record_to_dict(r) for r in batch]
        try:
            resp = _post_batch(args.api_url, args.auth_token, source_id, dicts)
            batch_ingested = resp.get("evidence_ingested", 0)
            batch_deduped = resp.get("evidence_deduplicated", 0)
            ingested += batch_ingested
            deduped += batch_deduped
            print(
                f"  batch {idx}/{n_batches}: "
                f"{batch_ingested} ingested, {batch_deduped} deduplicated"
            )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")[:300]
            print(
                f"  batch {idx}/{n_batches}: HTTP {exc.code} — {body}",
                file=sys.stderr,
            )
            failed += len(batch)
        except Exception as exc:  # noqa: BLE001
            print(f"  batch {idx}/{n_batches}: error — {exc}", file=sys.stderr)
            failed += len(batch)

    print(
        f"\nDone: {ingested} ingested, {deduped} deduplicated, {failed} failed"
        + (" — check errors above" if failed else "")
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
