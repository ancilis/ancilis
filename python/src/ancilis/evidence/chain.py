"""Cryptographic hash chain for evidence records."""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Genesis seed — the "previous_hash" for the very first record in any chain.
GENESIS_SEED = hashlib.sha256(b"ancilis-genesis-v1").hexdigest()


def canonical_payload(
    evaluation_id: str,
    timestamp: str,
    agent_id: str,
    tool_name: str,
    decision: str,
    mode: str,
    control_results: list[dict[str, Any]],
    active_overlays: list[str],
    data_classifications: list[str],
    active_certifications: list[str],
    total_duration_ms: float,
    previous_hash: str,
) -> str:
    """Build the canonical JSON string used as hash input.

    Fields are sorted alphabetically for determinism.
    """
    payload = {
        "active_certifications": active_certifications,
        "active_overlays": active_overlays,
        "agent_id": agent_id,
        "control_results": control_results,
        "data_classifications": data_classifications,
        "decision": decision,
        "evaluation_id": evaluation_id,
        "mode": mode,
        "previous_hash": previous_hash,
        "timestamp": timestamp,
        "tool_name": tool_name,
        "total_duration_ms": total_duration_ms,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(canonical: str) -> str:
    """SHA-256 hash of the canonical payload."""
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
