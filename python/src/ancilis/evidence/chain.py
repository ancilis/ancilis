"""Cryptographic hash chain for evidence records."""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Genesis seed — the "previous_hash" for the very first record in any chain.
GENESIS_SEED = hashlib.sha256(b"ancilis-genesis-v1").hexdigest()
_MISSING = object()


def canonical_payload(
    evaluation_id: str,
    timestamp: str,
    agent_id: str,
    source_type: str,
    tool_name: str,
    decision: str,
    mode: str,
    control_results: list[dict[str, Any]],
    active_overlays: list[str],
    data_classifications: list[str],
    active_certifications: list[str],
    total_duration_ms: float,
    previous_hash: str,
    output_summary: str | None = None,
    session_id: str | None = None,
    tenant_id: str | None = None,
    *,
    detected_data_types: list[str] | None | object = _MISSING,
    sdk_version: str | None | object = _MISSING,
    framework_version: str | None | object = _MISSING,
    classification_context: dict[str, Any] | None | object = _MISSING,
) -> str:
    """Build the canonical JSON string used as hash input.

    Fields are sorted alphabetically for determinism.
    Storage-owned columns are intentionally excluded: seq_id and record_id are
    persistence addresses, and record_hash is the output of this payload.
    Omit integrity metadata only when verifying records written before the
    ANC-922 hash payload expansion.
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
        "source_type": source_type,
        "timestamp": timestamp,
        "tool_name": tool_name,
        "total_duration_ms": total_duration_ms,
    }
    if output_summary is not None:
        payload["output_summary"] = output_summary
    if session_id is not None:
        payload["session_id"] = session_id
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    if detected_data_types is not _MISSING:
        payload["detected_data_types"] = detected_data_types or []
    if sdk_version is not _MISSING:
        payload["sdk_version"] = sdk_version
    if framework_version is not _MISSING:
        payload["framework_version"] = framework_version
    if classification_context is not _MISSING:
        payload["classification_context"] = classification_context or {}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(canonical: str) -> str:
    """SHA-256 hash of the canonical payload."""
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
