"""Cryptographic hash chain for evidence records."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

# Genesis seed — the "previous_hash" for the very first record in any chain.
# NOTE: This is a PUBLIC constant. It is the genesis for the legacy v1 (unkeyed
# SHA-256) chain format. v1 hashes are not cryptographically attestable against
# a writer-capable adversary; v2 (keyed HMAC) is what protects integrity.
GENESIS_SEED = hashlib.sha256(b"ancilis-genesis-v1").hexdigest()
_MISSING = object()

# Chain format versions. v1 = legacy unkeyed SHA-256 (pre-migration records).
# v2 = HMAC-SHA256 keyed chaining; the version is bound into the MAC input so a
# record cannot be silently downgraded to the weaker format.
CHAIN_FORMAT_V1 = 1
CHAIN_FORMAT_V2 = 2
CURRENT_CHAIN_FORMAT = CHAIN_FORMAT_V2

# Environment variable holding the chain key (preferred for CI/servers).
CHAIN_KEY_ENV = "ANCILIS_CHAIN_KEY"
# OS keyring coordinates (optional `keyring` dependency).
_KEYRING_SERVICE = "ancilis"
_KEYRING_USERNAME = "chain-key"


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
    """Legacy v1 hash: unkeyed SHA-256 of the canonical payload.

    Retained ONLY to verify pre-migration (v1) records. New records use
    :func:`compute_keyed_hash`. An unkeyed hash cannot prove integrity against
    an attacker who can write the DB (they can recompute it), so v1 records are
    reported by verify_chain as "legacy-unverified", never as cryptographically
    verified.
    """
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_keyed_hash(canonical: str, key: bytes, *, version: int = CHAIN_FORMAT_V2) -> str:
    """v2 chain hash: HMAC-SHA256 over the canonical payload, keyed and versioned.

    The format version is bound into the MAC input (``vN:<canonical>``) so a
    record's version cannot be tampered without invalidating the MAC, and a v2
    record can never be re-interpreted under the weaker v1 rules.
    """
    message = f"v{version}:{canonical}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class ChainKeyError(RuntimeError):
    """Raised/surfaced when a keyed (v2) chain cannot be verified without a key."""


def resolve_chain_key(explicit: bytes | str | None = None) -> bytes | None:
    """Resolve the evidence-chain HMAC key from outside the database.

    Precedence (key is intentionally NEVER stored in the evidence DB):
      1. an explicit value passed by the caller / KMS integration,
      2. the ``ANCILIS_CHAIN_KEY`` environment variable,
      3. the OS keyring (service ``ancilis``, username ``chain-key``) if the
         optional ``keyring`` package is installed.

    Returns the key as bytes, or ``None`` if no key is configured.
    """
    if explicit is not None:
        return explicit.encode("utf-8") if isinstance(explicit, str) else explicit
    env = os.environ.get(CHAIN_KEY_ENV)
    if env:
        return env.encode("utf-8")
    try:  # optional dependency; absence simply means "no keyring source"
        import keyring

        stored: str | None = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        if stored:
            return stored.encode("utf-8")
    except Exception:  # noqa: BLE001 — keyring is best-effort, never fatal
        pass
    return None
