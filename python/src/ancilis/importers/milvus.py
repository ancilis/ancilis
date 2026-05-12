"""Milvus distributed vector database audit-event importer — converts proxy access logs to AKSI EvaluationResults.

Milvus (https://milvus.io) is the largest open-source distributed vector
database, used at billion-vector tier by enterprises with very large RAG and
recommendation workloads. When the proxy access log is enabled in
``milvus.yaml`` under ``proxy.accesslog``, every collection / partition / index
/ user / role operation is captured. This importer turns each event into one
EvaluationResult. Different from Pinecone (managed namespaces) and Weaviate
(class+tenant) — Milvus has a distinct shard / collection / partition model
plus a first-class RBAC surface with users, roles, privileges, and a
``root`` superuser. Misuse of root or admin grants in a Milvus deployment is
the equivalent of running production code as AWS root.

Accepted on-disk shapes:

  1. Envelope with events:    ``{"events": [{...}, ...]}``  (canonical)
  2. Generic data envelope:   ``{"data": [{...}, ...]}``
  3. JSON array:              ``[{...}, {...}]``
  4. Single object:           ``{...}``  (treated as one event)
  5. JSONL stream:            one JSON object per line

Signal mapping (see shared/mappings/milvus-aksi-controls.json):

  Per-operation success
    * ``Search`` / ``Query``                            → PR-04 PASS  (data access governance)
    * ``Insert`` / ``Upsert``                           → PR-03 PASS  (provenance)
    * ``Delete``                                        → PR-05 PASS  (audit trail)

  Schema lifecycle (always FLAG, even on success)
    * ``CreateCollection`` / ``DropCollection``         → PR-05 FLAG  (schema lifecycle)
    * ``AlterCollection``                               → PR-05 FLAG  (schema change)
    * ``CreateIndex`` / ``DropIndex``                   → PR-05 FLAG  (perf-shape change)

  Privileged data movement (always FLAG)
    * ``Backup`` / ``Restore``                          → PR-02 FLAG  (privileged data movement)

  RBAC surface (always FLAG; admin-target grants & drops escalate to FAIL)
    * ``CreateUser`` / ``DropUser``                     → PR-02 FLAG
    * ``CreateRole`` / ``DropRole``                     → PR-02 FLAG
    * ``GrantPrivilege`` / ``RevokePrivilege``          → PR-02 FLAG
    * ``GrantPrivilege`` with role target == db_admin / root → PR-02 FAIL (admin grant)
    * ``DropUser`` whose target user has admin role     → PR-02 FAIL (admin removal needs governance)

  Status-driven outcomes (Milvus status.code int — code=0 means OK)
    * status.code = 1 (Unauthenticated)                 → PR-01 FAIL
    * status.code = 2 (PermissionDenied)                → PR-02 FAIL
    * status.code != 0 otherwise                        → DE-01 FAIL

  Identity/posture flags
    * ``is_root=true`` on routine ops (Search/Query/Insert/Upsert/Delete)
                                                        → PR-01 FAIL  (root usage on
                                                          routine traffic — like AWS
                                                          root running production)
    * ``is_admin=true`` on read-only ops (Search/Query) → PR-02 FLAG  (over-privileged)

  Search-quality flags (additive)
    * Search with limit > threshold (default 1000)      → PR-04 FLAG  (over-fetch)
    * Search with ``expr_present=false`` (no filter)    → PR-04 FLAG  (un-scoped vector search)
    * Search with ``with_payload=true``                 → PR-04 FLAG  (payload retrieval —
                                                          agent gets the document)

  Write-consistency flag
    * Insert / Upsert with consistency_level=Eventually → PR-03 FLAG  (data integrity risk)

  Synthetic findings (cross-event correlation)
    * Same user touching > N distinct collections (default 5)
                                                        → PR-02 FLAG  (cross-collection scope expansion)
    * > N RBAC-Grant operations within a 1-hour window (default 10)
                                                        → PR-02 FLAG  (privilege-grant burst)

Sanitization — what we DO NOT store:
    * full client_ip — masked to /16 (CloudTrail-style; the first two octets
      are kept for region-tier triage, the last two are zeroed)
    * full user_agent — first 80 chars retained verbatim plus a sha256 of the
      complete value so you can correlate without storing arbitrarily long
      vendor strings
    * filter / ``expr`` value — only the boolean ``expr_present`` is consumed
      from the source; we never write the expression body anywhere
    * ``search_params.params`` content — we keep only the structural shape
      (the count of param keys + sorted key NAMES, but NOT values) because
      tunable param values can encode information about underlying data
    * output field NAMES — Milvus exports a count via ``output_fields_count``
      and we surface only that count. Field names like ``ssn_embedding`` or
      ``passport_doc`` would leak schema-level semantics that the engine
      cannot redact downstream
    * partition_names raw — only the count is captured, since partition names
      can encode tenant or business-unit identifiers

The original file's sha256 is recorded in ``source_provenance`` so downstream
evidence can detect tampering without retaining sensitive bytes.

Why ``is_root=true`` on routine ops is a FAIL, not a FLAG:
    Milvus's ``root`` user is its built-in superuser, comparable to the AWS
    root account. Using root for day-to-day Search/Query/Insert traffic is a
    direct compliance violation under SOC 2 CC6.1, ISO 27001 A.9, and the AKSI
    PR-01 identity control: routine work should be performed by scoped service
    identities. A single Search-with-is_root true event indicates a
    misconfigured deployment, not just a posture nudge — hence FAIL.

Why a GrantPrivilege targeting db_admin or root is FAIL:
    Granting db_admin or any privilege bound to root meaningfully expands
    blast radius beyond a single-tenant scope. It is fundamentally distinct
    from a routine RBAC change (which is FLAG): admin-tier grants are the
    privilege escalation primitive that ransomware and supply-chain attackers
    most often exploit, and they require explicit governance review. Failing
    these by default forces them onto the BLOCK queue in enforce mode.

Why with_payload=true on Search is its own flag:
    Milvus search returns vector IDs by default. Setting ``with_payload=true``
    causes the server to return the underlying document content (text,
    metadata, possibly source URLs) — meaning the agent receives the actual
    record, not just a similarity reference. That converts a similarity probe
    into a data exfiltration channel, so we surface it independently of
    over-fetch and un-scoped flags.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table.
# This file lives at <repo>/python/src/ancilis/importers/milvus.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "milvus-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_OVER_FETCH_THRESHOLD = 1000
_DEFAULT_CROSS_COLLECTION_THRESHOLD = 5
_DEFAULT_PRIVILEGE_GRANT_BURST_THRESHOLD = 10
_DEFAULT_PRIVILEGE_GRANT_BURST_WINDOW_SECONDS = 3600
_USER_AGENT_PREFIX_LEN = 80

# Milvus operation tiers (case-insensitive lookup uses lowercase form).
_READ_OPS: frozenset[str] = frozenset({"search", "query"})
_INSERT_OPS: frozenset[str] = frozenset({"insert", "upsert"})
_DELETE_OPS: frozenset[str] = frozenset({"delete"})
_ROUTINE_OPS: frozenset[str] = _READ_OPS | _INSERT_OPS | _DELETE_OPS

_LIFECYCLE_OPS: dict[str, str] = {
    "createcollection": "operation_create_collection",
    "dropcollection": "operation_drop_collection",
    "altercollection": "operation_alter_collection",
    "createindex": "operation_create_index",
    "dropindex": "operation_drop_index",
}

_PRIVILEGED_DATA_OPS: dict[str, str] = {
    "backup": "operation_backup",
    "restore": "operation_restore",
}

_RBAC_OPS: frozenset[str] = frozenset({
    "createuser",
    "dropuser",
    "grantprivilege",
    "revokeprivilege",
    "createrole",
    "droprole",
})

_RBAC_GRANT_OPS: frozenset[str] = frozenset({"grantprivilege"})

# Roles that, when targeted by a GrantPrivilege, escalate to FAIL.
_ADMIN_TARGET_ROLES: frozenset[str] = frozenset({"db_admin", "root", "admin"})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load milvus-aksi-controls.json; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield dict objects from a JSONL stream, skipping blank/invalid lines."""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def _mask_client_ip(raw: Any) -> str | None:
    """Mask the last two octets of an IPv4 address (CloudTrail-style /16).

    For IPv6 we keep the first 32 bits of the network and zero the rest. If
    the input is not a parseable IP, return ``None`` so we never persist a
    raw arbitrary-string field that could be a hostname or PII.
    """
    if raw is None:
        return None
    try:
        addr = ipaddress.ip_address(str(raw))
    except (TypeError, ValueError):
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{addr}/16", strict=False)
        return str(net.network_address)
    # IPv6: zero everything beyond the first /32.
    net6 = ipaddress.ip_network(f"{addr}/32", strict=False)
    return str(net6.network_address)


def _truncate_user_agent(raw: Any) -> dict[str, Any] | None:
    """Return ``{"prefix": <first 80 chars>, "sha256": <hex>}`` for a UA string."""
    if raw is None:
        return None
    text = str(raw)
    if not text:
        return None
    return {
        "prefix": text[:_USER_AGENT_PREFIX_LEN],
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _structural_search_params(raw: Any) -> dict[str, Any]:
    """Keep only structural shape of search_params — never raw param values.

    We retain ``metric_type`` (a vendor enum like L2/IP/COSINE) and a sorted
    list of the param key NAMES under ``params``, plus a count. Values are
    discarded because tunable values like ``nprobe`` or ``ef`` reveal
    information about the underlying index / data distribution.
    """
    if not isinstance(raw, dict):
        return {}
    metric_type = raw.get("metric_type")
    params = raw.get("params")
    param_keys: list[str] = []
    if isinstance(params, dict):
        param_keys = sorted(str(k) for k in params)
    return {
        "metric_type": str(metric_type) if metric_type is not None else None,
        "param_keys": param_keys,
        "param_key_count": len(param_keys),
    }


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool_optional(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class MilvusImporter:
    """Parse a Milvus access-log export and convert to ``EvaluationResult`` records.

    The importer is import-safe: it never imports the optional ``pymilvus``
    client, so it works in environments where Milvus itself is not installed.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        over_fetch_threshold: int | None = None,
        cross_collection_threshold: int | None = None,
        privilege_grant_burst_threshold: int | None = None,
        privilege_grant_burst_window_seconds: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        self.over_fetch_threshold = int(
            over_fetch_threshold
            if over_fetch_threshold is not None
            else meta.get("over_fetch_threshold", _DEFAULT_OVER_FETCH_THRESHOLD)
        )
        self.cross_collection_threshold = int(
            cross_collection_threshold
            if cross_collection_threshold is not None
            else meta.get(
                "cross_collection_threshold", _DEFAULT_CROSS_COLLECTION_THRESHOLD
            )
        )
        self.privilege_grant_burst_threshold = int(
            privilege_grant_burst_threshold
            if privilege_grant_burst_threshold is not None
            else meta.get(
                "privilege_grant_burst_threshold",
                _DEFAULT_PRIVILEGE_GRANT_BURST_THRESHOLD,
            )
        )
        self.privilege_grant_burst_window_seconds = int(
            privilege_grant_burst_window_seconds
            if privilege_grant_burst_window_seconds is not None
            else meta.get(
                "privilege_grant_burst_window_seconds",
                _DEFAULT_PRIVILEGE_GRANT_BURST_WINDOW_SECONDS,
            )
        )

    # ------------------------------------------------------------------ public
    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Milvus access-log file and return one EvaluationResult per event.

        Synthetic EvaluationResults (cross-collection actor pattern, privilege-
        grant burst) may be appended at the end of the returned list.
        """
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Milvus access-log content from a JSON / JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # ----------------------------------------------------------------- private
    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON / JSONL / envelope and return a flat list of events."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [e for e in doc if isinstance(e, dict)]
            if isinstance(doc, dict):
                for envelope_key in ("events", "data", "logs"):
                    payload = doc.get(envelope_key)
                    if isinstance(payload, list):
                        return [e for e in payload if isinstance(e, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "milvus",
            "source_tool_name": "milvus",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # Pre-pass: figure out which users have an admin role (for DropUser FAIL).
        admin_users: set[str] = set()
        for ev in events:
            user = ev.get("user")
            role = str(ev.get("role") or "").lower()
            if isinstance(user, str) and role in _ADMIN_TARGET_ROLES:
                admin_users.add(user)

        results: list[EvaluationResult] = [
            self._parse_event(e, file_sha256=file_sha256, admin_users=admin_users)
            for e in events
        ]

        cross_collection = self._cross_collection_finding(
            events, file_sha256=file_sha256
        )
        if cross_collection is not None:
            results.append(cross_collection)

        privilege_burst = self._privilege_grant_burst_finding(
            events, file_sha256=file_sha256
        )
        if privilege_burst is not None:
            results.append(privilege_burst)
        return results

    # ---------------------------------------------------------------- per-event
    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        admin_users: set[str],
    ) -> EvaluationResult:
        event_id = str(
            event.get("id") or event.get("request_id") or uuid.uuid4()
        )
        operation_raw = str(event.get("operation") or "").strip()
        operation = operation_raw.lower()
        collection = str(event.get("collection_name") or "")
        partition_names = event.get("partition_names")
        partition_count = (
            len(partition_names) if isinstance(partition_names, list) else 0
        )
        consistency_level = (
            str(event.get("consistency_level")) if event.get("consistency_level") else None
        )
        user = event.get("user")
        role = str(event.get("role") or "").lower() or None
        is_admin = bool(event.get("is_admin"))
        is_root = bool(event.get("is_root"))
        rbac_action = event.get("rbac_action")

        limit = _coerce_int(event.get("limit"))
        topk = _coerce_int(event.get("topk"))
        result_count = _coerce_int(event.get("result_count"))
        output_fields_count = _coerce_int(event.get("output_fields_count"))
        duration_ms = _coerce_float(event.get("duration_ms"))
        expr_present = _coerce_bool_optional(event.get("expr_present"))
        with_payload = _coerce_bool_optional(event.get("with_payload"))

        search_params = _structural_search_params(event.get("search_params"))

        status_block = event.get("status") or {}
        if isinstance(status_block, dict):
            status_code = _coerce_int(status_block.get("code")) or 0
            status_reason = str(status_block.get("reason") or "") or None
        else:
            status_code = _coerce_int(status_block) or 0
            status_reason = None

        request_id = event.get("request_id")
        trace_id = event.get("trace_id")
        client_ip_masked = _mask_client_ip(event.get("client_ip"))
        user_agent_capsule = _truncate_user_agent(event.get("user_agent"))

        # Target user/role for RBAC ops — captured separately so we can flag
        # admin grants/drops without polluting common evidence.
        target_user = event.get("target_user") or event.get("user_target")
        target_role = (
            str(event.get("target_role") or event.get("role_target") or "").lower()
            or None
        )

        timestamp = (
            event.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )

        source_provenance = self._source_provenance(file_sha256=file_sha256)
        common_evidence: dict[str, Any] = {
            "milvus_event_id": event_id,
            "operation": operation_raw,
            "collection_name": collection,
            "partition_names_count": partition_count,
            "consistency_level": consistency_level,
            "user": str(user) if user is not None else None,
            "role": role,
            "is_admin": is_admin,
            "is_root": is_root,
            "rbac_action": rbac_action,
            "search_params": search_params,
            "topk": topk,
            "limit": limit,
            "expr_present": expr_present,
            "with_payload": with_payload,
            "output_fields_count": output_fields_count,
            "result_count": result_count,
            "duration_ms": duration_ms,
            "status_code": status_code,
            "status_reason": status_reason,
            "request_id": str(request_id) if request_id else None,
            "trace_id": str(trace_id) if trace_id else None,
            "client_ip_masked": client_ip_masked,
            "user_agent": user_agent_capsule,
            "target_user": str(target_user) if target_user else None,
            "target_role": target_role,
            "source_provenance": source_provenance,
            "source_tool": "milvus",
        }

        control_results: list[ControlResult] = []

        # 1. Status-driven failure paths take priority.
        if status_code != 0:
            if status_code == 1:
                signal, default_ctrl = "unauthenticated", "PR-01"
            elif status_code == 2:
                signal, default_ctrl = "permission_denied", "PR-02"
            else:
                signal, default_ctrl = "status_error_other", "DE-01"
            control_id = _control_for(signal, self._mappings, default_ctrl)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Milvus {operation_raw or 'op'} on collection={collection!r} "
                        f"failed with status.code={status_code} "
                        f"({status_reason or 'no reason given'})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # 2. Operation-success / lifecycle / RBAC mapping.
            self._append_operation_signal(
                operation,
                operation_raw,
                collection,
                user,
                target_user,
                target_role,
                admin_users,
                common_evidence,
                control_results,
            )

            # 3. is_root on routine ops → PR-01 FAIL (root usage in production).
            if is_root and operation in _ROUTINE_OPS:
                signal = "root_user_routine_op"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Milvus {operation_raw} on collection={collection!r} "
                            f"performed by root user (compliance violation — "
                            f"routine operations must use scoped service identities)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

            # 4. is_admin on read-only ops → PR-02 FLAG (over-privileged).
            if is_admin and not is_root and operation in _READ_OPS:
                signal = "admin_on_read_op"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Milvus {operation_raw} on collection={collection!r} "
                            f"performed by is_admin=true (over-privileged: "
                            f"read-only ops should use db_ro role)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

            # 5. Search-quality flags — only on Search operations.
            if operation == "search":
                if limit is not None and limit > self.over_fetch_threshold:
                    signal = "search_overfetch"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Milvus Search on collection={collection!r} "
                                f"requested limit={limit} above threshold="
                                f"{self.over_fetch_threshold} (potential over-fetch)"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                                "over_fetch_threshold": self.over_fetch_threshold,
                            },
                        )
                    )
                if expr_present is False:
                    signal = "search_unscoped"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Milvus Search on collection={collection!r} "
                                f"executed without filter expression "
                                f"(un-scoped vector search)"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                if with_payload is True:
                    signal = "search_with_payload"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Milvus Search on collection={collection!r} "
                                f"requested with_payload=true — agent receives "
                                f"document content in response (data exfiltration "
                                f"surface)"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )

            # 6. Eventually-consistent write — PR-03 FLAG.
            if (
                operation in _INSERT_OPS
                and consistency_level
                and consistency_level.lower() == "eventually"
            ):
                signal = "insert_eventual_consistency"
                control_id = _control_for(signal, self._mappings, "PR-03")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Milvus {operation_raw} on collection={collection!r} "
                            f"used consistency_level=Eventually (weak consistency "
                            f"on a write — provenance / data-integrity risk)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Milvus: operation={operation_raw} "
            f"collection={collection} status_code={status_code} "
            f"user={user!r}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"milvus-{event_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="milvus_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=str(request_id) if request_id else None,
        )

    def _append_operation_signal(
        self,
        operation: str,
        operation_raw: str,
        collection: str,
        user: Any,
        target_user: Any,
        target_role: str | None,
        admin_users: set[str],
        common_evidence: dict[str, Any],
        control_results: list[ControlResult],
    ) -> None:
        """Append the per-operation control result for non-error events."""
        if operation in _READ_OPS:
            signal = f"operation_{operation}_success"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Milvus {operation_raw} on collection={collection!r} "
                        f"by user={user!r} succeeded"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if operation in _INSERT_OPS:
            signal = f"operation_{operation}_success"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Milvus {operation_raw} on collection={collection!r} "
                        f"by user={user!r} succeeded"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if operation in _DELETE_OPS:
            signal = "operation_delete_success"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Milvus Delete on collection={collection!r} by "
                        f"user={user!r} succeeded (audit-trail event)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if operation in _LIFECYCLE_OPS:
            signal = _LIFECYCLE_OPS[operation]
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Milvus privileged schema op {operation_raw} on "
                        f"collection={collection!r} by user={user!r} (lifecycle "
                        f"governance event)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if operation in _PRIVILEGED_DATA_OPS:
            signal = _PRIVILEGED_DATA_OPS[operation]
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Milvus privileged data movement {operation_raw} on "
                        f"collection={collection!r} by user={user!r} — review "
                        f"backup/restore controls"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        if operation in _RBAC_OPS:
            # GrantPrivilege with admin/root target → FAIL (admin grant).
            if (
                operation == "grantprivilege"
                and target_role
                and target_role in _ADMIN_TARGET_ROLES
            ):
                signal = "admin_grant"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Milvus GrantPrivilege escalates target_role="
                            f"{target_role!r} (admin-tier grant by user={user!r}) "
                            f"— requires explicit governance review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            # DropUser whose target user has admin role → FAIL.
            if (
                operation == "dropuser"
                and isinstance(target_user, str)
                and target_user in admin_users
            ):
                signal = "admin_drop"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Milvus DropUser removes admin-tier user="
                            f"{target_user!r} (operator user={user!r}) — "
                            f"requires explicit governance review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            # Default RBAC change: PR-02 FLAG.
            signal = "rbac_change"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Milvus RBAC change {operation_raw} by user={user!r} "
                        f"(target_user={target_user!r} target_role={target_role!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return
        # Unknown / unmapped operation — PASS through under PR-04 so the
        # record exists, but tag it with a distinct signal for downstream review.
        if operation_raw:
            control_results.append(
                ControlResult(
                    control_id="PR-04",
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="PASS",
                    detail=(
                        f"Milvus operation {operation_raw} on collection="
                        f"{collection!r} (unmapped — surfaced for review)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "operation_other_success",
                    },
                )
            )

    # -------------------------------------------------------- synthetic findings

    def _cross_collection_finding(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        """Emit one synthetic FLAG when a user touches > N distinct collections.

        We pick the most-promiscuous user across the export. Returns ``None``
        when no user crosses the threshold.
        """
        user_to_collections: dict[str, set[str]] = defaultdict(set)
        user_event_counts: dict[str, int] = defaultdict(int)
        for ev in events:
            user = ev.get("user")
            collection = ev.get("collection_name")
            if not isinstance(user, str) or not user:
                continue
            if not isinstance(collection, str) or not collection:
                continue
            user_to_collections[user].add(collection)
            user_event_counts[user] += 1

        crossing = {
            u: cols
            for u, cols in user_to_collections.items()
            if len(cols) > self.cross_collection_threshold
        }
        if not crossing:
            return None

        top_user = max(
            crossing.keys(),
            key=lambda u: (len(crossing[u]), user_event_counts[u], u),
        )
        collections_touched = sorted(crossing[top_user])

        signal = "cross_collection_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        evidence: dict[str, Any] = {
            "milvus_event_id": f"synthetic-{uuid.uuid4()}",
            "signal": signal,
            "user": top_user,
            "collections_touched": collections_touched,
            "collection_count": len(collections_touched),
            "event_count": user_event_counts[top_user],
            "cross_collection_threshold": self.cross_collection_threshold,
            "all_crossing_users": {
                u: sorted(cols) for u, cols in crossing.items()
            },
            "source_provenance": self._source_provenance(file_sha256=file_sha256),
            "source_tool": "milvus",
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Milvus user={top_user!r} touched {len(collections_touched)} "
                f"distinct collections "
                f"(threshold={self.cross_collection_threshold}) in single export "
                f"(scope expansion)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"milvus-cross-collection-{top_user[:32]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="milvus_import_synthetic",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Synthetic cross-collection finding for user={top_user!r} "
                f"across {len(collections_touched)} collections"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=top_user,
        )

    def _privilege_grant_burst_finding(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        """Emit one synthetic FLAG when GrantPrivilege count in a 1h window exceeds threshold.

        We slide a window of ``privilege_grant_burst_window_seconds`` over the
        timeline of all GrantPrivilege events (sorted by timestamp). If any
        window contains more than the threshold, we emit a single synthetic
        finding describing the densest window observed.
        """
        grant_events: list[tuple[datetime, dict[str, Any]]] = []
        for ev in events:
            op = str(ev.get("operation") or "").lower()
            if op not in _RBAC_GRANT_OPS:
                continue
            ts_raw = ev.get("timestamp")
            ts = self._parse_timestamp(ts_raw)
            if ts is None:
                continue
            grant_events.append((ts, ev))

        if len(grant_events) <= self.privilege_grant_burst_threshold:
            return None

        grant_events.sort(key=lambda kv: kv[0])
        window = self.privilege_grant_burst_window_seconds
        densest_count = 0
        densest_start_idx = 0
        densest_end_idx = 0
        # Two-pointer sliding window on a sorted timeline.
        left = 0
        for right in range(len(grant_events)):
            while (
                grant_events[right][0] - grant_events[left][0]
            ).total_seconds() > window:
                left += 1
            count = right - left + 1
            if count > densest_count:
                densest_count = count
                densest_start_idx = left
                densest_end_idx = right

        if densest_count <= self.privilege_grant_burst_threshold:
            return None

        window_events = grant_events[densest_start_idx : densest_end_idx + 1]
        signal = "privilege_grant_burst"
        control_id = _control_for(signal, self._mappings, "PR-02")
        actors = sorted({
            str(ev.get("user")) for _, ev in window_events if ev.get("user")
        })
        evidence: dict[str, Any] = {
            "milvus_event_id": f"synthetic-{uuid.uuid4()}",
            "signal": signal,
            "burst_count": densest_count,
            "window_seconds": window,
            "threshold": self.privilege_grant_burst_threshold,
            "window_start": window_events[0][0].isoformat(),
            "window_end": window_events[-1][0].isoformat(),
            "actors_in_window": actors,
            "source_provenance": self._source_provenance(file_sha256=file_sha256),
            "source_tool": "milvus",
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Milvus GrantPrivilege burst: {densest_count} grants within "
                f"{window}s window (threshold="
                f"{self.privilege_grant_burst_threshold}); actors={actors}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"milvus-privilege-burst-{uuid.uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="milvus_import_synthetic",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Synthetic privilege-grant burst finding: {densest_count} "
                f"grants within {window}s"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    @staticmethod
    def _parse_timestamp(raw: Any) -> datetime | None:
        """Parse an ISO-8601 timestamp; tolerate ``Z`` suffix and missing tz."""
        if raw is None:
            return None
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        text = str(raw).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
