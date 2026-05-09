"""Weaviate vector search audit log importer — converts REST/gRPC operation logs to AKSI EvaluationResults.

Weaviate (https://weaviate.io) is the dominant open-source vector search engine
in self-hosted RAG stacks. It exposes class (collection) operations through
REST and gRPC surfaces; each operation (Get / Create / Update / Delete /
Aggregate / Explore / Backup / Restore) is captured in audit logs containing
operation type, class name, optional tenant (multi-tenant deployments), the
vectorizer module, query structural metadata (filter path keys, near-vector /
near-text presence, hybrid alpha), result counts, status, RBAC role, and
duration. Bulk exports come as ``{"logs": [...]}`` envelopes, ``{"data": [...]}``
envelopes, or JSONL streams.

Signal mapping (see shared/mappings/weaviate-aksi-controls.json):
  * operation in {Get, Aggregate, Explore} & success → PR-04 PASS  (data access governance)
  * operation in {Create, Update}        & success   → PR-03 PASS  (provenance)
  * operation == Delete                  & success   → PR-05 PASS  (audit trail)
  * operation in {Backup, Restore}                   → PR-05 FLAG  (privileged ops)
  * status_code 4xx                                  → PR-02 FLAG  (scope/auth)
  * status_code 5xx                                  → DE-01 FAIL  (provider failure)
  * limit > threshold                                → PR-04 FLAG  (over-fetch)
  * Get with no where_filter and no tenant           → PR-04 FLAG  (un-scoped query)
  * rbac_role == admin on a read-only op             → PR-02 FLAG  (over-privileged)
  * consistency_level == ONE on Create/Update        → PR-03 FLAG  (weak write consistency)

Cross-tenant access pattern: when a single ``user`` value touches more than
one ``tenant`` value across the loaded log, an additional synthetic
EvaluationResult is emitted with a single PR-02 FLAG ControlResult. This is
the only signal that requires correlation across entries; everything else is
per-entry.

Sanitization: the importer NEVER stores ``graphql_query`` bodies, where-filter
values, or near-vector / near-text contents. We capture only structural keys
(operation, class_name, tenant, vectorizer, where-filter path keys, presence
booleans for near_vector / near_text / hybrid, results_count, duration_ms,
consistency_level, RBAC role, status). The original file's sha256 is recorded
in source_provenance for tamper evidence.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table.
# This file lives at <repo>/python/src/ancilis/importers/weaviate.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "weaviate-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_LIMIT_THRESHOLD = 1000

# Read-only operations — used to flag admin-on-read and to drive operation→control mapping.
_READ_OPERATIONS = {"get", "aggregate", "explore"}
_WRITE_OPERATIONS = {"create", "update"}
_DELETE_OPERATIONS = {"delete"}
_PRIVILEGED_OPERATIONS = {"backup", "restore"}

# Comparison operators that may appear in a Weaviate where-filter path triple.
# We split the path on the first operator so any trailing value is dropped.
_FILTER_OPERATORS = {
    "==", "!=", ">", ">=", "<", "<=",
    "Equal", "NotEqual", "GreaterThan", "GreaterThanEqual",
    "LessThan", "LessThanEqual", "Like", "WithinGeoRange",
    "ContainsAny", "ContainsAll", "IsNull",
}

# Operation → default control + signal name. Keys are lowercase.
_OPERATION_DEFAULTS: dict[str, tuple[str, str, str]] = {
    # operation: (signal, default_control, result_level)
    "get": ("operation_get", "PR-04", "PASS"),
    "aggregate": ("operation_aggregate", "PR-04", "PASS"),
    "explore": ("operation_explore", "PR-04", "PASS"),
    "create": ("operation_create", "PR-03", "PASS"),
    "update": ("operation_update", "PR-03", "PASS"),
    "delete": ("operation_delete", "PR-05", "PASS"),
    "backup": ("operation_backup", "PR-05", "FLAG"),
    "restore": ("operation_restore", "PR-05", "FLAG"),
}


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the weaviate-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    """Resolve a signal name to an AKSI control via the mapping table."""
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from a JSONL string, skipping blanks/invalid lines."""
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
# Importer
# ---------------------------------------------------------------------------


class WeaviateImporter:
    """Parse a Weaviate audit-log export and convert to ``EvaluationResult`` records.

    The importer is import-safe: it never imports the optional ``weaviate-client``
    package, so it works in environments where Weaviate itself is not installed.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        limit_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Threshold precedence: explicit constructor arg > mapping metadata > default.
        if limit_threshold is not None:
            self.limit_threshold = int(limit_threshold)
        else:
            self.limit_threshold = int(
                meta.get("default_limit_threshold", _DEFAULT_LIMIT_THRESHOLD)
            )

    # ------------------------------------------------------------------ public
    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Weaviate export file from disk; returns one EvaluationResult per log entry,
        plus any synthetic findings (e.g. cross-tenant access pattern)."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return self._build_results(entries, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Weaviate export content from a string (no file hash)."""
        entries = self._entries_from_text(content)
        return self._build_results(entries, file_sha256=None)

    # ----------------------------------------------------------------- private
    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON / JSONL / envelope shape and return a flat list of log entries.

        Accepted shapes:
          * ``{"logs": [ {...}, ... ]}``     — primary audit-log envelope
          * ``{"data": [ {...}, ... ]}``     — generic data envelope
          * ``[ {...}, ... ]``               — bare list
          * JSONL — one log entry per line
        """
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
                if "logs" in doc and isinstance(doc["logs"], list):
                    return [e for e in doc["logs"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single bare entry.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "weaviate",
            "source_tool_name": "weaviate",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        entries: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Per-entry results plus synthetic cross-tenant findings."""
        results: list[EvaluationResult] = [
            self._parse_entry(e, file_sha256=file_sha256) for e in entries
        ]
        synthetic = self._cross_tenant_findings(entries, file_sha256=file_sha256)
        results.extend(synthetic)
        return results

    # ---------------------------------------------------------------- per-entry
    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        log_id = str(entry.get("id") or uuid.uuid4())
        operation_raw = str(entry.get("operation") or "").strip()
        operation = operation_raw.lower()
        class_name = entry.get("class_name") or entry.get("className") or ""
        tenant = entry.get("tenant")
        vectorizer = entry.get("vectorizer") or ""
        user = entry.get("user")
        timestamp = entry.get("timestamp") or datetime.now(timezone.utc).isoformat()
        rbac_role = str(entry.get("rbac_role") or "").lower() or None
        consistency_level = str(entry.get("consistency_level") or "").upper() or None
        operation_name = entry.get("operation_name")  # GraphQL surface

        try:
            limit = int(entry.get("limit") or 0)
        except (TypeError, ValueError):
            limit = 0

        try:
            results_count = int(entry.get("results_count") or 0)
        except (TypeError, ValueError):
            results_count = 0

        try:
            duration_ms = float(entry.get("duration_ms") or 0.0)
        except (TypeError, ValueError):
            duration_ms = 0.0

        try:
            status_code = int(entry.get("status_code") or 0)
        except (TypeError, ValueError):
            status_code = 0

        # Where filter — capture path KEYS only, never operators or values.
        # Weaviate exports sometimes flatten a filter into a triple
        # ``[<key>, <operator>, <value>]``; we split at the first operator and
        # drop everything from the operator onward so user-supplied values
        # never reach evidence_data.
        raw_where_path = entry.get("where_filter_path")
        where_filter_path_keys: list[str] = []
        where_filter_operator: str | None = None
        if isinstance(raw_where_path, list):
            for elem in raw_where_path:
                if not isinstance(elem, str):
                    continue
                if elem in _FILTER_OPERATORS:
                    where_filter_operator = elem
                    break
                where_filter_path_keys.append(elem)

        near_vector_present = bool(entry.get("near_vector_present"))
        near_text_present = bool(entry.get("near_text_present"))
        hybrid_alpha = entry.get("hybrid_alpha")

        # GraphQL surface — capture variable KEYS only, never values, and never the body.
        graphql_present = bool(entry.get("graphql_query"))
        raw_var_keys = entry.get("variables_keys")
        graphql_variable_keys: list[str] = []
        if isinstance(raw_var_keys, list):
            graphql_variable_keys = [str(k) for k in raw_var_keys if isinstance(k, str)]

        error_message = entry.get("error_message") or ""

        source_provenance = self._source_provenance(file_sha256=file_sha256)
        common_evidence: dict[str, Any] = {
            "weaviate_log_id": log_id,
            "operation": operation_raw or operation,
            "class_name": str(class_name) if class_name is not None else "",
            "tenant": str(tenant) if tenant else None,
            "vectorizer": str(vectorizer),
            "user": str(user) if user is not None else None,
            "rbac_role": rbac_role,
            "consistency_level": consistency_level,
            "limit": limit,
            "results_count": results_count,
            "duration_ms": duration_ms,
            "status_code": status_code,
            "where_filter_path_keys": where_filter_path_keys,
            "where_filter_operator": where_filter_operator,
            "where_filter_present": bool(where_filter_path_keys),
            "near_vector_present": near_vector_present,
            "near_text_present": near_text_present,
            "hybrid_alpha": hybrid_alpha,
            "graphql_query_present": graphql_present,
            "graphql_operation_name": str(operation_name) if operation_name else None,
            "graphql_variable_keys": graphql_variable_keys,
            "source_provenance": source_provenance,
            "source_tool": "weaviate",
        }

        control_results: list[ControlResult] = []
        is_success = 200 <= status_code < 300 or status_code == 0  # treat unknown as success-ish

        # 1. Status-code outcome — primary failure surface.
        if 500 <= status_code < 600:
            signal = "status_5xx"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Weaviate {operation_raw or 'op'} on class={class_name!s} "
                        f"failed with status={status_code}: "
                        f"{str(error_message)[:200] or 'server error'}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif 400 <= status_code < 500:
            signal = "status_4xx"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Weaviate {operation_raw or 'op'} on class={class_name!s} "
                        f"returned client error status={status_code} (scope/auth concern)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # 2. Operation-type signal — only when status is success-ish.
            if operation in _OPERATION_DEFAULTS:
                signal, default_control, level = _OPERATION_DEFAULTS[operation]
                control_id = _control_for(signal, self._mappings, default_control)
                if level == "PASS":
                    detail = (
                        f"Weaviate {operation_raw} on class={class_name!s} succeeded "
                        f"(tenant={tenant or '-'}, results={results_count}, "
                        f"duration_ms={duration_ms:.1f})"
                    )
                else:
                    detail = (
                        f"Weaviate privileged operation {operation_raw} on "
                        f"class={class_name!s} (tenant={tenant or '-'}) — review "
                        f"backup/restore controls"
                    )
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=level,
                        detail=detail,
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Unknown operation — surface as FLAG so it does not silently pass.
                control_results.append(
                    ControlResult(
                        control_id="PR-02",
                        control_name=_CONTROL_NAMES["PR-02"],
                        result="FLAG",
                        detail=(
                            f"Weaviate log {log_id} has unrecognized "
                            f"operation={operation_raw!r}"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": "operation_unknown",
                        },
                    )
                )

        # 3. limit > threshold — additive over-fetch flag.
        if limit > self.limit_threshold:
            signal = "limit_above_threshold"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Weaviate {operation_raw or 'op'} on class={class_name!s} "
                        f"requested limit={limit} above threshold={self.limit_threshold} "
                        f"(potential over-fetch)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "limit_threshold": self.limit_threshold,
                    },
                )
            )

        # 4. Un-scoped Get — additive (no where filter AND no tenant).
        if (
            operation == "get"
            and not where_filter_path_keys
            and not tenant
            and is_success
        ):
            signal = "unscoped_query"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Weaviate Get on class={class_name!s} executed without "
                        f"where filter and without tenant scope (un-scoped query "
                        f"may expose unrelated rows)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 5. RBAC admin on read-only op — additive over-privileged flag.
        # The principle: read-only operations (Get/Aggregate/Explore) should not
        # routinely be performed by admin-tier credentials. Admin role on read
        # is a least-privilege violation: every Get carries the blast radius
        # of a write because the same principal could mutate at will.
        if rbac_role == "admin" and operation in _READ_OPERATIONS:
            signal = "admin_on_read_op"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Weaviate {operation_raw} on class={class_name!s} performed "
                        f"by rbac_role=admin (over-privileged: read-only ops should "
                        f"use viewer/editor role)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 6. consistency_level=ONE on Create/Update — weak write consistency.
        if consistency_level == "ONE" and operation in _WRITE_OPERATIONS:
            signal = "consistency_one_on_write"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Weaviate {operation_raw} on class={class_name!s} used "
                        f"consistency_level=ONE (weak consistency for a write — "
                        f"use QUORUM or ALL for durable provenance)"
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
            f"Imported from Weaviate: {operation_raw or 'op'} on "
            f"class={class_name!s} tenant={tenant or '-'} "
            f"status={status_code} results={results_count}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"weaviate-{log_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="weaviate_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=str(tenant) if tenant else None,
        )

    # -------------------------------------------------------- synthetic findings
    def _cross_tenant_findings(
        self,
        entries: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Emit one synthetic EvaluationResult per user that touched >1 tenant.

        Cross-tenant access is the canonical lateral-movement signal in a
        multi-tenant Weaviate deployment: the same principal should not
        normally surface across tenant boundaries. We aggregate over the loaded
        log only — long-window cross-tenant detection lives in the engine, not
        the importer.
        """
        if not entries:
            return []

        # user → set of tenants observed (only string-typed, non-empty).
        user_to_tenants: dict[str, set[str]] = {}
        # user → list of (operation, class_name, tenant, log_id) for evidence.
        user_to_actions: dict[str, list[dict[str, Any]]] = {}
        for entry in entries:
            user = entry.get("user")
            tenant = entry.get("tenant")
            if not isinstance(user, str) or not user:
                continue
            if not isinstance(tenant, str) or not tenant:
                continue
            user_to_tenants.setdefault(user, set()).add(tenant)
            user_to_actions.setdefault(user, []).append(
                {
                    "log_id": str(entry.get("id") or ""),
                    "operation": str(entry.get("operation") or ""),
                    "class_name": str(entry.get("class_name") or ""),
                    "tenant": tenant,
                }
            )

        findings: list[EvaluationResult] = []
        source_provenance = self._source_provenance(file_sha256=file_sha256)
        for user, tenants in user_to_tenants.items():
            if len(tenants) < 2:
                continue
            tenant_list = sorted(tenants)
            actions = user_to_actions.get(user, [])
            signal = "cross_tenant_access"
            control_id = _control_for(signal, self._mappings, "PR-02")
            evidence: dict[str, Any] = {
                "signal": signal,
                "user": user,
                "tenants_touched": tenant_list,
                "tenant_count": len(tenant_list),
                "actions": actions,
                "source_provenance": source_provenance,
                "source_tool": "weaviate",
            }
            cr = ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result="FLAG",
                detail=(
                    f"Weaviate user={user} accessed {len(tenant_list)} distinct "
                    f"tenants ({', '.join(tenant_list)}) within the loaded log "
                    f"(possible cross-tenant access pattern)"
                ),
                evidence_data=evidence,
            )
            findings.append(
                EvaluationResult(
                    evaluation_id=str(uuid.uuid4()),
                    action_id=f"weaviate-cross-tenant-{user[:32]}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    agent_id=self.agent_id,
                    source_type="weaviate_import_synthetic",
                    mode=self.mode,
                    control_results=[cr],
                    decision="FLAG",
                    decision_reason=(
                        f"Synthetic cross-tenant access finding for user={user} "
                        f"across {len(tenant_list)} tenants"
                    ),
                    active_overlays=[],
                    data_classifications=[],
                    total_duration_ms=0.0,
                    session_id=user,
                )
            )
        return findings
