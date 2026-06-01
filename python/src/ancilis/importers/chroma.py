"""Chroma vector store operation log importer — converts Chroma operation logs to AKSI EvaluationResults.

Chroma (https://www.trychroma.com) is the most-used open-source vector store in
indie/small-team RAG stacks — chosen by roughly half of solo developers for its
zero-config local-first ergonomics. The same simplicity that makes Chroma the
default choice for prototypes also makes it a hot spot for misconfiguration in
production: default tenants/databases, unspecified embedding functions, and
include lists that pull raw embeddings or unfiltered documents back to the
caller. Each operation captured by Chroma's ``/api/v1/databases/{db}/operations``
audit endpoint (or the self-hosted operation log) becomes one EvaluationResult.

Accepted on-disk shapes:

  1. Envelope with operations:  ``{"operations": [{...}, ...]}``
  2. Generic data envelope:     ``{"data": [{...}, ...]}``
  3. JSON array:                ``[{...}, {...}]``
  4. Single object:             ``{...}``  (treated as one operation)
  5. JSONL stream:              one JSON object per line

Signal mapping (see shared/mappings/chroma-aksi-controls.json):

  Per-operation success
    * ``query`` / ``get``                          → PR-04 PASS  (data access governance)
    * ``add`` / ``upsert`` / ``update``            → PR-03 PASS  (input validation context)
    * ``delete``                                   → PR-05 PASS  (audit trail)

  Privileged / schema-change operations (always FLAG, even on success)
    * ``create_collection`` / ``delete_collection`` / ``modify``
                                                   → PR-05 FLAG  (schema-change governance)

  Errors
    * ``status=error`` & ``error_type=AuthorizationError`` → PR-02 FAIL (scope/authz)
    * ``status=error`` & ``error_type=DimensionMismatch``  → PR-03 FLAG (input validation)
    * ``status=error`` & ``error_type=InternalError``      → DE-01 FAIL (service failure)
    * ``status=error`` & other types                       → DE-01 FAIL (failure surface)

  Query / fetch quality flags (additive)
    * ``include`` contains ``"embeddings"``        → PR-04 FLAG (raw vectors in response)
    * ``include`` contains ``"documents"`` with no where_keys
      and no where_document_keys                   → PR-04 FLAG (un-scoped document fetch)
    * ``n_results`` > threshold (default 1000)     → PR-04 FLAG (over-fetch)

  Deployment-shape flags (additive)
    * ``tenant`` and ``database`` both default and ``user_id`` present
                                                   → PR-02 FLAG (single-tenant deployment with auth —
                                                                  common dev-mode misconfig pattern)
    * ``embedding_function="default"`` on production-looking collection
      (collection_name does not contain test/dev/local)
                                                   → PR-03 FLAG (unspecified embedding function;
                                                                  inconsistent vectors over time)

  Synthetic finding (cross-operation correlation)
    * Same ``user_id`` touching ≥3 distinct collections in one export
                                                   → PR-02 FLAG (scope expansion);
                                                                  emitted as a separate
                                                                  EvaluationResult.

Sanitization: filter VALUES, document content, embedding vectors, and query
text are NEVER persisted. We capture only structural information — the *names*
of where_keys / where_document_keys, the include list (since it is a fixed
vocabulary), counts (n_results, result_count, documents_count), durations, and
request/response sizes. The original file is hashed (sha256) for source
provenance so downstream evidence can detect tampering without retaining
sensitive data.

Why default-tenant/database detection is its own flag:
    Chroma's quickstart defaults are ``tenant="default_tenant"`` and
    ``database="default_database"``. In a single-user local dev environment
    that is fine. In a deployment where the operation log is also recording a
    ``user_id`` (i.e. an authentication layer is actually present), running
    every request against the default tenant/database means there is no
    isolation between the things that ``user_id`` distinguishes. The combination
    "we have auth, but everything goes to one bucket" is the canonical
    dev-mode-leaked-into-prod pattern; the importer surfaces it as a
    governance signal so reviewers can decide whether the deployment intended
    multi-tenant separation.

Why default-embedding-function on production-looking collections is a flag:
    Chroma falls back to the ``DefaultEmbeddingFunction`` (a small sentence
    transformer downloaded at runtime) when no explicit embedding function is
    supplied. The default is fine for prototyping but produces inconsistent
    vectors across versions — and silently switching embedding functions over
    time poisons recall. We treat ``embedding_function="default"`` on a
    collection whose name does not look like a test/dev/local fixture
    (``test_``, ``dev_``, ``-test``, ``local_`` etc.) as a PR-03 FLAG: the
    operation succeeded but the input-validation contract for vectors is not
    pinned.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table.
# This file lives at <repo>/python/src/ancilis/importers/chroma.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "chroma-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_N_RESULTS_THRESHOLD = 1000
_DEFAULT_CROSS_COLLECTION_THRESHOLD = 3
_DEFAULT_CROSS_COLLECTION_DETECTION = True

# Operation classes.
_READ_OPS: frozenset[str] = frozenset({"query", "get"})
_WRITE_OPS: frozenset[str] = frozenset({"add", "upsert", "update"})
_DELETE_OPS: frozenset[str] = frozenset({"delete"})
_LIFECYCLE_OPS: frozenset[str] = frozenset(
    {"create_collection", "delete_collection", "modify"}
)

# Default tenant / database labels used by Chroma's quickstart.
_DEFAULT_TENANT = "default_tenant"
_DEFAULT_DATABASE = "default_database"

# Substrings that mark a collection name as test/dev/local rather than
# production. We keep the rule conservative — any of these substrings, anywhere
# in the collection name, suppresses the embedding-function flag.
_NON_PROD_NAME_HINTS: tuple[str, ...] = (
    "test", "dev", "local", "staging", "scratch", "tmp", "demo",
)

# Map error_type values (case-insensitive, with optional "Error" suffix
# stripped) to mapping signal names.
_ERROR_TYPE_SIGNALS: dict[str, str] = {
    "authorization": "error_status_authorization",
    "authorizationerror": "error_status_authorization",
    "auth": "error_status_authorization",
    "dimensionmismatch": "error_status_dimension_mismatch",
    "internal": "error_status_internal",
    "internalerror": "error_status_internal",
}

# Default control if the mapping file is missing or stripped.
_DEFAULT_OPERATION_CONTROLS: dict[str, str] = {
    "operation_query_success": "PR-04",
    "operation_get_success": "PR-04",
    "operation_add_success": "PR-03",
    "operation_upsert_success": "PR-03",
    "operation_update_success": "PR-03",
    "operation_delete_success": "PR-05",
    "operation_create_collection": "PR-05",
    "operation_delete_collection": "PR-05",
    "operation_modify": "PR-05",
    "include_embeddings": "PR-04",
    "include_documents_unscoped": "PR-04",
    "n_results_exceeded": "PR-04",
    "default_tenant_database": "PR-02",
    "default_embedding_function": "PR-03",
    "cross_collection_pattern": "PR-02",
    "error_status_authorization": "PR-02",
    "error_status_dimension_mismatch": "PR-03",
    "error_status_internal": "DE-01",
    "error_status_other": "DE-01",
}


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------

def _load_mapping_table() -> dict[str, Any]:
    """Load chroma-aksi-controls.json; tolerate missing file."""
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
# Coercion helpers
# ---------------------------------------------------------------------------

def _coerce_int_optional(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _sanitize_key_list(value: Any) -> list[str]:
    """Return only the *names* of filter keys/operators, never their values.

    Accepts list[str] or, defensively, dict (taking dict keys). Values — which
    can carry user PII or business secrets — are dropped on the floor.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return sorted({str(k) for k in value if isinstance(k, (str, int))})
    if isinstance(value, dict):
        return sorted(str(k) for k in value)
    return []


def _sanitize_include(value: Any) -> list[str]:
    """Chroma's ``include`` is a fixed vocabulary list — keep as-is, sorted."""
    if value is None:
        return []
    if isinstance(value, list):
        return sorted({str(k) for k in value if isinstance(k, str)})
    return []


def _is_prod_collection_name(name: str) -> bool:
    """Heuristic: collection name does NOT look like a test/dev/local fixture."""
    if not name:
        return False
    lower = name.lower()
    return not any(hint in lower for hint in _NON_PROD_NAME_HINTS)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class ChromaImporter:
    """Parse a Chroma operation-log export and convert to ``EvaluationResult`` records.

    The importer is import-safe: it never imports the optional ``chromadb``
    package, so it works in environments where Chroma itself is not installed.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        n_results_threshold: int | None = None,
        cross_collection_threshold: int | None = None,
        detect_cross_collection: bool | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # n_results threshold precedence: ctor arg > mapping metadata > default.
        if n_results_threshold is not None:
            self.n_results_threshold = int(n_results_threshold)
        else:
            self.n_results_threshold = int(
                meta.get("default_n_results_threshold", _DEFAULT_N_RESULTS_THRESHOLD)
            )
        if cross_collection_threshold is not None:
            self.cross_collection_threshold = int(cross_collection_threshold)
        else:
            self.cross_collection_threshold = int(
                meta.get(
                    "cross_collection_threshold",
                    _DEFAULT_CROSS_COLLECTION_THRESHOLD,
                )
            )
        if detect_cross_collection is not None:
            self.detect_cross_collection = bool(detect_cross_collection)
        else:
            self.detect_cross_collection = bool(
                meta.get(
                    "default_cross_collection_detection",
                    _DEFAULT_CROSS_COLLECTION_DETECTION,
                )
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Chroma export file (JSON or JSONL) and return one
        EvaluationResult per operation, plus any synthetic findings."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        operations = self._operations_from_text(text)
        return self._build_results(operations, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a Chroma export from a JSON or JSONL string (no file hash)."""
        operations = self._operations_from_text(content)
        return self._build_results(operations, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _operations_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON / JSONL / envelope and return operation dicts.

        Accepted shapes:
          * ``{"operations": [...]}``   (canonical Chroma audit envelope)
          * ``{"data": [...]}``         (alternate envelope)
          * ``[ {...}, ... ]``          (bare list)
          * single object               (one operation)
          * JSONL                       (one op per line)
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
                for envelope_key in ("operations", "data"):
                    payload = doc.get(envelope_key)
                    if isinstance(payload, list):
                        return [e for e in payload if isinstance(e, dict)]
                # Single bare operation.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "chroma",
            "source_tool_name": "chroma",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        operations: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = [
            self._parse_operation(op, file_sha256=file_sha256) for op in operations
        ]
        if self.detect_cross_collection:
            synthetic = self._cross_collection_finding(
                operations, file_sha256=file_sha256
            )
            if synthetic is not None:
                results.append(synthetic)
        return results

    def _parse_operation(
        self,
        op: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        op_id = str(op.get("id") or op.get("operation_id") or uuid.uuid4())
        operation = str(op.get("operation") or "").strip().lower()
        collection_name = str(op.get("collection_name") or op.get("collection") or "")
        tenant = str(op.get("tenant") or "")
        database = str(op.get("database") or "")
        user_id_raw = op.get("user_id")
        user_id = str(user_id_raw) if user_id_raw is not None else None
        embedding_function = str(op.get("embedding_function") or "")
        n_results = _coerce_int_optional(op.get("n_results"))
        result_count = _coerce_int_optional(op.get("result_count"))
        documents_count = _coerce_int_optional(op.get("documents_count"))
        duration_ms = _coerce_float(op.get("duration_ms"))
        request_size_bytes = _coerce_int_optional(op.get("request_size_bytes"))
        response_size_bytes = _coerce_int_optional(op.get("response_size_bytes"))
        where_keys = _sanitize_key_list(op.get("where_keys"))
        where_document_keys = _sanitize_key_list(op.get("where_document_keys"))
        include = _sanitize_include(op.get("include"))
        status = str(op.get("status") or "ok").strip().lower()
        error_type_raw = op.get("error_type")
        error_type = str(error_type_raw) if error_type_raw is not None else ""
        timestamp = op.get("timestamp") or datetime.now(timezone.utc).isoformat()

        source_provenance = self._source_provenance(file_sha256=file_sha256)
        common_evidence: dict[str, Any] = {
            "chroma_operation_id": op_id,
            "operation": operation,
            "collection_name": collection_name,
            "tenant": tenant,
            "database": database,
            "user_id": user_id,
            "embedding_function": embedding_function,
            "n_results": n_results,
            "result_count": result_count,
            "documents_count": documents_count,
            "duration_ms": duration_ms,
            "request_size_bytes": request_size_bytes,
            "response_size_bytes": response_size_bytes,
            "where_keys": where_keys,
            "where_document_keys": where_document_keys,
            "where_filter_present": bool(where_keys or where_document_keys),
            "include": include,
            "status": status,
            "error_type": error_type or None,
            "source_provenance": source_provenance,
            "source_tool": "chroma",
        }

        control_results: list[ControlResult] = []

        # 1. Error path — takes priority over operation-success mapping.
        if status == "error":
            error_norm = error_type.strip().lower().replace("_", "")
            signal = _ERROR_TYPE_SIGNALS.get(error_norm, "error_status_other")
            # Authorization & internal & other → FAIL; dimension_mismatch → FLAG.
            result_level = (
                "FLAG" if signal == "error_status_dimension_mismatch" else "FAIL"
            )
            control_id = _control_for(
                signal,
                self._mappings,
                _DEFAULT_OPERATION_CONTROLS.get(signal, "DE-01"),
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Chroma {operation or 'op'} on collection={collection_name!r} "
                        f"failed with error_type={error_type!r} "
                        f"(user_id={user_id!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # 2. Operation-success mapping.
            op_signal, op_result = self._operation_signal(operation)
            if op_signal is not None:
                control_id = _control_for(
                    op_signal,
                    self._mappings,
                    _DEFAULT_OPERATION_CONTROLS.get(op_signal, "PR-04"),
                )
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=op_result,
                        detail=self._operation_detail(
                            operation,
                            collection_name,
                            user_id,
                            result_count,
                            documents_count,
                            op_result,
                        ),
                        evidence_data={**common_evidence, "signal": op_signal},
                    )
                )

            # 3. Query/get-quality flags — only on successful read-style ops.
            if operation in _READ_OPS:
                if "embeddings" in include:
                    control_results.append(
                        self._build_flag(
                            "include_embeddings",
                            common_evidence,
                            (
                                f"Chroma {operation} on collection={collection_name!r} "
                                f"requested include=['embeddings'] — raw vector "
                                f"contents exposed to caller (exfiltration surface)"
                            ),
                        )
                    )
                if (
                    "documents" in include
                    and not where_keys
                    and not where_document_keys
                ):
                    control_results.append(
                        self._build_flag(
                            "include_documents_unscoped",
                            common_evidence,
                            (
                                f"Chroma {operation} on collection={collection_name!r} "
                                f"included documents without where/where_document "
                                f"filter (un-scoped document fetch)"
                            ),
                        )
                    )
                if (
                    n_results is not None
                    and n_results > self.n_results_threshold
                ):
                    control_results.append(
                        self._build_flag(
                            "n_results_exceeded",
                            {
                                **common_evidence,
                                "n_results_threshold": self.n_results_threshold,
                            },
                            (
                                f"Chroma {operation} on collection={collection_name!r} "
                                f"requested n_results={n_results} > threshold="
                                f"{self.n_results_threshold} (over-fetch)"
                            ),
                        )
                    )

            # 4. Default tenant + database + auth-present — dev-mode misconfig.
            if (
                tenant == _DEFAULT_TENANT
                and database == _DEFAULT_DATABASE
                and user_id
            ):
                control_results.append(
                    self._build_flag(
                        "default_tenant_database",
                        common_evidence,
                        (
                            f"Chroma {operation or 'op'} ran with tenant="
                            f"{_DEFAULT_TENANT!r} and database={_DEFAULT_DATABASE!r} "
                            f"while user_id={user_id!r} is set — single-tenant "
                            f"deployment with auth (common dev-mode misconfig "
                            f"in production)"
                        ),
                    )
                )

            # 5. Default embedding function on a production-looking collection.
            if (
                embedding_function.lower() == "default"
                and _is_prod_collection_name(collection_name)
            ):
                control_results.append(
                    self._build_flag(
                        "default_embedding_function",
                        common_evidence,
                        (
                            f"Chroma {operation or 'op'} on collection="
                            f"{collection_name!r} used embedding_function='default' "
                            f"on a production-looking collection (unspecified "
                            f"embedding function — vectors will drift across "
                            f"library upgrades)"
                        ),
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
            f"Imported from Chroma: operation={operation} "
            f"collection={collection_name} status={status} "
            f"user_id={user_id!r}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"chroma-{op_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="chroma_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=user_id,
        )

    # -- Helpers ------------------------------------------------------------

    def _operation_signal(self, op: str) -> tuple[str | None, str]:
        """Return ``(signal_name, result_level)`` for a Chroma operation.

        ``result_level`` is "PASS" for routine read/write/delete and "FLAG" for
        privileged lifecycle/schema operations (which are always governance
        events even on success).
        """
        if op in _READ_OPS:
            return f"operation_{op}_success", "PASS"
        if op in _WRITE_OPS:
            return f"operation_{op}_success", "PASS"
        if op in _DELETE_OPS:
            return f"operation_{op}_success", "PASS"
        if op in _LIFECYCLE_OPS:
            # Match mapping table key shape — modify is keyed as
            # ``operation_modify`` while create/delete_collection are keyed
            # as ``operation_create_collection`` etc.
            return f"operation_{op}", "FLAG"
        # Unknown operation — emit a generic data-access PASS so downstream
        # consumers still get a record. We intentionally do not FAIL on
        # unknown ops because Chroma adds new ones in minor releases.
        if op:
            return "operation_query_success", "PASS"
        return None, "PASS"

    def _operation_detail(
        self,
        op: str,
        collection: str,
        user_id: str | None,
        result_count: int | None,
        documents_count: int | None,
        result_level: str,
    ) -> str:
        if result_level == "FLAG":
            return (
                f"Chroma privileged operation {op} on collection={collection!r} "
                f"by user_id={user_id!r} — review schema-change controls"
            )
        counts: list[str] = []
        if result_count is not None:
            counts.append(f"results={result_count}")
        if documents_count is not None:
            counts.append(f"documents={documents_count}")
        counts_str = f" {', '.join(counts)}" if counts else ""
        return (
            f"Chroma {op} on collection={collection!r} by user_id={user_id!r} "
            f"succeeded{counts_str}"
        )

    def _build_flag(
        self,
        signal: str,
        common_evidence: dict[str, Any],
        detail: str,
    ) -> ControlResult:
        control_id = _control_for(
            signal,
            self._mappings,
            _DEFAULT_OPERATION_CONTROLS.get(signal, "PR-04"),
        )
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=detail,
            evidence_data={**common_evidence, "signal": signal},
        )

    # -- Synthetic finding --------------------------------------------------

    def _cross_collection_finding(
        self,
        operations: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        """Emit one synthetic FLAG when a user_id touches ≥threshold collections.

        Hardcoded to one synthetic record covering the most-promiscuous user
        across all collections in the export, so a noisy log does not produce
        N synthetic findings. Returns ``None`` when no such pattern exists.
        """
        user_to_collections: dict[str, set[str]] = defaultdict(set)
        user_event_counts: dict[str, int] = defaultdict(int)
        for op in operations:
            user_id = op.get("user_id")
            collection = op.get("collection_name") or op.get("collection")
            if not user_id or not collection:
                continue
            user_str = str(user_id)
            collection_str = str(collection)
            user_to_collections[user_str].add(collection_str)
            user_event_counts[user_str] += 1

        crossing_users = {
            u: cols
            for u, cols in user_to_collections.items()
            if len(cols) >= self.cross_collection_threshold
        }
        if not crossing_users:
            return None

        # Pick the user with the most cross-collection events for the primary
        # synthetic finding (deterministic on ties via name).
        top_user = max(
            crossing_users,
            key=lambda u: (len(crossing_users[u]), user_event_counts[u], u),
        )
        collections_touched = sorted(crossing_users[top_user])

        signal = "cross_collection_pattern"
        control_id = _control_for(
            signal, self._mappings, _DEFAULT_OPERATION_CONTROLS[signal]
        )
        evidence: dict[str, Any] = {
            "chroma_operation_id": f"synthetic-{uuid.uuid4()}",
            "signal": signal,
            "user_id": top_user,
            "collections_touched": collections_touched,
            "collection_count": len(collections_touched),
            "operation_count": user_event_counts[top_user],
            "cross_collection_threshold": self.cross_collection_threshold,
            "all_crossing_users": {
                u: sorted(cols) for u, cols in crossing_users.items()
            },
            "source_provenance": self._source_provenance(file_sha256=file_sha256),
            "source_tool": "chroma",
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Chroma user_id={top_user!r} accessed "
                f"{len(collections_touched)} collections "
                f"({', '.join(collections_touched)}) in single export "
                f"(scope expansion ≥ {self.cross_collection_threshold} collections)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"chroma-synthetic-{uuid.uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="chroma_import_synthetic",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Synthetic finding: user_id={top_user!r} touched "
                f"{len(collections_touched)} collections in one export"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=top_user,
        )
