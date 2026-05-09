"""Pinecone vector store operation log importer — converts vector-store data-plane
operations to AKSI EvaluationResults.

Pinecone (https://www.pinecone.io) is the dominant managed vector store in
production agent stacks. Every query, upsert, delete, fetch, or stats operation
is the primary RAG/data-access surface — each one is potentially a data
exfiltration event and a governance signal. Pinecone exports operation logs
(or audit logs via the data plane) shaped roughly like::

    {
      "operations": [
        {
          "id": "op-...",
          "operation": "query" | "upsert" | "delete" | "fetch" | ...,
          "index": "production-rag",
          "namespace": "tenant-1234",
          "timestamp": "2026-...",
          "user_id": "...",
          "api_key_id": "...",
          "vector_count": 50,
          "top_k": 10,
          "filter_keys": ["userId", "category"],
          "include_metadata": true,
          "include_values": false,
          "score_distribution": {"min": 0.32, "max": 0.91, "median": 0.78},
          "latency_ms": 45,
          "status": "success" | "failure",
          "error_code": "...",
          "request_units": 1.5
        }
      ]
    }

Bulk shapes accepted:
  * ``{"operations": [...]}`` (canonical)
  * ``{"data": [...]}``        (alternate envelope)
  * single bare object         ``{...}`` (single operation)
  * JSONL                      one operation per line

Signal mapping (see shared/mappings/pinecone-aksi-controls.json):
  * operation=query success       → PR-04 PASS  (data access)
  * operation=upsert success      → PR-03 PASS  (input validation context)
  * operation=delete success      → PR-05 PASS  (audit trail)
  * operation=fetch + include_values=true → PR-04 FLAG (raw vectors exposed)
  * operation=query + top_k>threshold     → PR-04 FLAG (over-fetch)
  * operation=query + no filter_keys      → PR-04 FLAG (un-scoped query)
  * status=failure                → DE-01 FAIL (failure surface)
  * Cross-namespace pattern within single trace_id/api_key_id → PR-02 FLAG
    (scope expansion — same caller hitting multiple namespaces in one trace)

Sanitization: filter VALUES, vector data, and metadata payloads are NEVER
stored. Only filter KEY NAMES, vector counts, score distribution summaries,
and operation-shape fields are captured.
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
# This file lives at <repo>/python/src/ancilis/importers/pinecone.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "pinecone-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Operations that, on success, map to a specific control (default fallbacks
# used if the JSON mapping table is missing or stripped).
_DEFAULT_OPERATION_CONTROLS: dict[str, str] = {
    "query": "PR-04",
    "upsert": "PR-03",
    "delete": "PR-05",
    "fetch": "PR-04",
    "describe_index_stats": "PR-04",
    "list": "PR-04",
}

_DEFAULT_TOP_K_THRESHOLD = 100
_DEFAULT_CROSS_NAMESPACE_DETECTION = True


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------

def _load_mapping_table() -> dict[str, Any]:
    """Load the pinecone-aksi-controls.json mapping; tolerate missing file."""
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
    """Yield JSON objects from a JSONL string, ignoring blank/invalid lines."""
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

def _coerce_int(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coerce_float(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _sanitize_filter_keys(filter_keys: Any) -> list[str]:
    """Return a clean sorted list of filter KEY NAMES only.

    Values are NEVER retained. Accepts list[str] or dict (taking dict keys).
    Anything else is dropped.
    """
    if filter_keys is None:
        return []
    if isinstance(filter_keys, dict):
        return sorted(str(k) for k in filter_keys.keys())
    if isinstance(filter_keys, list):
        return sorted(str(k) for k in filter_keys if isinstance(k, (str, int)))
    return []


def _sanitize_score_distribution(dist: Any) -> dict[str, float]:
    """Keep only numeric summary stats of a score distribution; drop everything else."""
    if not isinstance(dist, dict):
        return {}
    out: dict[str, float] = {}
    for k in ("min", "max", "median", "mean", "stddev", "p50", "p95", "p99"):
        if k in dist:
            out[k] = _coerce_float(dist.get(k))
    return out


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class PineconeImporter:
    """Parse a Pinecone operation-log export and convert to ``EvaluationResult``s."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        top_k_threshold: int | None = None,
        detect_cross_namespace: bool | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # top_k threshold precedence: explicit ctor arg > mapping metadata > default.
        if top_k_threshold is not None:
            self.top_k_threshold = int(top_k_threshold)
        else:
            self.top_k_threshold = int(
                meta.get("default_top_k_threshold", _DEFAULT_TOP_K_THRESHOLD)
            )
        if detect_cross_namespace is not None:
            self.detect_cross_namespace = bool(detect_cross_namespace)
        else:
            self.detect_cross_namespace = bool(
                meta.get(
                    "default_cross_namespace_detection",
                    _DEFAULT_CROSS_NAMESPACE_DETECTION,
                )
            )

    # ------------------------------------------------------------------ public
    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Pinecone export file (JSON or JSONL) and return one
        EvaluationResult per operation."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        operations = self._operations_from_text(text)
        return self._parse_operations(operations, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a Pinecone export from a JSON or JSONL string."""
        operations = self._operations_from_text(content)
        return self._parse_operations(operations, file_sha256=None)

    # ----------------------------------------------------------------- private
    def _operations_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON / JSONL / envelope and return a flat list of operation dicts.

        Accepted shapes:
          * ``{"operations": [...]}``   (canonical)
          * ``{"data": [...]}``         (alternate envelope)
          * ``{"logs": [...]}``         (audit-log envelope)
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
                for envelope_key in ("operations", "data", "logs"):
                    payload = doc.get(envelope_key)
                    if isinstance(payload, list):
                        return [e for e in payload if isinstance(e, dict)]
                # Single bare operation.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "pinecone",
            "source_tool_name": "pinecone",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _parse_operations(
        self,
        operations: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Two-pass parse: first compute cross-namespace groups, then convert each op."""
        # Pre-pass: group namespaces seen per (trace_id, api_key_id) bucket so
        # we can flag scope expansion even when the per-op record alone looks fine.
        # A "trace" is identified by, in order of preference, trace_id, request_id,
        # session_id, then api_key_id (so requests from the same key still get
        # bucketed if no trace metadata is present).
        cross_ns_buckets: dict[str, set[str]] = {}
        if self.detect_cross_namespace:
            for op in operations:
                bucket = self._cross_namespace_bucket_key(op)
                if bucket is None:
                    continue
                ns = op.get("namespace")
                if ns is None or ns == "":
                    continue
                cross_ns_buckets.setdefault(bucket, set()).add(str(ns))

        results: list[EvaluationResult] = []
        for op in operations:
            results.append(
                self._parse_operation(
                    op,
                    file_sha256=file_sha256,
                    cross_ns_buckets=cross_ns_buckets,
                )
            )
        return results

    def _cross_namespace_bucket_key(self, op: dict[str, Any]) -> str | None:
        """Pick the strongest available correlation id to bucket cross-namespace activity by."""
        for key in ("trace_id", "request_id", "session_id", "api_key_id"):
            value = op.get(key)
            if value:
                return f"{key}={value}"
        return None

    def _parse_operation(
        self,
        op: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_ns_buckets: dict[str, set[str]],
    ) -> EvaluationResult:
        op_id = str(op.get("id") or op.get("operation_id") or uuid.uuid4())
        operation = str(op.get("operation") or op.get("op") or "unknown").strip().lower()
        index = str(op.get("index") or op.get("index_name") or "unknown")
        namespace_raw = op.get("namespace")
        namespace = str(namespace_raw) if namespace_raw is not None else ""
        user_id = op.get("user_id")
        api_key_id = op.get("api_key_id")
        trace_id = op.get("trace_id") or op.get("request_id") or op.get("session_id")

        vector_count = _coerce_int(op.get("vector_count"))
        top_k = _coerce_int(op.get("top_k")) if op.get("top_k") is not None else None
        include_metadata = bool(op.get("include_metadata"))
        include_values = bool(op.get("include_values"))
        latency_ms = _coerce_float(op.get("latency_ms"))
        request_units = _coerce_float(op.get("request_units"))
        score_distribution = _sanitize_score_distribution(op.get("score_distribution"))

        # Sanitized: only keys, never values.
        filter_keys = _sanitize_filter_keys(op.get("filter_keys") or op.get("filter"))

        status = str(op.get("status") or "success").strip().lower()
        error_code = op.get("error_code")
        timestamp = op.get("timestamp") or datetime.now(timezone.utc).isoformat()

        source_provenance = self._source_provenance(file_sha256=file_sha256)
        common_evidence: dict[str, Any] = {
            "pinecone_operation_id": op_id,
            "operation": operation,
            "index": index,
            "namespace": namespace,
            "vector_count": vector_count,
            "top_k": top_k,
            "include_metadata": include_metadata,
            "include_values": include_values,
            "filter_keys": filter_keys,
            "filter_key_count": len(filter_keys),
            "score_distribution": score_distribution,
            "latency_ms": latency_ms,
            "request_units": request_units,
            "status": status,
            "error_code": str(error_code) if error_code is not None else None,
            "user_id": str(user_id) if user_id is not None else None,
            "api_key_id": str(api_key_id) if api_key_id is not None else None,
            "trace_id": str(trace_id) if trace_id is not None else None,
            "source_provenance": source_provenance,
            "source_tool": "pinecone",
        }

        control_results: list[ControlResult] = []

        # 1. Status — failures take priority and produce DE-01 FAIL.
        if status == "failure" or status == "error":
            control_id = _control_for("status_failure", self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Pinecone {operation} on {index}/{namespace or '<default>'} "
                        f"failed (op_id={op_id}, error_code={error_code!r})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "status_failure",
                    },
                )
            )
        else:
            # 2. Successful operation — primary control mapping by op type.
            signal = f"operation_{operation}_success"
            default_op_control = _DEFAULT_OPERATION_CONTROLS.get(operation, "PR-04")
            # If the mapping does not have this exact signal, fall back to the
            # generic "operation_other_success" entry, then to the default control.
            if signal in self._mappings:
                control_id = self._mappings[signal]
            else:
                control_id = _control_for(
                    "operation_other_success", self._mappings, default_op_control
                )
                signal = (
                    signal
                    if operation in _DEFAULT_OPERATION_CONTROLS
                    else "operation_other_success"
                )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Pinecone {operation} on {index}/{namespace or '<default>'} "
                        f"succeeded (vectors={vector_count}, top_k={top_k}, "
                        f"latency_ms={latency_ms}, ru={request_units})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 3. fetch with include_values=true — raw vectors exposed (FLAG).
        if operation == "fetch" and include_values:
            control_id = _control_for(
                "fetch_include_values", self._mappings, "PR-04"
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Pinecone fetch on {index}/{namespace or '<default>'} "
                        f"requested include_values=true — raw vector contents "
                        f"exposed to caller (op_id={op_id})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "fetch_include_values",
                    },
                )
            )

        # 4. query with top_k > threshold — over-fetch (FLAG).
        if (
            operation == "query"
            and top_k is not None
            and top_k > self.top_k_threshold
        ):
            control_id = _control_for(
                "query_top_k_exceeded", self._mappings, "PR-04"
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Pinecone query top_k={top_k} exceeds threshold "
                        f"{self.top_k_threshold} on {index}/"
                        f"{namespace or '<default>'} (over-fetch; op_id={op_id})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "query_top_k_exceeded",
                        "top_k_threshold": self.top_k_threshold,
                    },
                )
            )

        # 5. query without filter_keys — un-scoped query (FLAG).
        if operation == "query" and not filter_keys:
            control_id = _control_for("query_no_filter", self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Pinecone query on {index}/{namespace or '<default>'} "
                        f"submitted without filter — un-scoped vector search "
                        f"(op_id={op_id})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "query_no_filter",
                    },
                )
            )

        # 6. Cross-namespace pattern — same trace/api_key touching multiple namespaces.
        if self.detect_cross_namespace:
            bucket = self._cross_namespace_bucket_key(op)
            if bucket is not None:
                ns_set = cross_ns_buckets.get(bucket, set())
                if len(ns_set) > 1:
                    control_id = _control_for(
                        "cross_namespace_pattern", self._mappings, "PR-02"
                    )
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Pinecone {operation} via {bucket} touched "
                                f"{len(ns_set)} namespaces "
                                f"({sorted(ns_set)}) — possible scope expansion "
                                f"(op_id={op_id})"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": "cross_namespace_pattern",
                                "cross_namespace_bucket": bucket,
                                "namespaces_in_bucket": sorted(ns_set),
                                "namespace_count_in_bucket": len(ns_set),
                            },
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
            f"Imported from Pinecone: {operation} on {index}/"
            f"{namespace or '<default>'} status={status} "
            f"vectors={vector_count} top_k={top_k}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"pinecone-{op_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="pinecone_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=latency_ms,
            session_id=str(trace_id) if trace_id else None,
        )
