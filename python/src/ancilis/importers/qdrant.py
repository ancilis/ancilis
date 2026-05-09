"""Qdrant vector store audit event importer — converts Qdrant audit logs to AKSI EvaluationResults.

Qdrant (https://qdrant.tech) is the dominant Rust-based open-source vector
database in self-hosted RAG stacks: high-throughput, payload-rich, with REST
and gRPC surfaces. When audit logging is enabled (Qdrant Cloud, or self-hosted
with logging configured), each request against a collection produces an event
record. This importer turns each event into one EvaluationResult.

Accepted on-disk shapes:

  1. Envelope with events:    ``{"events": [{...}, ...]}``
  2. Generic data envelope:   ``{"data": [{...}, ...]}``
  3. JSON array:              ``[{...}, {...}]``
  4. Single object:           ``{...}``  (treated as one event)
  5. JSONL stream:            one JSON object per line

Signal mapping (see shared/mappings/qdrant-aksi-controls.json):

  Per-operation success
    * ``search`` / ``scroll``                     → PR-04 PASS  (data access governance)
    * ``upsert``                                  → PR-03 PASS  (provenance / write integrity)
    * ``delete``                                  → PR-05 PASS  (audit trail)

  Privileged operations (always FLAG, even on success)
    * ``create_collection`` / ``delete_collection`` → PR-05 FLAG (schema-change governance)
    * ``snapshot_create`` / ``snapshot_recover``    → PR-05 FLAG (privileged backup ops)

  Errors
    * ``status=error`` & ``error_status=Forbidden`` → PR-02 FAIL (scope / authz)
    * ``status=error`` & ``error_status=BadRequest``→ PR-03 FLAG (input validation)
    * ``status=error`` & ``error_status=Internal``  → DE-01 FAIL (service failure)
    * ``status=error`` & ``error_status=NotFound``  → PR-02 FLAG (probing / missing scope)

  Search-quality flags (additive)
    * ``with_vectors=true``                        → PR-04 FLAG (raw vectors leaked)
    * No ``filter_keys`` on search                 → PR-04 FLAG (un-scoped query)
    * ``limit > threshold`` (default 500)          → PR-04 FLAG (over-fetch)
    * ``exact=true``                               → PR-04 FLAG (full-scan; expensive
                                                     and leaks score distribution)

  Synthetic finding (cross-event correlation)
    * Same actor across multiple collections       → PR-02 FLAG (scope expansion);
                                                     emitted as a separate
                                                     EvaluationResult.

Sanitization: filter values, vector arrays, and payload contents are NEVER
persisted. We capture only structural information — the *names* of filter keys,
counts (result_count, limit), and tunable booleans (with_vectors, with_payload,
exact, consistency). The original file is hashed (sha256) for source provenance
so downstream evidence can detect tampering without retaining sensitive data.

Why ``exact=true`` is its own flag:
    Qdrant's ``exact=true`` search disables the HNSW index and performs a
    brute-force full-scan over every vector in the segment. Beyond the obvious
    cost, exact scans return the *true* score distribution rather than the
    HNSW-approximated top-k, which leaks more information about neighbours
    than an approximate query of the same ``limit``. We treat repeated
    exact-true searches as a governance signal worth surfacing — separately
    from limit/filter flags — so reviewers can distinguish "expensive query"
    from "deliberate full-scan exfiltration probe."

Why cross-collection actor detection runs at the importer:
    A single event cannot tell you whether the actor is operating within a
    legitimate scope. By correlating events across the same export, the
    importer can identify actors who touched ≥2 distinct collections in one
    window and emit a synthetic PR-02 FLAG. This is the same pattern used by
    the Pinecone and Weaviate importers (cross-namespace / cross-tenant) and
    keeps scope-expansion detection vendor-consistent.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table.
# This file lives at <repo>/python/src/ancilis/importers/qdrant.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "qdrant-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_LIMIT_THRESHOLD = 500

# Read-style operations whose success is governed by PR-04.
_READ_OPS: frozenset[str] = frozenset({"search", "scroll"})
# Write-style operations whose success is governed by PR-03.
_WRITE_OPS: frozenset[str] = frozenset({"upsert"})
# Delete operations governed by PR-05.
_DELETE_OPS: frozenset[str] = frozenset({"delete"})
# Schema lifecycle ops — privileged, FLAG even on success.
_LIFECYCLE_OPS: frozenset[str] = frozenset(
    {"create_collection", "delete_collection"}
)
# Snapshot ops — privileged backup, FLAG even on success.
_SNAPSHOT_OPS: frozenset[str] = frozenset(
    {"snapshot_create", "snapshot_recover"}
)

# Map error_status values (case-insensitive) to the signal name used in the
# mapping table.
_ERROR_STATUS_SIGNALS: dict[str, str] = {
    "forbidden": "error_status_forbidden",
    "badrequest": "error_status_bad_request",
    "bad_request": "error_status_bad_request",
    "notfound": "error_status_not_found",
    "not_found": "error_status_not_found",
    "internal": "error_status_internal",
}

# Default control if the mapping file is missing or stripped.
_DEFAULT_OPERATION_CONTROLS: dict[str, str] = {
    "operation_search_success": "PR-04",
    "operation_scroll_success": "PR-04",
    "operation_upsert_success": "PR-03",
    "operation_delete_success": "PR-05",
    "operation_create_collection": "PR-05",
    "operation_delete_collection": "PR-05",
    "operation_snapshot_create": "PR-05",
    "operation_snapshot_recover": "PR-05",
    "search_with_vectors": "PR-04",
    "search_no_filter": "PR-04",
    "search_limit_exceeded": "PR-04",
    "search_exact_scan": "PR-04",
    "cross_collection_pattern": "PR-02",
    "error_status_forbidden": "PR-02",
    "error_status_bad_request": "PR-03",
    "error_status_internal": "DE-01",
    "error_status_not_found": "PR-02",
}


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------

def _load_mapping_table() -> dict[str, Any]:
    """Load qdrant-aksi-controls.json; tolerate missing file."""
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
# Filter-key sanitization
# ---------------------------------------------------------------------------

def _sanitize_filter_keys(filter_keys: Any) -> list[str]:
    """Return only the *names* of filter keys, never their values.

    Accepts a list[str] (the canonical Qdrant audit shape) or, defensively,
    a dict whose top-level keys are the filter fields. Filter *values* — which
    can carry user PII or business secrets — are dropped on the floor.
    """
    if filter_keys is None:
        return []
    if isinstance(filter_keys, list):
        return sorted({str(k) for k in filter_keys if isinstance(k, (str, int))})
    if isinstance(filter_keys, dict):
        return sorted(str(k) for k in filter_keys.keys())
    return []


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class QdrantImporter:
    """Parse a Qdrant audit-event export and convert to EvaluationResults."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        limit_threshold: int | None = None,
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
        if limit_threshold is not None:
            self.limit_threshold = int(limit_threshold)
        else:
            self.limit_threshold = int(
                meta.get("default_limit_threshold", _DEFAULT_LIMIT_THRESHOLD)
            )
        if detect_cross_collection is not None:
            self.detect_cross_collection = bool(detect_cross_collection)
        else:
            self.detect_cross_collection = bool(
                meta.get("default_cross_collection_detection", True)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Qdrant audit export file and return one EvaluationResult per event.

        A synthetic cross-collection EvaluationResult may be appended at the
        end of the returned list when an actor touches ≥2 collections in the
        same export.
        """
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Qdrant audit content from a JSON / JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON / JSONL / envelope and return event dicts."""
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
                if "events" in doc and isinstance(doc["events"], list):
                    return [e for e in doc["events"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single-event document.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "qdrant",
            "source_tool_name": "qdrant",
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
        results: list[EvaluationResult] = [
            self._parse_event(e, file_sha256=file_sha256) for e in events
        ]

        if self.detect_cross_collection:
            synthetic = self._cross_collection_finding(
                events, file_sha256=file_sha256
            )
            if synthetic is not None:
                results.append(synthetic)
        return results

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        event_id = str(event.get("id") or event.get("request_id") or uuid.uuid4())
        operation_raw = str(event.get("operation") or "").strip().lower()
        collection = str(event.get("collection") or "")
        shard_key = event.get("shard_key")
        actor = event.get("actor")
        api_key_hint = event.get("api_key_hint")
        request_id = event.get("request_id")
        status_raw = str(event.get("status") or "ok").strip().lower()
        error_status_raw = event.get("error_status")
        error_status_norm = (
            str(error_status_raw).strip().lower().replace(" ", "")
            if error_status_raw
            else ""
        )
        try:
            limit = int(event.get("limit")) if event.get("limit") is not None else None
        except (TypeError, ValueError):
            limit = None
        with_payload = bool(event.get("with_payload")) if event.get("with_payload") is not None else None
        with_vectors = bool(event.get("with_vectors")) if event.get("with_vectors") is not None else None
        try:
            score_threshold = (
                float(event.get("score_threshold"))
                if event.get("score_threshold") is not None
                else None
            )
        except (TypeError, ValueError):
            score_threshold = None
        exact = bool(event.get("exact")) if event.get("exact") is not None else False
        consistency = event.get("consistency")
        try:
            result_count = (
                int(event.get("result_count"))
                if event.get("result_count") is not None
                else None
            )
        except (TypeError, ValueError):
            result_count = None
        try:
            duration_ms = float(event.get("duration_ms") or 0.0)
        except (TypeError, ValueError):
            duration_ms = 0.0
        filter_keys = _sanitize_filter_keys(event.get("filter_keys"))

        source_provenance = self._source_provenance(file_sha256=file_sha256)
        common_evidence: dict[str, Any] = {
            "qdrant_event_id": event_id,
            "operation": operation_raw,
            "collection": collection,
            "shard_key": shard_key,
            "actor": actor,
            "api_key_hint": api_key_hint,
            "request_id": request_id,
            "status": status_raw,
            "error_status": error_status_raw,
            "limit": limit,
            "with_payload": with_payload,
            "with_vectors": with_vectors,
            "score_threshold": score_threshold,
            "exact": exact,
            "consistency": consistency,
            "result_count": result_count,
            "duration_ms": duration_ms,
            "filter_keys": filter_keys,
            "source_provenance": source_provenance,
            "source_tool": "qdrant",
        }

        control_results: list[ControlResult] = []

        # 1. Error path takes priority over operation-success mapping.
        if status_raw == "error":
            signal = _ERROR_STATUS_SIGNALS.get(
                error_status_norm, "error_status_internal"
            )
            # Internal & forbidden are FAIL; bad_request & not_found are FLAG.
            if signal in ("error_status_forbidden", "error_status_internal"):
                result_level = "FAIL"
            else:
                result_level = "FLAG"
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
                        f"Qdrant {operation_raw} on collection={collection!r} "
                        f"failed with error_status={error_status_raw!r} "
                        f"(actor={actor!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # 2. Operation-success mapping.
            op_signal, op_result = self._operation_signal(operation_raw)
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
                            operation_raw, collection, actor, result_count
                        ),
                        evidence_data={**common_evidence, "signal": op_signal},
                    )
                )

            # 3. Search-quality flags — additive on successful searches only.
            if operation_raw == "search":
                if with_vectors is True:
                    control_results.append(
                        self._build_flag(
                            "search_with_vectors",
                            common_evidence,
                            (
                                f"Qdrant search on {collection!r} returned raw vectors "
                                f"(with_vectors=true) — vector data exposure"
                            ),
                        )
                    )
                if not filter_keys:
                    control_results.append(
                        self._build_flag(
                            "search_no_filter",
                            common_evidence,
                            (
                                f"Qdrant search on {collection!r} ran with no filter_keys "
                                f"(un-scoped query)"
                            ),
                        )
                    )
                if limit is not None and limit > self.limit_threshold:
                    control_results.append(
                        self._build_flag(
                            "search_limit_exceeded",
                            {
                                **common_evidence,
                                "limit_threshold": self.limit_threshold,
                            },
                            (
                                f"Qdrant search on {collection!r} requested limit={limit} "
                                f"> threshold={self.limit_threshold} (over-fetch)"
                            ),
                        )
                    )
                if exact is True:
                    control_results.append(
                        self._build_flag(
                            "search_exact_scan",
                            common_evidence,
                            (
                                f"Qdrant search on {collection!r} requested exact=true "
                                f"(full-scan; expensive and leaks score distribution)"
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
            f"Imported from Qdrant: operation={operation_raw} "
            f"collection={collection} status={status_raw} "
            f"actor={actor!r}"
        )

        timestamp = (
            event.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"qdrant-{event_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="qdrant_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=str(request_id) if request_id else None,
        )

    # -- Helpers ------------------------------------------------------------

    def _operation_signal(self, op: str) -> tuple[str | None, str]:
        """Return ``(signal_name, result_level)`` for a Qdrant operation.

        ``result_level`` is "PASS" for routine read/write/delete and "FLAG" for
        privileged lifecycle/snapshot operations (which are always governance
        events even on success).
        """
        if op in _READ_OPS:
            return f"operation_{op}_success", "PASS"
        if op in _WRITE_OPS:
            return f"operation_{op}_success", "PASS"
        if op in _DELETE_OPS:
            return f"operation_{op}_success", "PASS"
        if op in _LIFECYCLE_OPS:
            return f"operation_{op}", "FLAG"
        if op in _SNAPSHOT_OPS:
            return f"operation_{op}", "FLAG"
        # Unknown operation — emit a generic data-access PASS so downstream
        # consumers still get a record. We intentionally do not FAIL on
        # unknown ops because Qdrant adds new ones in minor releases.
        if op:
            return "operation_search_success", "PASS"
        return None, "PASS"

    def _operation_detail(
        self,
        op: str,
        collection: str,
        actor: Any,
        result_count: int | None,
    ) -> str:
        if result_count is not None:
            return (
                f"Qdrant {op} on collection={collection!r} by actor={actor!r} "
                f"returned {result_count} result(s)"
            )
        return (
            f"Qdrant {op} on collection={collection!r} by actor={actor!r}"
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
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        """Emit one synthetic FLAG per export when an actor touched ≥2 collections.

        Hardcoded to one synthetic record covering the most-promiscuous actor
        across all collections in the export, so a noisy log does not produce
        N synthetic findings. Returns ``None`` when no such pattern exists.
        """
        actor_to_collections: dict[str, set[str]] = defaultdict(set)
        actor_event_counts: dict[str, int] = defaultdict(int)
        for ev in events:
            actor = ev.get("actor")
            collection = ev.get("collection")
            if not actor or not collection:
                continue
            actor_str = str(actor)
            collection_str = str(collection)
            actor_to_collections[actor_str].add(collection_str)
            actor_event_counts[actor_str] += 1

        crossing_actors = {
            a: cols for a, cols in actor_to_collections.items() if len(cols) >= 2
        }
        if not crossing_actors:
            return None

        # Pick the actor with the most cross-collection events for the
        # primary synthetic finding (deterministic on ties via name).
        top_actor = max(
            crossing_actors.keys(),
            key=lambda a: (len(crossing_actors[a]), actor_event_counts[a], a),
        )
        collections_touched = sorted(crossing_actors[top_actor])

        signal = "cross_collection_pattern"
        control_id = _control_for(
            signal, self._mappings, _DEFAULT_OPERATION_CONTROLS[signal]
        )
        evidence: dict[str, Any] = {
            "qdrant_event_id": f"synthetic-{uuid.uuid4()}",
            "signal": signal,
            "actor": top_actor,
            "collections_touched": collections_touched,
            "collection_count": len(collections_touched),
            "event_count": actor_event_counts[top_actor],
            "all_crossing_actors": {
                a: sorted(cols) for a, cols in crossing_actors.items()
            },
            "source_provenance": self._source_provenance(file_sha256=file_sha256),
            "source_tool": "qdrant",
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Qdrant actor {top_actor!r} accessed "
                f"{len(collections_touched)} collections "
                f"({', '.join(collections_touched)}) in single export "
                f"(scope expansion)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"qdrant-synthetic-{uuid.uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="qdrant_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Synthetic finding: actor {top_actor!r} touched "
                f"{len(collections_touched)} collections in one export"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
