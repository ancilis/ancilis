"""Tavily AI-search-API importer — maps agent web-search requests to AKSI controls.

Tavily (https://tavily.com) is an AI-native web search API built for autonomous
agents. Each request hits the open web through one of three endpoints:

  * ``search`` — return a ranked list of web results (and optionally an LLM-
    synthesized answer) for an agent query.
  * ``extract`` — pull the full text of one or more URLs (heavier surface;
    raw page content is dragged into the agent context).
  * ``qna`` — synthesize a direct natural-language answer over fresh web
    results, optionally including the ``raw_content`` (raw HTML/text) of each
    source — a known prompt-injection vector when an attacker controls a
    ranked page.

This is fundamentally different from internal-corpus RAG: every result has
third-party provenance, every page is a potential prompt-injection vector,
and the include/exclude domain lists themselves can encode targeting
strategy that's competitively sensitive. Tavily logs requests via
``GET /usage`` and webhook events; bulk exports come as ``{"requests": [...]}``
envelopes, ``{"data": [...]}`` arrays, or JSONL streams of the same record
shape.

Signal mapping (see shared/mappings/tavily-aksi-controls.json):
  * ``status=success`` & ``endpoint=search``                    → PR-04 PASS  (web data access — audit)
  * ``status=success`` & ``endpoint=extract``                   → PR-04 FLAG  (full-content extraction — bigger surface)
  * ``status=success`` & ``endpoint=qna`` &
    ``include_raw_content=true``                                → PR-04 FLAG  (raw HTML pulled — injection risk)
  * ``status=failed`` & ``error_code=INVALID_KEY``              → PR-01 FAIL  (auth failure)
  * ``status=failed`` & ``error_code=RATE_LIMITED``             → PR-02 FLAG  (capacity / abuse)
  * ``status=failed`` & ``error_code=TIMEOUT``                  → DE-01 FLAG  (provider failure)
  * ``status=failed`` & ``error_code=CONTENT_TOO_LARGE``        → PR-04 FLAG  (oversized ingest attempted)
  * ``prompt_injection_detected=true``                          → PR-01 FAIL  (Tavily detected prompt injection in results)
  * ``flagged_content`` non-empty                               → PR-03 FLAG  (content moderation)
  * ``unique_domains_returned`` > threshold                     → PR-04 FLAG  (broad-fan-out / recon-shaped)
  * ``include_domains`` empty AND ``exclude_domains`` empty
    AND ``topic=general``                                       → PR-04 FLAG  (un-scoped open web search)
  * Volume: same agent_id with > N searches in 1h               → PR-04 FLAG  (mass-search synthetic finding)
  * Cross-topic: same agent_id touching > N distinct topics
    in 1h                                                       → PR-05 PASS  (audit-trail breadth, captured)

Sanitization rules (privacy + competitive sensitivity):
  * The full ``query`` text is NEVER stored; only ``query_length`` is surfaced.
  * The ``answer`` body is NEVER stored; only ``answer_length`` is surfaced.
  * ``include_domains`` / ``exclude_domains`` are NEVER stored as full lists
    (they encode targeting strategy). Only counts and a sha256 hash of the
    sorted-joined list are surfaced — enough for posture lineage and
    cross-record matching, never enough to reconstruct the list.
  * ``api_key_id`` is captured last-4 only.
  * ``customer_metadata.user_id`` is captured last-8 only.
  * Other ``customer_metadata`` values are NEVER stored raw — only the key
    list is surfaced, so ops can see which dimensions are being labelled
    without leaking the labels themselves.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/tavily-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/tavily.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "tavily-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_VOLUME_THRESHOLD = 50
_DEFAULT_CROSS_TOPIC_THRESHOLD = 4
_DEFAULT_UNIQUE_DOMAINS_THRESHOLD = 50
_DEFAULT_ANSWER_LENGTH_THRESHOLD = 5000
_DEFAULT_DAYS_THRESHOLD = 30


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the tavily-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
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


def _last_n(value: Any, n: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    return text[-n:] if len(text) > n else text


def _hash_domain_list(domains: list[str]) -> dict[str, Any]:
    """Sanitized representation of a domain include/exclude list.

    Returns count + sha256 of the sorted, lowercased, joined list. Never
    returns the raw list — domain targeting strategy is competitively
    sensitive, but a stable hash still lets posture analysis match records
    that used the same list.
    """
    cleaned = sorted({d.strip().lower() for d in domains if isinstance(d, str) and d.strip()})
    joined = "\n".join(cleaned)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest() if cleaned else ""
    return {
        "count": len(cleaned),
        "sha256": digest,
    }


def _parse_iso_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class TavilyImporter:
    """Parse a Tavily request-log export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        volume_threshold: int | None = None,
        cross_topic_threshold: int | None = None,
        unique_domains_threshold: int | None = None,
        answer_length_threshold: int | None = None,
        days_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        self.volume_threshold = int(
            volume_threshold
            if volume_threshold is not None
            else meta.get("default_volume_threshold", _DEFAULT_VOLUME_THRESHOLD)
        )
        self.cross_topic_threshold = int(
            cross_topic_threshold
            if cross_topic_threshold is not None
            else meta.get("default_cross_topic_threshold", _DEFAULT_CROSS_TOPIC_THRESHOLD)
        )
        self.unique_domains_threshold = int(
            unique_domains_threshold
            if unique_domains_threshold is not None
            else meta.get(
                "default_unique_domains_threshold", _DEFAULT_UNIQUE_DOMAINS_THRESHOLD
            )
        )
        self.answer_length_threshold = int(
            answer_length_threshold
            if answer_length_threshold is not None
            else meta.get(
                "default_answer_length_threshold", _DEFAULT_ANSWER_LENGTH_THRESHOLD
            )
        )
        self.days_threshold = int(
            days_threshold
            if days_threshold is not None
            else meta.get("default_days_threshold", _DEFAULT_DAYS_THRESHOLD)
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Tavily export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        requests = self._requests_from_text(text)
        return self._build_results(requests, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Tavily export content from a JSON or JSONL string."""
        requests = self._requests_from_text(content)
        return self._build_results(requests, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _requests_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"requests": [...]}`` / ``{"data": [...]}`` / JSONL."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [r for r in doc if isinstance(r, dict)]
            if isinstance(doc, dict):
                if "requests" in doc and isinstance(doc["requests"], list):
                    return [r for r in doc["requests"] if isinstance(r, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [r for r in doc["data"] if isinstance(r, dict)]
                # Single request object.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        requests: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-request EvaluationResults plus volume / cross-topic synthetics."""
        # First pass: per-agent 1h windowed counts + topic sets for synthetic findings.
        # Each agent gets a sequence of (timestamp, topic) tuples. We pick the
        # 1h sliding window with the maximum hit count — if it crosses the
        # volume_threshold, we emit a synthetic mass-search finding. Same
        # window, distinct-topic count drives the cross-topic synthetic.
        agent_events: dict[str, list[tuple[datetime, str]]] = {}
        for req in requests:
            agent_id = self._extract_agent_id(req)
            if not agent_id:
                continue
            ts = _parse_iso_timestamp(req.get("timestamp"))
            if ts is None:
                continue
            topic = str(req.get("topic") or "").strip().lower() or "unknown"
            agent_events.setdefault(agent_id, []).append((ts, topic))

        volume_agents: dict[str, dict[str, Any]] = {}
        cross_topic_agents: dict[str, dict[str, Any]] = {}
        for agent_id, events in agent_events.items():
            if not events:
                continue
            events.sort(key=lambda e: e[0])
            # Sliding 1h window — best (max-count) window for volume,
            # best (max-distinct-topic) window for cross-topic.
            best_count = 0
            best_window_topics: set[str] = set()
            best_distinct = 0
            best_distinct_topics: set[str] = set()
            j = 0
            window_topics: dict[str, int] = {}
            for i in range(len(events)):
                # Advance left edge so window is <= 1h.
                while j <= i and (events[i][0] - events[j][0]).total_seconds() > 3600.0:
                    topic_j = events[j][1]
                    window_topics[topic_j] = window_topics.get(topic_j, 0) - 1
                    if window_topics[topic_j] <= 0:
                        window_topics.pop(topic_j, None)
                    j += 1
                topic_i = events[i][1]
                window_topics[topic_i] = window_topics.get(topic_i, 0) + 1
                count = i - j + 1
                if count > best_count:
                    best_count = count
                    best_window_topics = set(window_topics.keys())
                if len(window_topics) > best_distinct:
                    best_distinct = len(window_topics)
                    best_distinct_topics = set(window_topics.keys())
            if best_count > self.volume_threshold:
                volume_agents[agent_id] = {
                    "max_window_count": best_count,
                    "topics_in_window": sorted(best_window_topics),
                }
            if best_distinct > self.cross_topic_threshold:
                cross_topic_agents[agent_id] = {
                    "max_distinct_topics": best_distinct,
                    "topics_in_window": sorted(best_distinct_topics),
                }

        results: list[EvaluationResult] = [
            self._parse_request(
                req,
                file_sha256=file_sha256,
                volume_agents=volume_agents,
                cross_topic_agents=cross_topic_agents,
            )
            for req in requests
        ]

        # Synthetic per-agent volume findings.
        for agent_id, info in sorted(volume_agents.items()):
            results.append(
                self._synthetic_volume_result(
                    agent_id=agent_id,
                    info=info,
                    file_sha256=file_sha256,
                )
            )
        # Synthetic per-agent cross-topic findings.
        for agent_id, info in sorted(cross_topic_agents.items()):
            results.append(
                self._synthetic_cross_topic_result(
                    agent_id=agent_id,
                    info=info,
                    file_sha256=file_sha256,
                )
            )
        return results

    @staticmethod
    def _extract_agent_id(entry: dict[str, Any]) -> str | None:
        """Resolve agent_id from top-level field or customer_metadata."""
        agent_id = entry.get("agent_id")
        if isinstance(agent_id, str) and agent_id:
            return agent_id
        meta = entry.get("customer_metadata")
        if isinstance(meta, dict):
            cand = meta.get("agent_id")
            if isinstance(cand, str) and cand:
                return cand
        return None

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        request_id: str,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "tavily",
            "source_tool_name": "tavily",
            "source_tool_version": "",
            "request_id": request_id,
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _parse_request(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        volume_agents: dict[str, dict[str, Any]],
        cross_topic_agents: dict[str, dict[str, Any]],
    ) -> EvaluationResult:
        request_id = str(entry.get("id") or uuid.uuid4().hex[:16])
        endpoint = str(entry.get("endpoint") or "").strip().lower() or "unknown"
        api_key_id_raw = entry.get("api_key_id")
        api_key_id_last4 = _last_n(api_key_id_raw, 4)
        timestamp = entry.get("timestamp") or datetime.now(timezone.utc).isoformat()

        query_length = _coerce_int(entry.get("query_length"))
        search_depth = str(entry.get("search_depth") or "").strip().lower() or None
        topic = str(entry.get("topic") or "").strip().lower() or None
        include_answer = bool(entry.get("include_answer", False))
        include_raw_content = bool(entry.get("include_raw_content", False))
        include_images = bool(entry.get("include_images", False))
        max_results = _coerce_int(entry.get("max_results"))
        days = _coerce_int(entry.get("days"))
        results_count = _coerce_int(entry.get("results_count"))
        answer_length = _coerce_int(entry.get("answer_length"))
        total_response_size_bytes = _coerce_int(entry.get("total_response_size_bytes"))
        latency_ms = _coerce_float(entry.get("latency_ms"))
        status = str(entry.get("status") or "").strip().lower() or "unknown"
        error_code_raw = entry.get("error_code")
        error_code = (
            str(error_code_raw).strip().upper()
            if isinstance(error_code_raw, str) and error_code_raw.strip()
            else None
        )
        is_streaming = bool(entry.get("is_streaming", False))
        prompt_injection_detected = bool(entry.get("prompt_injection_detected", False))
        flagged_content_raw = entry.get("flagged_content") or []
        flagged_content = (
            [str(f) for f in flagged_content_raw if isinstance(f, str)]
            if isinstance(flagged_content_raw, list)
            else []
        )
        unique_domains_returned = _coerce_int(entry.get("unique_domains_returned"))

        include_domains_raw = entry.get("include_domains") or []
        exclude_domains_raw = entry.get("exclude_domains") or []
        include_domains = (
            [str(d) for d in include_domains_raw if isinstance(d, str)]
            if isinstance(include_domains_raw, list)
            else []
        )
        exclude_domains = (
            [str(d) for d in exclude_domains_raw if isinstance(d, str)]
            if isinstance(exclude_domains_raw, list)
            else []
        )
        include_domains_summary = _hash_domain_list(include_domains)
        exclude_domains_summary = _hash_domain_list(exclude_domains)

        # Institutional-source detection — include patterns like *.gov / *.edu
        # or bare suffixes "gov" / "edu". Surface as captured signal.
        institutional_hits: list[str] = []
        for d in include_domains:
            dn = d.strip().lower()
            if dn.endswith(".gov") or dn.endswith(".edu") or dn in {
                "*.gov", "*.edu", "gov", "edu",
            }:
                institutional_hits.append(d)

        agent_id_observed = self._extract_agent_id(entry)

        # customer_metadata: keep key list and last-8 of user_id only.
        meta_raw = entry.get("customer_metadata")
        customer_metadata_keys: list[str] = []
        customer_user_id_last8: str | None = None
        if isinstance(meta_raw, dict):
            customer_metadata_keys = sorted(meta_raw.keys())
            customer_user_id_last8 = _last_n(meta_raw.get("user_id"), 8)

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            request_id=request_id,
        )

        common_evidence: dict[str, Any] = {
            "tavily_request_id": request_id,
            "endpoint": endpoint,
            "api_key_id_last4": api_key_id_last4,
            "query_length": query_length,
            "search_depth": search_depth,
            "topic": topic,
            "include_answer": include_answer,
            "include_raw_content": include_raw_content,
            "include_images": include_images,
            "max_results": max_results,
            "days": days,
            "results_count": results_count,
            "answer_length": answer_length,
            "total_response_size_bytes": total_response_size_bytes,
            "latency_ms": latency_ms,
            "status": status,
            "error_code": error_code,
            "is_streaming": is_streaming,
            "prompt_injection_detected": prompt_injection_detected,
            "flagged_content": flagged_content,
            "unique_domains_returned": unique_domains_returned,
            "include_domains_summary": include_domains_summary,
            "exclude_domains_summary": exclude_domains_summary,
            "agent_id_observed": agent_id_observed,
            "customer_metadata_keys": customer_metadata_keys,
            "customer_user_id_last8": customer_user_id_last8,
            "timestamp": str(timestamp),
            "source_provenance": source_provenance,
            "source_tool": "tavily",
        }

        control_results: list[ControlResult] = []

        # 1. prompt_injection_detected — top-priority signal, evaluated first
        # because a detected injection should fail the request regardless of
        # status. (A failed search that ALSO returned an injection is still
        # a security-relevant event.)
        if prompt_injection_detected:
            signal = "prompt_injection_detected"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Tavily request {request_id} on endpoint={endpoint} flagged "
                        f"prompt_injection_detected=true — Tavily detected a prompt "
                        f"injection in returned web results"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 2. Primary status / endpoint signal — exactly one ControlResult.
        if status == "failed":
            if error_code == "INVALID_KEY":
                signal = "error_invalid_key"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Tavily request {request_id} on endpoint={endpoint} failed "
                            f"with INVALID_KEY (auth failure, key={api_key_id_last4})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif error_code == "RATE_LIMITED":
                signal = "error_rate_limited"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Tavily request {request_id} on endpoint={endpoint} "
                            f"rate-limited (capacity / abuse signal)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif error_code == "TIMEOUT":
                signal = "error_timeout"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Tavily request {request_id} on endpoint={endpoint} timed out "
                            f"(provider failure, latency_ms={latency_ms})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif error_code == "CONTENT_TOO_LARGE":
                signal = "error_content_too_large"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Tavily request {request_id} on endpoint={endpoint} failed "
                            f"with CONTENT_TOO_LARGE — oversized ingest attempted "
                            f"(total_response_size_bytes={total_response_size_bytes})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "error_unknown"
                control_results.append(
                    ControlResult(
                        control_id="DE-01",
                        control_name=_CONTROL_NAMES["DE-01"],
                        result="FLAG",
                        detail=(
                            f"Tavily request {request_id} on endpoint={endpoint} failed "
                            f"with unrecognized error_code={error_code_raw!r}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif status == "success":
            if endpoint == "search":
                signal = "endpoint_search_success"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Tavily request {request_id} endpoint=search succeeded — "
                            f"web data access audited (results_count={results_count}, "
                            f"unique_domains={unique_domains_returned})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif endpoint == "extract":
                signal = "endpoint_extract_success"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Tavily request {request_id} endpoint=extract succeeded — "
                            f"full-content extraction is a larger ingest surface "
                            f"(total_response_size_bytes={total_response_size_bytes})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif endpoint == "qna" and include_raw_content:
                signal = "endpoint_qna_raw_content"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Tavily request {request_id} endpoint=qna succeeded with "
                            f"include_raw_content=true — raw HTML pulled into agent "
                            f"context (prompt-injection vector)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif endpoint == "qna":
                signal = "endpoint_qna_success"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Tavily request {request_id} endpoint=qna succeeded "
                            f"(answer_length={answer_length})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "endpoint_unknown"
                control_results.append(
                    ControlResult(
                        control_id="PR-04",
                        control_name=_CONTROL_NAMES["PR-04"],
                        result="FLAG",
                        detail=(
                            f"Tavily request {request_id} succeeded with "
                            f"unrecognized endpoint={entry.get('endpoint')!r}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        else:
            # Unknown / missing status — surface as FLAG.
            control_results.append(
                ControlResult(
                    control_id="PR-04",
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="FLAG",
                    detail=(
                        f"Tavily request {request_id} on endpoint={endpoint} has "
                        f"unrecognized status={entry.get('status')!r}"
                    ),
                    evidence_data={**common_evidence, "signal": "status_unknown"},
                )
            )

        # 3. flagged_content moderation — additive PR-03 FLAG.
        if flagged_content:
            signal = "flagged_content"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Tavily request {request_id} returned flagged_content "
                        f"categories={flagged_content} (Tavily content moderation)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 4. Broad fan-out / recon-shaped search — additive PR-04 FLAG.
        if unique_domains_returned > self.unique_domains_threshold:
            signal = "broad_fanout"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Tavily request {request_id} returned "
                        f"{unique_domains_returned} unique domains (> threshold "
                        f"{self.unique_domains_threshold}) — possibly recon-shaped"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "unique_domains_threshold": self.unique_domains_threshold,
                    },
                )
            )

        # 5. Un-scoped open-web search — additive PR-04 FLAG.
        if (
            status == "success"
            and not include_domains
            and not exclude_domains
            and topic == "general"
        ):
            signal = "unscoped_open_web"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Tavily request {request_id} on endpoint={endpoint} performed "
                        f"un-scoped open-web search "
                        f"(no include_domains/exclude_domains, topic=general)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 6. Institutional-source captured — informational PASS surfaces the fact.
        if institutional_hits:
            signal = "institutional_sources"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Tavily request {request_id} restricted to institutional "
                        f"sources (matched {len(institutional_hits)} include patterns)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "institutional_match_count": len(institutional_hits),
                    },
                )
            )

        # 7. Deep historical search — captured PASS.
        if search_depth == "advanced" and days > self.days_threshold:
            signal = "deep_historical_search"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Tavily request {request_id} ran advanced search over "
                        f"{days} days (> threshold {self.days_threshold}) — deep "
                        f"historical search captured"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "days_threshold": self.days_threshold,
                    },
                )
            )

        # 8. topic=finance / topic=news — captured PASS (PR-impact / trading scope).
        if topic in {"finance", "news"} and status == "success":
            signal = "topic_finance_or_news"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Tavily request {request_id} on topic={topic} captured — "
                        f"potential trading or PR-impact scope"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 9. Large answer returned — captured PASS.
        if answer_length > self.answer_length_threshold:
            signal = "large_answer"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Tavily request {request_id} returned a large summary "
                        f"(answer_length={answer_length} > threshold "
                        f"{self.answer_length_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "answer_length_threshold": self.answer_length_threshold,
                    },
                )
            )

        # 10. Volume-pattern context on each contributing record (synthetic emitted separately).
        if (
            isinstance(agent_id_observed, str)
            and agent_id_observed in volume_agents
        ):
            signal = "volume_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            info = volume_agents[agent_id_observed]
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Tavily request {request_id} agent {agent_id_observed} "
                        f"is part of a mass-search pattern "
                        f"({info['max_window_count']} requests in 1h > threshold "
                        f"{self.volume_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "max_window_count": info["max_window_count"],
                        "volume_threshold": self.volume_threshold,
                    },
                )
            )

        # 11. Cross-topic-pattern context on each contributing record.
        if (
            isinstance(agent_id_observed, str)
            and agent_id_observed in cross_topic_agents
        ):
            signal = "cross_topic_pattern"
            control_id = _control_for(signal, self._mappings, "PR-05")
            info = cross_topic_agents[agent_id_observed]
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Tavily request {request_id} agent {agent_id_observed} "
                        f"is part of a cross-topic pattern "
                        f"({info['max_distinct_topics']} distinct topics in 1h > "
                        f"threshold {self.cross_topic_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "max_distinct_topics": info["max_distinct_topics"],
                        "topics_in_window": info["topics_in_window"],
                        "cross_topic_threshold": self.cross_topic_threshold,
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
            f"Imported from Tavily: endpoint={endpoint} status={status} "
            f"error_code={error_code or 'null'} "
            f"prompt_injection_detected={prompt_injection_detected} "
            f"results_count={results_count}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"tavily-{request_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="tavily_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=latency_ms,
            session_id=agent_id_observed or None,
        )

    def _synthetic_volume_result(
        self,
        *,
        agent_id: str,
        info: dict[str, Any],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-agent mass-search finding."""
        signal = "volume_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"tavily-volume-{agent_id}"
        evidence: dict[str, Any] = {
            "tavily_request_id": synthetic_id,
            "agent_id_observed": agent_id,
            "max_window_count": info["max_window_count"],
            "volume_threshold": self.volume_threshold,
            "topics_in_window": info["topics_in_window"],
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                request_id=synthetic_id,
            ),
            "source_tool": "tavily",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Tavily synthetic finding: agent {agent_id} ran "
                f"{info['max_window_count']} searches in a 1h window > threshold "
                f"{self.volume_threshold} (mass-search pattern)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="tavily_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Tavily: synthetic mass-search pattern for "
                f"agent={agent_id} count={info['max_window_count']}>threshold="
                f"{self.volume_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=agent_id,
        )

    def _synthetic_cross_topic_result(
        self,
        *,
        agent_id: str,
        info: dict[str, Any],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-agent cross-topic pattern finding."""
        signal = "cross_topic_pattern"
        control_id = _control_for(signal, self._mappings, "PR-05")
        synthetic_id = f"tavily-cross-topic-{agent_id}"
        evidence: dict[str, Any] = {
            "tavily_request_id": synthetic_id,
            "agent_id_observed": agent_id,
            "max_distinct_topics": info["max_distinct_topics"],
            "topics_in_window": info["topics_in_window"],
            "cross_topic_threshold": self.cross_topic_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                request_id=synthetic_id,
            ),
            "source_tool": "tavily",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="PASS",
            detail=(
                f"Tavily synthetic finding: agent {agent_id} touched "
                f"{info['max_distinct_topics']} distinct topics in a 1h window > "
                f"threshold {self.cross_topic_threshold} "
                f"(topics={', '.join(info['topics_in_window'])})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="tavily_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason=(
                f"Imported from Tavily: synthetic cross-topic pattern for "
                f"agent={agent_id} distinct_topics={info['max_distinct_topics']}>"
                f"threshold={self.cross_topic_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=agent_id,
        )
