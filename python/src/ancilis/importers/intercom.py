# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Intercom conversation importer — maps Fin AI customer-chat activity to AKSI controls.

Intercom (https://developers.intercom.com/) is the dominant chat-first
customer-engagement platform: Fin AI (their AI agent) handles real-time
conversations, qualifies leads, and deflects support tickets. Unlike
ticket-oriented helpdesks (Zendesk), every Intercom conversation is a
real-time customer-facing exchange, and every Fin reply is a net-new AI
message rendered to a human. That makes Intercom the runtime surface where
governance has to ask: did the AI actually resolve the customer's issue?
did the AI escalate when uncertain? did the AI handle a complaint, a legal
notice, or a regulator inquiry without a human in the loop?

This importer ingests Intercom ``/conversations`` exports (and webhook
captures) in four on-disk shapes:

  1. ``{"conversations": [...]}`` — primary conversations envelope
  2. ``{"data":          [...]}`` — generic data envelope
  3. JSONL                         — one conversation per line
  4. A single conversation object   — bare ``{"id": ..., "type": "conversation"}``

Each conversation aggregates its ``conversation_parts`` (comment, note,
assignment, close, open, snoozed, new_conversation_message, fin_answer,
fin_handoff) into a single :class:`EvaluationResult`. Synthetic results
are emitted for high-volume Fin resolution and bad-rating concentration
patterns across the export.

Signal mapping (see shared/mappings/intercom-aksi-controls.json):
  * ``fin_resolved=true`` (Fin AI fully resolved without human)
                                                                 → PR-04 FLAG
    (autonomous customer-facing resolution — surface for review;
    not FAIL because Fin escalates when uncertain, but governance
    needs visibility into the autonomous-resolution rate)
  * ``fin_resolved=true`` AND ``conversation_rating.rating <= 2``
                                                                 → PR-04 FAIL
    (Fin "resolved" but customer rated poorly — false-resolution)
  * ``fin_handoff_to_human=true``                                → PR-05 PASS
    (correct escalation = audit-trail evidence Fin recognized its limit)
  * ``source.delivered_as=automated`` AND ``assigned_to_ai=true``
                                                                 → PR-05 PASS
    (Fin-handled conversation captured)
  * conversation_parts contains ``part_type=fin_answer`` with
    ``statistics.fin_message_count > threshold`` (default 10) AND
    ``human_message_count == 0``                                 → PR-04 FAIL
    (Fin loop — too many AI messages without human escalation)
  * ``sla_status=missed`` AND ``assigned_to_ai=true``            → PR-02 FAIL
    (AI failed an SLA — quality-gate breach)
  * ``conversation_rating.rating <= 2`` AND ``fin_message_count > 0``
                                                                 → PR-04 FAIL
    (poor customer rating where AI was involved)
  * conversation_parts contains a part with ``redacted=true``    → PR-04 PASS
    (GDPR redaction recorded — good audit signal)
  * ``source.type=ai_agent`` AND ``source.delivered_as=customer_initiated``
                                                                 → PR-01 PASS captured
    (proactive AI engagement — consent-relevant)
  * ``tags`` contains complaint/legal/regulator/gdpr/ccpa AND
    ``assigned_to_ai=true``                                      → PR-04 FAIL
    (AI handling a sensitive matter — should escalate to human)
  * conversation_parts contains ``part_type=close`` AND
    ``author.type=fin``                                          → PR-02 FLAG
    (autonomous close by Fin)
  * ``statistics.time_to_resolve < 60`` (very fast) AND
    ``fin_resolved=true``                                        → PR-04 FLAG
    (suspiciously-fast AI resolution — potentially missed nuance)
  * High-volume Fin: > N conversations resolved by Fin in 1h
    (default 50) without > Y% human verification (default 5%)
                                                                 → PR-04 FLAG synthetic
  * Bad-rating concentration: > X% of Fin-handled conversations
    rated <= 2 (default 10%)                                     → PR-04 FAIL synthetic

Sanitization (security-critical — Intercom conversations are customer-facing
and routinely contain PII, complaint detail, and regulated content):

  * conversation_parts ``body`` text is NEVER stored — only ``body_length``
    and a count of redacted parts.
  * conversation_message ``body`` and ``subject`` are NEVER stored — only
    lengths.
  * conversation_rating ``remark`` text is NEVER stored — only
    ``remark_length``.
  * ``tags`` raw values are NOT stored as free text. Each tag name is
    truncated to 30 chars and accompanied by a sha256 of the full name;
    the importer additionally records whether any tag matches the
    ``sensitive_tag_patterns`` list.
  * ``contact_id`` is preserved verbatim (Intercom-issued opaque ID — no
    PII in its structure, already pseudonymous).
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``python-intercom`` client; conversation JSON
exports are parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/intercom.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "intercom-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_FIN_MESSAGE_LOOP_THRESHOLD = 10
_DEFAULT_FAST_RESOLVE_SECONDS = 60
_DEFAULT_HIGH_VOLUME_PER_HOUR = 50
_DEFAULT_BAD_RATING_CONCENTRATION = 0.10
_DEFAULT_HIGH_VOLUME_HUMAN_VERIFICATION_PCT = 0.05
_DEFAULT_LOW_RATING_THRESHOLD = 2
_DEFAULT_TAG_NAME_TRUNCATE_CHARS = 30
_DEFAULT_BAD_RATING_MIN_SAMPLE = 5
_DEFAULT_SENSITIVE_TAG_PATTERNS: tuple[str, ...] = (
    "complaint",
    "legal",
    "regulator",
    "gdpr",
    "ccpa",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the intercom-aksi-controls.json mapping; tolerate missing file."""
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


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from int (epoch s/ms) or ISO 8601 string."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:
            v = v / 1000.0
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            return None
    return None


def _format_timestamp(value: Any) -> str:
    """Render a timestamp value to an ISO 8601 string (UTC)."""
    dt = _parse_iso_timestamp(value)
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _redact_tag_name(name: str | None, truncate: int) -> dict[str, Any] | None:
    """Truncate a tag name; surface length + sha256."""
    if not name or not isinstance(name, str):
        return None
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return {
        "prefix": name[:truncate],
        "length": len(name),
        "sha256": digest,
    }


def _tag_matches_sensitive(name: str | None, patterns: Iterable[str]) -> bool:
    """Return True if a tag name matches any sensitive pattern (case-insensitive)."""
    if not name or not isinstance(name, str):
        return False
    n = name.strip().lower()
    if not n:
        return False
    for pattern in patterns:
        p = pattern.lower().strip()
        if not p:
            continue
        if p in n:
            return True
        if fnmatch.fnmatchcase(n, p):
            return True
    return False


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class IntercomImporter:
    """Parse an Intercom conversation export and convert each to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        fin_message_loop_threshold: int | None = None,
        fast_resolve_seconds: int | None = None,
        high_volume_per_hour: int | None = None,
        bad_rating_concentration: float | None = None,
        high_volume_human_verification_pct: float | None = None,
        low_rating_threshold: int | None = None,
        sensitive_tag_patterns: Iterable[str] | None = None,
        tag_name_truncate_chars: int | None = None,
        bad_rating_min_sample: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        if fin_message_loop_threshold is not None:
            self.fin_message_loop_threshold = int(fin_message_loop_threshold)
        else:
            self.fin_message_loop_threshold = int(
                meta.get(
                    "fin_message_loop_threshold",
                    _DEFAULT_FIN_MESSAGE_LOOP_THRESHOLD,
                )
            )

        if fast_resolve_seconds is not None:
            self.fast_resolve_seconds = int(fast_resolve_seconds)
        else:
            self.fast_resolve_seconds = int(
                meta.get("fast_resolve_seconds", _DEFAULT_FAST_RESOLVE_SECONDS)
            )

        if high_volume_per_hour is not None:
            self.high_volume_per_hour = int(high_volume_per_hour)
        else:
            self.high_volume_per_hour = int(
                meta.get("high_volume_per_hour", _DEFAULT_HIGH_VOLUME_PER_HOUR)
            )

        if bad_rating_concentration is not None:
            self.bad_rating_concentration = float(bad_rating_concentration)
        else:
            self.bad_rating_concentration = float(
                meta.get(
                    "bad_rating_concentration",
                    _DEFAULT_BAD_RATING_CONCENTRATION,
                )
            )

        if high_volume_human_verification_pct is not None:
            self.high_volume_human_verification_pct = float(
                high_volume_human_verification_pct
            )
        else:
            self.high_volume_human_verification_pct = float(
                meta.get(
                    "high_volume_human_verification_pct",
                    _DEFAULT_HIGH_VOLUME_HUMAN_VERIFICATION_PCT,
                )
            )

        if low_rating_threshold is not None:
            self.low_rating_threshold = int(low_rating_threshold)
        else:
            self.low_rating_threshold = int(
                meta.get("low_rating_threshold", _DEFAULT_LOW_RATING_THRESHOLD)
            )

        if sensitive_tag_patterns is not None:
            self.sensitive_tag_patterns: tuple[str, ...] = tuple(
                str(p) for p in sensitive_tag_patterns
            )
        else:
            meta_patterns = meta.get("sensitive_tag_patterns")
            if isinstance(meta_patterns, list) and meta_patterns:
                self.sensitive_tag_patterns = tuple(str(p) for p in meta_patterns)
            else:
                self.sensitive_tag_patterns = _DEFAULT_SENSITIVE_TAG_PATTERNS

        if tag_name_truncate_chars is not None:
            self.tag_name_truncate_chars = int(tag_name_truncate_chars)
        else:
            self.tag_name_truncate_chars = int(
                meta.get(
                    "tag_name_truncate_chars",
                    _DEFAULT_TAG_NAME_TRUNCATE_CHARS,
                )
            )

        if bad_rating_min_sample is not None:
            self.bad_rating_min_sample = int(bad_rating_min_sample)
        else:
            self.bad_rating_min_sample = int(
                meta.get("bad_rating_min_sample", _DEFAULT_BAD_RATING_MIN_SAMPLE)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an Intercom conversation export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        conversations = self._conversations_from_text(text)
        return self._build_results(conversations, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Intercom conversation content from a JSON or JSONL string."""
        conversations = self._conversations_from_text(content)
        return self._build_results(conversations, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _conversations_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"conversations": [...]}`` / ``{"data": [...]}`` / JSONL /
        single conversation."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [c for c in doc if isinstance(c, dict)]
            if isinstance(doc, dict):
                for key in ("conversations", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [c for c in doc[key] if isinstance(c, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "intercom_conversation",
            "source_tool_name": "intercom",
            "source_tool_version": "",
        }
        if conversation_id is not None:
            provenance["conversation_id"] = conversation_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        conversations: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-conversation EvaluationResults plus pattern synthetics."""
        # Pass 1: bucket Fin-handled conversations by hour for the
        # high-volume synthetic, and gather Fin-handled rating distribution
        # for the bad-rating-concentration synthetic.
        fin_handled_hour_buckets: dict[str, dict[str, Any]] = {}
        fin_handled_total = 0
        fin_handled_low_rated = 0

        for conv in conversations:
            assigned_to_ai = bool(conv.get("assigned_to_ai"))
            stats = conv.get("statistics") or {}
            fin_message_count = int(stats.get("fin_message_count") or 0) if isinstance(
                stats, dict
            ) else 0
            human_message_count = int(stats.get("human_message_count") or 0) if isinstance(
                stats, dict
            ) else 0
            fin_resolved = bool(conv.get("fin_resolved"))
            is_fin_handled = assigned_to_ai or fin_message_count > 0 or fin_resolved

            if not is_fin_handled:
                continue

            fin_handled_total += 1

            rating_obj = conv.get("conversation_rating")
            rating_val: int | None = None
            if isinstance(rating_obj, dict):
                r = rating_obj.get("rating")
                if isinstance(r, int):
                    rating_val = r
                elif isinstance(r, float):
                    rating_val = int(r)
            if rating_val is not None and rating_val <= self.low_rating_threshold:
                fin_handled_low_rated += 1

            if fin_resolved:
                ts = _parse_iso_timestamp(conv.get("created_at"))
                if ts is not None:
                    bucket_key = ts.strftime("%Y-%m-%dT%H")
                    bucket = fin_handled_hour_buckets.setdefault(
                        bucket_key,
                        {"resolved": 0, "human_verified": 0, "ids": []},
                    )
                    bucket["resolved"] += 1
                    if human_message_count > 0:
                        bucket["human_verified"] += 1
                    cid = conv.get("id")
                    if isinstance(cid, str):
                        bucket["ids"].append(cid)

        high_volume_buckets: dict[str, dict[str, Any]] = {}
        for bucket_key, bucket in fin_handled_hour_buckets.items():
            if bucket["resolved"] <= self.high_volume_per_hour:
                continue
            verified_pct = (
                bucket["human_verified"] / bucket["resolved"]
                if bucket["resolved"] > 0
                else 0.0
            )
            if verified_pct > self.high_volume_human_verification_pct:
                continue
            high_volume_buckets[bucket_key] = {
                **bucket,
                "verified_pct": verified_pct,
            }

        bad_rating_pct = (
            fin_handled_low_rated / fin_handled_total
            if fin_handled_total > 0
            else 0.0
        )
        bad_rating_triggered = (
            fin_handled_total >= self.bad_rating_min_sample
            and bad_rating_pct > self.bad_rating_concentration
        )

        results = [
            self._parse_conversation(
                conv,
                file_sha256=file_sha256,
            )
            for conv in conversations
        ]

        for bucket_key, bucket in sorted(high_volume_buckets.items()):
            results.append(
                self._synthetic_high_volume_fin_result(
                    bucket_key=bucket_key,
                    resolved_count=bucket["resolved"],
                    human_verified=bucket["human_verified"],
                    verified_pct=bucket["verified_pct"],
                    conversation_ids=bucket["ids"],
                    file_sha256=file_sha256,
                )
            )

        if bad_rating_triggered:
            results.append(
                self._synthetic_bad_rating_concentration_result(
                    fin_handled_total=fin_handled_total,
                    fin_handled_low_rated=fin_handled_low_rated,
                    pct=bad_rating_pct,
                    file_sha256=file_sha256,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Per-conversation parsing
    # ------------------------------------------------------------------

    def _parse_conversation(
        self,
        conv: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        conversation_id = str(conv.get("id") or uuid.uuid4())
        timestamp = _format_timestamp(conv.get("created_at"))
        state = (
            str(conv.get("state")).strip().lower()
            if isinstance(conv.get("state"), str)
            else None
        )
        contact_id = (
            str(conv.get("contact_id"))
            if isinstance(conv.get("contact_id"), str)
            else None
        )

        source = conv.get("source") if isinstance(conv.get("source"), dict) else {}
        source_type = (
            str(source.get("type")).strip().lower()
            if isinstance(source.get("type"), str)
            else None
        )
        source_delivered_as = (
            str(source.get("delivered_as")).strip().lower()
            if isinstance(source.get("delivered_as"), str)
            else None
        )

        assigned_to_ai = bool(conv.get("assigned_to_ai"))
        fin_resolved = bool(conv.get("fin_resolved"))
        fin_handoff_to_human = bool(conv.get("fin_handoff_to_human"))

        # Conversation rating — keep numeric rating + remark_length only.
        rating_obj = conv.get("conversation_rating")
        rating_val: int | None = None
        rating_remark_length: int | None = None
        if isinstance(rating_obj, dict):
            r = rating_obj.get("rating")
            if isinstance(r, int):
                rating_val = r
            elif isinstance(r, float):
                rating_val = int(r)
            rl = rating_obj.get("remark_length")
            if isinstance(rl, int):
                rating_remark_length = rl
            elif isinstance(rl, float):
                rating_remark_length = int(rl)

        # Statistics — keep numeric counters; never store body text.
        stats = conv.get("statistics") or {}
        fin_message_count = (
            int(stats.get("fin_message_count") or 0)
            if isinstance(stats, dict)
            else 0
        )
        human_message_count = (
            int(stats.get("human_message_count") or 0)
            if isinstance(stats, dict)
            else 0
        )
        first_response_time = (
            stats.get("first_response_time") if isinstance(stats, dict) else None
        )
        time_to_resolve_raw = (
            stats.get("time_to_resolve") if isinstance(stats, dict) else None
        )
        time_to_resolve: float | None = None
        if isinstance(time_to_resolve_raw, (int, float)):
            time_to_resolve = float(time_to_resolve_raw)

        # Conversation parts — count by part_type, count redacted, detect
        # Fin close and fin_answer presence. NEVER store body text.
        parts_raw = conv.get("conversation_parts") or []
        parts: list[dict[str, Any]] = []
        if isinstance(parts_raw, list):
            parts = [p for p in parts_raw if isinstance(p, dict)]
        elif isinstance(parts_raw, dict):
            # Some Intercom shapes wrap parts under {"conversation_parts": [...]}
            inner = parts_raw.get("conversation_parts")
            if isinstance(inner, list):
                parts = [p for p in inner if isinstance(p, dict)]

        part_count = len(parts)
        part_type_counts: dict[str, int] = {}
        redacted_part_count = 0
        has_fin_answer_part = False
        has_fin_close = False
        for part in parts:
            pt_raw = part.get("part_type")
            pt = pt_raw.strip().lower() if isinstance(pt_raw, str) else None
            if pt:
                part_type_counts[pt] = part_type_counts.get(pt, 0) + 1
            if part.get("redacted") is True:
                redacted_part_count += 1
            if pt == "fin_answer":
                has_fin_answer_part = True
            author = part.get("author") if isinstance(part.get("author"), dict) else {}
            author_type = (
                str(author.get("type")).strip().lower()
                if isinstance(author.get("type"), str)
                else None
            )
            if pt == "close" and author_type == "fin":
                has_fin_close = True

        # conversation_message — keep lengths only.
        cm = conv.get("conversation_message")
        cm_subject_length: int | None = None
        cm_body_length: int | None = None
        cm_delivered_as: str | None = None
        if isinstance(cm, dict):
            sl = cm.get("subject_length")
            if isinstance(sl, int):
                cm_subject_length = sl
            elif isinstance(sl, float):
                cm_subject_length = int(sl)
            bl = cm.get("body_length")
            if isinstance(bl, int):
                cm_body_length = bl
            elif isinstance(bl, float):
                cm_body_length = int(bl)
            da = cm.get("delivered_as")
            if isinstance(da, str):
                cm_delivered_as = da.strip().lower()

        # Tags — sanitize names; flag any sensitive matches.
        tags_raw = conv.get("tags") or []
        tag_records: list[dict[str, Any]] = []
        sensitive_tag_match = False
        if isinstance(tags_raw, list):
            for tag in tags_raw:
                if not isinstance(tag, dict):
                    continue
                tag_name = tag.get("name")
                if not isinstance(tag_name, str):
                    continue
                redacted = _redact_tag_name(tag_name, self.tag_name_truncate_chars)
                if redacted is not None:
                    tag_records.append(redacted)
                if _tag_matches_sensitive(tag_name, self.sensitive_tag_patterns):
                    sensitive_tag_match = True

        sla_obj = conv.get("sla_applied")
        sla_status: str | None = None
        sla_name_redacted: dict[str, Any] | None = None
        if isinstance(sla_obj, dict):
            ss = sla_obj.get("sla_status")
            if isinstance(ss, str):
                sla_status = ss.strip().lower()
            sn = sla_obj.get("sla_name")
            if isinstance(sn, str):
                sla_name_redacted = _redact_tag_name(
                    sn, self.tag_name_truncate_chars
                )

        common_evidence: dict[str, Any] = {
            "intercom_conversation_id": conversation_id,
            "state": state,
            "source_type": source_type,
            "source_delivered_as": source_delivered_as,
            "assigned_to_ai": assigned_to_ai,
            "fin_resolved": fin_resolved,
            "fin_handoff_to_human": fin_handoff_to_human,
            "conversation_rating": rating_val,
            "conversation_rating_remark_length": rating_remark_length,
            "part_count": part_count,
            "part_type_counts": part_type_counts,
            "redacted_part_count": redacted_part_count,
            "fin_message_count": fin_message_count,
            "human_message_count": human_message_count,
            "first_response_time": first_response_time,
            "time_to_resolve": time_to_resolve,
            "sla_status": sla_status,
            "sla_name": sla_name_redacted,
            "contact_id": contact_id,
            "tags": tag_records,
            "tag_count": len(tag_records),
            "sensitive_tag_match": sensitive_tag_match,
            "conversation_message_subject_length": cm_subject_length,
            "conversation_message_body_length": cm_body_length,
            "conversation_message_delivered_as": cm_delivered_as,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, conversation_id=conversation_id
            ),
            "source_tool": "intercom",
        }

        control_results: list[ControlResult] = []
        low_rating = (
            rating_val is not None and rating_val <= self.low_rating_threshold
        )

        # ------------------------------------------------------------------
        # 1. Fin-resolved signals (FAIL trumps FLAG when low rating present).
        # ------------------------------------------------------------------
        if fin_resolved and low_rating:
            control_results.append(
                self._cr(
                    signal="fin_resolved_low_rating",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Intercom conversation {conversation_id} fin_resolved=true "
                        f"but customer rated {rating_val} (<={self.low_rating_threshold}) "
                        f"— false-resolution: AI claimed resolution but customer "
                        f"experience contradicts it"
                    ),
                    common_evidence=common_evidence,
                )
            )
        elif fin_resolved:
            control_results.append(
                self._cr(
                    signal="fin_resolved_audit_logged",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"Intercom conversation {conversation_id} fully resolved by "
                        f"Fin AI without human intervention — surface autonomous "
                        f"customer-facing resolution for governance review"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 2. Correct escalation = audit-trail PASS.
        # ------------------------------------------------------------------
        if fin_handoff_to_human:
            control_results.append(
                self._cr(
                    signal="fin_handoff_to_human",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Intercom conversation {conversation_id} Fin handed off to "
                        f"human — correct escalation path recorded"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 3. Generic Fin-handled capture.
        # ------------------------------------------------------------------
        if (
            source_delivered_as == "automated"
            and assigned_to_ai
            and not fin_resolved
            and not fin_handoff_to_human
        ):
            control_results.append(
                self._cr(
                    signal="fin_handled_conversation",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Intercom conversation {conversation_id} Fin-handled "
                        f"(assigned_to_ai=true, delivered_as=automated) — captured"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 4. Fin loop detection — too many AI messages without escalation.
        # ------------------------------------------------------------------
        if (
            has_fin_answer_part
            and fin_message_count > self.fin_message_loop_threshold
            and human_message_count == 0
        ):
            control_results.append(
                self._cr(
                    signal="fin_message_loop",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Intercom conversation {conversation_id} Fin emitted "
                        f"{fin_message_count} messages (threshold "
                        f"{self.fin_message_loop_threshold}) with no human "
                        f"intervention — likely Fin loop, AI failed to escalate"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 5. SLA missed by AI.
        # ------------------------------------------------------------------
        if sla_status == "missed" and assigned_to_ai:
            control_results.append(
                self._cr(
                    signal="sla_missed_ai",
                    default="PR-02",
                    result="FAIL",
                    detail=(
                        f"Intercom conversation {conversation_id} AI-assigned "
                        f"conversation missed SLA — quality-gate breach"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 6. Low rating + AI involvement (additive when not already covered
        #    by fin_resolved_low_rating).
        # ------------------------------------------------------------------
        if low_rating and fin_message_count > 0 and not (fin_resolved):
            control_results.append(
                self._cr(
                    signal="low_rating_with_ai_involvement",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Intercom conversation {conversation_id} customer rated "
                        f"{rating_val} (<={self.low_rating_threshold}) on AI-involved "
                        f"conversation (fin_message_count={fin_message_count}) — "
                        f"poor AI customer experience"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 7. Redacted parts = good GDPR audit signal.
        # ------------------------------------------------------------------
        if redacted_part_count > 0:
            control_results.append(
                self._cr(
                    signal="redacted_part_audit",
                    default="PR-04",
                    result="PASS",
                    detail=(
                        f"Intercom conversation {conversation_id} contains "
                        f"{redacted_part_count} redacted part(s) — GDPR redaction "
                        f"recorded in audit trail"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 8. Proactive AI engagement.
        # ------------------------------------------------------------------
        if (
            source_type == "ai_agent"
            and source_delivered_as == "customer_initiated"
        ):
            control_results.append(
                self._cr(
                    signal="ai_proactive_engagement",
                    default="PR-01",
                    result="PASS",
                    detail=(
                        f"Intercom conversation {conversation_id} AI proactive "
                        f"engagement (source.type=ai_agent, "
                        f"delivered_as=customer_initiated) — consent-relevant "
                        f"event captured"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 9. Sensitive tag handled by AI.
        # ------------------------------------------------------------------
        if sensitive_tag_match and assigned_to_ai:
            control_results.append(
                self._cr(
                    signal="sensitive_tag_handled_by_ai",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Intercom conversation {conversation_id} tagged as "
                        f"sensitive (complaint/legal/regulator/gdpr/ccpa) but "
                        f"assigned to AI — should have been escalated to a human"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 10. Autonomous Fin close.
        # ------------------------------------------------------------------
        if has_fin_close:
            control_results.append(
                self._cr(
                    signal="fin_close_autonomous",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Intercom conversation {conversation_id} closed by Fin "
                        f"(part_type=close, author.type=fin) — autonomous close"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 11. Suspiciously fast AI resolve.
        # ------------------------------------------------------------------
        if (
            fin_resolved
            and time_to_resolve is not None
            and time_to_resolve < self.fast_resolve_seconds
        ):
            control_results.append(
                self._cr(
                    signal="suspiciously_fast_ai_resolve",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"Intercom conversation {conversation_id} Fin-resolved in "
                        f"{time_to_resolve}s (< {self.fast_resolve_seconds}s) — "
                        f"suspiciously fast resolution may have missed nuance"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # Fallback: nothing matched — surface as PR-05 PASS audit-captured.
        # ------------------------------------------------------------------
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Intercom conversation {conversation_id} state={state!r} "
                        f"captured — no pattern-specific signal matched"
                    ),
                    evidence_data={**common_evidence, "signal": "audit_captured"},
                )
            )

        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Intercom conversation: state={state or 'unknown'} "
            f"source_type={source_type or 'unknown'} "
            f"delivered_as={source_delivered_as or 'unknown'} "
            f"assigned_to_ai={assigned_to_ai} "
            f"fin_resolved={fin_resolved} "
            f"fin_handoff_to_human={fin_handoff_to_human}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"intercom-{conversation_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="intercom_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=contact_id or None,
        )

    def _cr(
        self,
        *,
        signal: str,
        default: str,
        result: str,
        detail: str,
        common_evidence: dict[str, Any],
    ) -> ControlResult:
        control_id = _control_for(signal, self._mappings, default)
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=result,
            detail=detail,
            evidence_data={**common_evidence, "signal": signal},
        )

    def _synthetic_high_volume_fin_result(
        self,
        *,
        bucket_key: str,
        resolved_count: int,
        human_verified: int,
        verified_pct: float,
        conversation_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-hour high-volume Fin resolution finding."""
        signal = "high_volume_fin_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"intercom-high-volume-fin-{bucket_key}"
        evidence: dict[str, Any] = {
            "intercom_conversation_id": synthetic_id,
            "hour_bucket": bucket_key,
            "resolved_count": resolved_count,
            "human_verified_count": human_verified,
            "human_verified_pct": verified_pct,
            "high_volume_per_hour": self.high_volume_per_hour,
            "high_volume_human_verification_pct": (
                self.high_volume_human_verification_pct
            ),
            "conversation_id_sample": conversation_ids[:25],
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, conversation_id=synthetic_id
            ),
            "source_tool": "intercom",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Intercom synthetic finding: {resolved_count} conversations "
                f"resolved by Fin in hour {bucket_key} (> threshold "
                f"{self.high_volume_per_hour}) with only {verified_pct:.1%} "
                f"human verification (<= {self.high_volume_human_verification_pct:.1%}) "
                f"— high-volume autonomous resolution requires governance review"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="intercom_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Intercom conversation: synthetic high-volume Fin "
                f"pattern hour={bucket_key} resolved={resolved_count}>"
                f"{self.high_volume_per_hour}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_bad_rating_concentration_result(
        self,
        *,
        fin_handled_total: int,
        fin_handled_low_rated: int,
        pct: float,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a bad-rating-concentration finding for the export."""
        signal = "bad_rating_concentration"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = "intercom-bad-rating-concentration"
        evidence: dict[str, Any] = {
            "intercom_conversation_id": synthetic_id,
            "fin_handled_total": fin_handled_total,
            "fin_handled_low_rated": fin_handled_low_rated,
            "low_rated_pct": pct,
            "bad_rating_concentration_threshold": self.bad_rating_concentration,
            "low_rating_threshold": self.low_rating_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, conversation_id=synthetic_id
            ),
            "source_tool": "intercom",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Intercom synthetic finding: {fin_handled_low_rated}/"
                f"{fin_handled_total} ({pct:.1%}) of Fin-handled conversations "
                f"were rated <= {self.low_rating_threshold} — exceeds bad-rating "
                f"concentration threshold {self.bad_rating_concentration:.1%}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="intercom_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Intercom conversation: synthetic bad-rating "
                f"concentration {fin_handled_low_rated}/{fin_handled_total} "
                f"({pct:.1%})>{self.bad_rating_concentration:.1%}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
