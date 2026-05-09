"""Zendesk audit-log importer — maps AI-agent customer-service activity to AKSI controls.

Zendesk (https://developer.zendesk.com/api-reference/ticketing/account-configuration/audit_logs/)
is the dominant customer-service platform. AI agents — Zendesk's own
Resolution Bot / AI Agents, Salesforce Service Cloud, and custom-built
bots — increasingly handle support tickets directly. Every public-facing
reply authored by a bot is a regulated brand-voice + accuracy + compliance
event: an autonomous reply that hallucinates a refund policy, mis-classifies
a ticket priority, or unilaterally marks a ticket "solved" without human
review can produce real customer harm and downstream regulatory exposure.

This importer ingests Zendesk's ``/api/v2/audit_logs`` and
``/api/v2/tickets/{id}/audits`` exports in four on-disk shapes:

  1. ``{"audits": [...]}`` — primary audit-record envelope
  2. ``{"events": [...]}`` — generic events envelope
  3. ``{"data":   [...]}`` — generic data envelope
  4. JSONL                   — one audit per line

Signal mapping (see shared/mappings/zendesk-aksi-controls.json):
  * actor_is_ai=true + Comment + public=true                          → PR-01 FLAG
    (agent reply visible to customer — accuracy/brand-voice review needed)
  * actor_is_ai=true + Comment + public=false                         → PR-05 PASS
    (agent internal note — captured)
  * actor_is_ai=true + Comment + public=true + via.channel=voice      → PR-04 FLAG
    (agent voice response — recording-consent territory)
  * actor_is_ai=true + Change of field=status to "solved"             → PR-02 FAIL
    (autonomous resolution requires explicit approval workflow)
  * actor_is_ai=true + Change of field=status to "closed"             → PR-02 FAIL
    (autonomous closure)
  * actor_is_ai=true + Change of field=priority                       → PR-05 FLAG
    (priority manipulation by AI — surface for review)
  * actor_is_ai=true + Change of field=assignee_id                    → PR-05 FLAG
  * actor_is_ai=true + satisfaction_rating value=bad                  → PR-04 FAIL
    (negative customer feedback on AI-handled ticket)
  * actor_role=admin + Change of field=tags + escalated_to_human tag  → PR-05 PASS
    (escalation workflow audit trail)
  * via.channel=api on Create event                                   → PR-01 FLAG
    (programmatic ticket creation — verify identity)
  * via.channel=ticket-merge                                          → PR-05 PASS
    (audit trail captured)
  * Multiple AI replies on same ticket without intervening human reply
    (default > 3 in a row)                                            → PR-04 FAIL
    synthetic (AI-only resolution stretch — escalation required)
  * Same actor_id (AI) acting on > N channels in export               → PR-05 FLAG
    synthetic (omnichannel surface)
  * Same actor_ai_model handling > N tickets in 1h (default 100)      → PR-04 FLAG
    synthetic (capacity audit)
  * actor_ai_model with > X% bad satisfaction (default 5%)            → PR-04 FAIL
    synthetic (negative-feedback rate)

Sanitization (security-critical — Zendesk audits ride very close to the
customer; raw comment text and field values can contain PII, account
identifiers, and free-text customer content that should never be retained
verbatim by the evidence layer):

  * ``event.body`` / ``event.html_body`` raw text is NEVER stored. Zendesk
    already provides ``body_length`` / ``html_body_length`` integers and
    that is what we capture verbatim.
  * ``event.value`` / ``event.previous_value`` raw values are NEVER stored.
    Only the ``field_name`` is retained — the question is *which* field
    changed, not *what* it was set to. (Exception: status transitions detect
    ``solved`` / ``closed`` in flight to drive the autonomous-resolution FAIL
    signal, but the raw value is not persisted to evidence.)
  * ``satisfaction_rating.comment`` text is NEVER stored — Zendesk provides
    ``comment_length`` and that is what we capture.
  * ``metadata.system.location`` is dropped entirely (city/region/country
    triple is too granular for an audit byproduct).
  * ``metadata.system.ip_address`` is reduced to a /16 IPv4 or /32 IPv6
    hextet pattern. RFC1918, loopback, and link-local addresses are
    preserved verbatim.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``zenpy`` package; Zendesk audit-log JSON
exports are parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at
# <repo>/python/src/ancilis/importers/zendesk.py — five .parent traversals
# after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "zendesk-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_CONSECUTIVE_AI_REPLIES_THRESHOLD = 3
_DEFAULT_AI_VOLUME_PER_HOUR_THRESHOLD = 100
_DEFAULT_AI_VOLUME_WINDOW_SECONDS = 3600
_DEFAULT_BAD_SATISFACTION_RATE_THRESHOLD = 0.05
_DEFAULT_BAD_SATISFACTION_MIN_SAMPLE = 20
_DEFAULT_CROSS_CHANNEL_THRESHOLD = 3
_DEFAULT_VOICE_CHANNELS: frozenset[str] = frozenset({"voice"})
_DEFAULT_AUTONOMOUS_TERMINAL_STATUSES: frozenset[str] = frozenset({"solved", "closed"})
_DEFAULT_ESCALATION_TAG_MARKERS: tuple[str, ...] = (
    "escalated_to_human",
    "human_escalation",
    "handoff_to_agent",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the zendesk-aksi-controls.json mapping; tolerate missing file."""
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


def _classify_ip(ip_value: str | None) -> str | None:
    """Reduce an IP to a /16 IPv4 or /32-hextet IPv6 pattern."""
    if not ip_value or not isinstance(ip_value, str):
        return None
    ip = ip_value.strip()
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return ip
        octets = ip.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.0.0/16"
        return ip
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from int (epoch ms or s) or ISO 8601 string."""
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


def _normalize_status_value(value: Any) -> str | None:
    """Lowercase + strip a status field value for autonomous-terminal detection."""
    if isinstance(value, str):
        v = value.strip().lower()
        return v or None
    return None


def _has_escalation_tag(value: Any, markers: Iterable[str]) -> bool:
    """Return True if a tags-field value contains any escalation marker.

    Zendesk tags can be encoded as a list, a comma/space separated string, or
    a single string. Markers may also be glob patterns.
    """
    if value is None:
        return False
    needles = tuple(m.strip().lower() for m in markers if m)
    if not needles:
        return False
    if isinstance(value, list):
        candidates = [str(v).strip().lower() for v in value if isinstance(v, (str, int))]
    elif isinstance(value, str):
        candidates = [
            t.strip().lower()
            for t in value.replace(",", " ").split()
            if t.strip()
        ]
    else:
        return False
    for tag in candidates:
        if not tag:
            continue
        for needle in needles:
            if "*" in needle or "?" in needle:
                if fnmatch.fnmatchcase(tag, needle):
                    return True
            elif needle == tag or needle in tag:
                return True
    return False


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class ZendeskImporter:
    """Parse a Zendesk audit-log export and convert each audit to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        consecutive_ai_replies_threshold: int | None = None,
        ai_volume_per_hour_threshold: int | None = None,
        ai_volume_window_seconds: int | None = None,
        bad_satisfaction_rate_threshold: float | None = None,
        bad_satisfaction_min_sample: int | None = None,
        cross_channel_threshold: int | None = None,
        voice_channels: Iterable[str] | None = None,
        autonomous_terminal_statuses: Iterable[str] | None = None,
        escalation_tag_markers: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Consecutive-AI-replies threshold.
        if consecutive_ai_replies_threshold is not None:
            self.consecutive_ai_replies_threshold = int(
                consecutive_ai_replies_threshold
            )
        else:
            self.consecutive_ai_replies_threshold = int(
                meta.get(
                    "consecutive_ai_replies_threshold",
                    _DEFAULT_CONSECUTIVE_AI_REPLIES_THRESHOLD,
                )
            )
        # AI-volume threshold + window.
        if ai_volume_per_hour_threshold is not None:
            self.ai_volume_per_hour_threshold = int(ai_volume_per_hour_threshold)
        else:
            self.ai_volume_per_hour_threshold = int(
                meta.get(
                    "ai_volume_per_hour_threshold",
                    _DEFAULT_AI_VOLUME_PER_HOUR_THRESHOLD,
                )
            )
        if ai_volume_window_seconds is not None:
            self.ai_volume_window_seconds = int(ai_volume_window_seconds)
        else:
            self.ai_volume_window_seconds = int(
                meta.get(
                    "ai_volume_window_seconds",
                    _DEFAULT_AI_VOLUME_WINDOW_SECONDS,
                )
            )
        # Bad-satisfaction rate + min-sample.
        if bad_satisfaction_rate_threshold is not None:
            self.bad_satisfaction_rate_threshold = float(
                bad_satisfaction_rate_threshold
            )
        else:
            self.bad_satisfaction_rate_threshold = float(
                meta.get(
                    "bad_satisfaction_rate_threshold",
                    _DEFAULT_BAD_SATISFACTION_RATE_THRESHOLD,
                )
            )
        if bad_satisfaction_min_sample is not None:
            self.bad_satisfaction_min_sample = int(bad_satisfaction_min_sample)
        else:
            self.bad_satisfaction_min_sample = int(
                meta.get(
                    "bad_satisfaction_min_sample",
                    _DEFAULT_BAD_SATISFACTION_MIN_SAMPLE,
                )
            )
        # Cross-channel threshold.
        if cross_channel_threshold is not None:
            self.cross_channel_threshold = int(cross_channel_threshold)
        else:
            self.cross_channel_threshold = int(
                meta.get(
                    "cross_channel_threshold", _DEFAULT_CROSS_CHANNEL_THRESHOLD
                )
            )
        # Voice channels.
        if voice_channels is not None:
            self.voice_channels: frozenset[str] = frozenset(
                str(c).strip().lower() for c in voice_channels if c
            )
        else:
            meta_voice = meta.get("voice_channels")
            if isinstance(meta_voice, list) and meta_voice:
                self.voice_channels = frozenset(
                    str(c).strip().lower() for c in meta_voice if c
                )
            else:
                self.voice_channels = _DEFAULT_VOICE_CHANNELS
        # Autonomous terminal statuses (solved/closed by default).
        if autonomous_terminal_statuses is not None:
            self.autonomous_terminal_statuses: frozenset[str] = frozenset(
                str(s).strip().lower() for s in autonomous_terminal_statuses if s
            )
        else:
            meta_terminal = meta.get("autonomous_terminal_statuses")
            if isinstance(meta_terminal, list) and meta_terminal:
                self.autonomous_terminal_statuses = frozenset(
                    str(s).strip().lower() for s in meta_terminal if s
                )
            else:
                self.autonomous_terminal_statuses = (
                    _DEFAULT_AUTONOMOUS_TERMINAL_STATUSES
                )
        # Escalation tag markers.
        if escalation_tag_markers is not None:
            self.escalation_tag_markers: tuple[str, ...] = tuple(
                str(m) for m in escalation_tag_markers if m
            )
        else:
            meta_tags = meta.get("escalation_tag_markers")
            if isinstance(meta_tags, list) and meta_tags:
                self.escalation_tag_markers = tuple(
                    str(m) for m in meta_tags if m
                )
            else:
                self.escalation_tag_markers = _DEFAULT_ESCALATION_TAG_MARKERS

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Zendesk audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        audits = self._audits_from_text(text)
        return self._build_results(audits, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Zendesk audit-log content from a JSON or JSONL string."""
        audits = self._audits_from_text(content)
        return self._build_results(audits, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _audits_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"audits": [...]}`` / ``{"events": [...]}`` /
        ``{"data": [...]}`` / JSONL / single audit."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [a for a in doc if isinstance(a, dict)]
            if isinstance(doc, dict):
                for key in ("audits", "events", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [a for a in doc[key] if isinstance(a, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        audits: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-audit EvaluationResults plus consecutive-replies / volume / cross-channel synthetics."""
        # Pass 1: aggregate cross-actor metrics.
        # - Consecutive AI replies per ticket: walk audits per ticket in
        #   chronological order, tracking runs of public AI Comments
        #   uninterrupted by a non-AI public Comment.
        # - AI volume per model: tickets touched within a sliding window.
        # - Cross-channel: distinct via.channel values per AI actor_id.
        # - Bad-satisfaction rate: per-model bad/total ratio.
        ticket_audits: dict[Any, list[dict[str, Any]]] = {}
        for audit in audits:
            tid = audit.get("ticket_id")
            if tid is None:
                continue
            ticket_audits.setdefault(tid, []).append(audit)

        # Sort each ticket's audits by created_at (ISO timestamp) for run detection.
        consecutive_offenders: dict[Any, dict[str, Any]] = {}
        for tid, t_audits in ticket_audits.items():
            sorted_audits = sorted(
                t_audits,
                key=lambda a: _parse_iso_timestamp(a.get("created_at"))
                or datetime.min.replace(tzinfo=timezone.utc),
            )
            run = 0
            run_actor: str | None = None
            run_model: str | None = None
            max_run = 0
            max_actor = None
            max_model = None
            for audit in sorted_audits:
                public_comment, has_public_human_comment = (
                    self._has_public_comment(audit)
                )
                if not public_comment and not has_public_human_comment:
                    # Non-comment events (status changes, internal notes, etc.) do
                    # not break or extend a public-AI-reply run.
                    continue
                if bool(audit.get("actor_is_ai")) and public_comment:
                    actor_id = audit.get("actor_id") or audit.get("author_id")
                    model = audit.get("actor_ai_model")
                    if (
                        run_actor is not None
                        and str(actor_id) != str(run_actor)
                    ):
                        run = 0
                    run += 1
                    run_actor = str(actor_id) if actor_id is not None else None
                    run_model = (
                        str(model) if isinstance(model, str) and model else run_model
                    )
                    if run > max_run:
                        max_run = run
                        max_actor = run_actor
                        max_model = run_model
                else:
                    # Any human public comment resets the run.
                    if has_public_human_comment:
                        run = 0
                        run_actor = None
                        run_model = None
            if max_run > self.consecutive_ai_replies_threshold:
                consecutive_offenders[tid] = {
                    "run_length": max_run,
                    "actor_id": max_actor,
                    "actor_ai_model": max_model,
                }

        # AI volume per model: count distinct ticket_ids per model in any
        # window of size ai_volume_window_seconds.
        model_ticket_ts: dict[str, list[tuple[datetime, Any]]] = {}
        # Bad-satisfaction per model.
        model_total: dict[str, int] = {}
        model_bad: dict[str, int] = {}
        # Cross-channel per AI actor.
        ai_actor_channels: dict[str, set[str]] = {}
        for audit in audits:
            is_ai = bool(audit.get("actor_is_ai"))
            model_raw = audit.get("actor_ai_model")
            model = (
                str(model_raw).strip()
                if isinstance(model_raw, str) and model_raw.strip()
                else None
            )
            ts = _parse_iso_timestamp(audit.get("created_at"))
            tid = audit.get("ticket_id")
            channel = self._audit_channel(audit)
            actor_id = audit.get("actor_id") or audit.get("author_id")
            if is_ai and model and ts is not None and tid is not None:
                model_ticket_ts.setdefault(model, []).append((ts, tid))
            if is_ai and actor_id is not None and channel:
                ai_actor_channels.setdefault(str(actor_id), set()).add(channel)
            # Bad-satisfaction: inspect satisfaction_rating on the audit OR any
            # event-level satisfaction_rating value (in flight only).
            sat_score = self._satisfaction_score(audit)
            if is_ai and model and sat_score in {"good", "bad"}:
                model_total[model] = model_total.get(model, 0) + 1
                if sat_score == "bad":
                    model_bad[model] = model_bad.get(model, 0) + 1

        ai_high_volume_models: dict[str, int] = {}
        window = self.ai_volume_window_seconds
        for model, entries in model_ticket_ts.items():
            sorted_entries = sorted(entries, key=lambda e: e[0])
            left = 0
            max_in_window = 0
            seen: dict[Any, int] = {}
            for right in range(len(sorted_entries)):
                tid_r = sorted_entries[right][1]
                seen[tid_r] = seen.get(tid_r, 0) + 1
                while (
                    sorted_entries[right][0] - sorted_entries[left][0]
                ).total_seconds() > window:
                    tid_l = sorted_entries[left][1]
                    seen[tid_l] -= 1
                    if seen[tid_l] <= 0:
                        seen.pop(tid_l, None)
                    left += 1
                count = len(seen)
                if count > max_in_window:
                    max_in_window = count
            if max_in_window > self.ai_volume_per_hour_threshold:
                ai_high_volume_models[model] = max_in_window

        bad_sat_offenders: dict[str, dict[str, Any]] = {}
        for model, total in model_total.items():
            if total < self.bad_satisfaction_min_sample:
                continue
            bad = model_bad.get(model, 0)
            rate = bad / total
            if rate > self.bad_satisfaction_rate_threshold:
                bad_sat_offenders[model] = {
                    "bad": bad,
                    "total": total,
                    "rate": rate,
                }

        cross_channel_actors: dict[str, list[str]] = {
            actor: sorted(channels)
            for actor, channels in ai_actor_channels.items()
            if len(channels) > self.cross_channel_threshold
        }

        results: list[EvaluationResult] = [
            self._parse_audit(
                audit,
                file_sha256=file_sha256,
                consecutive_offenders=consecutive_offenders,
                ai_high_volume_models=ai_high_volume_models,
                cross_channel_actors=cross_channel_actors,
            )
            for audit in audits
        ]

        # Synthetics — one per offender.
        for tid, info in sorted(
            consecutive_offenders.items(), key=lambda kv: str(kv[0])
        ):
            results.append(
                self._synthetic_consecutive_ai_replies_result(
                    ticket_id=tid,
                    info=info,
                    file_sha256=file_sha256,
                )
            )
        for model, count in sorted(ai_high_volume_models.items()):
            results.append(
                self._synthetic_ai_high_volume_result(
                    model=model,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for model, info in sorted(bad_sat_offenders.items()):
            results.append(
                self._synthetic_bad_satisfaction_rate_result(
                    model=model,
                    info=info,
                    file_sha256=file_sha256,
                )
            )
        for actor, channels in sorted(cross_channel_actors.items()):
            results.append(
                self._synthetic_cross_channel_result(
                    actor=actor,
                    channels=channels,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _has_public_comment(
        self, audit: dict[str, Any]
    ) -> tuple[bool, bool]:
        """Inspect events for (any_public_comment, public_human_comment).

        ``any_public_comment`` is True if any event in the audit is a public
        Comment / VoiceComment. ``public_human_comment`` is True if any of
        those public comments was authored by a non-AI actor.
        """
        events = audit.get("events")
        if not isinstance(events, list):
            return (False, False)
        is_ai = bool(audit.get("actor_is_ai"))
        any_public = False
        public_human = False
        for event in events:
            if not isinstance(event, dict):
                continue
            etype = str(event.get("type") or "").strip()
            if etype not in {"Comment", "VoiceComment"}:
                continue
            if not bool(event.get("public")):
                continue
            any_public = True
            if not is_ai:
                public_human = True
        return (any_public, public_human)

    def _audit_channel(self, audit: dict[str, Any]) -> str | None:
        """Resolve the via.channel for an audit. Falls back to first event."""
        via = audit.get("via")
        if isinstance(via, dict):
            ch = via.get("channel")
            if isinstance(ch, str) and ch.strip():
                return ch.strip().lower()
        events = audit.get("events")
        if isinstance(events, list):
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                ev_via = ev.get("via")
                if isinstance(ev_via, dict):
                    ch = ev_via.get("channel")
                    if isinstance(ch, str) and ch.strip():
                        return ch.strip().lower()
        return None

    def _satisfaction_score(self, audit: dict[str, Any]) -> str | None:
        """Return the satisfaction_rating.score, normalized to lowercase."""
        sr = audit.get("satisfaction_rating")
        if isinstance(sr, dict):
            score = sr.get("score")
            if isinstance(score, str) and score.strip():
                return score.strip().lower()
        events = audit.get("events")
        if isinstance(events, list):
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                ev_sr = ev.get("satisfaction_rating")
                if isinstance(ev_sr, dict):
                    score = ev_sr.get("score")
                    if isinstance(score, str) and score.strip():
                        return score.strip().lower()
                # also support a value field on a satisfaction_rating-typed event
                if (
                    str(ev.get("type") or "").strip().lower()
                    == "satisfaction_rating"
                ):
                    val = ev.get("value")
                    if isinstance(val, str) and val.strip():
                        return val.strip().lower()
                # field_name=satisfaction_rating Change events
                if (
                    str(ev.get("field_name") or "").strip().lower()
                    == "satisfaction_rating"
                ):
                    val = ev.get("value")
                    if isinstance(val, str) and val.strip():
                        return val.strip().lower()
        return None

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        audit_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "zendesk_audit_log",
            "source_tool_name": "zendesk",
            "source_tool_version": "",
        }
        if audit_id is not None:
            provenance["audit_id"] = audit_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-audit parsing
    # ------------------------------------------------------------------

    def _parse_audit(
        self,
        audit: dict[str, Any],
        *,
        file_sha256: str | None,
        consecutive_offenders: dict[Any, dict[str, Any]],
        ai_high_volume_models: dict[str, int],
        cross_channel_actors: dict[str, list[str]],
    ) -> EvaluationResult:
        audit_id = str(audit.get("id") or uuid.uuid4())
        ticket_id_raw = audit.get("ticket_id")
        ticket_id = (
            str(ticket_id_raw)
            if isinstance(ticket_id_raw, (str, int))
            else None
        )
        timestamp = _format_timestamp(audit.get("created_at"))
        actor_id_raw = audit.get("actor_id") or audit.get("author_id")
        actor_id = (
            str(actor_id_raw)
            if isinstance(actor_id_raw, (str, int))
            else None
        )
        author_role_raw = audit.get("author_role")
        author_role = (
            str(author_role_raw).strip().lower()
            if isinstance(author_role_raw, str) and author_role_raw.strip()
            else None
        )
        actor_is_ai = bool(audit.get("actor_is_ai"))
        actor_ai_model_raw = audit.get("actor_ai_model")
        actor_ai_model = (
            str(actor_ai_model_raw).strip()
            if isinstance(actor_ai_model_raw, str) and actor_ai_model_raw.strip()
            else None
        )
        channel = self._audit_channel(audit)
        satisfaction_score = self._satisfaction_score(audit)
        # Comment-length capture from satisfaction_rating (length only).
        sr = audit.get("satisfaction_rating")
        satisfaction_comment_length: int | None = None
        if isinstance(sr, dict):
            cl = sr.get("comment_length")
            if isinstance(cl, (int, float)):
                satisfaction_comment_length = int(cl)

        # Metadata.system.ip_address — masked. metadata.system.location is
        # dropped entirely; only client + ip are surfaced.
        metadata = audit.get("metadata")
        ip_redacted: str | None = None
        client = None
        if isinstance(metadata, dict):
            system = metadata.get("system")
            if isinstance(system, dict):
                ip_redacted = _classify_ip(
                    system.get("ip_address")
                    if isinstance(system.get("ip_address"), str)
                    else None
                )
                client_raw = system.get("client")
                client = (
                    str(client_raw)
                    if isinstance(client_raw, str) and client_raw.strip()
                    else None
                )

        events_raw = audit.get("events") or []
        events: list[dict[str, Any]] = (
            [e for e in events_raw if isinstance(e, dict)]
            if isinstance(events_raw, list)
            else []
        )

        # Build a sanitized per-event summary (NEVER body text or values).
        event_summaries: list[dict[str, Any]] = []
        any_public_comment = False
        any_internal_comment = False
        any_voice_comment = False
        any_create_event = False
        any_status_to_terminal: str | None = None
        any_priority_change = False
        any_assignee_change = False
        any_tag_escalation = False
        for event in events:
            etype = str(event.get("type") or "").strip()
            public = bool(event.get("public"))
            ev_via_raw = event.get("via")
            ev_channel = None
            if isinstance(ev_via_raw, dict):
                cand = ev_via_raw.get("channel")
                if isinstance(cand, str) and cand.strip():
                    ev_channel = cand.strip().lower()
            field_name_raw = event.get("field_name")
            field_name = (
                str(field_name_raw).strip().lower()
                if isinstance(field_name_raw, str) and field_name_raw.strip()
                else None
            )
            body_length_raw = event.get("body_length")
            body_length = (
                int(body_length_raw)
                if isinstance(body_length_raw, (int, float))
                else None
            )
            html_body_length_raw = event.get("html_body_length")
            html_body_length = (
                int(html_body_length_raw)
                if isinstance(html_body_length_raw, (int, float))
                else None
            )
            event_summaries.append(
                {
                    "type": etype or None,
                    "public": public,
                    "channel": ev_channel,
                    "field_name": field_name,
                    "body_length": body_length,
                    "html_body_length": html_body_length,
                }
            )
            if etype == "Comment" and public:
                any_public_comment = True
            if etype == "Comment" and not public:
                any_internal_comment = True
            if etype == "VoiceComment" and public:
                any_voice_comment = True
            if etype == "Create":
                any_create_event = True
            if etype == "Change" and field_name == "status":
                value_norm = _normalize_status_value(event.get("value"))
                if (
                    value_norm
                    and value_norm in self.autonomous_terminal_statuses
                ):
                    any_status_to_terminal = value_norm
            if etype == "Change" and field_name == "priority":
                any_priority_change = True
            if etype == "Change" and field_name == "assignee_id":
                any_assignee_change = True
            if (
                etype == "Change"
                and field_name == "tags"
                and (
                    _has_escalation_tag(
                        event.get("value"), self.escalation_tag_markers
                    )
                    or _has_escalation_tag(
                        event.get("previous_value"),
                        self.escalation_tag_markers,
                    )
                )
            ):
                any_tag_escalation = True

        common_evidence: dict[str, Any] = {
            "zendesk_audit_id": audit_id,
            "ticket_id": ticket_id,
            "actor_id": actor_id,
            "author_role": author_role,
            "actor_is_ai": actor_is_ai,
            "actor_ai_model": actor_ai_model,
            "via_channel": channel,
            "events": event_summaries,
            "event_count": len(event_summaries),
            "satisfaction_score": satisfaction_score,
            "satisfaction_comment_length": satisfaction_comment_length,
            "ip_address_redacted": ip_redacted,
            "client": client,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, audit_id=audit_id
            ),
            "source_tool": "zendesk",
        }

        control_results: list[ControlResult] = []

        # ------------------------------------------------------------------
        # 1. Public AI comment / internal AI note / AI voice response.
        # ------------------------------------------------------------------
        if actor_is_ai and any_voice_comment:
            control_results.append(
                self._cr(
                    signal="ai_voice_public_response",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI voice response (actor_ai_model="
                        f"{actor_ai_model!r}) — recording-consent + accuracy "
                        f"review required"
                    ),
                    common_evidence=common_evidence,
                )
            )
        elif (
            actor_is_ai
            and any_public_comment
            and channel in self.voice_channels
        ):
            # If the audit-level via.channel resolves to voice but events did
            # not have a VoiceComment type, still treat as a voice response.
            control_results.append(
                self._cr(
                    signal="ai_voice_public_response",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI public reply on voice channel — "
                        f"recording-consent territory"
                    ),
                    common_evidence=common_evidence,
                )
            )
        elif actor_is_ai and any_public_comment:
            control_results.append(
                self._cr(
                    signal="ai_public_comment",
                    default="PR-01",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI agent reply visible to the customer "
                        f"(actor_ai_model={actor_ai_model!r}, channel="
                        f"{channel!r}) — accuracy/brand-voice review required"
                    ),
                    common_evidence=common_evidence,
                )
            )
        if (
            actor_is_ai
            and any_internal_comment
            and not any_public_comment
            and not any_voice_comment
        ):
            control_results.append(
                self._cr(
                    signal="ai_internal_note",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI internal note (public=false) — captured"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 2. Autonomous status transitions (solved / closed) — FAIL.
        # ------------------------------------------------------------------
        if actor_is_ai and any_status_to_terminal == "solved":
            control_results.append(
                self._cr(
                    signal="ai_autonomous_status_solved",
                    default="PR-02",
                    result="FAIL",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI-driven status transition to 'solved' — "
                        f"autonomous resolution requires explicit approval "
                        f"workflow"
                    ),
                    common_evidence=common_evidence,
                )
            )
        if actor_is_ai and any_status_to_terminal == "closed":
            control_results.append(
                self._cr(
                    signal="ai_autonomous_status_closed",
                    default="PR-02",
                    result="FAIL",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI-driven status transition to 'closed' — "
                        f"autonomous closure requires governance approval"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 3. AI-driven priority / assignee changes.
        # ------------------------------------------------------------------
        if actor_is_ai and any_priority_change:
            control_results.append(
                self._cr(
                    signal="ai_priority_change",
                    default="PR-05",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI-driven priority change — surface for review"
                    ),
                    common_evidence=common_evidence,
                )
            )
        if actor_is_ai and any_assignee_change:
            control_results.append(
                self._cr(
                    signal="ai_assignee_change",
                    default="PR-05",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is an AI-driven assignee change — surface for review"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 4. Bad satisfaction on AI-handled ticket — FAIL.
        # ------------------------------------------------------------------
        if actor_is_ai and satisfaction_score == "bad":
            control_results.append(
                self._cr(
                    signal="bad_satisfaction_on_ai_ticket",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"carries a 'bad' satisfaction rating on an "
                        f"AI-handled ticket (actor_ai_model="
                        f"{actor_ai_model!r}) — negative customer feedback"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 5. Escalation workflow (admin tagging escalated_to_human).
        # ------------------------------------------------------------------
        if author_role == "admin" and any_tag_escalation:
            control_results.append(
                self._cr(
                    signal="escalation_to_human",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"records an admin escalation-to-human tag — "
                        f"escalation workflow audit trail captured"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 6. Programmatic ticket creation via API channel.
        # ------------------------------------------------------------------
        if any_create_event and channel == "api":
            control_results.append(
                self._cr(
                    signal="api_autonomous_create",
                    default="PR-01",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is a programmatic ticket creation via API channel "
                        f"— verify identity"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 7. Ticket-merge audit trail.
        # ------------------------------------------------------------------
        if channel == "ticket-merge":
            control_results.append(
                self._cr(
                    signal="ticket_merge",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is a ticket-merge event — audit trail captured"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 8. Cross-cutting markers (consecutive AI replies / high-volume /
        #    cross-channel) — surfaced on each contributing audit.
        # ------------------------------------------------------------------
        if ticket_id_raw is not None and ticket_id_raw in consecutive_offenders:
            info = consecutive_offenders[ticket_id_raw]
            control_results.append(
                self._cr(
                    signal="consecutive_ai_replies",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"is part of a consecutive-AI-replies pattern "
                        f"(run_length={info['run_length']} > threshold "
                        f"{self.consecutive_ai_replies_threshold}) — "
                        f"AI-only resolution stretch, escalation required"
                    ),
                    common_evidence={
                        **common_evidence,
                        "consecutive_ai_run_length": info["run_length"],
                        "consecutive_ai_replies_threshold": (
                            self.consecutive_ai_replies_threshold
                        ),
                    },
                )
            )
        if (
            actor_ai_model
            and actor_ai_model in ai_high_volume_models
        ):
            count = ai_high_volume_models[actor_ai_model]
            control_results.append(
                self._cr(
                    signal="ai_high_volume",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} model {actor_ai_model!r} "
                        f"is part of a high-volume pattern (tickets="
                        f"{count} > threshold "
                        f"{self.ai_volume_per_hour_threshold} in "
                        f"{self.ai_volume_window_seconds}s window)"
                    ),
                    common_evidence={
                        **common_evidence,
                        "ai_volume_count": count,
                        "ai_volume_per_hour_threshold": (
                            self.ai_volume_per_hour_threshold
                        ),
                        "ai_volume_window_seconds": self.ai_volume_window_seconds,
                    },
                )
            )
        if actor_id and actor_id in cross_channel_actors:
            channels_list = cross_channel_actors[actor_id]
            control_results.append(
                self._cr(
                    signal="cross_channel_ai",
                    default="PR-05",
                    result="FLAG",
                    detail=(
                        f"Zendesk audit {audit_id} actor {actor_id!r} is part "
                        f"of a cross-channel pattern "
                        f"({len(channels_list)} channels > threshold "
                        f"{self.cross_channel_threshold})"
                    ),
                    common_evidence={
                        **common_evidence,
                        "cross_channel_channels": channels_list,
                        "cross_channel_threshold": self.cross_channel_threshold,
                    },
                )
            )

        # ------------------------------------------------------------------
        # Fallback: no signal matched — capture the audit as PASS so the
        # evidence-chain remains contiguous.
        # ------------------------------------------------------------------
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Zendesk audit {audit_id} on ticket {ticket_id!r} "
                        f"captured — no pattern-specific signal matched"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "audit_captured",
                    },
                )
            )

        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Zendesk audit log: ticket={ticket_id or 'unknown'} "
            f"actor={actor_id or 'unknown'} actor_is_ai={actor_is_ai} "
            f"actor_ai_model={actor_ai_model or 'none'} "
            f"channel={channel or 'unknown'} "
            f"events={len(event_summaries)}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"zendesk-{audit_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="zendesk_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=ticket_id or actor_id,
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

    # ------------------------------------------------------------------
    # Synthetic findings
    # ------------------------------------------------------------------

    def _synthetic_consecutive_ai_replies_result(
        self,
        *,
        ticket_id: Any,
        info: dict[str, Any],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "consecutive_ai_replies"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"zendesk-consecutive-ai-{ticket_id}"
        evidence: dict[str, Any] = {
            "zendesk_audit_id": synthetic_id,
            "ticket_id": str(ticket_id),
            "actor_id": info.get("actor_id"),
            "actor_ai_model": info.get("actor_ai_model"),
            "consecutive_ai_run_length": info.get("run_length"),
            "consecutive_ai_replies_threshold": (
                self.consecutive_ai_replies_threshold
            ),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, audit_id=synthetic_id
            ),
            "source_tool": "zendesk",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Zendesk synthetic finding: ticket {ticket_id} carries "
                f"{info.get('run_length')} consecutive AI public replies "
                f"without an intervening human reply — exceeds threshold "
                f"{self.consecutive_ai_replies_threshold}; escalation required"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="zendesk_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Zendesk audit log: synthetic consecutive-AI-"
                f"replies pattern for ticket={ticket_id} run_length="
                f"{info.get('run_length')}>threshold="
                f"{self.consecutive_ai_replies_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=str(ticket_id),
        )

    def _synthetic_ai_high_volume_result(
        self,
        *,
        model: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "ai_high_volume"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"zendesk-ai-volume-{model}"
        evidence: dict[str, Any] = {
            "zendesk_audit_id": synthetic_id,
            "actor_ai_model": model,
            "ai_volume_count": count,
            "ai_volume_per_hour_threshold": self.ai_volume_per_hour_threshold,
            "ai_volume_window_seconds": self.ai_volume_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, audit_id=synthetic_id
            ),
            "source_tool": "zendesk",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Zendesk synthetic finding: AI model {model!r} handled "
                f"{count} tickets in a {self.ai_volume_window_seconds}s "
                f"window — exceeds capacity threshold "
                f"{self.ai_volume_per_hour_threshold}; capacity audit warranted"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="zendesk_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Zendesk audit log: synthetic AI-high-volume "
                f"pattern for model={model} count={count}>threshold="
                f"{self.ai_volume_per_hour_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_bad_satisfaction_rate_result(
        self,
        *,
        model: str,
        info: dict[str, Any],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "bad_satisfaction_rate"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"zendesk-bad-sat-rate-{model}"
        rate = float(info.get("rate") or 0.0)
        evidence: dict[str, Any] = {
            "zendesk_audit_id": synthetic_id,
            "actor_ai_model": model,
            "bad_satisfaction_count": info.get("bad"),
            "bad_satisfaction_total": info.get("total"),
            "bad_satisfaction_rate": rate,
            "bad_satisfaction_rate_threshold": self.bad_satisfaction_rate_threshold,
            "bad_satisfaction_min_sample": self.bad_satisfaction_min_sample,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, audit_id=synthetic_id
            ),
            "source_tool": "zendesk",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Zendesk synthetic finding: AI model {model!r} produced "
                f"{info.get('bad')}/{info.get('total')} 'bad' satisfaction "
                f"ratings ({rate:.2%}) — exceeds threshold "
                f"{self.bad_satisfaction_rate_threshold:.2%}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="zendesk_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Zendesk audit log: synthetic bad-satisfaction-"
                f"rate pattern for model={model} rate={rate:.2%}>threshold="
                f"{self.bad_satisfaction_rate_threshold:.2%}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_channel_result(
        self,
        *,
        actor: str,
        channels: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_channel_ai"
        control_id = _control_for(signal, self._mappings, "PR-05")
        synthetic_id = f"zendesk-cross-channel-{actor}"
        evidence: dict[str, Any] = {
            "zendesk_audit_id": synthetic_id,
            "actor_id": actor,
            "actor_is_ai": True,
            "cross_channel_channels": channels,
            "cross_channel_channel_count": len(channels),
            "cross_channel_threshold": self.cross_channel_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, audit_id=synthetic_id
            ),
            "source_tool": "zendesk",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Zendesk synthetic finding: AI actor {actor} acted on "
                f"{len(channels)} channels ({', '.join(channels)}) — "
                f"exceeds cross-channel threshold "
                f"{self.cross_channel_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="zendesk_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Zendesk audit log: synthetic cross-channel "
                f"pattern for actor={actor} channels={len(channels)}>"
                f"threshold={self.cross_channel_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=actor,
        )
