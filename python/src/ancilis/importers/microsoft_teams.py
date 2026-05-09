"""Microsoft Teams audit-log importer — maps Graph ``directoryAudits`` (Teams)
and Purview unified-audit Teams events to AKSI controls.

Microsoft Teams is the parallel-to-Slack collaboration surface for
Microsoft-centric organizations and presents the SAME agent-driven
exfiltration threat model: agents (apps/bots) post messages to channels,
share files via SharePoint/OneDrive, install themselves into teams, and join
or record meetings. Microsoft Graph ``/auditLogs/directoryAudits`` (and the
Purview unified audit log) emit a stream of ``activityDisplayName`` values:
``MessageSent``, ``FileUploaded``, ``FileSharedExternally``,
``MeetingStarted``, ``MeetingRecordingShared``, ``ChatCreated``,
``MemberAddedToTeam``, ``GuestAddedToTeam``, ``AppInstalled``,
``BotAddedToConversation``, ``PolicyChanged``, ``MessageHasLink``,
``DLPRuleMatched``.

This importer ingests Teams audit-log exports in four on-disk shapes:

  1. ``{"events": [...]}`` — the canonical Graph/Purview envelope used here
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                  — one event per line
  4. single event           — a bare object

Signal mapping (see shared/mappings/microsoft-teams-aksi-controls.json):
  * ``MessageSent`` & actor.type in {app,bot} & public channel               → PR-04 PASS
  * ``MessageSent`` & actor.type in {app,bot} & has_link & external link     → PR-04 FLAG
  * ``FileUploaded`` by app/bot                                              → PR-04 FLAG
  * ``FileUploaded`` by app/bot with sensitive extension                     → PR-04 FLAG (escalated signal)
  * ``FileSharedExternally``                                                 → DE-01 FAIL  (top priority)
  * ``MeetingRecordingShared`` with target.is_external=true                  → DE-01 FAIL  (recording leaving org)
  * ``GuestAddedToTeam``                                                     → PR-02 FLAG
  * ``MemberAddedToTeam`` with details.new_role in privileged_role_set       → PR-02 FAIL
  * ``AppInstalled`` to a team                                               → PR-01 FLAG
  * ``BotAddedToConversation``                                               → PR-01 FLAG
  * ``PolicyChanged`` on tenant                                              → PR-02 FAIL
  * ``DLPRuleMatched`` with details.dlp_rule="PII_DETECTED"                  → PR-04 FAIL
  * ``DLPRuleMatched`` other rules                                           → PR-04 FLAG
  * channel_type=shared (cross-tenant Shared Channel) + bot actor            → PR-04 FLAG
  * actor.type=system                                                        → PR-05 PASS
  * cross-team pattern: same bot touching > N teams                          → PR-02 FLAG synthetic
  * cross-tenant pattern: same actor across multiple tenant_id values        → PR-02 FLAG synthetic

Sanitization (security-critical — Teams audit events can carry user emails,
target names of channels/teams/files, and IPs):

  * ``actor.email`` is reduced to its DOMAIN ONLY (``alice@corp.example.com``
    → ``"@corp.example.com"``). The local-part identifies a person; the
    domain is a tenant-correlation key.
  * ``target.name`` is NEVER stored — channel/team/file names can carry
    confidential project codenames or PII (e.g. ``acme-acquisition-q3``).
    Only the supplied ``name_length`` is captured.
  * ``context.ip`` is masked to /16 (CloudTrail-style): RFC1918 private
    addresses preserved verbatim, public IPv4 reduced to ``A.B.0.0/16``,
    public IPv6 reduced to first-32-bits ``::/32``.
  * ``details.link_target_domain`` is preserved (it's a domain, not a full
    URL); raw URLs are NEVER stored.
  * ``details.file_size_bytes`` is stored verbatim — useful posture metric.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``microsoft-graph-core``; Teams audit JSON
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


# Mapping table lives at <repo>/shared/mappings/microsoft-teams-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/microsoft_teams.py —
# five .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "microsoft-teams-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_AGENT_ACTOR_TYPES: frozenset[str] = frozenset({"app", "bot"})

_DEFAULT_PRIVILEGED_ROLES: frozenset[str] = frozenset(
    {"Owner", "GlobalAdmin", "TeamsAdmin"}
)

_DEFAULT_SENSITIVE_EXTENSIONS: frozenset[str] = frozenset(
    {".csv", ".xlsx", ".sqlite", ".db", ".json", ".zip", ".sql", ".bak", ".pst", ".kdbx"}
)

_DEFAULT_SHARED_CHANNEL_TYPES: frozenset[str] = frozenset({"shared"})

_DEFAULT_CROSS_TEAM_THRESHOLD = 5

# Built-in fallback action patterns (mirror the mapping file).
_DEFAULT_ACTIVITY_PATTERNS: tuple[dict[str, Any], ...] = (
    {"activity": "MessageSent", "actor_type": "app",
     "signal": "agent_message_sent", "result": "PASS", "control": "PR-04"},
    {"activity": "MessageSent", "actor_type": "bot",
     "signal": "agent_message_sent", "result": "PASS", "control": "PR-04"},
    {"activity": "FileUploaded", "actor_type": "app",
     "signal": "agent_file_uploaded", "result": "FLAG", "control": "PR-04"},
    {"activity": "FileUploaded", "actor_type": "bot",
     "signal": "agent_file_uploaded", "result": "FLAG", "control": "PR-04"},
    {"activity": "FileSharedExternally", "actor_type": "*",
     "signal": "file_shared_externally", "result": "FAIL", "control": "DE-01"},
    {"activity": "MeetingStarted", "actor_type": "*",
     "signal": "meeting_started", "result": "PASS", "control": "PR-05"},
    {"activity": "MeetingRecordingShared", "actor_type": "*",
     "signal": "meeting_recording_shared", "result": "PASS", "control": "PR-05"},
    {"activity": "ChatCreated", "actor_type": "*",
     "signal": "chat_created", "result": "PASS", "control": "PR-05"},
    {"activity": "MemberAddedToTeam", "actor_type": "*",
     "signal": "member_added_to_team", "result": "PASS", "control": "PR-05"},
    {"activity": "GuestAddedToTeam", "actor_type": "*",
     "signal": "guest_added_to_team", "result": "FLAG", "control": "PR-02"},
    {"activity": "AppInstalled", "actor_type": "*",
     "signal": "app_installed", "result": "FLAG", "control": "PR-01"},
    {"activity": "BotAddedToConversation", "actor_type": "*",
     "signal": "bot_added_to_conversation", "result": "FLAG", "control": "PR-01"},
    {"activity": "PolicyChanged", "actor_type": "*",
     "signal": "tenant_policy_changed", "result": "FAIL", "control": "PR-02"},
    {"activity": "MessageHasLink", "actor_type": "*",
     "signal": "message_has_link", "result": "PASS", "control": "PR-05"},
    {"activity": "DLPRuleMatched", "actor_type": "*",
     "signal": "dlp_rule_matched", "result": "FLAG", "control": "PR-04"},
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load microsoft-teams-aksi-controls.json; tolerate missing file."""
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


def _email_domain_only(email: str | None) -> str | None:
    """Reduce ``alice@corp.example.com`` → ``"@corp.example.com"``."""
    if not email or not isinstance(email, str):
        return None
    e = email.strip()
    if not e or "@" not in e:
        return None
    domain = e.rsplit("@", 1)[1].strip()
    if not domain:
        return None
    return f"@{domain}"


def _classify_ip(ip_value: str | None) -> str | None:
    """Mask an IP to /16 (CloudTrail-style)."""
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
    # IPv6
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _matches_activity_pattern(
    activity: str, actor_type: str, pattern: dict[str, Any]
) -> bool:
    act_pat = str(pattern.get("activity", ""))
    actor_pat = str(pattern.get("actor_type", "*"))
    return (
        fnmatch.fnmatchcase(activity, act_pat)
        and fnmatch.fnmatchcase(actor_type, actor_pat)
    )


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class MicrosoftTeamsImporter:
    """Parse a Microsoft Teams audit-log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_team_threshold: int | None = None,
        agent_actor_types: Iterable[str] | None = None,
        privileged_roles: Iterable[str] | None = None,
        sensitive_extensions: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Activity patterns precedence: mapping table > built-in defaults.
        meta_patterns = meta.get("action_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._activity_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._activity_patterns = _DEFAULT_ACTIVITY_PATTERNS
        # Agent (app/bot) actor types — used for additive flags.
        if agent_actor_types is not None:
            self.agent_actor_types: frozenset[str] = frozenset(
                str(a).lower() for a in agent_actor_types
            )
        else:
            meta_agent = meta.get("agent_actor_types")
            if isinstance(meta_agent, list) and meta_agent:
                self.agent_actor_types = frozenset(str(a).lower() for a in meta_agent)
            else:
                self.agent_actor_types = _DEFAULT_AGENT_ACTOR_TYPES
        # Privileged role set — case sensitive (matches Teams role labels).
        if privileged_roles is not None:
            self.privileged_roles: frozenset[str] = frozenset(
                str(r) for r in privileged_roles
            )
        else:
            meta_roles = meta.get("privileged_role_set")
            if isinstance(meta_roles, list) and meta_roles:
                self.privileged_roles = frozenset(str(r) for r in meta_roles)
            else:
                self.privileged_roles = _DEFAULT_PRIVILEGED_ROLES
        # Sensitive extensions (lower-case, leading dot).
        if sensitive_extensions is not None:
            self.sensitive_extensions: frozenset[str] = frozenset(
                str(e).lower() for e in sensitive_extensions
            )
        else:
            meta_ext = meta.get("sensitive_extensions")
            if isinstance(meta_ext, list) and meta_ext:
                self.sensitive_extensions = frozenset(
                    str(e).lower() for e in meta_ext
                )
            else:
                self.sensitive_extensions = _DEFAULT_SENSITIVE_EXTENSIONS
        meta_shared = meta.get("shared_channel_types")
        if isinstance(meta_shared, list) and meta_shared:
            self.shared_channel_types: frozenset[str] = frozenset(
                str(s).lower() for s in meta_shared
            )
        else:
            self.shared_channel_types = _DEFAULT_SHARED_CHANNEL_TYPES
        # DLP signal mapping — Purview rule names → AKSI signal label.
        dlp_map = meta.get("dlp_signal_mapping")
        if isinstance(dlp_map, dict) and dlp_map:
            self._dlp_signal_mapping: dict[str, str] = {
                str(k): str(v) for k, v in dlp_map.items()
            }
        else:
            self._dlp_signal_mapping = {
                "PII_DETECTED": "dlp_pii_detected",
                "DEFAULT": "dlp_rule_matched",
            }
        # Cross-team threshold precedence: explicit arg > mapping metadata > default.
        if cross_team_threshold is not None:
            self.cross_team_threshold = int(cross_team_threshold)
        else:
            self.cross_team_threshold = int(
                meta.get("cross_team_threshold", _DEFAULT_CROSS_TEAM_THRESHOLD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Microsoft Teams audit-log file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Microsoft Teams audit-log content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events":[...]}`` / ``{"data":[...]}`` / JSONL / single."""
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
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-event EvaluationResults plus cross-team / cross-tenant synthetic findings."""
        actor_teams: dict[str, set[str]] = {}
        actor_tenants: dict[str, set[str]] = {}
        for event in events:
            actor = event.get("actor") or {}
            if not isinstance(actor, dict):
                continue
            actor_type = str(actor.get("type") or "").lower()
            actor_id_raw = actor.get("id")
            if not isinstance(actor_id_raw, str) or not actor_id_raw:
                continue
            ctx = event.get("context") or {}
            if not isinstance(ctx, dict):
                ctx = {}
            team_id = ctx.get("team_id")
            if (
                actor_type in self.agent_actor_types
                and isinstance(team_id, str)
                and team_id
            ):
                actor_teams.setdefault(actor_id_raw, set()).add(team_id)
            tenant_id = ctx.get("tenant_id")
            if isinstance(tenant_id, str) and tenant_id:
                actor_tenants.setdefault(actor_id_raw, set()).add(tenant_id)

        cross_team_actors = {
            actor_id: sorted(teams)
            for actor_id, teams in actor_teams.items()
            if len(teams) > self.cross_team_threshold
        }
        cross_tenant_actors = {
            actor_id: sorted(tenants)
            for actor_id, tenants in actor_tenants.items()
            if len(tenants) > 1
        }

        results = [
            self._parse_event(
                event,
                file_sha256=file_sha256,
                cross_team_actors=cross_team_actors,
                cross_tenant_actors=cross_tenant_actors,
            )
            for event in events
        ]

        for actor_id, teams in sorted(cross_team_actors.items()):
            results.append(
                self._synthetic_cross_team_result(
                    actor_id=actor_id,
                    teams=teams,
                    file_sha256=file_sha256,
                )
            )
        for actor_id, tenants in sorted(cross_tenant_actors.items()):
            results.append(
                self._synthetic_cross_tenant_result(
                    actor_id=actor_id,
                    tenants=tenants,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "microsoft_teams_audit",
            "source_tool_name": "microsoft_teams",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_activity(
        self, activity: str, actor_type: str
    ) -> dict[str, Any] | None:
        """Find the first activity-pattern that matches; ``None`` if no match."""
        for pattern in self._activity_patterns:
            if _matches_activity_pattern(activity, actor_type, pattern):
                return pattern
        return None

    # ------------------------------------------------------------------
    # Per-event parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_team_actors: dict[str, list[str]],
        cross_tenant_actors: dict[str, list[str]],
    ) -> EvaluationResult:
        event_id = str(event.get("id") or uuid.uuid4())
        activity = str(event.get("activityDisplayName") or "").strip()
        activity_dt = event.get("activityDateTime")
        if isinstance(activity_dt, str) and activity_dt:
            event_time = activity_dt
        else:
            event_time = datetime.now(timezone.utc).isoformat()

        # ---- actor (sanitized) ----
        actor = event.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        actor_type = str(actor.get("type") or "").strip().lower()
        actor_id = (
            str(actor.get("id"))
            if isinstance(actor.get("id"), str)
            else None
        )
        actor_email_domain = _email_domain_only(actor.get("email"))

        # ---- target (sanitized — name NEVER stored, only length) ----
        target = event.get("target") or {}
        if not isinstance(target, dict):
            target = {}
        target_id = (
            str(target.get("id"))
            if isinstance(target.get("id"), str)
            else None
        )
        target_type = str(target.get("type") or "").strip().lower()
        try:
            target_name_length_raw = target.get("name_length")
            target_name_length = (
                int(target_name_length_raw)
                if target_name_length_raw is not None
                else None
            )
        except (TypeError, ValueError):
            target_name_length = None
        target_is_external = (
            bool(target.get("is_external"))
            if isinstance(target.get("is_external"), bool)
            else None
        )
        target_is_private = (
            bool(target.get("is_private"))
            if isinstance(target.get("is_private"), bool)
            else None
        )

        # ---- context (sanitized) ----
        ctx = event.get("context") or {}
        if not isinstance(ctx, dict):
            ctx = {}
        team_id = (
            str(ctx.get("team_id"))
            if isinstance(ctx.get("team_id"), str)
            else None
        )
        channel_type = (
            str(ctx.get("channel_type")).lower()
            if isinstance(ctx.get("channel_type"), str)
            else None
        )
        tenant_id = (
            str(ctx.get("tenant_id"))
            if isinstance(ctx.get("tenant_id"), str)
            else None
        )
        ip_redacted = _classify_ip(ctx.get("ip"))

        # ---- details (sanitized) ----
        details = event.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        app_id = (
            str(details.get("app_id"))
            if isinstance(details.get("app_id"), str)
            else None
        )
        bot_id = (
            str(details.get("bot_id"))
            if isinstance(details.get("bot_id"), str)
            else None
        )
        try:
            file_size_raw = details.get("file_size_bytes")
            file_size_bytes = (
                int(file_size_raw) if file_size_raw is not None else None
            )
        except (TypeError, ValueError):
            file_size_bytes = None
        file_extension_raw = details.get("file_extension")
        file_extension = (
            str(file_extension_raw).lower()
            if isinstance(file_extension_raw, str)
            else None
        )
        has_link = (
            bool(details.get("has_link"))
            if isinstance(details.get("has_link"), bool)
            else None
        )
        link_target_domain = (
            str(details.get("link_target_domain"))
            if isinstance(details.get("link_target_domain"), str)
            else None
        )
        dlp_rule = (
            str(details.get("dlp_rule"))
            if isinstance(details.get("dlp_rule"), str)
            else None
        )
        new_role = (
            str(details.get("new_role"))
            if isinstance(details.get("new_role"), str)
            else None
        )

        # The "tenant primary domain" used to classify external links.
        tenant_primary_domain: str | None = None
        ctx_primary = ctx.get("tenant_primary_domain")
        if isinstance(ctx_primary, str):
            tenant_primary_domain = ctx_primary.lower().strip() or None

        common_evidence: dict[str, Any] = {
            "teams_event_id": event_id,
            "activity": activity,
            "event_time": event_time,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "actor_email_domain": actor_email_domain,
            "target_id": target_id,
            "target_type": target_type,
            "target_name_length": target_name_length,
            "target_is_external": target_is_external,
            "target_is_private": target_is_private,
            "team_id": team_id,
            "channel_type": channel_type,
            "tenant_id": tenant_id,
            "ip_redacted": ip_redacted,
            "app_id": app_id,
            "bot_id": bot_id,
            "file_extension": file_extension,
            "file_size_bytes": file_size_bytes,
            "has_link": has_link,
            "link_target_domain": link_target_domain,
            "dlp_rule": dlp_rule,
            "new_role": new_role,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "microsoft_teams",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. system actor short-circuit — Microsoft-internal events.
        # PR-05 PASS regardless of activity — it's a Graph/Purview-emitted
        # internal event, not an agent action.
        # ----------------------------------------------------------------
        if actor_type == "system":
            signal = "system_actor_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Teams event {event_id}: activity={activity} "
                        f"actor.type=system — Microsoft-internal event"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return self._finalize(
                event_id=event_id,
                activity=activity,
                actor_type=actor_type,
                target_type=target_type,
                channel_type=channel_type,
                tenant_id=tenant_id,
                event_time=event_time,
                control_results=control_results,
            )

        # ----------------------------------------------------------------
        # 2. Activity-specific composite signals (take precedence over the
        # generic activity-pattern table).
        # Order: DLP → recording-shared-external → owner-role-grant →
        # agent-message-with-external-link → file-uploaded-sensitive-ext.
        # ----------------------------------------------------------------
        composite_handled = False

        # 2a. DLP rule matched — escalate PII to FAIL.
        if activity == "DLPRuleMatched":
            composite_handled = True
            if dlp_rule and dlp_rule.upper() == "PII_DETECTED":
                signal = self._dlp_signal_mapping.get(
                    "PII_DETECTED", "dlp_pii_detected"
                )
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Teams event {event_id}: DLP rule {dlp_rule} "
                            f"matched — PII detected on agent surface"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                lookup_key = (dlp_rule or "DEFAULT").upper()
                signal = self._dlp_signal_mapping.get(
                    lookup_key,
                    self._dlp_signal_mapping.get("DEFAULT", "dlp_rule_matched"),
                )
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Teams event {event_id}: DLP rule "
                            f"{dlp_rule or 'unspecified'} matched"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # 2b. Meeting recording shared externally → DE-01 FAIL.
        elif activity == "MeetingRecordingShared" and target_is_external is True:
            composite_handled = True
            signal = "meeting_recording_shared_external"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Teams event {event_id}: meeting recording shared "
                        f"externally (target.is_external=true) — recording "
                        f"leaving organisation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 2c. Owner role grant via MemberAddedToTeam → PR-02 FAIL.
        elif (
            activity == "MemberAddedToTeam"
            and new_role is not None
            and new_role in self.privileged_roles
        ):
            composite_handled = True
            signal = "owner_role_grant"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Teams event {event_id}: privileged role "
                        f"{new_role!r} granted via MemberAddedToTeam "
                        f"team={team_id} — admin scope expansion"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 2d. Agent message with external link → PR-04 FLAG.
        elif (
            activity == "MessageSent"
            and actor_type in self.agent_actor_types
            and has_link is True
            and link_target_domain
            and (
                tenant_primary_domain is None
                or link_target_domain.lower().lstrip("@")
                != tenant_primary_domain.lstrip("@")
            )
        ):
            composite_handled = True
            signal = "agent_message_external_link"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Teams event {event_id}: {actor_type} actor sent "
                        f"message containing external link "
                        f"(link_target_domain={link_target_domain}) — "
                        f"potential exfiltration"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 2e. Bot file upload with sensitive extension → escalated PR-04 FLAG.
        elif (
            activity == "FileUploaded"
            and actor_type in self.agent_actor_types
            and file_extension is not None
            and file_extension in self.sensitive_extensions
        ):
            composite_handled = True
            signal = "agent_file_uploaded_sensitive_ext"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Teams event {event_id}: {actor_type} actor uploaded "
                        f"file with sensitive extension {file_extension} "
                        f"(size={file_size_bytes})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Activity-pattern table fallback.
        # ----------------------------------------------------------------
        if not composite_handled:
            pattern = self._classify_activity(activity, actor_type)
            if pattern is not None:
                signal = str(pattern.get("signal", "unknown_activity"))
                control_id = _control_for(
                    signal, self._mappings, str(pattern.get("control", "PR-05"))
                )
                result = str(pattern.get("result", "PASS"))
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=result,
                        detail=(
                            f"Teams event {event_id}: activity={activity} "
                            f"actor.type={actor_type or 'unknown'} "
                            f"classified as {signal} ({result})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "unknown_activity"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Teams event {event_id}: activity={activity!r} "
                            f"actor.type={actor_type or 'unknown'} has no "
                            f"matching pattern — surfaced for review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 4. Cross-tenant Shared Channel surface (additive flag).
        # A bot acting in a shared (cross-tenant) channel is exfil-relevant
        # regardless of activity classification.
        # ----------------------------------------------------------------
        if (
            actor_type in self.agent_actor_types
            and channel_type is not None
            and channel_type in self.shared_channel_types
        ):
            signal = "shared_channel_bot_activity"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Teams event {event_id}: {actor_type} actor "
                        f"operating in shared channel "
                        f"(channel_type={channel_type}) — cross-tenant surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Cross-team pattern marker (per-event).
        # ----------------------------------------------------------------
        if actor_id and actor_id in cross_team_actors:
            signal = "cross_team_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Teams event {event_id}: actor {actor_id} part of "
                        f"cross-team pattern "
                        f"({len(cross_team_actors[actor_id])} teams > "
                        f"threshold {self.cross_team_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_team_teams": cross_team_actors[actor_id],
                        "cross_team_threshold": self.cross_team_threshold,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 6. Cross-tenant pattern marker (per-event).
        # ----------------------------------------------------------------
        if actor_id and actor_id in cross_tenant_actors:
            signal = "cross_tenant_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Teams event {event_id}: actor {actor_id} part of "
                        f"cross-tenant pattern "
                        f"({len(cross_tenant_actors[actor_id])} tenants)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_tenant_tenants": cross_tenant_actors[actor_id],
                    },
                )
            )

        return self._finalize(
            event_id=event_id,
            activity=activity,
            actor_type=actor_type,
            target_type=target_type,
            channel_type=channel_type,
            tenant_id=tenant_id,
            event_time=event_time,
            control_results=control_results,
        )

    def _finalize(
        self,
        *,
        event_id: str,
        activity: str,
        actor_type: str,
        target_type: str,
        channel_type: str | None,
        tenant_id: str | None,
        event_time: str,
        control_results: list[ControlResult],
    ) -> EvaluationResult:
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Microsoft Teams audit log: activity={activity} "
            f"actor.type={actor_type or 'unknown'} "
            f"target.type={target_type or 'unknown'} "
            f"channel_type={channel_type or 'unknown'} "
            f"tenant={tenant_id or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"teams-{event_id[:32]}",
            timestamp=event_time,
            agent_id=self.agent_id,
            source_type="microsoft_teams_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=tenant_id or None,
        )

    def _synthetic_cross_team_result(
        self,
        *,
        actor_id: str,
        teams: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor cross-team pattern finding (bot spreading)."""
        signal = "cross_team_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"teams-cross-team-{actor_id}"
        evidence: dict[str, Any] = {
            "teams_event_id": synthetic_id,
            "actor_id": actor_id,
            "cross_team_teams": teams,
            "cross_team_count": len(teams),
            "cross_team_threshold": self.cross_team_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "microsoft_teams",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Teams synthetic finding: actor {actor_id} acted in "
                f"{len(teams)} teams in this export — exceeds cross-team "
                f"threshold {self.cross_team_threshold} (bot spreading)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="microsoft_teams_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Microsoft Teams audit log: synthetic "
                f"cross-team pattern actor={actor_id} teams={len(teams)} "
                f">threshold={self.cross_team_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_tenant_result(
        self,
        *,
        actor_id: str,
        tenants: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor cross-tenant pattern finding."""
        signal = "cross_tenant_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"teams-cross-tenant-{actor_id}"
        evidence: dict[str, Any] = {
            "teams_event_id": synthetic_id,
            "actor_id": actor_id,
            "cross_tenant_tenants": tenants,
            "cross_tenant_count": len(tenants),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "microsoft_teams",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Teams synthetic finding: actor {actor_id} active in "
                f"{len(tenants)} tenants ({', '.join(tenants)}) — "
                f"cross-tenant pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="microsoft_teams_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Microsoft Teams audit log: synthetic "
                f"cross-tenant pattern actor={actor_id} "
                f"tenants={len(tenants)}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
