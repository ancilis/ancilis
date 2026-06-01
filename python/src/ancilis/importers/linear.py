# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Linear audit-event importer — maps agent project-management activity to AKSI controls.

Linear (https://linear.app) is the dominant project-management tool for
engineering teams. Agents increasingly file issues, comment on threads, link
pull requests, escalate priority, and shuffle workflow state inside Linear —
and those mutations form a parallel audit trail to source control. A bot that
quietly bumps a backlog ticket to ``Urgent`` priority, or deletes a started
issue, is making a workflow-altering change that today's evidence pipelines
do not capture.

This importer ingests Linear's GraphQL audit-log exports and webhook captures
in three on-disk shapes:

  1. ``{"events": [...]}`` — primary audit-log envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                  — one event per line

Signal mapping (see shared/mappings/linear-aksi-controls.json):
  * ``Issue.create`` by user (actorIsBot=false, trigger=user)               → PR-05 PASS
  * ``Issue.create`` by bot/agent (actorIsBot=true OR trigger=agent)        → PR-01 FLAG
  * ``Issue.update`` priority→1 (Urgent) by bot/agent                       → PR-02 FLAG
  * ``Issue.update`` stateType regression (started/completed → backlog)    → PR-05 FLAG
  * ``Issue.remove`` of in-progress / completed issue                       → PR-02 FAIL
    (audit-trail destruction — deleting a started/completed issue removes
    evidence of work performed)
  * ``Issue.archive``                                                       → PR-05 PASS
  * ``Comment.create`` by bot on high-priority (1 or 2) issue              → PR-01 FLAG
  * ``Comment.remove``                                                      → PR-05 FLAG
  * ``Project.update`` by bot                                               → PR-05 FLAG
  * ``Project.archive``                                                     → PR-05 PASS
  * ``Team.update`` with permission change                                  → PR-02 FLAG
  * ``Document.create``/``update``/``remove``                               → PR-04 PASS (captured)
  * ``Attachment.create`` with non-allowlisted external host                → PR-04 FLAG
  * ``trigger=automation``                                                  → PR-05 PASS (audit trail)
  * ``trigger=webhook``                                                     → PR-01 FLAG
  * Issue with ``title_length`` > threshold (default 200) by bot           → PR-05 FLAG
  * Issue with ``description_length`` > threshold (default 10000)          → PR-04 FLAG
  * bot-velocity pattern: same bot actorId creating > N issues in a 1h
    window (default N=20)                                                   → PR-02 FLAG synthetic
  * cross-team pattern: same bot touching > N teams (default N=5)           → PR-02 FLAG synthetic

Sanitization (security-critical — Linear audit logs can carry PII in actor
names, emails, free-text titles, and IPs):
  * ``actorName`` raw is NEVER stored — we keep length + sha256 of the full
    name (so identical names collide while not retaining the value).
  * ``actorEmail`` is reduced to ``@domain`` only.
  * Issue ``title`` / ``description`` text is NEVER stored — Linear already
    provides ``title_length`` / ``description_length`` integers and that is
    what we capture verbatim.
  * ``labelIds`` raw values are NOT stored — we capture only the count.
    Labels can carry sensitive metadata like ``customer-x``.
  * ``ip_address`` is reduced to a /16 pattern (first two octets) for IPv4
    and a /32-hextet pattern for IPv6. RFC1918 / loopback / link-local
    addresses are preserved verbatim.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``linear-py`` package (none exists); audit-log
JSON exports are parsed with the standard library only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at
# <repo>/python/src/ancilis/importers/linear.py — five .parent traversals
# after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "linear-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_BOT_VELOCITY_THRESHOLD = 20
_DEFAULT_BOT_VELOCITY_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_TEAM_THRESHOLD = 5
_DEFAULT_LARGE_TITLE_CHARS = 200
_DEFAULT_LARGE_DESCRIPTION_CHARS = 10000
_DEFAULT_HIGH_PRIORITY_LEVELS: frozenset[int] = frozenset({1, 2})
_DEFAULT_IN_PROGRESS_STATES: frozenset[str] = frozenset({"started", "completed"})
_DEFAULT_REGRESSION_FROM_STATES: frozenset[str] = frozenset({"started", "completed"})
_DEFAULT_REGRESSION_TO_STATES: frozenset[str] = frozenset({"backlog"})
_DEFAULT_ALLOWLIST_ATTACHMENT_HOSTS: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the linear-aksi-controls.json mapping; tolerate missing file."""
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


def _redact_actor_name(name: str | None) -> dict[str, Any] | None:
    """Capture length + sha256 of full actor name (NEVER store raw name)."""
    if not name or not isinstance(name, str):
        return None
    n = name.strip()
    if not n:
        return None
    digest = hashlib.sha256(n.encode("utf-8")).hexdigest()
    return {"length": len(n), "sha256": digest}


def _redact_email(email: str | None) -> str | None:
    """Reduce an email to ``@domain`` only."""
    if not email or not isinstance(email, str):
        return None
    em = email.strip()
    if "@" not in em:
        return None
    return "@" + em.rsplit("@", 1)[1]


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


def _extract_host(url: str) -> str | None:
    """Return the lowercased hostname of a URL, or None if unparseable."""
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.hostname or "").strip().lower()
    return host or None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class LinearImporter:
    """Parse a Linear audit-log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        bot_velocity_threshold: int | None = None,
        bot_velocity_window_seconds: int | None = None,
        cross_team_threshold: int | None = None,
        large_title_chars: int | None = None,
        large_description_chars: int | None = None,
        allowlist_attachment_hosts: Iterable[str] | None = None,
        high_priority_levels: Iterable[int] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Bot-velocity threshold + window.
        if bot_velocity_threshold is not None:
            self.bot_velocity_threshold = int(bot_velocity_threshold)
        else:
            self.bot_velocity_threshold = int(
                meta.get("bot_velocity_threshold", _DEFAULT_BOT_VELOCITY_THRESHOLD)
            )
        if bot_velocity_window_seconds is not None:
            self.bot_velocity_window_seconds = int(bot_velocity_window_seconds)
        else:
            self.bot_velocity_window_seconds = int(
                meta.get(
                    "bot_velocity_window_seconds",
                    _DEFAULT_BOT_VELOCITY_WINDOW_SECONDS,
                )
            )
        # Cross-team threshold.
        if cross_team_threshold is not None:
            self.cross_team_threshold = int(cross_team_threshold)
        else:
            self.cross_team_threshold = int(
                meta.get("cross_team_threshold", _DEFAULT_CROSS_TEAM_THRESHOLD)
            )
        # Large-title / large-description thresholds.
        if large_title_chars is not None:
            self.large_title_chars = int(large_title_chars)
        else:
            self.large_title_chars = int(
                meta.get("large_title_chars", _DEFAULT_LARGE_TITLE_CHARS)
            )
        if large_description_chars is not None:
            self.large_description_chars = int(large_description_chars)
        else:
            self.large_description_chars = int(
                meta.get(
                    "large_description_chars", _DEFAULT_LARGE_DESCRIPTION_CHARS
                )
            )
        # Attachment-host allowlist.
        if allowlist_attachment_hosts is not None:
            self.allowlist_attachment_hosts: frozenset[str] = frozenset(
                str(h).strip().lower() for h in allowlist_attachment_hosts if h
            )
        else:
            meta_allowlist = meta.get("allowlist_attachment_hosts")
            if isinstance(meta_allowlist, list):
                self.allowlist_attachment_hosts = frozenset(
                    str(h).strip().lower() for h in meta_allowlist if h
                )
            else:
                self.allowlist_attachment_hosts = _DEFAULT_ALLOWLIST_ATTACHMENT_HOSTS
        # High-priority levels (1=Urgent, 2=High by default).
        if high_priority_levels is not None:
            self.high_priority_levels: frozenset[int] = frozenset(
                int(p) for p in high_priority_levels
            )
        else:
            meta_hp = meta.get("high_priority_levels")
            if isinstance(meta_hp, list) and meta_hp:
                try:
                    self.high_priority_levels = frozenset(int(p) for p in meta_hp)
                except (TypeError, ValueError):
                    self.high_priority_levels = _DEFAULT_HIGH_PRIORITY_LEVELS
            else:
                self.high_priority_levels = _DEFAULT_HIGH_PRIORITY_LEVELS
        # State sets (regression and in-progress definitions are mapping-driven).
        meta_in_progress = meta.get("in_progress_state_types")
        if isinstance(meta_in_progress, list) and meta_in_progress:
            self.in_progress_states: frozenset[str] = frozenset(
                str(s).strip().lower() for s in meta_in_progress if s
            )
        else:
            self.in_progress_states = _DEFAULT_IN_PROGRESS_STATES
        meta_regr_from = meta.get("regression_from_state_types")
        if isinstance(meta_regr_from, list) and meta_regr_from:
            self.regression_from_states: frozenset[str] = frozenset(
                str(s).strip().lower() for s in meta_regr_from if s
            )
        else:
            self.regression_from_states = _DEFAULT_REGRESSION_FROM_STATES
        meta_regr_to = meta.get("regression_to_state_types")
        if isinstance(meta_regr_to, list) and meta_regr_to:
            self.regression_to_states: frozenset[str] = frozenset(
                str(s).strip().lower() for s in meta_regr_to if s
            )
        else:
            self.regression_to_states = _DEFAULT_REGRESSION_TO_STATES

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Linear audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Linear audit-log content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events": [...]}`` / ``{"data": [...]}`` / JSONL / single event."""
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
        """Build per-event EvaluationResults plus bot-velocity / cross-team synthetics."""
        # Pass 1: aggregate (actor, team) for cross-team detection and
        # (actor, timestamp) for bot-velocity detection (Issue.create only).
        actor_teams: dict[str, set[str]] = {}
        bot_issue_create_ts: dict[str, list[datetime]] = {}
        actor_is_bot: dict[str, bool] = {}

        for ev in events:
            actor = ev.get("actorId")
            if not isinstance(actor, str) or not actor:
                continue
            is_bot = bool(ev.get("actorIsBot"))
            trigger = str(ev.get("trigger") or "").strip().lower()
            actor_is_bot[actor] = (
                actor_is_bot.get(actor, False) or is_bot or trigger == "agent"
            )
            data = ev.get("data") or {}
            if isinstance(data, dict):
                team_id = data.get("teamId")
                if isinstance(team_id, str) and team_id:
                    actor_teams.setdefault(actor, set()).add(team_id)
            type_field = str(ev.get("type") or "")
            action_field = str(ev.get("action") or "")
            if (
                type_field == "Issue"
                and action_field == "create"
                and (is_bot or trigger == "agent")
            ):
                ts = _parse_iso_timestamp(ev.get("createdAt"))
                if ts is not None:
                    bot_issue_create_ts.setdefault(actor, []).append(ts)

        cross_team_actors: dict[str, list[str]] = {
            actor: sorted(teams)
            for actor, teams in actor_teams.items()
            if actor_is_bot.get(actor, False) and len(teams) > self.cross_team_threshold
        }

        bot_velocity_actors: dict[str, int] = {}
        window = self.bot_velocity_window_seconds
        for actor, timestamps in bot_issue_create_ts.items():
            if len(timestamps) <= self.bot_velocity_threshold:
                continue
            sorted_ts = sorted(timestamps)
            left = 0
            max_in_window = 0
            for right in range(len(sorted_ts)):
                while (sorted_ts[right] - sorted_ts[left]).total_seconds() > window:
                    left += 1
                count = right - left + 1
                if count > max_in_window:
                    max_in_window = count
            if max_in_window > self.bot_velocity_threshold:
                bot_velocity_actors[actor] = max_in_window

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                cross_team_actors=cross_team_actors,
                bot_velocity_actors=bot_velocity_actors,
            )
            for ev in events
        ]

        for actor, count in sorted(bot_velocity_actors.items()):
            results.append(
                self._synthetic_bot_velocity_result(
                    actor=actor,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for actor, teams in sorted(cross_team_actors.items()):
            results.append(
                self._synthetic_cross_team_result(
                    actor=actor,
                    teams=teams,
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
            "source_format": "linear_audit_log",
            "source_tool_name": "linear",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-event parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_team_actors: dict[str, list[str]],
        bot_velocity_actors: dict[str, int],
    ) -> EvaluationResult:
        event_id = str(event.get("id") or uuid.uuid4())
        type_field = str(event.get("type") or "").strip()
        action_field = str(event.get("action") or "").strip()
        timestamp = _format_timestamp(event.get("createdAt"))
        actor_id_raw = event.get("actorId")
        actor_id = str(actor_id_raw) if isinstance(actor_id_raw, str) else ""
        actor_is_bot = bool(event.get("actorIsBot"))
        actor_name_redacted = _redact_actor_name(
            event.get("actorName") if isinstance(event.get("actorName"), str) else None
        )
        actor_email_domain = _redact_email(
            event.get("actorEmail") if isinstance(event.get("actorEmail"), str) else None
        )
        organization_id = (
            str(event.get("organizationId"))
            if isinstance(event.get("organizationId"), str) and event.get("organizationId")
            else None
        )
        trigger = str(event.get("trigger") or "").strip().lower() or None
        is_agent_trigger = trigger == "agent"

        data = event.get("data") or {}
        if not isinstance(data, dict):
            data = {}

        # Verbatim structured data fields.
        issue_id = (
            str(data.get("issueId"))
            if isinstance(data.get("issueId"), str) and data.get("issueId")
            else None
        )
        issue_identifier = (
            str(data.get("issueIdentifier"))
            if isinstance(data.get("issueIdentifier"), str) and data.get("issueIdentifier")
            else None
        )
        title_length_raw = data.get("title_length")
        title_length: int | None = (
            int(title_length_raw)
            if isinstance(title_length_raw, (int, float))
            else None
        )
        description_length_raw = data.get("description_length")
        description_length: int | None = (
            int(description_length_raw)
            if isinstance(description_length_raw, (int, float))
            else None
        )
        priority_raw = data.get("priority")
        priority: int | None = (
            int(priority_raw)
            if isinstance(priority_raw, (int, float))
            else None
        )
        state_id = (
            str(data.get("stateId"))
            if isinstance(data.get("stateId"), str) and data.get("stateId")
            else None
        )
        state_type_raw = data.get("stateType")
        state_type = (
            str(state_type_raw).strip().lower()
            if isinstance(state_type_raw, str) and state_type_raw
            else None
        )
        previous_state_type_raw = (
            data.get("previousStateType")
            or data.get("previous_state_type")
            or data.get("oldStateType")
        )
        previous_state_type = (
            str(previous_state_type_raw).strip().lower()
            if isinstance(previous_state_type_raw, str) and previous_state_type_raw
            else None
        )
        previous_priority_raw = (
            data.get("previousPriority") or data.get("previous_priority")
        )
        previous_priority: int | None = (
            int(previous_priority_raw)
            if isinstance(previous_priority_raw, (int, float))
            else None
        )
        label_ids_raw = data.get("labelIds")
        label_ids_count = (
            len(label_ids_raw) if isinstance(label_ids_raw, list) else 0
        )
        assignee_id = (
            str(data.get("assigneeId"))
            if isinstance(data.get("assigneeId"), str) and data.get("assigneeId")
            else None
        )
        creator_id = (
            str(data.get("creatorId"))
            if isinstance(data.get("creatorId"), str) and data.get("creatorId")
            else None
        )
        subscriber_ids_raw = data.get("subscriberIds")
        subscriber_count = (
            len(subscriber_ids_raw) if isinstance(subscriber_ids_raw, list) else 0
        )
        estimate_raw = data.get("estimate")
        estimate: int | float | None = (
            float(estimate_raw)
            if isinstance(estimate_raw, (int, float))
            else None
        )
        due_date = (
            str(data.get("dueDate"))
            if isinstance(data.get("dueDate"), str) and data.get("dueDate")
            else None
        )
        linked_repo_hosts_raw = data.get("linkedRepoUrls_hosts") or []
        linked_repo_hosts: list[str] = (
            [str(h).strip().lower() for h in linked_repo_hosts_raw if h]
            if isinstance(linked_repo_hosts_raw, list)
            else []
        )
        linked_attachment_count_raw = data.get("linkedAttachmentCount")
        linked_attachment_count = (
            int(linked_attachment_count_raw)
            if isinstance(linked_attachment_count_raw, (int, float))
            else 0
        )
        parent_issue_id = (
            str(data.get("parentIssueId"))
            if isinstance(data.get("parentIssueId"), str) and data.get("parentIssueId")
            else None
        )
        team_id = (
            str(data.get("teamId"))
            if isinstance(data.get("teamId"), str) and data.get("teamId")
            else None
        )
        team_key = (
            str(data.get("teamKey"))
            if isinstance(data.get("teamKey"), str) and data.get("teamKey")
            else None
        )
        ip_redacted = _classify_ip(
            data.get("ip_address")
            if isinstance(data.get("ip_address"), str)
            else None
        )
        # Attachment-specific fields.
        attachment_url = (
            str(data.get("url"))
            if isinstance(data.get("url"), str) and data.get("url")
            else None
        )
        attachment_host = _extract_host(attachment_url) if attachment_url else None
        # Project-specific change keys (which fields changed, by name only).
        changed_keys_raw = data.get("changedKeys") or data.get("changed_keys") or []
        changed_keys: list[str] = (
            [str(k) for k in changed_keys_raw]
            if isinstance(changed_keys_raw, list)
            else []
        )
        # Team permission change marker.
        permission_changed = bool(
            data.get("permissionChanged") or data.get("permission_changed")
        )
        old_permission = (
            str(data.get("oldPermission") or data.get("old_permission") or "")
            or None
        )
        new_permission = (
            str(data.get("newPermission") or data.get("new_permission") or "")
            or None
        )

        common_evidence: dict[str, Any] = {
            "linear_event_id": event_id,
            "type": type_field or None,
            "action": action_field or None,
            "actor_id": actor_id or None,
            "actor_is_bot": actor_is_bot,
            "actor_name_redacted": actor_name_redacted,
            "actor_email_domain": actor_email_domain,
            "organization_id": organization_id,
            "team_id": team_id,
            "team_key": team_key,
            "issue_id": issue_id,
            "issue_identifier": issue_identifier,
            "title_length": title_length,
            "description_length": description_length,
            "priority": priority,
            "previous_priority": previous_priority,
            "state_id": state_id,
            "state_type": state_type,
            "previous_state_type": previous_state_type,
            "label_ids_count": label_ids_count,
            "assignee_id": assignee_id,
            "creator_id": creator_id,
            "subscriber_count": subscriber_count,
            "estimate": estimate,
            "due_date": due_date,
            "linked_repo_hosts": linked_repo_hosts,
            "linked_attachment_count": linked_attachment_count,
            "parent_issue_id": parent_issue_id,
            "attachment_host": attachment_host,
            "changed_keys": changed_keys,
            "permission_changed": permission_changed,
            "old_permission": old_permission,
            "new_permission": new_permission,
            "ip_address_redacted": ip_redacted,
            "trigger": trigger,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "linear",
        }

        control_results: list[ControlResult] = []
        bot_or_agent = actor_is_bot or is_agent_trigger

        # ----------------------------------------------------------------
        # 1. Primary type+action classification.
        # ----------------------------------------------------------------
        if type_field == "Issue" and action_field == "create":
            if bot_or_agent:
                signal = "agent_authored_issue"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Linear event {event_id} Issue.create authored by "
                            f"agent (actorIsBot={actor_is_bot}, trigger={trigger!r}) "
                            f"on issue={issue_identifier or issue_id or 'unknown'} "
                            f"— surface for human review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "issue_create_user"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Linear event {event_id} Issue.create by user on "
                            f"issue={issue_identifier or issue_id or 'unknown'} "
                            f"— audit-trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "Issue" and action_field == "update":
            # Priority escalation by bot/agent.
            if (
                bot_or_agent
                and priority is not None
                and priority == 1
                and (previous_priority is None or previous_priority != 1)
            ):
                signal = "priority_escalation_by_bot"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Linear event {event_id} Issue.update bumped "
                            f"priority to Urgent (priority=1) by bot/agent on "
                            f"issue={issue_identifier or issue_id or 'unknown'} "
                            f"— verify warrant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            # State regression (started/completed → backlog).
            if (
                previous_state_type in self.regression_from_states
                and state_type in self.regression_to_states
            ):
                signal = "issue_state_regression"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Linear event {event_id} Issue.update regressed "
                            f"state from {previous_state_type!r} to "
                            f"{state_type!r} on issue="
                            f"{issue_identifier or issue_id or 'unknown'} — "
                            f"audit anomaly"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "Issue" and action_field == "remove":
            if state_type in self.in_progress_states:
                signal = "issue_remove_in_progress"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Linear event {event_id} Issue.remove of in-progress "
                            f"issue (stateType={state_type!r}) "
                            f"identifier={issue_identifier or issue_id or 'unknown'} "
                            f"— deleting started/completed work destroys audit trail"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "Issue" and action_field == "archive":
            signal = "issue_archive"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Linear event {event_id} Issue.archive on "
                        f"issue={issue_identifier or issue_id or 'unknown'} "
                        f"— audit-trail captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif type_field == "Comment" and action_field == "create":
            if bot_or_agent and priority is not None and priority in self.high_priority_levels:
                signal = "bot_comment_high_priority"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Linear event {event_id} Comment.create by bot/agent "
                            f"on high-priority (priority={priority}) "
                            f"issue={issue_identifier or issue_id or 'unknown'} "
                            f"— bot commentary on high-pri should be human-attributable"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "Comment" and action_field == "remove":
            signal = "comment_remove"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} Comment.remove on "
                        f"issue={issue_identifier or issue_id or 'unknown'} "
                        f"— comment deletion impacts audit completeness"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif type_field == "Project" and action_field == "update":
            if bot_or_agent and any(
                k in {"name", "description", "dueDate"} for k in changed_keys
            ):
                signal = "project_update_by_bot"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Linear event {event_id} Project.update by bot/agent "
                            f"changed keys={changed_keys!r} — verify warrant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "Project" and action_field == "archive":
            signal = "project_archive"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Linear event {event_id} Project.archive — "
                        f"audit-trail captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif type_field == "Team" and action_field == "update":
            if permission_changed or (old_permission and new_permission and old_permission != new_permission):
                signal = "team_permission_change"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Linear event {event_id} Team.update on "
                            f"team={team_key or team_id or 'unknown'} carries a "
                            f"permission change (old={old_permission!r}, "
                            f"new={new_permission!r}) — privilege event"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "Document" and action_field in {"create", "update", "remove"}:
            signal = "document_event"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Linear event {event_id} Document.{action_field} "
                        f"captured — content not stored, only structure"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif (
            type_field == "Attachment"
            and action_field == "create"
            and attachment_host
            and (
                not self.allowlist_attachment_hosts
                or attachment_host not in self.allowlist_attachment_hosts
            )
        ):
            signal = "external_attachment"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} Attachment.create with "
                        f"external host={attachment_host!r} not in allowlist "
                        f"{sorted(self.allowlist_attachment_hosts) or 'EMPTY'} "
                        f"— exfiltration surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Trigger-source signals (additive, may also fire alongside primary).
        # ----------------------------------------------------------------
        if trigger == "webhook":
            signal = "trigger_webhook"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} triggered by external webhook "
                        f"— verify provenance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif trigger == "automation":
            signal = "trigger_automation"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Linear event {event_id} triggered by automation — "
                        f"audit-trail expected"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Verbose-bot-output: long title from a bot.
        # ----------------------------------------------------------------
        if (
            type_field == "Issue"
            and bot_or_agent
            and title_length is not None
            and title_length > self.large_title_chars
        ):
            signal = "long_title_by_bot"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} Issue.{action_field} by "
                        f"bot/agent with title_length={title_length} > "
                        f"{self.large_title_chars} — verbose-bot-output anomaly"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Long description (any actor) — large content from agent surface.
        # ----------------------------------------------------------------
        if (
            type_field == "Issue"
            and description_length is not None
            and description_length > self.large_description_chars
        ):
            signal = "long_description"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} Issue.{action_field} carries "
                        f"description_length={description_length} > "
                        f"{self.large_description_chars} — what is in there?"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Bot-velocity / cross-team pattern markers (informational on
        # contributing events; the synthetic per-actor finding is added separately).
        # ----------------------------------------------------------------
        if actor_id and actor_id in bot_velocity_actors:
            signal = "bot_velocity_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} actor {actor_id} is part of a "
                        f"bot-velocity pattern ({bot_velocity_actors[actor_id]} "
                        f"Issue.creates > threshold {self.bot_velocity_threshold} "
                        f"in {self.bot_velocity_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bot_velocity_count": bot_velocity_actors[actor_id],
                        "bot_velocity_threshold": self.bot_velocity_threshold,
                        "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
                    },
                )
            )
        if actor_id and actor_id in cross_team_actors:
            signal = "cross_team_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} actor {actor_id} is part of a "
                        f"cross-team pattern ({len(cross_team_actors[actor_id])} "
                        f"teams > threshold {self.cross_team_threshold})"
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
        # 6. No-match fallback — surface unknown type+action so it is not silent.
        # ----------------------------------------------------------------
        if not control_results:
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Linear event {event_id} type={type_field!r} "
                        f"action={action_field!r} has no matching pattern — "
                        f"surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Linear audit log: type={type_field or 'unknown'} "
            f"action={action_field or 'unknown'} "
            f"actor={actor_id or 'unknown'} "
            f"actor_is_bot={actor_is_bot} trigger={trigger or 'none'} "
            f"issue={issue_identifier or issue_id or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"linear-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="linear_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=team_id or organization_id,
        )

    def _synthetic_bot_velocity_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-bot velocity pattern finding."""
        signal = "bot_velocity_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"linear-bot-velocity-{actor}"
        evidence: dict[str, Any] = {
            "linear_event_id": synthetic_id,
            "actor_id": actor,
            "actor_is_bot": True,
            "bot_velocity_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "linear",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Linear synthetic finding: bot {actor} created {count} issues "
                f"in a {self.bot_velocity_window_seconds}s window — exceeds "
                f"bot-velocity threshold {self.bot_velocity_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="linear_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Linear audit log: synthetic bot-velocity "
                f"pattern for bot={actor} count={count}>threshold="
                f"{self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_team_result(
        self,
        *,
        actor: str,
        teams: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-bot cross-team pattern finding."""
        signal = "cross_team_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"linear-cross-team-{actor}"
        evidence: dict[str, Any] = {
            "linear_event_id": synthetic_id,
            "actor_id": actor,
            "actor_is_bot": True,
            "cross_team_teams": teams,
            "cross_team_team_count": len(teams),
            "cross_team_threshold": self.cross_team_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "linear",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Linear synthetic finding: bot {actor} touched {len(teams)} "
                f"teams in this export ({', '.join(teams)}) — exceeds "
                f"cross-team threshold {self.cross_team_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="linear_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Linear audit log: synthetic cross-team pattern "
                f"for bot={actor} teams={len(teams)}>threshold="
                f"{self.cross_team_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
