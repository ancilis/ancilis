"""Slack audit-log importer — maps Slack ``audit/v1/logs`` actions to AKSI controls.

Slack is the #1 destination for agent output in enterprise: agents post status
updates, share files, summarize calls, mention users. Each agent message is a
potential exfiltration surface — sensitive data leaving the controlled
environment for a chat platform that often federates externally (Slack
Connect, shared channels, external user invites). Slack's ``audit/v1/logs``
endpoint emits a stream of high-fidelity actions: ``message_posted``,
``file_uploaded``, ``file_shared_externally``, ``channel_created``,
``user_invited_to_channel``, ``user_invited_to_workspace``,
``external_user_added``, ``dm_created``, ``user_logout``,
``files_acknowledged_dnsr`` (Data Native State Removal), and many more.

This importer ingests Slack audit-log exports in four on-disk shapes:

  1. ``{"entries": [...]}`` — the canonical Slack audit-log envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one entry per line
  4. single entry            — a bare object

Signal mapping (see shared/mappings/slack-aksi-controls.json):
  * ``action=message_posted`` & actor.type in {app,bot}                     → PR-04 PASS
  * ``action=message_posted`` to a ``channel.is_external_shared=true``     → PR-04 FLAG
  * ``action=message_posted`` to external channel with ``has_links=true``  → PR-04 FAIL
  * ``action=file_uploaded`` by app/bot                                    → PR-04 FLAG
  * ``action=file_shared_externally``                                      → DE-01 FAIL  (top priority)
  * ``action=external_user_added``                                         → PR-02 FLAG
  * ``action=channel_created`` & ``is_external_shared=true``               → PR-02 FLAG
  * ``action=user_invited_to_channel``                                     → PR-05 PASS  (audit trail)
  * ``action=dm_created`` & actor in {app,bot}                             → PR-04 FLAG  (social-engineering surface)
  * ``action=user_logout``                                                 → PR-05 PASS
  * ``action=files_acknowledged_dnsr``                                     → PR-04 PASS  (compliance event)
  * actor.type in {app,bot} acting on ``entity.user`` (other than self)    → PR-02 FLAG  (privilege check)
  * cross-channel pattern: same bot actor posting to ≥ N channels          → PR-02 FLAG synthetic
  * cross-workspace pattern: same actor across multiple location.id values → PR-02 FLAG synthetic

Sanitization (security-critical — Slack audit entries can contain message
text, file names, recipient channel names, and full IPs):

  * ``actor.user.email`` is reduced to its DOMAIN ONLY (``alice@corp.example.com``
    → ``"@corp.example.com"``). The local-part is sensitive (it identifies a
    person); the domain is a workspace-correlation key.
  * ``context.user_agent`` is truncated to first 80 chars + a sha256 of the
    full string. Full UAs can carry version-leak and tracking data.
  * ``entity.message.text`` is NEVER stored. The leak channel can BE the
    message text. Only ``text_length`` and ``has_links`` are surfaced.
  * ``entity.file.name`` is NEVER stored. File names can carry confidential
    project codenames or PII (e.g. ``acme-acquisition-q3.pdf``). Only
    ``filetype``, ``size``, and ``is_external`` are captured.
  * ``context.ip_address`` is masked to /16 (CloudTrail-style): RFC1918
    private addresses preserved verbatim, public IPv4 reduced to
    ``A.B.0.0/16``, public IPv6 reduced to first-32-bits ``::/32``.
  * ``entity.file.size`` is stored verbatim — it's a useful posture metric
    (10MB ZIP shared externally is a different signal than a 1KB log line).
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``slack-sdk``; Slack audit JSON exports are parsed
with the standard library only.
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


# Mapping table lives at <repo>/shared/mappings/slack-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/slack.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "slack-aksi-controls.json"
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

_DEFAULT_CROSS_CHANNEL_THRESHOLD = 10

# Built-in fallback action patterns (mirror shared/mappings/slack-aksi-controls.json).
_DEFAULT_ACTION_PATTERNS: tuple[dict[str, Any], ...] = (
    {"action": "message_posted", "actor_type": "app",
     "signal": "agent_message_posted", "result": "PASS", "control": "PR-04"},
    {"action": "message_posted", "actor_type": "bot",
     "signal": "agent_message_posted", "result": "PASS", "control": "PR-04"},
    {"action": "file_uploaded", "actor_type": "app",
     "signal": "agent_file_uploaded", "result": "FLAG", "control": "PR-04"},
    {"action": "file_uploaded", "actor_type": "bot",
     "signal": "agent_file_uploaded", "result": "FLAG", "control": "PR-04"},
    {"action": "file_shared_externally", "actor_type": "*",
     "signal": "file_shared_externally", "result": "FAIL", "control": "DE-01"},
    {"action": "external_user_added", "actor_type": "*",
     "signal": "external_user_added", "result": "FLAG", "control": "PR-02"},
    {"action": "channel_created", "actor_type": "*",
     "signal": "channel_created", "result": "PASS", "control": "PR-05"},
    {"action": "user_invited_to_channel", "actor_type": "*",
     "signal": "user_invited_to_channel", "result": "PASS", "control": "PR-05"},
    {"action": "user_invited_to_workspace", "actor_type": "*",
     "signal": "user_invited_to_workspace", "result": "PASS", "control": "PR-05"},
    {"action": "dm_created", "actor_type": "app",
     "signal": "agent_dm_created", "result": "FLAG", "control": "PR-04"},
    {"action": "dm_created", "actor_type": "bot",
     "signal": "agent_dm_created", "result": "FLAG", "control": "PR-04"},
    {"action": "user_logout", "actor_type": "*",
     "signal": "user_logout", "result": "PASS", "control": "PR-05"},
    {"action": "files_acknowledged_dnsr", "actor_type": "*",
     "signal": "dnsr_acknowledged", "result": "PASS", "control": "PR-04"},
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the slack-aksi-controls.json mapping; tolerate missing file."""
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
    """Reduce ``alice@corp.example.com`` → ``"@corp.example.com"``.

    The local-part is sensitive (it identifies a person). The domain is a
    workspace-correlation key — useful for posture without leaking identity.
    Returns ``None`` for falsy / non-string / no-``@`` inputs.
    """
    if not email or not isinstance(email, str):
        return None
    e = email.strip()
    if not e or "@" not in e:
        return None
    domain = e.rsplit("@", 1)[1].strip()
    if not domain:
        return None
    return f"@{domain}"


def _truncate_user_agent(ua: str | None) -> dict[str, Any] | None:
    """Truncate a user-agent to first 80 chars + sha256 of the full value.

    Full UAs leak version detail and tracking data; the first 80 chars are
    enough to characterise the client family, and the sha256 lets analysts
    correlate identical UAs without storing the full string.
    """
    if not ua or not isinstance(ua, str):
        return None
    s = ua.strip()
    if not s:
        return None
    truncated = s[:80]
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return {"prefix": truncated, "sha256": digest}


def _classify_ip(ip_value: str | None) -> str | None:
    """Mask an IP to a /16 (CloudTrail-style).

    * RFC1918 / loopback / link-local preserved verbatim (already non-routable).
    * Public IPv4 → ``A.B.0.0/16``.
    * Public IPv6 → first-32-bits + ``::/32``.
    * Hostnames / unparsable values preserved verbatim (no IP to mask).
    """
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


def _matches_action_pattern(
    action: str, actor_type: str, pattern: dict[str, Any]
) -> bool:
    act_pat = str(pattern.get("action", ""))
    actor_pat = str(pattern.get("actor_type", "*"))
    return (
        fnmatch.fnmatchcase(action, act_pat)
        and fnmatch.fnmatchcase(actor_type, actor_pat)
    )


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SlackImporter:
    """Parse a Slack audit-log export and convert each entry to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_channel_threshold: int | None = None,
        agent_actor_types: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Action patterns precedence: mapping table > built-in defaults.
        meta_patterns = meta.get("action_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._action_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._action_patterns = _DEFAULT_ACTION_PATTERNS
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
        # Cross-channel threshold precedence: explicit arg > mapping metadata > default.
        if cross_channel_threshold is not None:
            self.cross_channel_threshold = int(cross_channel_threshold)
        else:
            self.cross_channel_threshold = int(
                meta.get("cross_channel_threshold", _DEFAULT_CROSS_CHANNEL_THRESHOLD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Slack audit-log file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return self._build_results(entries, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Slack audit-log content from a JSON or JSONL string."""
        entries = self._entries_from_text(content)
        return self._build_results(entries, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"entries":[...]}`` / ``{"data":[...]}`` / JSONL / single."""
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
                if "entries" in doc and isinstance(doc["entries"], list):
                    return [e for e in doc["entries"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single entry.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        entries: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-entry EvaluationResults plus cross-channel/-workspace synthetic findings."""
        # First pass: aggregate channels per (bot) actor + workspaces per actor.
        actor_channels: dict[str, set[str]] = {}
        actor_workspaces: dict[str, set[str]] = {}
        for entry in entries:
            actor = entry.get("actor") or {}
            if not isinstance(actor, dict):
                continue
            actor_type = str(actor.get("type") or "").lower()
            user = actor.get("user") or {}
            if not isinstance(user, dict):
                user = {}
            actor_user_id = user.get("id")
            if not isinstance(actor_user_id, str) or not actor_user_id:
                continue
            entity = entry.get("entity") or {}
            if not isinstance(entity, dict):
                entity = {}
            channel = entity.get("channel") or {}
            if isinstance(channel, dict):
                channel_id = channel.get("id")
                action = str(entry.get("action") or "")
                # Only count message_posted by an agent actor for cross-channel.
                if (
                    actor_type in self.agent_actor_types
                    and action == "message_posted"
                    and isinstance(channel_id, str)
                    and channel_id
                ):
                    actor_channels.setdefault(actor_user_id, set()).add(channel_id)
            ctx = entry.get("context") or {}
            if isinstance(ctx, dict):
                loc = ctx.get("location") or {}
                if isinstance(loc, dict):
                    loc_id = loc.get("id")
                    if isinstance(loc_id, str) and loc_id:
                        actor_workspaces.setdefault(actor_user_id, set()).add(loc_id)

        cross_channel_actors = {
            actor_id: sorted(channels)
            for actor_id, channels in actor_channels.items()
            if len(channels) >= self.cross_channel_threshold
        }
        cross_workspace_actors = {
            actor_id: sorted(workspaces)
            for actor_id, workspaces in actor_workspaces.items()
            if len(workspaces) > 1
        }

        results = [
            self._parse_entry(
                entry,
                file_sha256=file_sha256,
                cross_channel_actors=cross_channel_actors,
                cross_workspace_actors=cross_workspace_actors,
            )
            for entry in entries
        ]

        for actor_id, channels in sorted(cross_channel_actors.items()):
            results.append(
                self._synthetic_cross_channel_result(
                    actor_user_id=actor_id,
                    channels=channels,
                    file_sha256=file_sha256,
                )
            )
        for actor_id, workspaces in sorted(cross_workspace_actors.items()):
            results.append(
                self._synthetic_cross_workspace_result(
                    actor_user_id=actor_id,
                    workspaces=workspaces,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        entry_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "slack_audit",
            "source_tool_name": "slack",
            "source_tool_version": "",
        }
        if entry_id is not None:
            provenance["entry_id"] = entry_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_action(
        self, action: str, actor_type: str
    ) -> dict[str, Any] | None:
        """Find the first action-pattern that matches; ``None`` if no match."""
        for pattern in self._action_patterns:
            if _matches_action_pattern(action, actor_type, pattern):
                return pattern
        return None

    # ------------------------------------------------------------------
    # Per-entry parsing
    # ------------------------------------------------------------------

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_channel_actors: dict[str, list[str]],
        cross_workspace_actors: dict[str, list[str]],
    ) -> EvaluationResult:
        entry_id = str(entry.get("id") or uuid.uuid4())
        action = str(entry.get("action") or "").strip()
        date_create = entry.get("date_create")
        if isinstance(date_create, (int, float)) and date_create > 0:
            try:
                event_time = datetime.fromtimestamp(
                    float(date_create), tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError, OverflowError):
                event_time = datetime.now(timezone.utc).isoformat()
        else:
            event_time = datetime.now(timezone.utc).isoformat()

        # ---- actor (sanitized) ----
        actor = entry.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        actor_type = str(actor.get("type") or "").strip().lower()
        actor_user = actor.get("user") or {}
        if not isinstance(actor_user, dict):
            actor_user = {}
        actor_user_id = (
            str(actor_user.get("id"))
            if isinstance(actor_user.get("id"), str)
            else None
        )
        actor_user_name = (
            str(actor_user.get("name"))
            if isinstance(actor_user.get("name"), str)
            else None
        )
        actor_email_domain = _email_domain_only(actor_user.get("email"))

        # ---- entity (sanitized) ----
        entity = entry.get("entity") or {}
        if not isinstance(entity, dict):
            entity = {}
        entity_type = str(entity.get("type") or "").strip().lower()
        channel = entity.get("channel") or {}
        if not isinstance(channel, dict):
            channel = {}
        channel_id = (
            str(channel.get("id"))
            if isinstance(channel.get("id"), str)
            else None
        )
        # NOTE: channel name is NOT sensitive in the same way as message text or
        # file name (it's already widely visible to all members); keep for
        # posture analysis but mark intent explicitly.
        channel_name = (
            str(channel.get("name"))
            if isinstance(channel.get("name"), str)
            else None
        )
        channel_is_private = (
            bool(channel.get("is_private"))
            if isinstance(channel.get("is_private"), bool)
            else None
        )
        channel_is_external_shared = (
            bool(channel.get("is_external_shared"))
            if isinstance(channel.get("is_external_shared"), bool)
            else None
        )

        # File entity (file.name NEVER captured).
        file_obj = entity.get("file") or {}
        if not isinstance(file_obj, dict):
            file_obj = {}
        file_id = (
            str(file_obj.get("id"))
            if isinstance(file_obj.get("id"), str)
            else None
        )
        file_filetype = (
            str(file_obj.get("filetype"))
            if isinstance(file_obj.get("filetype"), str)
            else None
        )
        try:
            file_size_raw = file_obj.get("size")
            file_size = int(file_size_raw) if file_size_raw is not None else None
        except (TypeError, ValueError):
            file_size = None
        file_is_external = (
            bool(file_obj.get("is_external"))
            if isinstance(file_obj.get("is_external"), bool)
            else None
        )

        # Message entity (message.text NEVER captured).
        message_obj = entity.get("message") or {}
        if not isinstance(message_obj, dict):
            message_obj = {}
        try:
            text_length_raw = message_obj.get("text_length")
            message_text_length = (
                int(text_length_raw) if text_length_raw is not None else None
            )
        except (TypeError, ValueError):
            message_text_length = None
        message_has_links = (
            bool(message_obj.get("has_links"))
            if isinstance(message_obj.get("has_links"), bool)
            else None
        )

        # User-entity (target user — used for "bot acting on user" check).
        target_user = entity.get("user") or {}
        if not isinstance(target_user, dict):
            target_user = {}
        target_user_id = (
            str(target_user.get("id"))
            if isinstance(target_user.get("id"), str)
            else None
        )

        # ---- context (sanitized) ----
        ctx = entry.get("context") or {}
        if not isinstance(ctx, dict):
            ctx = {}
        location = ctx.get("location") or {}
        if not isinstance(location, dict):
            location = {}
        location_id = (
            str(location.get("id"))
            if isinstance(location.get("id"), str)
            else None
        )
        location_domain = (
            str(location.get("domain"))
            if isinstance(location.get("domain"), str)
            else None
        )
        ip_redacted = _classify_ip(ctx.get("ip_address"))
        ua_redacted = _truncate_user_agent(ctx.get("ua"))

        common_evidence: dict[str, Any] = {
            "slack_entry_id": entry_id,
            "action": action,
            "event_time": event_time,
            "actor_type": actor_type,
            "actor_user_id": actor_user_id,
            "actor_user_name": actor_user_name,
            "actor_email_domain": actor_email_domain,
            "entity_type": entity_type,
            "channel_id": channel_id,
            "channel_name": channel_name,
            "channel_is_private": channel_is_private,
            "channel_is_external_shared": channel_is_external_shared,
            "file_id": file_id,
            "file_filetype": file_filetype,
            "file_size": file_size,
            "file_is_external": file_is_external,
            "message_text_length": message_text_length,
            "message_has_links": message_has_links,
            "target_user_id": target_user_id,
            "location_id": location_id,
            "location_domain": location_domain,
            "ip_redacted": ip_redacted,
            "user_agent_redacted": ua_redacted,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, entry_id=entry_id
            ),
            "source_tool": "slack",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Action classification (primary signal).
        # Specialised composite signals take precedence over the generic
        # action-pattern table. Order: file_shared_externally → message
        # to external channel (with optional links) → channel created
        # external → action pattern.
        # ----------------------------------------------------------------
        composite_signal: str | None = None
        if action == "message_posted" and channel_is_external_shared is True:
            if message_has_links is True:
                composite_signal = "agent_message_external_with_links"
                signal = composite_signal
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Slack entry {entry_id}: message posted with links to "
                            f"external-shared channel {channel_id} — agent leaking "
                            f"links externally"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                composite_signal = "agent_message_external"
                signal = composite_signal
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Slack entry {entry_id}: message posted to "
                            f"external-shared channel {channel_id} — exfiltration "
                            f"surface"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif action == "channel_created" and channel_is_external_shared is True:
            composite_signal = "external_channel_created"
            signal = composite_signal
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Slack entry {entry_id}: external-shared channel "
                        f"{channel_id} created — new external connection"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        if composite_signal is None:
            pattern = self._classify_action(action, actor_type)
            if pattern is not None:
                signal = str(pattern.get("signal", "unknown_action"))
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
                            f"Slack entry {entry_id}: action={action} "
                            f"actor.type={actor_type or 'unknown'} "
                            f"classified as {signal} ({result})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Unknown action — surface as PR-05 FLAG so it doesn't silently pass.
                # Slack adds new audit-log actions regularly; mapping covers the
                # high-signal subset.
                signal = "unknown_action"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Slack entry {entry_id}: action={action!r} "
                            f"actor.type={actor_type or 'unknown'} has no matching "
                            f"pattern — surfaced for review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 2. Bot acting on a user entity (privilege check).
        # An app/bot taking action whose ENTITY is a user (other than the bot's
        # own user) is a privilege check — could be impersonation, scope
        # violation, or hostile DM scaffolding.
        # ----------------------------------------------------------------
        if (
            actor_type in self.agent_actor_types
            and entity_type == "user"
            and target_user_id
            and target_user_id != actor_user_id
        ):
            signal = "bot_targeting_user"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Slack entry {entry_id}: {actor_type} actor "
                        f"{actor_user_id} acted on user {target_user_id} "
                        f"(action={action}) — privilege check"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Cross-channel pattern marker (per-entry).
        # The synthetic per-actor finding is added separately in the second pass.
        # ----------------------------------------------------------------
        if actor_user_id and actor_user_id in cross_channel_actors:
            signal = "cross_channel_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Slack entry {entry_id}: actor {actor_user_id} part of "
                        f"cross-channel pattern "
                        f"({len(cross_channel_actors[actor_user_id])} channels >= "
                        f"threshold {self.cross_channel_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_channel_channels": cross_channel_actors[
                            actor_user_id
                        ],
                        "cross_channel_threshold": self.cross_channel_threshold,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 4. Cross-workspace pattern marker (per-entry).
        # ----------------------------------------------------------------
        if actor_user_id and actor_user_id in cross_workspace_actors:
            signal = "cross_workspace_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Slack entry {entry_id}: actor {actor_user_id} part of "
                        f"cross-workspace pattern "
                        f"({len(cross_workspace_actors[actor_user_id])} workspaces)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_workspace_locations": cross_workspace_actors[
                            actor_user_id
                        ],
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
            f"Imported from Slack audit log: action={action} "
            f"actor.type={actor_type or 'unknown'} "
            f"entity.type={entity_type or 'unknown'} "
            f"channel.is_external_shared={channel_is_external_shared} "
            f"workspace={location_domain or location_id or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"slack-{entry_id[:32]}",
            timestamp=event_time,
            agent_id=self.agent_id,
            source_type="slack_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=location_id or None,
        )

    def _synthetic_cross_channel_result(
        self,
        *,
        actor_user_id: str,
        channels: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor cross-channel pattern finding (bot spreading)."""
        signal = "cross_channel_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"slack-cross-channel-{actor_user_id}"
        evidence: dict[str, Any] = {
            "slack_entry_id": synthetic_id,
            "actor_user_id": actor_user_id,
            "cross_channel_channels": channels,
            "cross_channel_channel_count": len(channels),
            "cross_channel_threshold": self.cross_channel_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                entry_id=synthetic_id,
            ),
            "source_tool": "slack",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Slack synthetic finding: actor {actor_user_id} posted to "
                f"{len(channels)} channels in this export — meets/exceeds "
                f"cross-channel threshold {self.cross_channel_threshold} "
                f"(bot spreading)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="slack_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Slack audit log: synthetic cross-channel pattern "
                f"actor={actor_user_id} channels={len(channels)}>=threshold="
                f"{self.cross_channel_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_workspace_result(
        self,
        *,
        actor_user_id: str,
        workspaces: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor cross-workspace pattern finding."""
        signal = "cross_workspace_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"slack-cross-workspace-{actor_user_id}"
        evidence: dict[str, Any] = {
            "slack_entry_id": synthetic_id,
            "actor_user_id": actor_user_id,
            "cross_workspace_locations": workspaces,
            "cross_workspace_location_count": len(workspaces),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                entry_id=synthetic_id,
            ),
            "source_tool": "slack",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Slack synthetic finding: actor {actor_user_id} active in "
                f"{len(workspaces)} workspaces "
                f"({', '.join(workspaces)}) — cross-workspace pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="slack_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Slack audit log: synthetic cross-workspace pattern "
                f"actor={actor_user_id} workspaces={len(workspaces)}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
