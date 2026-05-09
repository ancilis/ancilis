"""Discord audit-log importer — maps ``/guilds/{guild.id}/audit-logs`` entries
to AKSI controls.

Discord is the dominant chat platform for developer / community use cases —
a distinct demographic from the Slack / Microsoft Teams (corporate)
collaboration surfaces. Servers (guilds) range from small private groups to
public communities with hundreds of thousands of members. AI bots
(custom-built, ChatGPT bot extensions, Discord's native Clyde AI) are first-
class citizens of the platform: they post messages, moderate channels,
delete content, route members, and accept slash commands. The
``/guilds/{guild.id}/audit-logs`` endpoint emits a stream of integer
``action_type`` codes (1..212+) that capture every privileged operation in
the guild — guild config changes, channel CRUD, role grants, bans/kicks,
prunes, invite creation, webhook lifecycle, integration installs,
AutoModeration rule + action events, and Clyde-AI lifecycle events.

This importer ingests Discord audit-log exports in four on-disk shapes:

  1. ``{"audit_log_entries":[...]}`` — the canonical Discord envelope
  2. ``{"data":[...]}``                — generic data envelope
  3. ``{"events":[...]}``              — alternate envelope used by exporters
  4. JSONL                              — one entry per line

Signal mapping (see shared/mappings/discord-aksi-controls.json):
  * action_type=22 (MEMBER_BAN_ADD)                           → PR-05 PASS
  * action_type=20 (MEMBER_KICK) by bot                       → PR-02 FAIL
  * action_type=21 (MEMBER_PRUNE) members_removed > N         → PR-02 FAIL
  * action_type=25 (MEMBER_ROLE_UPDATE) granting privileged   → PR-02 FAIL
  * action_type=28 (BOT_ADD)                                  → PR-01 FLAG
  * action_type=14 (CHANNEL_OVERWRITE_CREATE) for @everyone   → PR-02 FLAG
  * action_type=12 (CHANNEL_DELETE)                           → PR-02 FLAG
  * action_type=42 (INVITE_DELETE)                            → PR-05 PASS
  * action_type=40 (INVITE_CREATE) max_uses=0                 → PR-04 FLAG
  * action_type=50 (WEBHOOK_CREATE)                           → PR-01 FLAG
  * action_type=51 (WEBHOOK_UPDATE) changing url              → PR-04 FLAG
  * action_type=72 (MESSAGE_DELETE) by bot/automod            → PR-05 FLAG
  * action_type=73 (MESSAGE_BULK_DELETE) count > N            → PR-02 FAIL
  * action_type=80 (INTEGRATION_CREATE)                       → PR-01 FLAG
  * action_type=140-142 (AUTOMOD_RULE_*)                      → captured (PASS/FLAG)
  * action_type=143-144 (AUTOMOD_BLOCK / FLAG)                → PR-05 PASS
  * action_type=145 (AUTOMOD_USER_TIMEOUT)                    → PR-05 PASS
  * action_type=146 (AUTOMOD_QUARANTINE)                      → PR-04 PASS
  * action_type=200/201/202 (CLYDE_AI_*)                      → captured (PASS)
  * action_type=120 (APPLICATION_COMMAND_PERMISSION_UPDATE)   → PR-05 PASS
  * Bot-action-burst: same bot user_id with > N actions in a 1h window
    (default 50)                                              → PR-02 FLAG synthetic
  * Mass-message-delete: same actor with > N MESSAGE_DELETE
    in a 1h window (default 200)                              → PR-04 FLAG synthetic

Sanitization (security-critical — Discord audit entries can contain reasons,
role names, and changes[] payloads with old + new values that often encode
PII / IR-narrative / org structure):

  * ``user_id`` and ``target_id`` are pseudonymous Discord snowflakes; we
    capture them VERBATIM (they're stable correlation keys but reveal no
    direct identity without resolution against the guild member list).
  * ``changes[].new_value`` and ``changes[].old_value`` are NEVER stored.
    We emit only the LIST of change KEYS (e.g. ``["name", "topic"]``) so
    posture analysis can see what kind of mutation happened without
    leaking the values themselves.
  * ``reason`` (free-form text supplied by the actor) is captured as
    ``{"length": N, "sha256": "..."}`` — long enough to spot redaction
    failures, hashed so identical reasons correlate across entries.
  * ``options.role_name`` (used by MEMBER_ROLE_UPDATE / role-targeted
    overwrites) is captured as ``{"length": N, "sha256": "..."}`` — role
    names frequently encode organisational structure ("Engineering Lead",
    "Founders Circle") that we don't want to write to the evidence store
    verbatim, but the hash is still useful for correlation.
  * ``options.count`` and ``options.members_removed`` ARE captured —
    they're the primary mass-action signal (bulk delete count, prune size).
  * ``options.delete_member_days`` is captured — it's the prune horizon.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``discord.py``; Discord audit JSON exports are
parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/discord-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/discord.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "discord-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_BOT_ACTION_BURST_THRESHOLD = 50
_DEFAULT_BOT_ACTION_BURST_WINDOW_SECONDS = 3600
_DEFAULT_MASS_MESSAGE_DELETE_THRESHOLD = 200
_DEFAULT_MASS_MESSAGE_DELETE_WINDOW_SECONDS = 3600
_DEFAULT_MASS_PRUNE_THRESHOLD = 50
_DEFAULT_MASS_BULK_DELETE_THRESHOLD = 100

_DEFAULT_PRIVILEGED_ROLE_PATTERNS: tuple[str, ...] = (
    "*admin*",
    "*Admin*",
    "*ADMIN*",
    "*moderator*",
    "*Moderator*",
    "*MOD*",
    "*Mod*",
    "*owner*",
    "*Owner*",
    "*staff*",
    "*Staff*",
    "*manage*",
    "*Manage*",
)

# Built-in fallback action_type → signal/result/control mapping
# (mirrors shared/mappings/discord-aksi-controls.json).
_DEFAULT_ACTION_PATTERNS: tuple[dict[str, Any], ...] = (
    {"action_type": 22, "actor_kind": "*",
     "signal": "member_ban_add", "result": "PASS", "control": "PR-05"},
    {"action_type": 23, "actor_kind": "*",
     "signal": "member_ban_remove", "result": "PASS", "control": "PR-05"},
    {"action_type": 20, "actor_kind": "user",
     "signal": "member_kick", "result": "PASS", "control": "PR-05"},
    {"action_type": 20, "actor_kind": "bot",
     "signal": "bot_member_kick", "result": "FAIL", "control": "PR-02"},
    {"action_type": 28, "actor_kind": "*",
     "signal": "bot_add", "result": "FLAG", "control": "PR-01"},
    {"action_type": 12, "actor_kind": "*",
     "signal": "channel_delete", "result": "FLAG", "control": "PR-02"},
    {"action_type": 42, "actor_kind": "*",
     "signal": "invite_delete", "result": "PASS", "control": "PR-05"},
    {"action_type": 50, "actor_kind": "*",
     "signal": "webhook_create", "result": "FLAG", "control": "PR-01"},
    {"action_type": 52, "actor_kind": "*",
     "signal": "webhook_delete", "result": "PASS", "control": "PR-05"},
    {"action_type": 80, "actor_kind": "*",
     "signal": "integration_create", "result": "FLAG", "control": "PR-01"},
    {"action_type": 82, "actor_kind": "*",
     "signal": "integration_delete", "result": "PASS", "control": "PR-05"},
    {"action_type": 140, "actor_kind": "*",
     "signal": "automod_rule_create", "result": "PASS", "control": "PR-05"},
    {"action_type": 141, "actor_kind": "*",
     "signal": "automod_rule_update", "result": "PASS", "control": "PR-05"},
    {"action_type": 142, "actor_kind": "*",
     "signal": "automod_rule_delete", "result": "FLAG", "control": "PR-02"},
    {"action_type": 143, "actor_kind": "*",
     "signal": "automod_block_message", "result": "PASS", "control": "PR-05"},
    {"action_type": 144, "actor_kind": "*",
     "signal": "automod_flag_to_channel", "result": "PASS", "control": "PR-05"},
    {"action_type": 145, "actor_kind": "*",
     "signal": "automod_user_timeout", "result": "PASS", "control": "PR-05"},
    {"action_type": 146, "actor_kind": "*",
     "signal": "automod_quarantine_user", "result": "PASS", "control": "PR-04"},
    {"action_type": 120, "actor_kind": "*",
     "signal": "application_command_permission_update",
     "result": "PASS", "control": "PR-05"},
    {"action_type": 200, "actor_kind": "*",
     "signal": "clyde_ai_profile_update", "result": "PASS", "control": "PR-05"},
    {"action_type": 201, "actor_kind": "*",
     "signal": "clyde_ai_enabled", "result": "PASS", "control": "PR-05"},
    {"action_type": 202, "actor_kind": "*",
     "signal": "clyde_ai_disabled", "result": "PASS", "control": "PR-05"},
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load discord-aksi-controls.json; tolerate missing file."""
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


def _hash_redact(value: str | None) -> dict[str, Any] | None:
    """Reduce a free-form string to ``{length, sha256}`` for posture-only use.

    Used for ``reason`` (often a paragraph of moderator narrative) and
    ``options.role_name`` (frequently encodes organisational structure such
    as "Engineering Lead" or "Founders Circle"). Returns ``None`` for
    falsy / non-string / empty inputs.
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return {"length": len(s), "sha256": digest}


def _change_keys(changes: Any) -> list[str]:
    """Extract only the ``key`` names from a Discord ``changes`` array.

    Discord's ``changes`` array is the most sensitive field in an audit
    entry — each element carries ``{key, old_value, new_value}`` where the
    values are the actual data being mutated (channel topics, role names,
    permission bitfields, etc.). We capture only the LIST OF KEYS so
    posture analysis can answer "did anyone mutate field X?" without ever
    storing X's value.
    """
    if not isinstance(changes, list):
        return []
    keys: list[str] = []
    for ch in changes:
        if not isinstance(ch, dict):
            continue
        k = ch.get("key")
        if isinstance(k, str) and k:
            keys.append(k)
    return keys


def _matches_action_pattern(
    action_type: int, actor_kind: str, pattern: dict[str, Any]
) -> bool:
    pat_type = pattern.get("action_type")
    if pat_type is None:
        return False
    try:
        if int(pat_type) != int(action_type):
            return False
    except (TypeError, ValueError):
        return False
    actor_pat = str(pattern.get("actor_kind", "*"))
    return fnmatch.fnmatchcase(actor_kind, actor_pat)


def _parse_iso8601(value: Any) -> datetime | None:
    """Parse ISO-8601 (Discord uses RFC-3339); tolerate ``Z`` suffix."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class DiscordImporter:
    """Parse a Discord audit-log export and convert each entry to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        bot_action_burst_threshold: int | None = None,
        bot_action_burst_window_seconds: int | None = None,
        mass_message_delete_threshold: int | None = None,
        mass_message_delete_window_seconds: int | None = None,
        mass_prune_threshold: int | None = None,
        mass_bulk_delete_threshold: int | None = None,
        privileged_role_patterns: Iterable[str] | None = None,
        bot_user_ids: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # action_type → human-readable name (e.g. 22 → "MEMBER_BAN_ADD").
        names_meta = meta.get("action_type_names")
        if isinstance(names_meta, dict) and names_meta:
            self._action_type_names: dict[int, str] = {}
            for k, v in names_meta.items():
                try:
                    self._action_type_names[int(k)] = str(v)
                except (TypeError, ValueError):
                    continue
        else:
            self._action_type_names = {}
        # Action patterns precedence: mapping table > built-in defaults.
        meta_patterns = meta.get("action_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._action_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._action_patterns = _DEFAULT_ACTION_PATTERNS
        # Privileged role patterns (fnmatch, used against changes[].new_value
        # when classification rolls up to ``options.role_name`` we capture
        # via hash; the raw new_value flows through here only for live
        # privilege-grant detection during this single parse pass and is
        # NEVER stored as evidence).
        if privileged_role_patterns is not None:
            self.privileged_role_patterns: tuple[str, ...] = tuple(
                str(p) for p in privileged_role_patterns
            )
        else:
            meta_priv = meta.get("privileged_role_patterns")
            if isinstance(meta_priv, list) and meta_priv:
                self.privileged_role_patterns = tuple(str(p) for p in meta_priv)
            else:
                self.privileged_role_patterns = _DEFAULT_PRIVILEGED_ROLE_PATTERNS
        # Threshold precedence: explicit arg > mapping metadata > default.
        self.bot_action_burst_threshold = self._resolve_int(
            bot_action_burst_threshold,
            meta.get("bot_action_burst_threshold"),
            _DEFAULT_BOT_ACTION_BURST_THRESHOLD,
        )
        self.bot_action_burst_window_seconds = self._resolve_int(
            bot_action_burst_window_seconds,
            meta.get("bot_action_burst_window_seconds"),
            _DEFAULT_BOT_ACTION_BURST_WINDOW_SECONDS,
        )
        self.mass_message_delete_threshold = self._resolve_int(
            mass_message_delete_threshold,
            meta.get("mass_message_delete_threshold"),
            _DEFAULT_MASS_MESSAGE_DELETE_THRESHOLD,
        )
        self.mass_message_delete_window_seconds = self._resolve_int(
            mass_message_delete_window_seconds,
            meta.get("mass_message_delete_window_seconds"),
            _DEFAULT_MASS_MESSAGE_DELETE_WINDOW_SECONDS,
        )
        self.mass_prune_threshold = self._resolve_int(
            mass_prune_threshold,
            meta.get("mass_prune_threshold"),
            _DEFAULT_MASS_PRUNE_THRESHOLD,
        )
        self.mass_bulk_delete_threshold = self._resolve_int(
            mass_bulk_delete_threshold,
            meta.get("mass_bulk_delete_threshold"),
            _DEFAULT_MASS_BULK_DELETE_THRESHOLD,
        )
        # Optional explicit set of bot user_ids — when provided, the
        # importer treats matching ``user_id`` values as bot actors even
        # if no ``actor_kind`` field is present in the entry.
        if bot_user_ids is not None:
            self.bot_user_ids: frozenset[str] = frozenset(
                str(uid) for uid in bot_user_ids
            )
        else:
            self.bot_user_ids = frozenset()

    @staticmethod
    def _resolve_int(
        explicit: int | None, meta_value: Any, default: int
    ) -> int:
        if explicit is not None:
            return int(explicit)
        if meta_value is not None:
            try:
                return int(meta_value)
            except (TypeError, ValueError):
                return default
        return default

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Discord audit-log file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return self._build_results(entries, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Discord audit-log content from a JSON or JSONL string."""
        entries = self._entries_from_text(content)
        return self._build_results(entries, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"audit_log_entries":[...]}`` / ``{"data":[...]}``
        / ``{"events":[...]}`` / JSONL / single."""
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
                if (
                    "audit_log_entries" in doc
                    and isinstance(doc["audit_log_entries"], list)
                ):
                    return [
                        e for e in doc["audit_log_entries"]
                        if isinstance(e, dict)
                    ]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                if "events" in doc and isinstance(doc["events"], list):
                    return [e for e in doc["events"] if isinstance(e, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _is_bot_actor(self, entry: dict[str, Any]) -> bool:
        """Best-effort actor-kind detection.

        Discord's audit-log API does NOT include an ``actor_type`` field;
        the actor is identified only by ``user_id``. To detect bot actors
        the importer relies on (in priority order):

          1. ``user.bot=true`` if the entry embeds the actor user object
          2. explicit ``actor_kind`` (used by ancilis-internal exports)
          3. importer-supplied ``bot_user_ids`` set
          4. ``options.automod_rule_trigger_type`` present (AutoMod actions
             are emitted with ``user_id`` set to the bot owning the rule)
        """
        actor_kind = entry.get("actor_kind")
        if isinstance(actor_kind, str) and actor_kind.lower() == "bot":
            return True
        user = entry.get("user")
        if isinstance(user, dict) and user.get("bot") is True:
            return True
        user_id = entry.get("user_id")
        if isinstance(user_id, str) and user_id and user_id in self.bot_user_ids:
            return True
        opts = entry.get("options")
        return (
            isinstance(opts, dict)
            and opts.get("automod_rule_trigger_type") is not None
        )

    def _build_results(
        self,
        entries: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-entry EvaluationResults plus burst / mass-delete syntheses."""
        # First pass: aggregate per-actor action timestamps for burst
        # detection (any action_type) and per-actor MESSAGE_DELETE
        # timestamps for mass-message-delete pattern detection.
        actor_actions: dict[str, list[datetime]] = defaultdict(list)
        actor_msg_deletes: dict[str, list[datetime]] = defaultdict(list)
        actor_is_bot: dict[str, bool] = {}
        for entry in entries:
            user_id = entry.get("user_id")
            if not isinstance(user_id, str) or not user_id:
                continue
            ts = _parse_iso8601(entry.get("created_at"))
            if ts is None:
                continue
            try:
                action_type = int(entry.get("action_type"))
            except (TypeError, ValueError):
                continue
            is_bot = self._is_bot_actor(entry)
            if is_bot:
                actor_actions[user_id].append(ts)
            # If the actor was ever seen as a bot we keep that — the
            # synthetic burst finding is relevant per actor identity.
            actor_is_bot[user_id] = actor_is_bot.get(user_id, False) or is_bot
            if action_type == 72:  # MESSAGE_DELETE
                actor_msg_deletes[user_id].append(ts)

        bot_burst_actors = self._find_burst_windows(
            actor_actions,
            self.bot_action_burst_threshold,
            self.bot_action_burst_window_seconds,
        )
        mass_delete_actors = self._find_burst_windows(
            actor_msg_deletes,
            self.mass_message_delete_threshold,
            self.mass_message_delete_window_seconds,
        )

        results = [
            self._parse_entry(
                entry,
                file_sha256=file_sha256,
                bot_burst_actors=bot_burst_actors,
                mass_delete_actors=mass_delete_actors,
            )
            for entry in entries
        ]

        for actor_id, count in sorted(bot_burst_actors.items()):
            results.append(
                self._synthetic_bot_burst_result(
                    actor_user_id=actor_id,
                    action_count=count,
                    file_sha256=file_sha256,
                )
            )
        for actor_id, count in sorted(mass_delete_actors.items()):
            results.append(
                self._synthetic_mass_message_delete_result(
                    actor_user_id=actor_id,
                    delete_count=count,
                    file_sha256=file_sha256,
                )
            )
        return results

    @staticmethod
    def _find_burst_windows(
        actor_timestamps: dict[str, list[datetime]],
        threshold: int,
        window_seconds: int,
    ) -> dict[str, int]:
        """Return ``{actor_id: max_count}`` for any actor whose densest
        sliding window of ``window_seconds`` contains ``> threshold``
        timestamps. Threshold is strict — a window of exactly
        ``threshold`` does not trigger.
        """
        out: dict[str, int] = {}
        window = timedelta(seconds=window_seconds)
        for actor_id, ts_list in actor_timestamps.items():
            if len(ts_list) <= threshold:
                continue
            ordered = sorted(ts_list)
            best = 0
            j = 0
            for i in range(len(ordered)):
                while j < len(ordered) and ordered[j] - ordered[i] <= window:
                    j += 1
                count = j - i
                if count > best:
                    best = count
            if best > threshold:
                out[actor_id] = best
        return out

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        entry_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "discord_audit",
            "source_tool_name": "discord",
            "source_tool_version": "",
        }
        if entry_id is not None:
            provenance["entry_id"] = entry_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_action(
        self, action_type: int, actor_kind: str
    ) -> dict[str, Any] | None:
        """Find the first action-pattern that matches; ``None`` if no match."""
        for pattern in self._action_patterns:
            if _matches_action_pattern(action_type, actor_kind, pattern):
                return pattern
        return None

    def _action_type_name(self, action_type: int) -> str:
        return self._action_type_names.get(action_type, f"ACTION_TYPE_{action_type}")

    # ------------------------------------------------------------------
    # Per-entry parsing
    # ------------------------------------------------------------------

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        bot_burst_actors: dict[str, int],
        mass_delete_actors: dict[str, int],
    ) -> EvaluationResult:
        entry_id = str(entry.get("id") or uuid.uuid4())
        try:
            action_type = int(entry.get("action_type"))
        except (TypeError, ValueError):
            action_type = -1
        action_type_name = self._action_type_name(action_type)

        created_at = entry.get("created_at")
        event_time = (
            created_at
            if isinstance(created_at, str) and created_at
            else datetime.now(timezone.utc).isoformat()
        )

        # ---- actor / target (verbatim — pseudonymous snowflakes) ----
        user_id = (
            str(entry.get("user_id"))
            if isinstance(entry.get("user_id"), str)
            else None
        )
        target_id = (
            str(entry.get("target_id"))
            if isinstance(entry.get("target_id"), str)
            else None
        )
        is_bot = self._is_bot_actor(entry)
        actor_kind = "bot" if is_bot else "user"

        # ---- changes (KEYS only — values NEVER stored) ----
        change_keys = _change_keys(entry.get("changes"))

        # ---- reason (length + sha256 — raw text NEVER stored) ----
        reason_redacted = _hash_redact(entry.get("reason"))

        # ---- options (allowed: count, members_removed, delete_member_days,
        # channel_id, message_id, type. role_name → length+sha256 only.) ----
        options = entry.get("options") or {}
        if not isinstance(options, dict):
            options = {}
        try:
            options_count_raw = options.get("count")
            options_count = (
                int(options_count_raw) if options_count_raw is not None else None
            )
        except (TypeError, ValueError):
            options_count = None
        try:
            members_removed_raw = options.get("members_removed")
            options_members_removed = (
                int(members_removed_raw)
                if members_removed_raw is not None
                else None
            )
        except (TypeError, ValueError):
            options_members_removed = None
        try:
            delete_days_raw = options.get("delete_member_days")
            options_delete_member_days = (
                int(delete_days_raw)
                if delete_days_raw is not None
                else None
            )
        except (TypeError, ValueError):
            options_delete_member_days = None
        options_channel_id = (
            str(options.get("channel_id"))
            if isinstance(options.get("channel_id"), str)
            else None
        )
        options_message_id = (
            str(options.get("message_id"))
            if isinstance(options.get("message_id"), str)
            else None
        )
        options_type = (
            str(options.get("type")).lower()
            if isinstance(options.get("type"), str)
            else None
        )
        options_role_name_redacted = _hash_redact(options.get("role_name"))
        # AutoMod-emitted entries set ``automod_rule_trigger_type`` —
        # captured verbatim (it's a small enum, not user content).
        try:
            automod_rule_trigger_raw = options.get("automod_rule_trigger_type")
            automod_rule_trigger_type = (
                int(automod_rule_trigger_raw)
                if automod_rule_trigger_raw is not None
                else None
            )
        except (TypeError, ValueError):
            automod_rule_trigger_type = None

        common_evidence: dict[str, Any] = {
            "discord_entry_id": entry_id,
            "action_type": action_type,
            "action_type_name": action_type_name,
            "event_time": event_time,
            "user_id": user_id,
            "target_id": target_id,
            "actor_kind": actor_kind,
            "change_keys": change_keys,
            "reason_redacted": reason_redacted,
            "options_count": options_count,
            "options_members_removed": options_members_removed,
            "options_delete_member_days": options_delete_member_days,
            "options_channel_id": options_channel_id,
            "options_message_id": options_message_id,
            "options_type": options_type,
            "options_role_name_redacted": options_role_name_redacted,
            "automod_rule_trigger_type": automod_rule_trigger_type,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, entry_id=entry_id
            ),
            "source_tool": "discord",
        }

        control_results: list[ControlResult] = []
        composite_handled = False

        # ----------------------------------------------------------------
        # Composite signals — take precedence over the action_type table.
        # Order matters: most-specific to least-specific.
        # ----------------------------------------------------------------

        # MEMBER_PRUNE (21) with members_removed > threshold → PR-02 FAIL.
        if action_type == 21:
            if (
                options_members_removed is not None
                and options_members_removed > self.mass_prune_threshold
            ):
                composite_handled = True
                signal = "mass_member_prune"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Discord entry {entry_id}: MEMBER_PRUNE removed "
                            f"{options_members_removed} members "
                            f"(> threshold {self.mass_prune_threshold}) — "
                            f"mass-prune by {actor_kind} actor {user_id}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Below-threshold prune still captured as an audit event.
                composite_handled = True
                signal = "member_prune_small"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Discord entry {entry_id}: MEMBER_PRUNE removed "
                            f"{options_members_removed or 0} members "
                            f"(<= threshold {self.mass_prune_threshold})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # MESSAGE_BULK_DELETE (73) with count > threshold → PR-02 FAIL.
        elif action_type == 73:
            if (
                options_count is not None
                and options_count > self.mass_bulk_delete_threshold
            ):
                composite_handled = True
                signal = "mass_message_bulk_delete"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Discord entry {entry_id}: MESSAGE_BULK_DELETE "
                            f"deleted {options_count} messages "
                            f"(> threshold {self.mass_bulk_delete_threshold}) "
                            f"by {actor_kind} actor {user_id}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                composite_handled = True
                signal = "message_bulk_delete_small"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Discord entry {entry_id}: MESSAGE_BULK_DELETE "
                            f"deleted {options_count or 0} messages "
                            f"(<= threshold {self.mass_bulk_delete_threshold})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # MEMBER_ROLE_UPDATE (25) granting a privileged role → PR-02 FAIL.
        # The check inspects changes[].new_value for role-name patterns
        # (raw value used here ONLY to classify; it is NOT stored).
        elif action_type == 25:
            granted_privileged = self._role_update_grants_privileged(
                entry.get("changes")
            )
            if granted_privileged:
                composite_handled = True
                signal = "privileged_role_grant"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Discord entry {entry_id}: MEMBER_ROLE_UPDATE "
                            f"granted privileged role to {target_id} by "
                            f"{actor_kind} actor {user_id}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # CHANNEL_OVERWRITE_CREATE (14) granting permissions to @everyone
        # (options.type=='role' and target/role-id == guild id semantically;
        # in the audit log this is signalled by ``options.type='role'`` with
        # role_name absent or matching @everyone). We capture as PR-02 FLAG
        # whenever an overwrite is created with options.type='role' and the
        # role-name redaction came back empty (= @everyone has no name).
        elif action_type == 14:
            if (
                options_type == "role"
                and options_role_name_redacted is None
            ):
                composite_handled = True
                signal = "everyone_overwrite_grant"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Discord entry {entry_id}: CHANNEL_OVERWRITE_CREATE "
                            f"granted role-overwrite (likely @everyone) on "
                            f"channel {target_id} by {actor_kind} actor "
                            f"{user_id}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # INVITE_CREATE (40) with max_uses=0 (unlimited) → PR-04 FLAG.
        # max_uses=0 is the Discord convention for an unlimited public
        # invite — a high-risk surface for community-facing servers.
        elif action_type == 40:
            max_uses = self._change_int_value(entry.get("changes"), "max_uses")
            if max_uses == 0:
                composite_handled = True
                signal = "unlimited_invite_create"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Discord entry {entry_id}: INVITE_CREATE with "
                            f"max_uses=0 (unlimited) by {actor_kind} actor "
                            f"{user_id} — public invite surface"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                composite_handled = True
                signal = "invite_create_capped"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Discord entry {entry_id}: INVITE_CREATE "
                            f"max_uses={max_uses if max_uses is not None else 'unspecified'}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # WEBHOOK_UPDATE (51) changing the URL → PR-04 FLAG.
        # A webhook URL change retargets the destination — high signal for
        # exfil setup ("repoint #status to attacker.example.com").
        elif action_type == 51:
            if "url" in change_keys or "channel_id" in change_keys:
                composite_handled = True
                signal = "webhook_url_change"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Discord entry {entry_id}: WEBHOOK_UPDATE "
                            f"changed {sorted(change_keys)} on webhook "
                            f"{target_id} by {actor_kind} actor {user_id} — "
                            f"webhook destination change"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # MESSAGE_DELETE (72) by bot or by AutoMod → PR-05 FLAG (audit
        # completeness — "who removed evidence of this conversation?").
        elif action_type == 72 and is_bot:
            composite_handled = True
            signal = "bot_message_delete"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Discord entry {entry_id}: MESSAGE_DELETE by "
                        f"bot/automod actor {user_id} on channel "
                        f"{options_channel_id or 'unknown'} — "
                        f"audit-completeness concern"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # Action-pattern table fallback.
        # ----------------------------------------------------------------
        if not composite_handled:
            pattern = self._classify_action(action_type, actor_kind)
            if pattern is not None:
                signal = str(pattern.get("signal", "unknown_action_type"))
                control_id = _control_for(
                    signal,
                    self._mappings,
                    str(pattern.get("control", "PR-05")),
                )
                result = str(pattern.get("result", "PASS"))
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=result,
                        detail=(
                            f"Discord entry {entry_id}: action_type="
                            f"{action_type} ({action_type_name}) by "
                            f"{actor_kind} actor {user_id or 'unknown'} "
                            f"classified as {signal} ({result})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Unknown action_type — surface as PR-05 FLAG so it doesn't
                # silently pass. Discord adds new action_type codes
                # regularly; the mapping covers the high-signal subset.
                signal = "unknown_action_type"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Discord entry {entry_id}: action_type="
                            f"{action_type} ({action_type_name}) has no "
                            f"matching pattern — surfaced for review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # Bot-action-burst pattern marker (per-entry).
        # ----------------------------------------------------------------
        if user_id and user_id in bot_burst_actors:
            signal = "bot_action_burst_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Discord entry {entry_id}: bot actor {user_id} part "
                        f"of action-burst pattern "
                        f"({bot_burst_actors[user_id]} actions in a "
                        f"{self.bot_action_burst_window_seconds}s window > "
                        f"threshold {self.bot_action_burst_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "burst_action_count": bot_burst_actors[user_id],
                        "burst_threshold": self.bot_action_burst_threshold,
                        "burst_window_seconds": (
                            self.bot_action_burst_window_seconds
                        ),
                    },
                )
            )

        # ----------------------------------------------------------------
        # Mass-message-delete pattern marker (per-entry).
        # ----------------------------------------------------------------
        if user_id and user_id in mass_delete_actors:
            signal = "mass_message_delete_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Discord entry {entry_id}: actor {user_id} part of "
                        f"mass-message-delete pattern "
                        f"({mass_delete_actors[user_id]} MESSAGE_DELETE "
                        f"actions in a "
                        f"{self.mass_message_delete_window_seconds}s window "
                        f"> threshold {self.mass_message_delete_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "delete_count": mass_delete_actors[user_id],
                        "delete_threshold": (
                            self.mass_message_delete_threshold
                        ),
                        "delete_window_seconds": (
                            self.mass_message_delete_window_seconds
                        ),
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
            f"Imported from Discord audit log: action_type={action_type} "
            f"({action_type_name}) actor_kind={actor_kind} "
            f"user_id={user_id or 'unknown'} target_id={target_id or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"discord-{entry_id[:32]}",
            timestamp=event_time,
            agent_id=self.agent_id,
            source_type="discord_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=user_id or None,
        )

    def _role_update_grants_privileged(self, changes: Any) -> bool:
        """Return True if a MEMBER_ROLE_UPDATE adds a privileged role.

        Discord encodes role grants as ``changes=[{key:"$add", new_value:[
        {"id":"...", "name":"Admin"}, ...]}, ...]``. We inspect the
        ``new_value`` array (used here ONLY for classification; the raw
        names are NOT written to evidence). Removals (``key=="$remove"``)
        are not treated as privilege grants.
        """
        if not isinstance(changes, list):
            return False
        for ch in changes:
            if not isinstance(ch, dict):
                continue
            if str(ch.get("key", "")).lower() != "$add":
                continue
            new_value = ch.get("new_value")
            if not isinstance(new_value, list):
                continue
            for item in new_value:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    continue
                for pat in self.privileged_role_patterns:
                    if fnmatch.fnmatchcase(name, pat):
                        return True
        return False

    @staticmethod
    def _change_int_value(changes: Any, key: str) -> int | None:
        """Return ``new_value`` for ``key`` as an int, or None.

        Used here ONLY to classify (e.g. "is max_uses 0?"); the raw value
        is NOT written to evidence.
        """
        if not isinstance(changes, list):
            return None
        for ch in changes:
            if not isinstance(ch, dict):
                continue
            if ch.get("key") != key:
                continue
            try:
                return int(ch.get("new_value"))
            except (TypeError, ValueError):
                return None
        return None

    # ------------------------------------------------------------------
    # Synthetic findings
    # ------------------------------------------------------------------

    def _synthetic_bot_burst_result(
        self,
        *,
        actor_user_id: str,
        action_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor bot-action-burst finding."""
        signal = "bot_action_burst_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"discord-bot-burst-{actor_user_id}"
        evidence: dict[str, Any] = {
            "discord_entry_id": synthetic_id,
            "user_id": actor_user_id,
            "burst_action_count": action_count,
            "burst_threshold": self.bot_action_burst_threshold,
            "burst_window_seconds": self.bot_action_burst_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                entry_id=synthetic_id,
            ),
            "source_tool": "discord",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Discord synthetic finding: bot actor {actor_user_id} "
                f"performed {action_count} actions in a "
                f"{self.bot_action_burst_window_seconds}s window — exceeds "
                f"threshold {self.bot_action_burst_threshold} (bot burst)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="discord_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Discord audit log: synthetic bot-action-burst "
                f"actor={actor_user_id} count={action_count}>"
                f"threshold={self.bot_action_burst_threshold} window="
                f"{self.bot_action_burst_window_seconds}s"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_mass_message_delete_result(
        self,
        *,
        actor_user_id: str,
        delete_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor mass-message-delete finding."""
        signal = "mass_message_delete_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"discord-mass-msg-delete-{actor_user_id}"
        evidence: dict[str, Any] = {
            "discord_entry_id": synthetic_id,
            "user_id": actor_user_id,
            "delete_count": delete_count,
            "delete_threshold": self.mass_message_delete_threshold,
            "delete_window_seconds": self.mass_message_delete_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                entry_id=synthetic_id,
            ),
            "source_tool": "discord",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Discord synthetic finding: actor {actor_user_id} performed "
                f"{delete_count} MESSAGE_DELETE actions in a "
                f"{self.mass_message_delete_window_seconds}s window — "
                f"exceeds threshold {self.mass_message_delete_threshold} "
                f"(audit-completeness concern)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="discord_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Discord audit log: synthetic "
                f"mass-message-delete actor={actor_user_id} "
                f"count={delete_count}>threshold="
                f"{self.mass_message_delete_threshold} window="
                f"{self.mass_message_delete_window_seconds}s"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
