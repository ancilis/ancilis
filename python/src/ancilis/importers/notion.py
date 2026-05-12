# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Notion audit-event importer — maps agent knowledge-management activity to AKSI controls.

Notion (https://notion.so) is the dominant knowledge-management platform for
modern teams. Agents now create pages, edit databases, comment on threads,
and increasingly use Notion as a long-term ``AI memory`` surface — a place
where what the agent learned yesterday becomes persistent context tomorrow.
A bot quietly deleting a page, a public-link share with no expiry, or a
write-scope grant to a new integration are all workflow-altering events
that today's evidence pipelines do not capture.

This importer ingests Notion's ``/v1/audit_logs`` (Enterprise) exports and
webhook captures in three on-disk shapes:

  1. ``{"events": [...]}`` — primary audit-log envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                  — one event per line

Signal mapping (see shared/mappings/notion-aksi-controls.json):
  * ``page.created`` actor.type=person                                → PR-05 PASS
  * ``page.created`` actor.type=bot                                   → PR-01 FLAG
    (agent-created knowledge — surface for review)
  * ``page.updated`` actor.type=bot                                   → PR-05 PASS
    (audit trail of bot edit captured)
  * ``page.deleted`` actor.type=bot                                   → PR-02 FAIL
    (bot deleting knowledge = audit destruction unless explicitly
    approved workflow)
  * ``page.deleted`` actor.type=person                                → PR-05 PASS
  * ``page.shared_publicly`` is_password_protected=false              → DE-01 FAIL
    (public unprotected page = exfiltration surface)
  * ``page.shared_publicly`` is_password_protected=true               → PR-04 FLAG
  * ``page.shared_publicly`` expires_at=null                          → PR-04 FAIL
    (permanent public link)
  * ``page.shared_with_user`` shared_with_email_domain != primary    → PR-04 FLAG
  * ``database.schema_changed`` schema_changes contains "removed_*"  → PR-05 FLAG
  * ``database.row_deleted`` actor.type=bot                           → PR-02 FLAG
  * ``integration.added``                                              → PR-01 FLAG
  * ``integration.scope_added`` scope in write_scope_names            → PR-02 FLAG
  * ``workspace.exported`` format=html size > threshold               → PR-04 FAIL
  * ``workspace.exported`` format in {markdown, pdf}                  → PR-04 FLAG
  * ``user.added`` actor.type=person + actor.is_external=true         → PR-02 FLAG
  * ``user.removed``                                                   → PR-05 PASS
  * ``comment.added`` actor.type=bot on high-priority page            → PR-01 FLAG
  * bot-velocity pattern: same bot actor doing > N edits in 1h
    (default N=50)                                                    → PR-02 FLAG synthetic
  * cross-page pattern: same bot touching > N distinct page_ids
    (default N=100)                                                   → PR-02 FLAG synthetic

Sanitization (security-critical — Notion audit logs can carry PII in actor
names, emails, page titles, schema column names, link IDs and IPs):
  * ``actor.name`` raw is NEVER stored — we keep length + sha256 of the
    full name (so identical names collide while not retaining the value).
  * ``actor.email`` is reduced to ``@domain`` only.
  * Page ``title`` text is NEVER stored — Notion's audit feed already
    provides ``page_title_length`` (length only), and that is what we
    capture verbatim.
  * ``schema_changes`` raw column-name values are NOT stored — we keep
    only the count and a per-change-type tally (``added`` / ``removed`` /
    other) so that ``removed_column:customer_pii`` does not leak.
  * ``publicly_shared_link.id`` keeps only the trailing 8 characters
    (sufficient to correlate with later events without retaining the
    full link identifier).
  * ``ip_address`` is reduced to a /16 pattern (first two octets) for
    IPv4 and a /32-hextet pattern for IPv6. RFC1918 / loopback /
    link-local addresses are preserved verbatim.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``notion-client`` package; audit-log JSON
exports are parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch  # noqa: F401  # reserved for future tag-pattern matching
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Path to the shared mapping table. This file lives at
# <repo>/python/src/ancilis/importers/notion.py — five .parent traversals
# after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "notion-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_BOT_VELOCITY_THRESHOLD = 50
_DEFAULT_BOT_VELOCITY_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_PAGE_THRESHOLD = 100
_DEFAULT_EXPORT_SIZE_THRESHOLD_BYTES = 100_000_000
_DEFAULT_HIGH_PRIORITY_PAGE_TAGS: frozenset[str] = frozenset(
    {"confidential", "restricted", "secret", "pii", "legal"}
)
_DEFAULT_AGENT_MARKER_PATTERNS: frozenset[str] = frozenset(
    {"[ai]", "[agent]", "(generated)", "(ai)"}
)
_DEFAULT_WRITE_SCOPE_NAMES: frozenset[str] = frozenset(
    {"update_content", "insert_content", "read_content"}
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the notion-aksi-controls.json mapping; tolerate missing file."""
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


def _normalize_email_domain(domain: str | None) -> str | None:
    """Normalize a shared_with_email_domain that may or may not be ``@``-prefixed."""
    if not domain or not isinstance(domain, str):
        return None
    d = domain.strip()
    if not d:
        return None
    if not d.startswith("@"):
        d = "@" + d
    return d.lower()


def _truncate_link_id(link_id: str | None) -> str | None:
    """Keep only the trailing 8 characters of a publicly_shared_link.id."""
    if not link_id or not isinstance(link_id, str):
        return None
    s = link_id.strip()
    if not s:
        return None
    return s[-8:]


def _summarize_schema_changes(changes: Any) -> dict[str, Any]:
    """Summarize ``schema_changes`` to count + per-type tally only.

    Notion sends entries like ``"added_column:tags"`` or
    ``"removed_column:owner"``. We never store the column-name suffix —
    only the change-type prefix (``added`` / ``removed`` / other) and a
    total count. This prevents the column name (which can carry PII like
    ``customer_pii``) from leaking into evidence.
    """
    if not isinstance(changes, list):
        return {"count": 0, "added": 0, "removed": 0, "other": 0}
    added = 0
    removed = 0
    other = 0
    for c in changes:
        if not isinstance(c, str):
            other += 1
            continue
        prefix = c.split(":", 1)[0].strip().lower()
        if prefix.startswith("added"):
            added += 1
        elif prefix.startswith("removed"):
            removed += 1
        else:
            other += 1
    return {
        "count": len(changes),
        "added": added,
        "removed": removed,
        "other": other,
    }


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


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class NotionImporter:
    """Parse a Notion audit-log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        bot_velocity_threshold: int | None = None,
        bot_velocity_window_seconds: int | None = None,
        cross_page_threshold: int | None = None,
        export_size_threshold_bytes: int | None = None,
        high_priority_page_tags: Iterable[str] | None = None,
        agent_marker_patterns: Iterable[str] | None = None,
        write_scope_names: Iterable[str] | None = None,
        primary_workspace_domain: str | None = None,
    ) -> None:
        # Imported lazily here so the module-level import surface stays small
        # and the SDK remains importable without circular issues.
        from ancilis.engine.result import EvaluationResult  # noqa: F401

        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
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
        if cross_page_threshold is not None:
            self.cross_page_threshold = int(cross_page_threshold)
        else:
            self.cross_page_threshold = int(
                meta.get("cross_page_threshold", _DEFAULT_CROSS_PAGE_THRESHOLD)
            )
        if export_size_threshold_bytes is not None:
            self.export_size_threshold_bytes = int(export_size_threshold_bytes)
        else:
            self.export_size_threshold_bytes = int(
                meta.get(
                    "export_size_threshold_bytes",
                    _DEFAULT_EXPORT_SIZE_THRESHOLD_BYTES,
                )
            )
        if high_priority_page_tags is not None:
            self.high_priority_page_tags: frozenset[str] = frozenset(
                str(t).strip().lower() for t in high_priority_page_tags if t
            )
        else:
            meta_tags = meta.get("high_priority_page_tags")
            if isinstance(meta_tags, list) and meta_tags:
                self.high_priority_page_tags = frozenset(
                    str(t).strip().lower() for t in meta_tags if t
                )
            else:
                self.high_priority_page_tags = _DEFAULT_HIGH_PRIORITY_PAGE_TAGS
        if agent_marker_patterns is not None:
            self.agent_marker_patterns: frozenset[str] = frozenset(
                str(p).strip().lower() for p in agent_marker_patterns if p
            )
        else:
            meta_markers = meta.get("agent_marker_patterns")
            if isinstance(meta_markers, list) and meta_markers:
                self.agent_marker_patterns = frozenset(
                    str(p).strip().lower() for p in meta_markers if p
                )
            else:
                self.agent_marker_patterns = _DEFAULT_AGENT_MARKER_PATTERNS
        if write_scope_names is not None:
            self.write_scope_names: frozenset[str] = frozenset(
                str(s).strip().lower() for s in write_scope_names if s
            )
        else:
            meta_scopes = meta.get("write_scope_names")
            if isinstance(meta_scopes, list) and meta_scopes:
                self.write_scope_names = frozenset(
                    str(s).strip().lower() for s in meta_scopes if s
                )
            else:
                self.write_scope_names = _DEFAULT_WRITE_SCOPE_NAMES
        if primary_workspace_domain is not None:
            self.primary_workspace_domain: str | None = (
                _normalize_email_domain(primary_workspace_domain)
            )
        else:
            meta_domain = meta.get("primary_workspace_domain")
            self.primary_workspace_domain = (
                _normalize_email_domain(meta_domain)
                if isinstance(meta_domain, str) and meta_domain.strip()
                else None
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[Any]:
        """Parse a Notion audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[Any]:
        """Parse Notion audit-log content from a JSON or JSONL string."""
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
    ) -> list[Any]:
        """Build per-event EvaluationResults plus bot-velocity / cross-page synthetics."""
        # Pass 1: aggregate per-bot-actor edit timestamps and distinct page_ids.
        actor_pages: dict[str, set[str]] = {}
        bot_edit_ts: dict[str, list[datetime]] = {}
        actor_is_bot: dict[str, bool] = {}

        for ev in events:
            actor = ev.get("actor") or {}
            if not isinstance(actor, dict):
                continue
            actor_id = actor.get("id")
            if not isinstance(actor_id, str) or not actor_id:
                continue
            actor_type = str(actor.get("type") or "").strip().lower()
            is_bot = actor_type == "bot"
            actor_is_bot[actor_id] = actor_is_bot.get(actor_id, False) or is_bot
            page_id = ev.get("page_id")
            if isinstance(page_id, str) and page_id:
                actor_pages.setdefault(actor_id, set()).add(page_id)
            if is_bot:
                ts = _parse_iso_timestamp(ev.get("timestamp"))
                if ts is not None:
                    bot_edit_ts.setdefault(actor_id, []).append(ts)

        cross_page_actors: dict[str, int] = {
            actor: len(pages)
            for actor, pages in actor_pages.items()
            if actor_is_bot.get(actor, False)
            and len(pages) > self.cross_page_threshold
        }

        bot_velocity_actors: dict[str, int] = {}
        window = self.bot_velocity_window_seconds
        for actor, timestamps in bot_edit_ts.items():
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
                cross_page_actors=cross_page_actors,
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
        for actor, page_count in sorted(cross_page_actors.items()):
            results.append(
                self._synthetic_cross_page_result(
                    actor=actor,
                    page_count=page_count,
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
            "source_format": "notion_audit_log",
            "source_tool_name": "notion",
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
        cross_page_actors: dict[str, int],
        bot_velocity_actors: dict[str, int],
    ) -> Any:
        from ancilis.engine.result import ControlResult, EvaluationResult

        event_id = str(event.get("id") or uuid.uuid4())
        type_field = str(event.get("type") or "").strip()
        timestamp = _format_timestamp(event.get("timestamp"))

        actor = event.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        actor_id_raw = actor.get("id")
        actor_id = str(actor_id_raw) if isinstance(actor_id_raw, str) else ""
        actor_type = str(actor.get("type") or "").strip().lower() or None
        actor_is_bot = actor_type == "bot"
        actor_is_external = bool(actor.get("is_external"))
        actor_name_redacted = _redact_actor_name(
            actor.get("name") if isinstance(actor.get("name"), str) else None
        )
        actor_email_domain = _redact_email(
            actor.get("email") if isinstance(actor.get("email"), str) else None
        )

        workspace_id = (
            str(event.get("workspace_id"))
            if isinstance(event.get("workspace_id"), str) and event.get("workspace_id")
            else None
        )
        page_id = (
            str(event.get("page_id"))
            if isinstance(event.get("page_id"), str) and event.get("page_id")
            else None
        )
        page_title_length_raw = event.get("page_title_length")
        page_title_length: int | None = (
            int(page_title_length_raw)
            if isinstance(page_title_length_raw, (int, float))
            else None
        )

        details = event.get("details") or {}
        if not isinstance(details, dict):
            details = {}

        # Page-move parents.
        from_parent_id = (
            str(details.get("from_parent_id"))
            if isinstance(details.get("from_parent_id"), str)
            and details.get("from_parent_id")
            else None
        )
        to_parent_id = (
            str(details.get("to_parent_id"))
            if isinstance(details.get("to_parent_id"), str)
            and details.get("to_parent_id")
            else None
        )

        # Sharing.
        shared_with_user_id = (
            str(details.get("shared_with_user_id"))
            if isinstance(details.get("shared_with_user_id"), str)
            and details.get("shared_with_user_id")
            else None
        )
        shared_with_email_domain = _normalize_email_domain(
            details.get("shared_with_email_domain")
            if isinstance(details.get("shared_with_email_domain"), str)
            else None
        )
        publicly_shared_link = details.get("publicly_shared_link")
        link_id_truncated: str | None = None
        link_is_password_protected: bool | None = None
        link_expires_at: str | None = None
        link_present = False
        if isinstance(publicly_shared_link, dict):
            link_present = True
            link_id_truncated = _truncate_link_id(
                publicly_shared_link.get("id")
                if isinstance(publicly_shared_link.get("id"), str)
                else None
            )
            ipp = publicly_shared_link.get("is_password_protected")
            if isinstance(ipp, bool):
                link_is_password_protected = ipp
            exp = publicly_shared_link.get("expires_at")
            link_expires_at = (
                exp.strip() if isinstance(exp, str) and exp.strip() else None
            )

        # Schema changes (sanitized).
        schema_summary = _summarize_schema_changes(details.get("schema_changes"))

        # Integrations.
        integration_id = (
            str(details.get("integration_id"))
            if isinstance(details.get("integration_id"), str)
            and details.get("integration_id")
            else None
        )
        scope_added_raw = details.get("scope_added")
        scope_added = (
            str(scope_added_raw).strip().lower()
            if isinstance(scope_added_raw, str) and scope_added_raw.strip()
            else None
        )

        # Workspace export.
        export_format_raw = details.get("export_format")
        export_format = (
            str(export_format_raw).strip().lower()
            if isinstance(export_format_raw, str) and export_format_raw.strip()
            else None
        )
        export_size_raw = details.get("export_size_bytes")
        export_size_bytes: int | None = (
            int(export_size_raw)
            if isinstance(export_size_raw, (int, float))
            else None
        )

        # Page tags (used for high-priority comment detection).
        page_tags_raw = details.get("page_tags") or []
        page_tags = (
            [str(t).strip().lower() for t in page_tags_raw if isinstance(t, str)]
            if isinstance(page_tags_raw, list)
            else []
        )
        page_is_high_priority = any(
            t in self.high_priority_page_tags for t in page_tags
        )

        # IP redaction.
        ip_raw = event.get("ip_address")
        ip_redacted = _classify_ip(ip_raw if isinstance(ip_raw, str) else None)

        common_evidence: dict[str, Any] = {
            "notion_event_id": event_id,
            "type": type_field or None,
            "actor_id": actor_id or None,
            "actor_type": actor_type,
            "actor_is_bot": actor_is_bot,
            "actor_is_external": actor_is_external,
            "actor_name_redacted": actor_name_redacted,
            "actor_email_domain": actor_email_domain,
            "workspace_id": workspace_id,
            "page_id": page_id,
            "page_title_length": page_title_length,
            "from_parent_id": from_parent_id,
            "to_parent_id": to_parent_id,
            "shared_with_user_id": shared_with_user_id,
            "shared_with_email_domain": shared_with_email_domain,
            "publicly_shared_link_present": link_present,
            "publicly_shared_link_id_last8": link_id_truncated,
            "publicly_shared_link_is_password_protected": link_is_password_protected,
            "publicly_shared_link_expires_at": link_expires_at,
            "schema_changes_count": schema_summary["count"],
            "schema_changes_added": schema_summary["added"],
            "schema_changes_removed": schema_summary["removed"],
            "schema_changes_other": schema_summary["other"],
            "integration_id": integration_id,
            "scope_added": scope_added,
            "export_format": export_format,
            "export_size_bytes": export_size_bytes,
            "page_tags_high_priority": page_is_high_priority,
            "ip_address_redacted": ip_redacted,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "notion",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # Primary type-driven classification.
        # ----------------------------------------------------------------
        if type_field == "page.created":
            if actor_is_bot:
                signal = "page_created_by_bot"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} page.created by bot "
                            f"actor {actor_id or 'unknown'} on page="
                            f"{page_id or 'unknown'} — agent-created knowledge, "
                            f"surface for human review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "page_created_by_user"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Notion event {event_id} page.created by user "
                            f"actor {actor_id or 'unknown'} on page="
                            f"{page_id or 'unknown'} — audit-trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "page.updated":
            if actor_is_bot:
                signal = "page_updated_by_bot"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Notion event {event_id} page.updated by bot "
                            f"actor {actor_id or 'unknown'} on page="
                            f"{page_id or 'unknown'} — bot-edit audit trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "page.deleted":
            if actor_is_bot:
                signal = "page_deleted_by_bot"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Notion event {event_id} page.deleted by bot "
                            f"actor {actor_id or 'unknown'} on page="
                            f"{page_id or 'unknown'} — bot deleting knowledge "
                            f"destroys audit trail unless explicitly approved"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "page_deleted_by_user"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Notion event {event_id} page.deleted by user "
                            f"actor {actor_id or 'unknown'} on page="
                            f"{page_id or 'unknown'} — audit-trail captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "page.shared_publicly":
            # Three independent signals can fire on a single shared_publicly
            # event: (a) password protection state, (b) expiry state.
            if link_is_password_protected is False:
                signal = "public_unprotected_share"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Notion event {event_id} page.shared_publicly "
                            f"with password protection DISABLED on page="
                            f"{page_id or 'unknown'} — public unprotected "
                            f"page is an exfiltration surface"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif link_is_password_protected is True:
                signal = "public_protected_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} page.shared_publicly "
                            f"with password protection enabled on page="
                            f"{page_id or 'unknown'} — public-but-protected "
                            f"surface, verify warrant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            if link_present and link_expires_at is None:
                signal = "public_no_expiry"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Notion event {event_id} page.shared_publicly "
                            f"with no expiry (expires_at=null) on page="
                            f"{page_id or 'unknown'} — permanent public link"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "page.shared_with_user":
            # Compare shared_with_email_domain to the configured primary
            # workspace domain. If no primary domain is configured we cannot
            # know what counts as ``external``, so we do not fire.
            if (
                shared_with_email_domain
                and self.primary_workspace_domain
                and shared_with_email_domain != self.primary_workspace_domain
            ):
                signal = "external_share"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} page.shared_with_user "
                            f"to external domain {shared_with_email_domain!r} "
                            f"(primary={self.primary_workspace_domain!r}) on "
                            f"page={page_id or 'unknown'} — external sharing"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "database.schema_changed":
            if schema_summary["removed"] > 0:
                signal = "schema_column_removal"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} database.schema_changed "
                            f"removed {schema_summary['removed']} column(s) "
                            f"on page={page_id or 'unknown'} — audit-completeness "
                            f"concern (column names not stored)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "database.row_deleted":
            if actor_is_bot:
                signal = "row_deleted_by_bot"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} database.row_deleted by "
                            f"bot actor {actor_id or 'unknown'} on page="
                            f"{page_id or 'unknown'} — bot deleting structured "
                            f"data, surface for review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "integration.added":
            signal = "integration_added"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Notion event {event_id} integration.added "
                        f"integration_id={integration_id or 'unknown'} — "
                        f"new integration is a new automation surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif type_field == "integration.scope_added":
            if scope_added and scope_added in self.write_scope_names:
                signal = "write_scope_grant"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} integration.scope_added "
                            f"granted scope={scope_added!r} to integration="
                            f"{integration_id or 'unknown'} — write-scope grant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "workspace.exported":
            if (
                export_format == "html"
                and export_size_bytes is not None
                and export_size_bytes > self.export_size_threshold_bytes
            ):
                signal = "workspace_export_html_large"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Notion event {event_id} workspace.exported "
                            f"format=html size={export_size_bytes}B exceeds "
                            f"threshold {self.export_size_threshold_bytes}B "
                            f"— bulk workspace export = mass exfiltration"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif export_format in {"markdown", "pdf"}:
                signal = "workspace_export_small"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} workspace.exported "
                            f"format={export_format!r} size="
                            f"{export_size_bytes if export_size_bytes is not None else 'unknown'} "
                            f"— smaller bulk export, surface for review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "user.added":
            # External user added by a person (the bot/system path is a
            # separate concern). Notion marks externals via actor.is_external
            # on the inviting actor; we use that as the signal.
            if actor_type == "person" and actor_is_external:
                signal = "external_user_added"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Notion event {event_id} user.added invited by "
                            f"external person actor {actor_id or 'unknown'} "
                            f"— external user added"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif type_field == "user.removed":
            signal = "user_removed"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Notion event {event_id} user.removed — "
                        f"audit-trail captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif (
            type_field == "comment.added"
            and actor_is_bot
            and page_is_high_priority
        ):
            signal = "bot_comment_high_priority"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Notion event {event_id} comment.added by bot "
                        f"actor {actor_id or 'unknown'} on high-priority "
                        f"page={page_id or 'unknown'} (tags hit "
                        f"{sorted(self.high_priority_page_tags)}) — bot "
                        f"commentary on critical content"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # Velocity / cross-page pattern markers (informational on contributing
        # events; the synthetic per-actor finding is added separately).
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
                        f"Notion event {event_id} actor {actor_id} is part "
                        f"of a bot-velocity pattern "
                        f"({bot_velocity_actors[actor_id]} edits > threshold "
                        f"{self.bot_velocity_threshold} in "
                        f"{self.bot_velocity_window_seconds}s window)"
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
        if actor_id and actor_id in cross_page_actors:
            signal = "cross_page_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Notion event {event_id} actor {actor_id} is part of "
                        f"a cross-page pattern ({cross_page_actors[actor_id]} "
                        f"distinct page_ids > threshold "
                        f"{self.cross_page_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_page_page_count": cross_page_actors[actor_id],
                        "cross_page_threshold": self.cross_page_threshold,
                    },
                )
            )

        # ----------------------------------------------------------------
        # No-match fallback — surface unknown type so it is not silent.
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
                        f"Notion event {event_id} type={type_field!r} has no "
                        f"matching pattern — surfaced for review"
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
            f"Imported from Notion audit log: type={type_field or 'unknown'} "
            f"actor={actor_id or 'unknown'} actor_type={actor_type or 'unknown'} "
            f"actor_is_bot={actor_is_bot} page={page_id or 'none'} "
            f"workspace={workspace_id or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"notion-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="notion_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=workspace_id,
        )

    def _synthetic_bot_velocity_result(
        self,
        *,
        actor: str,
        count: int,
        file_sha256: str | None,
    ) -> Any:
        """Synthesize a per-bot velocity pattern finding."""
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "bot_velocity_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"notion-bot-velocity-{actor}"
        evidence: dict[str, Any] = {
            "notion_event_id": synthetic_id,
            "actor_id": actor,
            "actor_type": "bot",
            "actor_is_bot": True,
            "bot_velocity_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "notion",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Notion synthetic finding: bot {actor} performed {count} "
                f"edits in a {self.bot_velocity_window_seconds}s window — "
                f"exceeds bot-velocity threshold {self.bot_velocity_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="notion_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Notion audit log: synthetic bot-velocity "
                f"pattern for bot={actor} count={count}>threshold="
                f"{self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_page_result(
        self,
        *,
        actor: str,
        page_count: int,
        file_sha256: str | None,
    ) -> Any:
        """Synthesize a per-bot cross-page pattern finding."""
        from ancilis.engine.result import ControlResult, EvaluationResult

        signal = "cross_page_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"notion-cross-page-{actor}"
        evidence: dict[str, Any] = {
            "notion_event_id": synthetic_id,
            "actor_id": actor,
            "actor_type": "bot",
            "actor_is_bot": True,
            "cross_page_page_count": page_count,
            "cross_page_threshold": self.cross_page_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "notion",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Notion synthetic finding: bot {actor} touched {page_count} "
                f"distinct pages in this export — exceeds cross-page "
                f"threshold {self.cross_page_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="notion_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Notion audit log: synthetic cross-page pattern "
                f"for bot={actor} pages={page_count}>threshold="
                f"{self.cross_page_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
