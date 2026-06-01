# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Confluence audit-record importer — maps agent knowledge-base activity to AKSI controls.

Atlassian Confluence (https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-audit/)
is the dominant knowledge-management platform for Atlassian-shop customers —
the parallel to Notion. Agents now create pages, edit spaces, comment on
threads, archive obsolete content, and increasingly use Confluence as a long-
term ``AI memory`` surface — a place where what the agent learned yesterday
becomes persistent context tomorrow. A bot quietly deleting a page, a space
flipped to anonymous access, a 200MB PDF export, or a restriction removal on
a sensitive page are all workflow-altering events that today's evidence
pipelines do not capture.

This importer ingests Confluence's ``/wiki/api/v2/audit-records`` exports
and webhook captures in four on-disk shapes:

  1. ``{"results": [...]}`` — primary audit-records envelope
  2. ``{"events":  [...]}`` — generic events envelope
  3. ``{"data":    [...]}`` — generic data envelope
  4. JSONL                  — one record per line

Signal mapping (see shared/mappings/confluence-aksi-controls.json):
  * category=page summary "Page created" + author.isBot=true       → PR-01 FLAG
    (agent-created knowledge — surface for human review)
  * category=page summary "Page deleted" + author.isBot=true       → PR-02 FAIL
    (bot deleting knowledge = audit destruction; parallels Notion bot-deletion)
  * category=page summary "Page exported as PDF/HTML"              → PR-04 FLAG
    (export = data leaving system)
  * category=page summary "Page exported as PDF/HTML" + size > T   → PR-04 FAIL
    (bulk export = mass exfiltration surface)
  * category=page summary "Restrictions removed" OR
    changedValues field=restrictions changedTo less restrictive    → PR-04 FAIL
    (visibility increase, parallel to Jira's security-level logic)
  * category=permissions summary "Anonymous access enabled"        → DE-01 FAIL
    (public space = exfiltration surface)
  * category=permissions summary "Permission scheme updated" +
    spaceType=public                                                → PR-02 FLAG
  * category=space summary "Space archived"                        → PR-05 PASS
    (archive = audit-trail captured)
  * category=space summary "Space deleted"                         → PR-02 FAIL
    (space destruction = audit-trail destruction)
  * category=user summary "User added to organization" +
    author.type=appLink                                             → PR-02 FLAG
    (programmatic user provisioning)
  * category=group summary "Group added to space" with admin perms → PR-02 FLAG
  * actionFromAuthor=anonymous                                      → PR-01 FAIL
    (anonymous edits = identity-unverifiable action)
  * actionFromAuthor=appLink                                        → PR-01 FLAG
    (app-driven action — verify identity of app)
  * isAutomatedAction=true + category=page                          → PR-05 PASS
    (automation audit captured)
  * Bot-velocity: bot author > N edits in 1h (default 30)          → PR-02 FLAG
  * Cross-space: bot touching > N spaces (default 5)                → PR-02 FLAG

Sanitization (security-critical — Confluence audit records can carry tenant
identifiers, customer page titles, free-text incident detail in change diffs,
and PII in displayName / email / userAgent / remoteAddress):

  * ``subjectName`` text is NEVER stored — we keep length + sha256 only
    (e.g. a page title like "Customer Onboarding — ACME Corp" never lands
    in evidence). ``subjectId`` is kept verbatim (Atlassian opaque ID).
  * ``spaceKey`` is kept verbatim (operator-managed short code, e.g. "ENG").
    ``spaceName`` is NEVER stored — Atlassian permits free-form text here.
  * ``summary`` is truncated to 200 chars and accompanied by sha256 + length.
  * ``author.accountId`` is kept verbatim (Atlassian opaque ID).
  * ``author.displayName`` is reduced to length + sha256.
  * ``author.email`` is reduced to ``@domain`` only.
  * ``context.changedValues`` retain ONLY ``field`` names — the
    ``changedFrom`` / ``changedTo`` values are NOT stored. (Exception:
    restriction-direction detection inspects values in-flight to set the
    boolean ``has_restriction_decrease``, but the raw values are not
    persisted to evidence_data.)
  * ``associatedItems`` retain only count + ``type`` tally.
  * ``remoteAddress`` is reduced to a /16 IPv4 or /32 IPv6 hextet pattern.
    RFC1918, loopback, and link-local addresses are preserved verbatim.
  * ``userAgent`` keeps only the first 80 characters + sha256 of the full
    string (so identical UAs collide while not retaining the value).
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``atlassian-python-api``; Confluence audit-record
JSON exports are parsed with the standard library only.
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

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/confluence.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "confluence-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_EXPORT_SIZE_THRESHOLD = 50_000_000
_DEFAULT_BOT_VELOCITY_THRESHOLD = 30
_DEFAULT_BOT_VELOCITY_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_SPACE_THRESHOLD = 5
_DEFAULT_SUMMARY_TRUNCATE_CHARS = 200
_DEFAULT_USER_AGENT_PREFIX_CHARS = 80

# Restriction-direction tokens. We treat anything in this set as "more
# permissive" (i.e. fewer restrictions). When changedTo lands here from a
# changedFrom that does NOT, we flag a visibility increase — parallel to the
# Jira ``security_level_to_public`` logic.
_RESTRICTION_PERMISSIVE_VALUES: frozenset[str] = frozenset(
    {"", "none", "open", "public", "everyone", "anonymous", "anyone"}
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the confluence-aksi-controls.json mapping; tolerate missing file."""
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


def _classify_remote_address(remote_address: str | None) -> str | None:
    """Reduce a remoteAddress to a /16 IPv4 or /32-hextet IPv6 pattern."""
    if not remote_address or not isinstance(remote_address, str):
        return None
    ip = remote_address.strip()
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


def _redact_text(value: str | None) -> dict[str, Any] | None:
    """Capture length + sha256 of full text (NEVER store raw value)."""
    if not value or not isinstance(value, str):
        return None
    s = value
    if not s:
        return None
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return {"length": len(s), "sha256": digest}


def _redact_summary(summary: str | None, truncate: int) -> dict[str, Any] | None:
    """Truncate a summary to ``truncate`` chars; surface length + sha256."""
    if not summary or not isinstance(summary, str):
        return None
    s = summary
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return {
        "prefix": s[:truncate],
        "length": len(s),
        "sha256": digest,
    }


def _redact_user_agent(
    ua: str | None, prefix_chars: int
) -> dict[str, Any] | None:
    """Capture first ``prefix_chars`` chars + sha256 of full user-agent."""
    if not ua or not isinstance(ua, str):
        return None
    s = ua
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return {
        "prefix": s[:prefix_chars],
        "length": len(s),
        "sha256": digest,
    }


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


def _summary_lower(summary: str | None) -> str:
    return summary.lower() if isinstance(summary, str) else ""


def _summary_contains(summary: str | None, needle: str) -> bool:
    return needle.lower() in _summary_lower(summary)


def _normalize_token(value: Any) -> str:
    """Normalize a free-form audit-record token to lowercase trimmed string."""
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class ConfluenceImporter:
    """Parse a Confluence audit-record export and convert each record to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        export_size_threshold: int | None = None,
        bot_velocity_threshold: int | None = None,
        bot_velocity_window_seconds: int | None = None,
        cross_space_threshold: int | None = None,
        summary_truncate_chars: int | None = None,
        user_agent_prefix_chars: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        if export_size_threshold is not None:
            self.export_size_threshold = int(export_size_threshold)
        else:
            self.export_size_threshold = int(
                meta.get("export_size_threshold", _DEFAULT_EXPORT_SIZE_THRESHOLD)
            )
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
        if cross_space_threshold is not None:
            self.cross_space_threshold = int(cross_space_threshold)
        else:
            self.cross_space_threshold = int(
                meta.get("cross_space_threshold", _DEFAULT_CROSS_SPACE_THRESHOLD)
            )
        if summary_truncate_chars is not None:
            self.summary_truncate_chars = int(summary_truncate_chars)
        else:
            self.summary_truncate_chars = int(
                meta.get("summary_truncate_chars", _DEFAULT_SUMMARY_TRUNCATE_CHARS)
            )
        if user_agent_prefix_chars is not None:
            self.user_agent_prefix_chars = int(user_agent_prefix_chars)
        else:
            self.user_agent_prefix_chars = int(
                meta.get("user_agent_prefix_chars", _DEFAULT_USER_AGENT_PREFIX_CHARS)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Confluence audit-record export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Confluence audit-record content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"results": [...]}`` / ``{"events": [...]}`` / ``{"data": [...]}`` /
        JSONL / single record."""
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
                for key in ("results", "events", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [r for r in doc[key] if isinstance(r, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        records: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-record EvaluationResults plus bot-velocity / cross-space synthetics."""
        # Pass 1: aggregate per-bot-account edit timestamps and distinct space keys.
        author_spaces: dict[str, set[str]] = {}
        bot_edit_ts: dict[str, list[datetime]] = {}
        author_is_bot: dict[str, bool] = {}

        for rec in records:
            author = rec.get("author") or {}
            if not isinstance(author, dict):
                continue
            account_id = author.get("accountId")
            if not isinstance(account_id, str) or not account_id:
                continue
            is_bot = bool(author.get("isBot"))
            author_is_bot[account_id] = (
                author_is_bot.get(account_id, False) or is_bot
            )
            space_key = rec.get("spaceKey")
            if isinstance(space_key, str) and space_key:
                author_spaces.setdefault(account_id, set()).add(space_key)
            if is_bot:
                ts = _parse_iso_timestamp(rec.get("creationDate"))
                if ts is not None:
                    bot_edit_ts.setdefault(account_id, []).append(ts)

        cross_space_actors: dict[str, int] = {
            account: len(spaces)
            for account, spaces in author_spaces.items()
            if author_is_bot.get(account, False)
            and len(spaces) > self.cross_space_threshold
        }

        bot_velocity_actors: dict[str, int] = {}
        window = self.bot_velocity_window_seconds
        for account, timestamps in bot_edit_ts.items():
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
                bot_velocity_actors[account] = max_in_window

        results = [
            self._parse_record(
                rec,
                file_sha256=file_sha256,
                cross_space_actors=cross_space_actors,
                bot_velocity_actors=bot_velocity_actors,
            )
            for rec in records
        ]

        for account, count in sorted(bot_velocity_actors.items()):
            results.append(
                self._synthetic_bot_velocity_result(
                    account=account,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for account, space_count in sorted(cross_space_actors.items()):
            results.append(
                self._synthetic_cross_space_result(
                    account=account,
                    space_count=space_count,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "confluence_audit_record",
            "source_tool_name": "confluence",
            "source_tool_version": "",
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-record parsing
    # ------------------------------------------------------------------

    def _parse_record(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_space_actors: dict[str, int],
        bot_velocity_actors: dict[str, int],
    ) -> EvaluationResult:
        record_id = str(record.get("id") or uuid.uuid4())
        category = _normalize_token(record.get("category"))
        summary_raw = record.get("summary")
        summary = summary_raw if isinstance(summary_raw, str) else ""
        timestamp = _format_timestamp(record.get("creationDate"))

        subject_type = _normalize_token(record.get("subjectType")) or None
        subject_id = (
            str(record.get("subjectId"))
            if isinstance(record.get("subjectId"), (str, int))
            and str(record.get("subjectId"))
            else None
        )
        subject_name_redacted = _redact_text(
            record.get("subjectName")
            if isinstance(record.get("subjectName"), str)
            else None
        )
        space_key = (
            str(record.get("spaceKey"))
            if isinstance(record.get("spaceKey"), str) and record.get("spaceKey")
            else None
        )

        # author block
        author = record.get("author") or {}
        if not isinstance(author, dict):
            author = {}
        author_account_id = (
            str(author.get("accountId"))
            if isinstance(author.get("accountId"), str) and author.get("accountId")
            else None
        )
        author_type = _normalize_token(author.get("type")) or None
        author_is_bot = bool(author.get("isBot"))
        author_display_name_redacted = _redact_text(
            author.get("displayName")
            if isinstance(author.get("displayName"), str)
            else None
        )
        author_email_domain = _redact_email(
            author.get("email")
            if isinstance(author.get("email"), str)
            else None
        )

        action_from_author = _normalize_token(record.get("actionFromAuthor")) or None
        is_automated_action = bool(record.get("isAutomatedAction"))

        remote_address_redacted = _classify_remote_address(
            record.get("remoteAddress")
            if isinstance(record.get("remoteAddress"), str)
            else None
        )
        user_agent_redacted = _redact_user_agent(
            record.get("userAgent")
            if isinstance(record.get("userAgent"), str)
            else None,
            self.user_agent_prefix_chars,
        )
        summary_redacted = _redact_summary(summary, self.summary_truncate_chars)

        # context.changedValues (field names only)
        context = record.get("context") or {}
        if not isinstance(context, dict):
            context = {}
        changed_values_raw = context.get("changedValues") or []
        changed_field_names: list[str] = []
        has_restriction_change = False
        has_restriction_decrease = False
        if isinstance(changed_values_raw, list):
            for cv in changed_values_raw:
                if not isinstance(cv, dict):
                    continue
                field_name_raw = cv.get("field")
                if not isinstance(field_name_raw, str):
                    continue
                field_name = field_name_raw.strip()
                if not field_name:
                    continue
                changed_field_names.append(field_name)
                fn_lower = field_name.lower()
                if "restriction" in fn_lower:
                    has_restriction_change = True
                    # Inspect (in-flight only) the changedTo / changedFrom to
                    # infer whether the restriction set became more permissive.
                    # Raw values are NOT persisted to evidence_data.
                    changed_to = cv.get("changedTo")
                    changed_from = cv.get("changedFrom")
                    to_str = (
                        str(changed_to).strip().lower()
                        if isinstance(changed_to, str)
                        else ""
                    )
                    from_str = (
                        str(changed_from).strip().lower()
                        if isinstance(changed_from, str)
                        else ""
                    )
                    if (
                        to_str in _RESTRICTION_PERMISSIVE_VALUES
                        and from_str
                        and from_str not in _RESTRICTION_PERMISSIVE_VALUES
                    ):
                        has_restriction_decrease = True

        changed_values_count = len(changed_field_names)

        # associatedItems — count + per-type tally only
        associated_items_raw = record.get("associatedItems") or []
        associated_count = 0
        associated_type_tally: dict[str, int] = {}
        if isinstance(associated_items_raw, list):
            for item in associated_items_raw:
                if not isinstance(item, dict):
                    continue
                associated_count += 1
                tn_raw = item.get("type")
                tn = (
                    str(tn_raw).strip().lower()
                    if isinstance(tn_raw, str) and tn_raw.strip()
                    else "unknown"
                )
                associated_type_tally[tn] = associated_type_tally.get(tn, 0) + 1

        # export size — Confluence audit records can attach a size field on the
        # context for export events, e.g. ``context.exportSizeBytes`` or
        # ``context.size``. We probe both, conservatively cast to int.
        export_size_raw = (
            context.get("exportSizeBytes")
            if isinstance(context.get("exportSizeBytes"), (int, float))
            else context.get("size")
            if isinstance(context.get("size"), (int, float))
            else None
        )
        export_size_bytes: int | None = (
            int(export_size_raw) if isinstance(export_size_raw, (int, float)) else None
        )

        # space type (for permission_scheme_public_space)
        space_type = _normalize_token(context.get("spaceType")) or None

        # group permissions list (for group_admin_added_to_space)
        group_permissions_raw = context.get("permissions") or []
        group_permission_tokens = (
            [str(p).strip().lower() for p in group_permissions_raw if isinstance(p, str)]
            if isinstance(group_permissions_raw, list)
            else []
        )
        has_admin_permission = any(
            "admin" in p for p in group_permission_tokens
        )

        common_evidence: dict[str, Any] = {
            "confluence_record_id": record_id,
            "category": category or None,
            "summary": summary_redacted,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "subject_name_redacted": subject_name_redacted,
            "space_key": space_key,
            "author_account_id": author_account_id,
            "author_type": author_type,
            "author_is_bot": author_is_bot,
            "author_display_name_redacted": author_display_name_redacted,
            "author_email_domain": author_email_domain,
            "action_from_author": action_from_author,
            "is_automated_action": is_automated_action,
            "remote_address_redacted": remote_address_redacted,
            "user_agent_redacted": user_agent_redacted,
            "changed_value_field_names": changed_field_names,
            "changed_values_count": changed_values_count,
            "has_restriction_change": has_restriction_change,
            "has_restriction_decrease": has_restriction_decrease,
            "associated_items_count": associated_count,
            "associated_items_type_tally": associated_type_tally,
            "export_size_bytes": export_size_bytes,
            "space_type": space_type,
            "has_admin_permission": has_admin_permission,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=record_id
            ),
            "source_tool": "confluence",
        }

        control_results: list[ControlResult] = []

        # ------------------------------------------------------------------
        # 1. actionFromAuthor — fires regardless of category.
        # ------------------------------------------------------------------
        if action_from_author == "anonymous":
            control_results.append(
                self._cr(
                    signal="anonymous_action",
                    default="PR-01",
                    result="FAIL",
                    detail=(
                        f"Confluence record {record_id} actionFromAuthor=anonymous "
                        f"on category={category!r} — anonymous action cannot be "
                        f"attributed to an identity"
                    ),
                    common_evidence=common_evidence,
                )
            )
        elif action_from_author == "applink":
            control_results.append(
                self._cr(
                    signal="app_link_action",
                    default="PR-01",
                    result="FLAG",
                    detail=(
                        f"Confluence record {record_id} actionFromAuthor=appLink "
                        f"on category={category!r} — app-driven action; verify "
                        f"the app's identity and authorization"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 2. Category-driven primary signals.
        # ------------------------------------------------------------------
        if category == "page":
            if _summary_contains(summary, "page created") and author_is_bot:
                control_results.append(
                    self._cr(
                        signal="page_created_by_bot",
                        default="PR-01",
                        result="FLAG",
                        detail=(
                            f"Confluence record {record_id} page.created by bot "
                            f"author {author_account_id or 'unknown'} on space="
                            f"{space_key or 'unknown'} — agent-created knowledge, "
                            f"surface for human review"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if _summary_contains(summary, "page deleted") and author_is_bot:
                control_results.append(
                    self._cr(
                        signal="page_deleted_by_bot",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"Confluence record {record_id} page.deleted by bot "
                            f"author {author_account_id or 'unknown'} on space="
                            f"{space_key or 'unknown'} — bot deleting knowledge "
                            f"destroys audit trail unless explicitly approved"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if (
                _summary_contains(summary, "page exported as pdf")
                or _summary_contains(summary, "page exported as html")
                or _summary_contains(summary, "page exported")
            ):
                if (
                    export_size_bytes is not None
                    and export_size_bytes > self.export_size_threshold
                ):
                    control_results.append(
                        self._cr(
                            signal="page_export_large",
                            default="PR-04",
                            result="FAIL",
                            detail=(
                                f"Confluence record {record_id} page export "
                                f"size={export_size_bytes}B exceeds threshold "
                                f"{self.export_size_threshold}B — bulk export = "
                                f"mass exfiltration surface"
                            ),
                            common_evidence=common_evidence,
                        )
                    )
                else:
                    control_results.append(
                        self._cr(
                            signal="page_export",
                            default="PR-04",
                            result="FLAG",
                            detail=(
                                f"Confluence record {record_id} page exported "
                                f"on space={space_key or 'unknown'} — data "
                                f"leaving system, surface for review"
                            ),
                            common_evidence=common_evidence,
                        )
                    )
            if (
                _summary_contains(summary, "restrictions removed")
                or has_restriction_decrease
            ):
                control_results.append(
                    self._cr(
                        signal="restrictions_removed",
                        default="PR-04",
                        result="FAIL",
                        detail=(
                            f"Confluence record {record_id} restriction removal "
                            f"on subject={subject_id or 'unknown'} space="
                            f"{space_key or 'unknown'} — visibility increase is "
                            f"a potential data-exposure event"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if is_automated_action:
                control_results.append(
                    self._cr(
                        signal="automated_page_event",
                        default="PR-05",
                        result="PASS",
                        detail=(
                            f"Confluence record {record_id} automated page "
                            f"event on space={space_key or 'unknown'} — "
                            f"automation audit captured"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        if category == "permissions":
            if _summary_contains(summary, "anonymous access enabled"):
                control_results.append(
                    self._cr(
                        signal="anonymous_access_enabled",
                        default="DE-01",
                        result="FAIL",
                        detail=(
                            f"Confluence record {record_id} anonymous access "
                            f"enabled on space={space_key or 'unknown'} — "
                            f"public space is an exfiltration surface"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            elif (
                _summary_contains(summary, "permission scheme updated")
                and space_type == "public"
            ):
                control_results.append(
                    self._cr(
                        signal="permission_scheme_public_space",
                        default="PR-02",
                        result="FLAG",
                        detail=(
                            f"Confluence record {record_id} permission scheme "
                            f"update on public space={space_key or 'unknown'} "
                            f"— review who/which projects affected"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        if category == "space":
            if _summary_contains(summary, "space archived"):
                control_results.append(
                    self._cr(
                        signal="space_archived",
                        default="PR-05",
                        result="PASS",
                        detail=(
                            f"Confluence record {record_id} space archived "
                            f"({space_key or 'unknown'}) — audit-trail captured"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            elif _summary_contains(summary, "space deleted"):
                control_results.append(
                    self._cr(
                        signal="space_deleted",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"Confluence record {record_id} space deleted "
                            f"({space_key or 'unknown'}) — space destruction "
                            f"removes audit context for every page within"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        if (
            category == "user"
            and _summary_contains(summary, "user added to organization")
            and author_type == "applink"
        ):
            control_results.append(
                self._cr(
                    signal="app_link_user_added",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Confluence record {record_id} user added to "
                        f"organization by appLink author "
                        f"{author_account_id or 'unknown'} — programmatic "
                        f"user provisioning warrants review"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if (
            category == "group"
            and _summary_contains(summary, "group added to space")
            and has_admin_permission
        ):
            control_results.append(
                self._cr(
                    signal="group_admin_added_to_space",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Confluence record {record_id} group added to "
                        f"space={space_key or 'unknown'} with admin "
                        f"permissions — space-admin grant requires "
                        f"governance review"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 3. Velocity / cross-space pattern markers (informational on
        #    contributing records; the synthetic per-account finding is added
        #    separately).
        # ------------------------------------------------------------------
        if author_account_id and author_account_id in bot_velocity_actors:
            count = bot_velocity_actors[author_account_id]
            control_results.append(
                self._cr(
                    signal="bot_velocity_pattern",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Confluence record {record_id} author "
                        f"{author_account_id!r} is part of a bot-velocity "
                        f"pattern ({count} edits > threshold "
                        f"{self.bot_velocity_threshold} in "
                        f"{self.bot_velocity_window_seconds}s window)"
                    ),
                    common_evidence={
                        **common_evidence,
                        "bot_velocity_count": count,
                        "bot_velocity_threshold": self.bot_velocity_threshold,
                        "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
                    },
                )
            )
        if author_account_id and author_account_id in cross_space_actors:
            space_count = cross_space_actors[author_account_id]
            control_results.append(
                self._cr(
                    signal="cross_space_pattern",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Confluence record {record_id} author "
                        f"{author_account_id!r} is part of a cross-space "
                        f"pattern ({space_count} distinct spaces > threshold "
                        f"{self.cross_space_threshold})"
                    ),
                    common_evidence={
                        **common_evidence,
                        "cross_space_space_count": space_count,
                        "cross_space_threshold": self.cross_space_threshold,
                    },
                )
            )

        # ------------------------------------------------------------------
        # Fallback — nothing matched, captured as PR-05 PASS.
        # ------------------------------------------------------------------
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Confluence record {record_id} category={category!r} "
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
            f"Imported from Confluence audit record: category={category or 'unknown'} "
            f"author_account_id={author_account_id or 'unknown'} "
            f"author_type={author_type or 'unknown'} "
            f"author_is_bot={author_is_bot} "
            f"action_from_author={action_from_author or 'unknown'} "
            f"space={space_key or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"confluence-{record_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="confluence_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=space_key,
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

    def _synthetic_bot_velocity_result(
        self,
        *,
        account: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-bot velocity pattern finding."""
        signal = "bot_velocity_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"confluence-bot-velocity-{account}"
        evidence: dict[str, Any] = {
            "confluence_record_id": synthetic_id,
            "author_account_id": account,
            "author_is_bot": True,
            "bot_velocity_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "confluence",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Confluence synthetic finding: bot {account} performed {count} "
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
            source_type="confluence_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Confluence audit record: synthetic bot-velocity "
                f"pattern for account={account} count={count}>threshold="
                f"{self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=account or None,
        )

    def _synthetic_cross_space_result(
        self,
        *,
        account: str,
        space_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-bot cross-space pattern finding."""
        signal = "cross_space_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"confluence-cross-space-{account}"
        evidence: dict[str, Any] = {
            "confluence_record_id": synthetic_id,
            "author_account_id": account,
            "author_is_bot": True,
            "cross_space_space_count": space_count,
            "cross_space_threshold": self.cross_space_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "confluence",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Confluence synthetic finding: bot {account} touched "
                f"{space_count} distinct spaces in this export — exceeds "
                f"cross-space threshold {self.cross_space_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="confluence_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Confluence audit record: synthetic cross-space "
                f"pattern for account={account} spaces={space_count}>threshold="
                f"{self.cross_space_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=account or None,
        )
