"""Jira audit-record importer — maps agent project-management activity to AKSI controls.

Atlassian Jira (https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-audit-records/)
is the dominant project-management tool in enterprise: agents file tickets,
transition statuses, change permissions, and run automation rules. Jira's
``/rest/api/3/auditing/record`` endpoint records every project, permission,
workflow, user, and configuration change with the actor account, event source,
and a structured ``changedValues`` diff. For agents that operate inside a
customer's Jira tenant, this audit feed is the canonical evidence source: it
captures *what* the agent did, *which* objects it touched, and *whether* the
action was automation-driven.

This importer ingests audit-record exports in four on-disk shapes:

  1. ``{"records": [...]}`` — primary auditing-records envelope
  2. ``{"events":  [...]}`` — generic events envelope
  3. ``{"data":    [...]}`` — generic data envelope
  4. JSONL                  — one record per line

Signal mapping (see shared/mappings/jira-aksi-controls.json):
  * category=``user management`` summary "User created"           → PR-01 FLAG
  * category=``user management`` summary "User deleted"           → PR-05 PASS
  * category=``user management`` summary "User permissions ..."   → PR-02 FLAG
  * category=``permissions`` summary "Global permission ..."      → PR-02 FAIL
  * category=``permissions`` summary "Project permission scheme"  → PR-02 FLAG
  * category=``workflows`` summary "Workflow scheme updated" +
    isAutomatedAction=true                                        → PR-05 FLAG
  * category=``workflows`` summary "Workflow scheme deleted"      → PR-02 FAIL
  * category=``configuration`` "Server configuration updated"     → PR-02 FLAG
  * category=``auto-configuration``                               → PR-05 PASS
  * category=``issue`` author bot, summary "Issue created"        → PR-01 FLAG
  * category=``issue`` summary "Issue deleted" + active sprint    → PR-02 FAIL
  * category=``issue`` summary "Issue cloned" by bot              → PR-05 FLAG
  * eventSource=``AUTOMATION``                                    → PR-05 PASS
  * eventSource=``API``                                           → captured (PR-05 PASS)
  * isAutomatedAction=true                                        → PR-05 PASS
  * changedValues "Issue Security Level" → "Public" (or restrictive removed)
                                                                  → PR-04 FAIL
  * changedValues "Reporter" change post-creation                 → PR-05 FLAG
  * objectItem.typeName=PERMISSION_SCHEME with non-empty
    changedValues                                                 → PR-02 FLAG
  * Bot-velocity: bot authorAccountId creating > N issues in 1h   → PR-02 FLAG
  * Cross-project: same authorAccountId touching > N projects     → PR-02 FLAG

Sanitization (security-critical — Jira audit records are operator-generated and
generally trustworthy, but ``description``/``summary``/``changedValues`` can
carry tenant identifiers, customer names, or even free-text incident detail
that should not be retained verbatim by the evidence layer):

  * ``summary`` is truncated to 200 chars and accompanied by a sha256 of the
    full string and the full length. Identical summaries collide; the full
    text is recoverable only from the original Jira tenant.
  * ``description`` is NEVER stored as text — only its length and sha256.
  * ``changedValues`` retain ONLY the ``fieldName``s, plus a count and a
    boolean ``has_security_level_change`` / ``has_reporter_change`` /
    ``has_visibility_increase``. The ``changedFrom`` / ``changedTo`` values
    are NOT stored. (Exception: visibility-increase detection inspects
    ``changedTo`` in-flight to set the boolean, but the raw value is not
    persisted to evidence.)
  * ``associatedItems`` retain only ``typeName``s.
  * ``objectItem`` retains ``typeName`` and ``parentId`` only — ``name`` /
    ``id`` are kept (these are Jira-managed structured identifiers).
  * ``remoteAddress`` is reduced to a /16 IPv4 or /32 IPv6 hextet pattern.
    RFC1918, loopback, and link-local IPs are preserved verbatim.
  * ``authorKey`` and ``authorAccountId`` are kept verbatim (Atlassian-issued
    opaque IDs, no PII in their structure).
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``atlassian-python-api``; Jira audit-record JSON
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


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/jira.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "jira-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_BOT_ACCOUNT_PATTERNS: tuple[str, ...] = (
    "*[bot]*",
    "*-bot",
    "bot-*",
    "automation*",
    "agent-*",
    "*-agent",
    "557058:agent-*",
    "557058:bot-*",
)
_DEFAULT_BOT_VELOCITY_THRESHOLD = 20
_DEFAULT_BOT_VELOCITY_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_PROJECT_THRESHOLD = 10
_DEFAULT_SUMMARY_TRUNCATE_CHARS = 200

# Granted-state markers Jira uses in summary text for global-permission events.
_GLOBAL_PERMISSION_GRANT_MARKERS: tuple[str, ...] = (
    "granted",
    "added",
    "created",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the jira-aksi-controls.json mapping; tolerate missing file."""
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


def _redact_description(description: str | None) -> dict[str, Any] | None:
    """Description text is never stored — only length + sha256."""
    if not description or not isinstance(description, str):
        return None
    return {
        "length": len(description),
        "sha256": hashlib.sha256(description.encode("utf-8")).hexdigest(),
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


def _account_matches_bot(
    account_id: str | None, patterns: Iterable[str]
) -> bool:
    """Return True if ``account_id`` matches any bot account pattern.

    A pattern containing literal square brackets (e.g. ``*[bot]*``) is treated
    as a substring match against ``[bot]`` rather than being passed through to
    :func:`fnmatch.fnmatchcase` — fnmatch interprets ``[...]`` as a character
    class, which would over-match real account IDs (any account containing
    one of the bracketed characters would match). All other patterns are
    standard glob patterns.
    """
    if not account_id:
        return False
    aid = account_id.strip().lower()
    if not aid:
        return False
    for pattern in patterns:
        p = pattern.lower()
        if "[" in p and "]" in p:
            # Treat the bracketed portion as a literal substring needle.
            start = p.index("[")
            end = p.index("]") + 1
            needle = p[start:end]
            if needle and needle in aid:
                return True
            continue
        if fnmatch.fnmatchcase(aid, p):
            return True
    return False


def _summary_lower(summary: str | None) -> str:
    return summary.lower() if isinstance(summary, str) else ""


def _summary_contains(summary: str | None, needle: str) -> bool:
    return needle.lower() in _summary_lower(summary)


def _is_global_permission_grant(summary: str | None) -> bool:
    """`Global permission ... granted/added/created` → grant event."""
    s = _summary_lower(summary)
    if "global permission" not in s:
        return False
    return any(marker in s for marker in _GLOBAL_PERMISSION_GRANT_MARKERS)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class JiraImporter:
    """Parse a Jira audit-record export and convert each record to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        bot_account_patterns: Iterable[str] | None = None,
        bot_velocity_threshold: int | None = None,
        bot_velocity_window_seconds: int | None = None,
        cross_project_threshold: int | None = None,
        summary_truncate_chars: int | None = None,
        active_sprint_issue_ids: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Bot-account patterns: explicit arg > mapping metadata > default.
        if bot_account_patterns is not None:
            self.bot_account_patterns: tuple[str, ...] = tuple(
                str(p) for p in bot_account_patterns
            )
        else:
            meta_bot = meta.get("bot_account_patterns")
            if isinstance(meta_bot, list) and meta_bot:
                self.bot_account_patterns = tuple(str(p) for p in meta_bot)
            else:
                self.bot_account_patterns = _DEFAULT_BOT_ACCOUNT_PATTERNS
        # Bot-velocity threshold and window.
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
        # Cross-project threshold.
        if cross_project_threshold is not None:
            self.cross_project_threshold = int(cross_project_threshold)
        else:
            self.cross_project_threshold = int(
                meta.get("cross_project_threshold", _DEFAULT_CROSS_PROJECT_THRESHOLD)
            )
        # Summary truncation length.
        if summary_truncate_chars is not None:
            self.summary_truncate_chars = int(summary_truncate_chars)
        else:
            self.summary_truncate_chars = int(
                meta.get("summary_truncate_chars", _DEFAULT_SUMMARY_TRUNCATE_CHARS)
            )
        # Active-sprint issue IDs (operator-supplied; engine territory). When an
        # issue deletion targets one of these IDs we treat it as active-sprint
        # destruction and FAIL the record.
        if active_sprint_issue_ids is not None:
            self.active_sprint_issue_ids: frozenset[str] = frozenset(
                str(x) for x in active_sprint_issue_ids
            )
        else:
            self.active_sprint_issue_ids = frozenset()

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Jira audit-record export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Jira audit-record content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"records": [...]}`` / ``{"events": [...]}`` / ``{"data": [...]}`` /
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
                for key in ("records", "events", "data"):
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
        """Build per-record EvaluationResults plus bot-velocity / cross-project synthetics."""
        # Pass 1: aggregate (account, project) for cross-project and
        # (bot-account, issue-create timestamp) for bot-velocity.
        account_projects: dict[str, set[str]] = {}
        account_is_bot: dict[str, bool] = {}
        bot_issue_create_ts: dict[str, list[datetime]] = {}

        for rec in records:
            account = rec.get("authorAccountId")
            if not isinstance(account, str) or not account:
                continue
            is_bot = _account_matches_bot(account, self.bot_account_patterns)
            account_is_bot[account] = account_is_bot.get(account, False) or is_bot

            project_id = self._project_id_from_record(rec)
            if project_id:
                account_projects.setdefault(account, set()).add(project_id)

            category = str(rec.get("category") or "").strip().lower()
            summary = rec.get("summary")
            if (
                is_bot
                and category == "issue"
                and _summary_contains(summary, "issue created")
            ):
                ts = _parse_iso_timestamp(rec.get("created"))
                if ts is not None:
                    bot_issue_create_ts.setdefault(account, []).append(ts)

        cross_project_accounts: dict[str, list[str]] = {
            account: sorted(projects)
            for account, projects in account_projects.items()
            if len(projects) > self.cross_project_threshold
        }

        bot_velocity_accounts: dict[str, int] = {}
        window = self.bot_velocity_window_seconds
        for account, timestamps in bot_issue_create_ts.items():
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
                bot_velocity_accounts[account] = max_in_window

        results = [
            self._parse_record(
                rec,
                file_sha256=file_sha256,
                cross_project_accounts=cross_project_accounts,
                bot_velocity_accounts=bot_velocity_accounts,
            )
            for rec in records
        ]

        for account, projects in sorted(cross_project_accounts.items()):
            results.append(
                self._synthetic_cross_project_result(
                    account=account,
                    is_bot=account_is_bot.get(account, False),
                    projects=projects,
                    file_sha256=file_sha256,
                )
            )
        for account, count in sorted(bot_velocity_accounts.items()):
            results.append(
                self._synthetic_bot_velocity_result(
                    account=account,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _project_id_from_record(self, record: dict[str, Any]) -> str | None:
        """Resolve the project id this audit record touches (best effort).

        Strategy:
          1. ``objectItem.parentId`` when ``objectItem.typeName == PROJECT`` or
             when the object lives under a project (ISSUE, PERMISSION_SCHEME).
          2. associatedItems entry with ``typeName == "PROJECT"`` → its ``id``.
        """
        obj = record.get("objectItem")
        if isinstance(obj, dict):
            type_name = str(obj.get("typeName") or "").upper()
            obj_id = obj.get("id")
            parent_id = obj.get("parentId")
            if type_name == "PROJECT" and isinstance(obj_id, (str, int)):
                return str(obj_id)
            if isinstance(parent_id, (str, int)) and str(parent_id):
                return str(parent_id)
        associated = record.get("associatedItems")
        if isinstance(associated, list):
            for item in associated:
                if not isinstance(item, dict):
                    continue
                if str(item.get("typeName") or "").upper() == "PROJECT":
                    iid = item.get("id")
                    if isinstance(iid, (str, int)) and str(iid):
                        return str(iid)
        return None

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "jira_audit_record",
            "source_tool_name": "jira",
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
        cross_project_accounts: dict[str, list[str]],
        bot_velocity_accounts: dict[str, int],
    ) -> EvaluationResult:
        record_id = str(record.get("id") or uuid.uuid4())
        category = str(record.get("category") or "").strip().lower()
        summary_raw = record.get("summary")
        summary = summary_raw if isinstance(summary_raw, str) else ""
        timestamp = _format_timestamp(record.get("created"))
        author_key = (
            str(record.get("authorKey"))
            if isinstance(record.get("authorKey"), str)
            else None
        )
        author_account_id = (
            str(record.get("authorAccountId"))
            if isinstance(record.get("authorAccountId"), str)
            else None
        )
        author_is_bot = _account_matches_bot(
            author_account_id, self.bot_account_patterns
        )
        event_source_raw = record.get("eventSource")
        event_source = (
            str(event_source_raw).strip().upper()
            if isinstance(event_source_raw, str) and event_source_raw.strip()
            else None
        )
        is_automated_action = bool(record.get("isAutomatedAction"))

        object_item = record.get("objectItem")
        if not isinstance(object_item, dict):
            object_item = {}
        object_type = (
            str(object_item.get("typeName")).upper()
            if isinstance(object_item.get("typeName"), str)
            else None
        )
        object_id = (
            str(object_item.get("id"))
            if isinstance(object_item.get("id"), (str, int))
            else None
        )
        object_parent_id = (
            str(object_item.get("parentId"))
            if isinstance(object_item.get("parentId"), (str, int))
            else None
        )

        changed_values_raw = record.get("changedValues") or []
        changed_field_names: list[str] = []
        has_security_level_change = False
        has_visibility_increase = False
        has_reporter_change = False
        if isinstance(changed_values_raw, list):
            for cv in changed_values_raw:
                if not isinstance(cv, dict):
                    continue
                field_name_raw = cv.get("fieldName")
                if not isinstance(field_name_raw, str):
                    continue
                field_name = field_name_raw.strip()
                if not field_name:
                    continue
                changed_field_names.append(field_name)
                fn_lower = field_name.lower()
                if "security level" in fn_lower or fn_lower == "issue security level":
                    has_security_level_change = True
                    # Inspect (in-flight only) the changedTo + changedFrom to
                    # determine whether visibility increased. The raw values
                    # are NOT persisted to evidence_data.
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
                    permissive = {"public", "none", "", "everyone"}
                    if (
                        to_str in permissive
                        and from_str
                        and from_str not in permissive
                    ) or ("public" in to_str and "public" not in from_str):
                        has_visibility_increase = True
                if fn_lower == "reporter":
                    has_reporter_change = True
        changed_values_count = len(changed_field_names)

        associated_items_raw = record.get("associatedItems") or []
        associated_type_names: list[str] = []
        if isinstance(associated_items_raw, list):
            for item in associated_items_raw:
                if not isinstance(item, dict):
                    continue
                tn = item.get("typeName")
                if isinstance(tn, str) and tn.strip():
                    associated_type_names.append(tn.strip())

        remote_address_redacted = _classify_remote_address(
            record.get("remoteAddress")
            if isinstance(record.get("remoteAddress"), str)
            else None
        )
        summary_redacted = _redact_summary(summary, self.summary_truncate_chars)
        description_redacted = _redact_description(
            record.get("description")
            if isinstance(record.get("description"), str)
            else None
        )

        common_evidence: dict[str, Any] = {
            "jira_record_id": record_id,
            "category": category or None,
            "summary": summary_redacted,
            "description": description_redacted,
            "author_key": author_key,
            "author_account_id": author_account_id,
            "author_is_bot": author_is_bot,
            "event_source": event_source,
            "is_automated_action": is_automated_action,
            "object_item_type": object_type,
            "object_item_id": object_id,
            "object_item_parent_id": object_parent_id,
            "changed_value_field_names": changed_field_names,
            "changed_values_count": changed_values_count,
            "has_security_level_change": has_security_level_change,
            "has_visibility_increase": has_visibility_increase,
            "has_reporter_change": has_reporter_change,
            "associated_item_type_names": associated_type_names,
            "remote_address_redacted": remote_address_redacted,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=record_id
            ),
            "source_tool": "jira",
        }

        control_results: list[ControlResult] = []

        # ------------------------------------------------------------------
        # 1. Category-driven primary signals.
        # ------------------------------------------------------------------
        if category == "user management":
            if _summary_contains(summary, "user created"):
                control_results.append(
                    self._cr(
                        signal="user_created",
                        default="PR-01",
                        result="FLAG",
                        detail=(
                            f"Jira record {record_id} user provisioning event — "
                            f"verify approval (account_id={author_account_id!r})"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            elif _summary_contains(summary, "user deleted"):
                control_results.append(
                    self._cr(
                        signal="user_deleted",
                        default="PR-05",
                        result="PASS",
                        detail=(
                            f"Jira record {record_id} user deletion recorded — "
                            f"audit trail present"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            elif _summary_contains(summary, "user permissions") or _summary_contains(
                summary, "permissions updated"
            ):
                control_results.append(
                    self._cr(
                        signal="user_permission_change",
                        default="PR-02",
                        result="FLAG",
                        detail=(
                            f"Jira record {record_id} user-permission change — "
                            f"privilege change requires governance review"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        if category == "permissions":
            if _is_global_permission_grant(summary):
                control_results.append(
                    self._cr(
                        signal="global_permission_grant",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"Jira record {record_id} global permission grant — "
                            f"org-level permission grants need governance approval"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            elif _summary_contains(summary, "project permission scheme"):
                control_results.append(
                    self._cr(
                        signal="project_permission_scheme_change",
                        default="PR-02",
                        result="FLAG",
                        detail=(
                            f"Jira record {record_id} project permission-scheme "
                            f"change — review who/which projects affected"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        if category == "workflows":
            if _summary_contains(summary, "workflow scheme deleted"):
                control_results.append(
                    self._cr(
                        signal="workflow_scheme_deleted",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"Jira record {record_id} workflow scheme deletion — "
                            f"workflow destruction undermines downstream evidence"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            elif (
                _summary_contains(summary, "workflow scheme updated")
                and is_automated_action
            ):
                control_results.append(
                    self._cr(
                        signal="workflow_scheme_automated_update",
                        default="PR-05",
                        result="FLAG",
                        detail=(
                            f"Jira record {record_id} workflow scheme updated by "
                            f"automated action — verify automation provenance"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        if category == "configuration" and _summary_contains(
            summary, "server configuration updated"
        ):
            control_results.append(
                self._cr(
                    signal="server_configuration_updated",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Jira record {record_id} server-level configuration change "
                        f"— system-wide configuration drift surface"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if category == "auto-configuration":
            control_results.append(
                self._cr(
                    signal="auto_configuration",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Jira record {record_id} auto-configuration event — "
                        f"automation audit trail recorded"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if category == "issue":
            issue_created = _summary_contains(summary, "issue created")
            issue_deleted = _summary_contains(summary, "issue deleted")
            issue_cloned = _summary_contains(summary, "issue cloned")
            if issue_created and author_is_bot:
                control_results.append(
                    self._cr(
                        signal="agent_authored_issue",
                        default="PR-01",
                        result="FLAG",
                        detail=(
                            f"Jira record {record_id} issue creation by bot/agent "
                            f"account {author_account_id!r} — surface for review"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if (
                issue_deleted
                and object_type == "ISSUE"
                and object_id is not None
                and object_id in self.active_sprint_issue_ids
            ):
                control_results.append(
                    self._cr(
                        signal="active_sprint_issue_deleted",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"Jira record {record_id} issue deletion targeted "
                            f"in-active-sprint issue id={object_id!r} — deleting an "
                            f"in-flight sprint issue destroys audit context"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if issue_cloned and author_is_bot:
                control_results.append(
                    self._cr(
                        signal="bot_issue_clone",
                        default="PR-05",
                        result="FLAG",
                        detail=(
                            f"Jira record {record_id} issue clone by bot/agent "
                            f"account {author_account_id!r} — bot duplication "
                            f"warrants review"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        # ------------------------------------------------------------------
        # 2. Object-type / changedValues additive signals.
        # ------------------------------------------------------------------
        if object_type == "PERMISSION_SCHEME" and changed_values_count > 0:
            control_results.append(
                self._cr(
                    signal="permission_scheme_change",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Jira record {record_id} permission-scheme object "
                        f"changed (fields={changed_field_names!r}) — "
                        f"permission-model change surface"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if has_security_level_change and has_visibility_increase:
            control_results.append(
                self._cr(
                    signal="security_level_to_public",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Jira record {record_id} Issue Security Level changed "
                        f"to a more permissive (public/none) value — visibility "
                        f"increase is a potential data-exposure event"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if has_reporter_change and category == "issue" and not _summary_contains(
            summary, "issue created"
        ):
            control_results.append(
                self._cr(
                    signal="reporter_post_creation_change",
                    default="PR-05",
                    result="FLAG",
                    detail=(
                        f"Jira record {record_id} Reporter field changed after "
                        f"issue creation — audit-completeness anomaly"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 3. Event-source / automation provenance (additive PASS/captures).
        # ------------------------------------------------------------------
        if event_source == "AUTOMATION":
            control_results.append(
                self._cr(
                    signal="automation_event",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Jira record {record_id} eventSource=AUTOMATION — "
                        f"Jira Automation audit trail captured"
                    ),
                    common_evidence=common_evidence,
                )
            )
        elif event_source == "API":
            control_results.append(
                self._cr(
                    signal="api_event",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Jira record {record_id} eventSource=API — "
                        f"third-party integration action captured "
                        f"(account={author_account_id!r})"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if is_automated_action and event_source != "AUTOMATION":
            # Automation-flag without explicit AUTOMATION source — still
            # capture as audit evidence but distinct from category-specific
            # flags above (e.g. workflow_scheme_automated_update).
            control_results.append(
                self._cr(
                    signal="automated_action",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Jira record {record_id} isAutomatedAction=true — "
                        f"automation provenance captured"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 4. Cross-project / bot-velocity informational markers.
        # ------------------------------------------------------------------
        if author_account_id and author_account_id in cross_project_accounts:
            projects = cross_project_accounts[author_account_id]
            control_results.append(
                self._cr(
                    signal="cross_project_pattern",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Jira record {record_id} author {author_account_id!r} "
                        f"is part of a cross-project pattern "
                        f"({len(projects)} projects > "
                        f"threshold {self.cross_project_threshold})"
                    ),
                    common_evidence={
                        **common_evidence,
                        "cross_project_projects": projects,
                        "cross_project_threshold": self.cross_project_threshold,
                    },
                )
            )

        if author_account_id and author_account_id in bot_velocity_accounts:
            count = bot_velocity_accounts[author_account_id]
            control_results.append(
                self._cr(
                    signal="bot_velocity_pattern",
                    default="PR-02",
                    result="FLAG",
                    detail=(
                        f"Jira record {record_id} author {author_account_id!r} "
                        f"is part of a bot-velocity pattern "
                        f"({count} issue-creates > "
                        f"threshold {self.bot_velocity_threshold} "
                        f"in {self.bot_velocity_window_seconds}s window)"
                    ),
                    common_evidence={
                        **common_evidence,
                        "bot_velocity_count": count,
                        "bot_velocity_threshold": self.bot_velocity_threshold,
                        "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
                    },
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
                        f"Jira record {record_id} category={category!r} captured — "
                        f"no pattern-specific signal matched"
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
            f"Imported from Jira audit record: category={category or 'unknown'} "
            f"author_account_id={author_account_id or 'unknown'} "
            f"event_source={event_source or 'unknown'} "
            f"is_automated_action={is_automated_action} "
            f"object_type={object_type or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"jira-{record_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="jira_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=author_account_id or None,
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

    def _synthetic_cross_project_result(
        self,
        *,
        account: str,
        is_bot: bool,
        projects: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-account cross-project pattern finding."""
        signal = "cross_project_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"jira-cross-project-{account}"
        evidence: dict[str, Any] = {
            "jira_record_id": synthetic_id,
            "author_account_id": account,
            "author_is_bot": is_bot,
            "cross_project_projects": projects,
            "cross_project_project_count": len(projects),
            "cross_project_threshold": self.cross_project_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "jira",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Jira synthetic finding: account {account} touched "
                f"{len(projects)} projects in this export "
                f"({', '.join(projects)}) — exceeds cross-project threshold "
                f"{self.cross_project_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="jira_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Jira audit record: synthetic cross-project pattern "
                f"for account={account} projects={len(projects)}>threshold="
                f"{self.cross_project_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=account or None,
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
        synthetic_id = f"jira-bot-velocity-{account}"
        evidence: dict[str, Any] = {
            "jira_record_id": synthetic_id,
            "author_account_id": account,
            "author_is_bot": True,
            "bot_velocity_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "jira",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Jira synthetic finding: bot account {account} created "
                f"{count} issues in a {self.bot_velocity_window_seconds}s window "
                f"— exceeds bot-velocity threshold "
                f"{self.bot_velocity_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="jira_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Jira audit record: synthetic bot-velocity pattern "
                f"for account={account} count={count}>threshold="
                f"{self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=account or None,
        )
