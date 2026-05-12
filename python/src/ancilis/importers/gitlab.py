# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""GitLab audit-events importer — maps self-hosted code-platform activity to AKSI controls.

GitLab (https://docs.gitlab.com/ee/api/audit_events.html) is the dominant
self-hosted code platform — preferred by enterprises that cannot put proprietary
code on GitHub. The ``/api/v4/audit_events`` and project-level ``audit_events``
endpoints record every push, MR open/merge, approval, policy_violation,
PAT/deploy-token lifecycle event, permission change, protected-branch lifecycle,
CI secrets-provider change, container-registry push, package publish,
vulnerability dismissal, and ``secret_detection_finding`` for projects, groups,
and users. The threat model is identical to GitHub: code provenance, branch
protection, credential lifecycle, and supply-chain artifact governance.
GitLab's vocabulary is different (``event_name`` strings rather than
``action`` dotted-strings, nested ``details`` rather than top-level fields).

This importer ingests GitLab audit_events exports in three on-disk shapes:

  1. ``{"events": [...]}`` — primary GitLab audit-events envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one event per line

Signal mapping (see shared/mappings/gitlab-aksi-controls.json):
  * ``push`` to non-protected branch                                    → PR-05 PASS
  * ``push`` with ``force_push=true`` to protected branch               → PR-02 FAIL
    (force-push to protected branch = compliance violation)
  * ``merge_request_created`` by ``author_class=Bot`` or User whose
    author_name matches an agent marker ("bot"/"claude"/"copilot"/"devin") → PR-01 FLAG
    (agent-authored MR — must be reviewed by a human)
  * ``merge_request_merged`` with ``approval_count=0``                   → PR-02 FAIL
    (merged without approval — branch-protection bypass)
  * ``merge_request_merged`` with ``merge_method=squash`` to protected   → PR-05 PASS
  * ``policy_violation``                                                 → PR-02 FAIL
  * ``personal_access_token_created`` with ``expires_at=null``          → PR-01 FAIL
    (non-expiring PAT — credential lifecycle violation)
  * ``personal_access_token_created`` ``scope_list`` contains ``api``
    AND ``expires_at > 1 year``                                         → PR-01 FLAG
  * ``personal_access_token_created`` normal                            → PR-01 PASS
  * ``deploy_token_created``                                            → PR-01 FLAG
    (deploy token = long-lived credential)
  * ``permission_changed`` ``to=maintainer/owner`` from lower            → PR-02 FAIL
  * ``permission_changed`` ``to=`` lower from higher                     → PR-05 PASS
  * ``protected_branch_destroyed``                                      → PR-02 FAIL
  * ``protected_branch_created``                                        → PR-05 PASS
  * ``ci_secrets_provider_changed``                                     → PR-01 FLAG
  * ``container_registry_image_pushed`` to public registry              → PR-04 FLAG
  * ``container_registry_image_pushed`` private                         → PR-04 PASS
  * ``package_published`` to public registry                            → PR-04 FLAG
  * ``vulnerability_dismissed`` ``severity=critical/high``              → PR-02 FAIL
  * ``secret_detection_finding``                                        → DE-01 FAIL
  * ``user_added`` to admin role                                         → PR-02 FLAG
  * ``user_removed``                                                    → PR-05 PASS
  * ``is_two_factor_enabled=false`` on push to protected                → PR-01 FLAG
  * ``is_admin=true`` on routine read action                             → PR-02 FLAG
  * cross-project pattern: same author_id touching ≥ N projects         → PR-02 FLAG synthetic
  * bot-velocity pattern: same Bot author creating ≥ N MRs in 1h window → PR-02 FLAG synthetic

Sanitization (security-critical — GitLab audit events can carry author IPs,
free-form custom_messages, and author display names that contain PII):
  * ``ip_address`` is reduced to a /16 pattern (first two octets) for IPv4 and
    /32 hextet pattern for IPv6. RFC1918 private addresses are preserved
    verbatim. Loopback/link-local preserved.
  * ``user_agent`` is captured as the first 80 characters plus a sha256 hash
    of the full string.
  * ``custom_message`` is reduced to length + sha256 (raw never stored).
  * ``author_name`` is reduced to length + sha256 (potential PII).
  * ``author_email_domain`` is stored verbatim only when already domain-only
    (starts with ``@`` or has no local part).
  * Audit-critical structured fields are captured verbatim: event_name,
    author_id, author_class, entity_type, target_type, target_details,
    branch_name, merge_method, approval_count, force_push, operation_method,
    is_admin, is_two_factor_enabled, scope_list, expires_at.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``python-gitlab``; GitLab audit-events JSON exports
are parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/gitlab.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "gitlab-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Default event_name patterns (mirrors the canonical _metadata.event_patterns
# in the JSON mapping table — used as a fallback if the JSON is missing).
_DEFAULT_EVENT_PATTERNS: tuple[dict[str, Any], ...] = (
    {"event_name": "push", "signal": "gitlab_push",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "merge_request_created", "signal": "gitlab_mr_created",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "merge_request_merged", "signal": "gitlab_mr_merged",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "approval_added", "signal": "gitlab_approval_added",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "policy_violation", "signal": "gitlab_policy_violation",
     "result": "FAIL", "control": "PR-02"},
    {"event_name": "personal_access_token_created", "signal": "gitlab_pat_created",
     "result": "PASS", "control": "PR-01"},
    {"event_name": "personal_access_token_*", "signal": "gitlab_pat_lifecycle",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "deploy_token_created", "signal": "gitlab_deploy_token_created",
     "result": "FLAG", "control": "PR-01"},
    {"event_name": "deploy_token_*", "signal": "gitlab_deploy_token_lifecycle",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "user_added", "signal": "gitlab_user_added",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "user_removed", "signal": "gitlab_user_removed",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "permission_changed", "signal": "gitlab_permission_changed",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "protected_branch_created",
     "signal": "gitlab_protected_branch_created",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "protected_branch_destroyed",
     "signal": "gitlab_protected_branch_destroyed",
     "result": "FAIL", "control": "PR-02"},
    {"event_name": "ci_secrets_provider_changed",
     "signal": "gitlab_ci_secrets_provider_changed",
     "result": "FLAG", "control": "PR-01"},
    {"event_name": "container_registry_image_pushed",
     "signal": "gitlab_container_image_pushed",
     "result": "PASS", "control": "PR-04"},
    {"event_name": "package_published", "signal": "gitlab_package_published",
     "result": "PASS", "control": "PR-04"},
    {"event_name": "vulnerability_dismissed",
     "signal": "gitlab_vulnerability_dismissed",
     "result": "PASS", "control": "PR-05"},
    {"event_name": "secret_detection_finding",
     "signal": "gitlab_secret_detection_finding",
     "result": "FAIL", "control": "DE-01"},
)

_DEFAULT_PROTECTED_BRANCH_PATTERNS: tuple[str, ...] = (
    "main", "master", "release/*", "prod*",
)
_DEFAULT_AGENT_MARKER_PATTERNS: tuple[str, ...] = (
    "*bot*", "*claude*", "*copilot*", "*devin*",
)
_DEFAULT_CROSS_PROJECT_THRESHOLD = 5
_DEFAULT_BOT_VELOCITY_THRESHOLD = 10
_DEFAULT_BOT_VELOCITY_WINDOW_SECONDS = 3600
_DEFAULT_LONG_LIVED_PAT_DAYS = 365
_DEFAULT_NON_EXPIRING_PAT_SEVERITY = "FAIL"

# Permission ranking used to detect privilege escalation. GitLab's project /
# group access levels (lowercase string) ordered weakest → strongest.
_PERMISSION_RANK: dict[str, int] = {
    "guest": 0,
    "reporter": 1,
    "developer": 2,
    "maintainer": 3,
    "owner": 4,
}

# Permissions considered "high privilege" — escalation TO any of these from
# a strictly lower rank is treated as a privilege-escalation FAIL.
_HIGH_PERMISSIONS: frozenset[str] = frozenset({"maintainer", "owner"})

# Routine read event_names — when an admin performs one of these we surface
# an over-privileged FLAG.
_ROUTINE_READ_EVENTS: frozenset[str] = frozenset({
    "repository_read",
    "project_read",
    "merge_request_read",
    "issue_read",
    "wiki_read",
    "package_read",
    "container_registry_image_read",
})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the gitlab-aksi-controls.json mapping; tolerate missing file."""
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


def _classify_ip(addr_value: str | None) -> str | None:
    """Reduce an ip_address to a /16 IPv4 or /32-hextet IPv6 pattern."""
    if not addr_value or not isinstance(addr_value, str):
        return None
    ip = addr_value.strip()
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


def _redact_user_agent(user_agent: str | None) -> dict[str, str] | None:
    """Capture first 80 chars + sha256 hash of full UA."""
    if not user_agent or not isinstance(user_agent, str):
        return None
    ua = user_agent.strip()
    if not ua:
        return None
    digest = hashlib.sha256(ua.encode("utf-8")).hexdigest()
    return {"prefix": ua[:80], "sha256": digest}


def _redact_freetext(value: str | None) -> dict[str, Any] | None:
    """Reduce a free-text field (custom_message, author_name) to length + sha256."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return {"length": len(s), "sha256": digest}


def _normalize_email_domain(email_domain: str | None) -> str | None:
    """If already domain-only (``@example.com`` or ``example.com``) preserve.

    GitLab's some-configs policy strips the local part already; we accept that
    domain-only form verbatim. If a full ``user@domain`` slips through, reduce
    to ``@domain`` only.
    """
    if not email_domain or not isinstance(email_domain, str):
        return None
    s = email_domain.strip()
    if not s:
        return None
    if "@" not in s:
        # Plain domain without ``@`` prefix → normalize to ``@domain``.
        return "@" + s
    if s.startswith("@"):
        # Already in ``@domain`` form.
        return s
    # Full ``user@domain`` slipped through — keep only domain.
    return "@" + s.rsplit("@", 1)[1]


def _matches_event_name(event_name: str, pattern: dict[str, Any]) -> bool:
    return fnmatch.fnmatchcase(event_name, str(pattern.get("event_name", "")))


def _matches_any(value: str, patterns: Iterable[str]) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return any(fnmatch.fnmatchcase(lowered, p.lower()) for p in patterns)


def _is_protected_branch(branch_or_ref: str, patterns: Iterable[str]) -> bool:
    """Match a GitLab branch_name or ref against branch glob patterns."""
    if not branch_or_ref:
        return False
    branch = branch_or_ref
    for prefix in ("refs/heads/", "refs/tags/"):
        if branch.startswith(prefix):
            branch = branch[len(prefix):]
            break
    return any(fnmatch.fnmatchcase(branch, p) for p in patterns)


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


class GitLabImporter:
    """Parse a GitLab audit-events export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        protected_branch_patterns: Iterable[str] | None = None,
        agent_marker_patterns: Iterable[str] | None = None,
        cross_project_threshold: int | None = None,
        bot_velocity_threshold: int | None = None,
        bot_velocity_window_seconds: int | None = None,
        long_lived_pat_days: int | None = None,
        non_expiring_pat_severity: str | None = None,
        public_registry_hosts: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Event patterns: mapping table > built-in defaults.
        meta_patterns = meta.get("event_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._event_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._event_patterns = _DEFAULT_EVENT_PATTERNS
        # Protected-branch patterns.
        if protected_branch_patterns is not None:
            self.protected_branch_patterns: tuple[str, ...] = tuple(
                str(p) for p in protected_branch_patterns
            )
        else:
            meta_protected = meta.get("protected_branch_patterns")
            if isinstance(meta_protected, list) and meta_protected:
                self.protected_branch_patterns = tuple(
                    str(p) for p in meta_protected
                )
            else:
                self.protected_branch_patterns = _DEFAULT_PROTECTED_BRANCH_PATTERNS
        # Agent-marker patterns.
        if agent_marker_patterns is not None:
            self.agent_marker_patterns: tuple[str, ...] = tuple(
                str(p) for p in agent_marker_patterns
            )
        else:
            meta_markers = meta.get("agent_marker_patterns")
            if isinstance(meta_markers, list) and meta_markers:
                self.agent_marker_patterns = tuple(str(p) for p in meta_markers)
            else:
                self.agent_marker_patterns = _DEFAULT_AGENT_MARKER_PATTERNS
        # Cross-project threshold.
        if cross_project_threshold is not None:
            self.cross_project_threshold = int(cross_project_threshold)
        else:
            self.cross_project_threshold = int(
                meta.get("cross_project_threshold", _DEFAULT_CROSS_PROJECT_THRESHOLD)
            )
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
        # PAT lifecycle thresholds.
        if long_lived_pat_days is not None:
            self.long_lived_pat_days = int(long_lived_pat_days)
        else:
            self.long_lived_pat_days = int(
                meta.get("long_lived_pat_days", _DEFAULT_LONG_LIVED_PAT_DAYS)
            )
        if non_expiring_pat_severity is not None:
            self.non_expiring_pat_severity = str(non_expiring_pat_severity).upper()
        else:
            self.non_expiring_pat_severity = str(
                meta.get(
                    "non_expiring_pat_severity",
                    _DEFAULT_NON_EXPIRING_PAT_SEVERITY,
                )
            ).upper()
        # Public-registry host allowlist (operator-supplied). When a registry
        # host matches one of these, container_registry_image_pushed and
        # package_published flip to PR-04 FLAG.
        if public_registry_hosts is not None:
            self.public_registry_hosts: frozenset[str] = frozenset(
                str(h).lower() for h in public_registry_hosts
            )
        else:
            self.public_registry_hosts = frozenset()

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a GitLab audit-events export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse GitLab audit-events content from a JSON or JSONL string."""
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
        """Build per-event EvaluationResults plus cross-project / bot-velocity synthetics."""
        # Pass 1: aggregate (author_id, project) for cross-project detection
        # and (author_id, mr_create timestamp) for bot-velocity detection.
        author_projects: dict[str, set[str]] = {}
        author_class: dict[str, str] = {}
        bot_mr_create_ts: dict[str, list[datetime]] = {}

        for ev in events:
            author_id = ev.get("author_id")
            if author_id is None:
                continue
            akey = str(author_id)
            details = ev.get("details") if isinstance(ev.get("details"), dict) else {}
            cls = details.get("author_class") if isinstance(details, dict) else None
            if isinstance(cls, str) and cls:
                # Promote to Bot once observed (any single Bot record promotes).
                cur = author_class.get(akey)
                if cur != "Bot":
                    author_class[akey] = "Bot" if cls == "Bot" else (cur or cls)
            entity_type = ev.get("entity_type")
            entity_id = ev.get("entity_id")
            if (
                isinstance(entity_type, str)
                and entity_type == "Project"
                and entity_id is not None
            ):
                author_projects.setdefault(akey, set()).add(str(entity_id))
            event_name = ev.get("event_name")
            if (
                event_name == "merge_request_created"
                and author_class.get(akey) == "Bot"
            ):
                ts = _parse_iso_timestamp(ev.get("created_at"))
                if ts is not None:
                    bot_mr_create_ts.setdefault(akey, []).append(ts)

        cross_project_authors: dict[str, list[str]] = {
            author: sorted(projects)
            for author, projects in author_projects.items()
            if len(projects) > self.cross_project_threshold
        }

        # Bot-velocity: any author with > N MR-creates within the window.
        bot_velocity_authors: dict[str, int] = {}
        window = self.bot_velocity_window_seconds
        for author, timestamps in bot_mr_create_ts.items():
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
                bot_velocity_authors[author] = max_in_window

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                cross_project_authors=cross_project_authors,
                bot_velocity_authors=bot_velocity_authors,
            )
            for ev in events
        ]

        for author, projects in sorted(cross_project_authors.items()):
            results.append(
                self._synthetic_cross_project_result(
                    author_id=author,
                    author_class=author_class.get(author, "User"),
                    projects=projects,
                    file_sha256=file_sha256,
                )
            )
        for author, count in sorted(bot_velocity_authors.items()):
            results.append(
                self._synthetic_bot_velocity_result(
                    author_id=author,
                    count=count,
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
            "source_format": "gitlab_audit_events",
            "source_tool_name": "gitlab",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_event(self, event_name: str) -> dict[str, Any] | None:
        """Find the first event_name pattern that matches; ``None`` if no match."""
        for pattern in self._event_patterns:
            if _matches_event_name(event_name, pattern):
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
        cross_project_authors: dict[str, list[str]],
        bot_velocity_authors: dict[str, int],
    ) -> EvaluationResult:
        event_id_raw = event.get("id")
        event_id = (
            str(event_id_raw)
            if event_id_raw is not None
            else str(uuid.uuid4())
        )
        event_name = str(event.get("event_name") or "").strip()
        timestamp = _format_timestamp(event.get("created_at"))
        author_id_raw = event.get("author_id")
        author_id = (
            str(author_id_raw) if author_id_raw is not None else ""
        )
        author_name_raw = event.get("author_name")
        author_name_redacted = _redact_freetext(
            author_name_raw if isinstance(author_name_raw, str) else None
        )
        entity_id_raw = event.get("entity_id")
        entity_id = (
            int(entity_id_raw) if isinstance(entity_id_raw, (int, float)) else None
        )
        entity_type = (
            event.get("entity_type")
            if isinstance(event.get("entity_type"), str)
            else None
        )

        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        if not isinstance(details, dict):
            details = {}

        author_class = (
            details.get("author_class")
            if isinstance(details.get("author_class"), str)
            else None
        )
        author_email_domain = _normalize_email_domain(
            details.get("author_email_domain")
            if isinstance(details.get("author_email_domain"), str)
            else None
        )
        target_id_raw = details.get("target_id")
        target_id = (
            int(target_id_raw) if isinstance(target_id_raw, (int, float)) else None
        )
        target_type = (
            details.get("target_type")
            if isinstance(details.get("target_type"), str)
            else None
        )
        target_details = (
            details.get("target_details")
            if isinstance(details.get("target_details"), str)
            else None
        )
        # ip_address can appear top-level or in details — top-level wins.
        ip_top = event.get("ip_address")
        ip_value = (
            ip_top if isinstance(ip_top, str) else details.get("ip_address")
        )
        ip_redacted = _classify_ip(ip_value if isinstance(ip_value, str) else None)
        user_agent_redacted = _redact_user_agent(
            details.get("user_agent")
            if isinstance(details.get("user_agent"), str)
            else None
        )
        custom_message_redacted = _redact_freetext(
            details.get("custom_message")
            if isinstance(details.get("custom_message"), str)
            else None
        )
        from_value = (
            details.get("from")
            if isinstance(details.get("from"), str)
            else None
        )
        to_value = (
            details.get("to")
            if isinstance(details.get("to"), str)
            else None
        )
        branch_name = (
            details.get("branch_name")
            if isinstance(details.get("branch_name"), str)
            else None
        )
        ref = (
            details.get("ref")
            if isinstance(details.get("ref"), str)
            else None
        )
        merge_method = (
            details.get("merge_method")
            if isinstance(details.get("merge_method"), str)
            else None
        )
        approval_count_raw = details.get("approval_count")
        approval_count = (
            int(approval_count_raw)
            if isinstance(approval_count_raw, (int, float))
            else None
        )
        force_push = (
            bool(details.get("force_push"))
            if details.get("force_push") is not None
            else None
        )
        operation_method = (
            details.get("operation_method")
            if isinstance(details.get("operation_method"), str)
            else None
        )
        is_admin = (
            bool(details.get("is_admin"))
            if details.get("is_admin") is not None
            else None
        )
        is_two_factor_enabled = (
            bool(details.get("is_two_factor_enabled"))
            if details.get("is_two_factor_enabled") is not None
            else None
        )
        scope_list_raw = details.get("scope_list")
        scope_list: list[str] | None
        if isinstance(scope_list_raw, list):
            scope_list = [str(s) for s in scope_list_raw if isinstance(s, str)]
        else:
            scope_list = None
        expires_at_raw = details.get("expires_at")
        expires_at = (
            expires_at_raw
            if isinstance(expires_at_raw, str) and expires_at_raw.strip()
            else None
        )
        # severity for vulnerability_dismissed.
        severity = (
            details.get("severity")
            if isinstance(details.get("severity"), str)
            else None
        )
        # registry_visibility / package_visibility: "public"|"private".
        registry_visibility = (
            details.get("registry_visibility")
            if isinstance(details.get("registry_visibility"), str)
            else None
        )
        package_visibility = (
            details.get("package_visibility")
            if isinstance(details.get("package_visibility"), str)
            else None
        )
        registry_host = (
            details.get("registry_host")
            if isinstance(details.get("registry_host"), str)
            else None
        )

        # Determine the "branch" string used for protected-branch matching:
        # branch_name takes precedence, else ref, else target_details.
        protected_input = branch_name or ref or (target_details or "")
        is_protected = _is_protected_branch(
            protected_input or "", self.protected_branch_patterns
        )

        common_evidence: dict[str, Any] = {
            "gitlab_event_id": event_id,
            "event_name": event_name,
            "author_id": author_id or None,
            "author_class": author_class,
            "author_name_redacted": author_name_redacted,
            "author_email_domain": author_email_domain,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "target_id": target_id,
            "target_type": target_type,
            "target_details": target_details,
            "branch_name": branch_name,
            "ref": ref,
            "merge_method": merge_method,
            "approval_count": approval_count,
            "force_push": force_push,
            "operation_method": operation_method,
            "is_admin": is_admin,
            "is_two_factor_enabled": is_two_factor_enabled,
            "scope_list": scope_list,
            "expires_at": expires_at,
            "severity": severity,
            "registry_visibility": registry_visibility,
            "package_visibility": package_visibility,
            "registry_host": registry_host,
            "from_value": from_value,
            "to_value": to_value,
            "ip_redacted": ip_redacted,
            "user_agent_redacted": user_agent_redacted,
            "custom_message_redacted": custom_message_redacted,
            "is_protected_branch": is_protected,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "gitlab",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Force-push to protected branch — compliance violation.
        # ----------------------------------------------------------------
        if (
            event_name == "push"
            and force_push is True
            and is_protected
        ):
            signal = "force_push_protected"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"GitLab event {event_id} push with force_push=true to "
                        f"protected branch {protected_input!r} — compliance violation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Primary event_name classification.
        # ----------------------------------------------------------------
        pattern = self._classify_event(event_name) if event_name else None

        if pattern is not None:
            signal = str(pattern.get("signal", "unknown_event"))
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
                        f"GitLab event {event_id} event_name={event_name!r} "
                        f"on {entity_type or 'entity'}={entity_id} "
                        f"author_id={author_id or 'unknown'} "
                        f"classified as {signal} ({result})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitLab event {event_id} event_name={event_name!r} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Agent-authored MR — must be reviewed by a human.
        # Triggers when author_class=Bot OR author_name matches an agent marker.
        # ----------------------------------------------------------------
        if event_name == "merge_request_created":
            is_agent = author_class == "Bot"
            if not is_agent and isinstance(author_name_raw, str):
                is_agent = _matches_any(
                    author_name_raw, self.agent_marker_patterns
                )
            if is_agent:
                signal = "agent_authored_mr"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"GitLab event {event_id} merge_request_created authored "
                            f"by agent (author_class={author_class!r}) — "
                            f"requires human review before merge"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 4. MR merged with zero approvals — branch-protection bypass.
        # ----------------------------------------------------------------
        if (
            event_name == "merge_request_merged"
            and approval_count is not None
            and approval_count == 0
        ):
            signal = "mr_merged_no_approval"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"GitLab event {event_id} merge_request_merged with "
                        f"approval_count=0 on target {target_details!r} — "
                        f"branch-protection bypass"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. MR merged via squash to protected — explicit governance pass.
        # ----------------------------------------------------------------
        if (
            event_name == "merge_request_merged"
            and merge_method == "squash"
            and is_protected
        ):
            signal = "mr_squash_protected"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"GitLab event {event_id} merge_request_merged via squash "
                        f"to protected branch {protected_input!r} — clean history"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 6. PAT lifecycle — non-expiring / long-lived API-scoped.
        # ----------------------------------------------------------------
        if event_name == "personal_access_token_created":
            # Non-expiring: expires_at is missing/null.
            if expires_at is None:
                signal = "non_expiring_pat"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=self.non_expiring_pat_severity,
                        detail=(
                            f"GitLab event {event_id} personal_access_token_created "
                            f"with no expires_at — non-expiring PAT is a credential "
                            f"lifecycle violation"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Long-lived API-scoped: scope_list contains "api" and
                # expires_at > long_lived_pat_days days from event timestamp.
                expires_dt = _parse_iso_timestamp(expires_at)
                event_dt = _parse_iso_timestamp(event.get("created_at"))
                if (
                    scope_list
                    and "api" in scope_list
                    and expires_dt is not None
                    and event_dt is not None
                    and (
                        expires_dt - event_dt
                    )
                    > timedelta(days=self.long_lived_pat_days)
                ):
                    signal = "long_lived_api_pat"
                    control_id = _control_for(signal, self._mappings, "PR-01")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"GitLab event {event_id} personal_access_token_created "
                                f"with api scope and expires_at={expires_at!r} "
                                f"(> {self.long_lived_pat_days} days) — long-lived "
                                f"API-scoped PAT"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )

        # ----------------------------------------------------------------
        # 7. Permission change — escalation FAIL / deescalation PASS.
        # ----------------------------------------------------------------
        if event_name == "permission_changed" and from_value and to_value:
            from_rank = _PERMISSION_RANK.get((from_value or "").lower(), -1)
            to_rank = _PERMISSION_RANK.get((to_value or "").lower(), -1)
            to_lower = (to_value or "").lower()
            if (
                from_rank >= 0
                and to_rank >= 0
                and to_rank > from_rank
                and to_lower in _HIGH_PERMISSIONS
            ):
                signal = "permission_escalation"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"GitLab event {event_id} permission_changed "
                            f"from={from_value!r} to={to_value!r} — privilege "
                            f"escalation to high-privilege role"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif (
                from_rank >= 0
                and to_rank >= 0
                and to_rank < from_rank
            ):
                signal = "permission_deescalation"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"GitLab event {event_id} permission_changed "
                            f"from={from_value!r} to={to_value!r} — "
                            f"privilege deescalation"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 8. Vulnerability dismissed at critical/high — FAIL.
        # ----------------------------------------------------------------
        if (
            event_name == "vulnerability_dismissed"
            and (severity or "").lower() in {"critical", "high"}
        ):
            signal = "vulnerability_dismissed_critical"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"GitLab event {event_id} vulnerability_dismissed at "
                        f"severity={severity!r} — high/critical vulnerabilities "
                        f"must not be silently dismissed"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 9. Admin user added — privilege grant FLAG.
        # ----------------------------------------------------------------
        if event_name == "user_added" and (
            (to_value or "").lower() in {"admin", "owner"}
            or (target_details or "").lower().find("admin") >= 0
        ):
            signal = "admin_user_added"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitLab event {event_id} user_added with role={to_value!r} "
                        f"target={target_details!r} — admin/owner privilege grant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 10. No-MFA on push to protected — additive FLAG.
        # ----------------------------------------------------------------
        if (
            event_name == "push"
            and is_protected
            and is_two_factor_enabled is False
        ):
            signal = "no_mfa_protected_push"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitLab event {event_id} push to protected branch "
                        f"{protected_input!r} without 2FA enabled — credential "
                        f"hygiene violation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 11. Admin on routine read action — over-privileged FLAG.
        # ----------------------------------------------------------------
        if (
            is_admin is True
            and event_name in _ROUTINE_READ_EVENTS
        ):
            signal = "admin_routine_read"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitLab event {event_id} admin user performed routine "
                        f"read event_name={event_name!r} — over-privileged action"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 12. Public registry / package — supply-chain artifact FLAG.
        # registry_visibility/package_visibility="public" OR registry_host in
        # operator-supplied public_registry_hosts allowlist.
        # ----------------------------------------------------------------
        if event_name == "container_registry_image_pushed":
            is_public = (registry_visibility or "").lower() == "public"
            if not is_public and registry_host:
                is_public = registry_host.lower() in self.public_registry_hosts
            if is_public:
                signal = "public_registry_push"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"GitLab event {event_id} container_registry_image_pushed "
                            f"to public registry — supply-chain artifact exposure"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        if event_name == "package_published":
            is_public = (package_visibility or "").lower() == "public"
            if not is_public and registry_host:
                is_public = registry_host.lower() in self.public_registry_hosts
            if is_public:
                signal = "public_package_publish"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"GitLab event {event_id} package_published to public "
                            f"registry — potential supply-chain artifact"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 13. Cross-project pattern — informational marker on contributing events.
        # ----------------------------------------------------------------
        if author_id and author_id in cross_project_authors:
            signal = "cross_project_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitLab event {event_id} author_id={author_id} "
                        f"is part of a cross-project pattern "
                        f"({len(cross_project_authors[author_id])} projects > "
                        f"threshold {self.cross_project_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_project_projects": cross_project_authors[author_id],
                        "cross_project_threshold": self.cross_project_threshold,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 14. Bot-velocity pattern — informational marker on contributing events.
        # ----------------------------------------------------------------
        if author_id and author_id in bot_velocity_authors:
            signal = "bot_velocity_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitLab event {event_id} author_id={author_id} "
                        f"is part of a bot-velocity pattern "
                        f"({bot_velocity_authors[author_id]} MR-creates > "
                        f"threshold {self.bot_velocity_threshold} "
                        f"in {self.bot_velocity_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bot_velocity_count": bot_velocity_authors[author_id],
                        "bot_velocity_threshold": self.bot_velocity_threshold,
                        "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
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
            f"Imported from GitLab audit events: event_name={event_name} "
            f"author_id={author_id or 'unknown'} "
            f"author_class={author_class or 'unknown'} "
            f"entity_type={entity_type or 'unknown'} "
            f"target_details={target_details or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"gitlab-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="gitlab_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=str(target_id) if target_id is not None else None,
        )

    def _synthetic_cross_project_result(
        self,
        *,
        author_id: str,
        author_class: str,
        projects: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-author cross-project pattern finding."""
        signal = "cross_project_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"gitlab-cross-project-{author_id}"
        evidence: dict[str, Any] = {
            "gitlab_event_id": synthetic_id,
            "author_id": author_id,
            "author_class": author_class,
            "cross_project_projects": projects,
            "cross_project_project_count": len(projects),
            "cross_project_threshold": self.cross_project_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "gitlab",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"GitLab synthetic finding: author_id={author_id} "
                f"({author_class}) touched {len(projects)} projects "
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
            source_type="gitlab_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from GitLab audit events: synthetic cross-project "
                f"pattern for author_id={author_id} projects={len(projects)}>"
                f"threshold={self.cross_project_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_bot_velocity_result(
        self,
        *,
        author_id: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-bot velocity pattern finding."""
        signal = "bot_velocity_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"gitlab-bot-velocity-{author_id}"
        evidence: dict[str, Any] = {
            "gitlab_event_id": synthetic_id,
            "author_id": author_id,
            "author_class": "Bot",
            "bot_velocity_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "gitlab",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"GitLab synthetic finding: bot author_id={author_id} opened "
                f"{count} MRs in a {self.bot_velocity_window_seconds}s window "
                f"— exceeds bot-velocity threshold {self.bot_velocity_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="gitlab_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from GitLab audit events: synthetic bot-velocity "
                f"pattern for bot author_id={author_id} count={count}>"
                f"threshold={self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
