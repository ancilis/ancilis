"""GitHub audit-log importer — maps coding-agent and human GitHub activity to AKSI controls.

GitHub (https://docs.github.com/en/rest/orgs/audit-log) is THE evidence source
for what an AI coding agent (Claude Code, Cursor, Devin, Aider, ...) actually
produced: every push, PR open/merge/comment, issue change, branch creation,
secret rotation, and access-control change is recorded in the org audit log.
For agents that modify code, GitHub records the *outcome* of their work — far
more durable than any single tool-call trace.

This importer ingests org-audit-log exports and webhook captures in three
on-disk shapes:

  1. ``{"events": [...]}`` — primary GitHub audit-log envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one event per line

Signal mapping (see shared/mappings/github-aksi-controls.json):
  * ``git.push`` to non-protected branch                                → PR-05 PASS
  * ``git.push`` to protected branch (main/master/release/* — patterns
    configurable)                                                        → PR-05 PASS (capture)
  * ``git.push`` with ``branch_protection_evasion`` non-null            → PR-02 FAIL
    (admin override of branch protection — critical compliance violation)
  * ``git.push`` from forked head_repository                            → PR-04 FLAG
    (untrusted source content — a fork pushing into the upstream repo
    surface is a code-supply-chain risk)
  * ``pull_request.create`` by ``actor_is_bot=true`` /
    ``is_ml_powered_action=true`` / ``external_app_name`` set           → PR-01 FLAG
    (agent-authored PR — must be reviewed by a human, not auto-merged)
  * ``pull_request.merge`` to protected branch                          → PR-05 PASS
  * ``pull_request.merge`` with ``branch_protection_evasion`` non-null  → PR-02 FAIL
  * ``pull_request.comment`` by bot                                     → PR-05 PASS
  * ``repo.destroy``                                                    → PR-02 FAIL (irreversible)
  * ``repo.create`` private=false                                       → PR-04 FLAG (public IP exposure)
  * ``team.add_member`` to admin team                                   → PR-02 FLAG
  * ``members.update_role`` new_role=owner                              → PR-02 FAIL (org owner promotion)
  * ``org.invite_member`` external email domain                         → PR-02 FLAG
  * ``secret_scanning.alert.create``                                    → DE-01 FAIL (secret leaked)
  * ``code_scanning.alert.dismiss`` severity=critical/high              → PR-02 FAIL
  * ``personal_access_token.create``                                    → PR-01 FLAG
  * ``oauth_application.create``                                        → PR-01 FLAG
  * ``deploy_key.create``                                               → PR-01 FLAG
  * ``repository_secret.create``/``.update``                            → PR-01 PASS
  * ``repository_environment.protection_rule.create``                   → PR-05 PASS
  * ``branch_protection.update`` weakening                              → PR-02 FAIL
  * ``workflow_run`` failed in protected workflow                       → DE-01 FLAG
  * ``repo.access`` from non-allowlisted country                        → PR-01 FLAG
  * cross-repo pattern: same actor (esp. bot) > N repos in export       → PR-02 FLAG synthetic
  * bot-velocity pattern: > N PRs from a single bot in 1h window        → PR-02 FLAG synthetic

Sanitization (security-critical — audit logs can carry actor IPs, full
user-agents, and external app names that may include tenant identifiers):
  * ``actor_ip`` is reduced to a /16 pattern (first two octets) for IPv4 and
    /32 hextet pattern for IPv6. RFC1918 private addresses are preserved
    verbatim. Loopback/link-local preserved.
  * ``user_agent`` is captured as the first 80 characters plus a sha256 hash
    of the full string (so identical agents collide while not retaining the
    full token-bearing fingerprint).
  * Pull-request titles, commit messages, and any free-text body fields are
    NOT stored. We only capture structured fields (numeric IDs, action,
    actor, ref, branch_protection_evasion verbatim, transport_protocol_name,
    pull_request_id, merge_method, is_ml_powered_action, external_app_name,
    permission, country_code, workflow_run_id, alert severity).
  * Email addresses are reduced to domain-only when present.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``PyGithub``; GitHub audit-log JSON exports are
parsed with the standard library only.
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
#   <repo>/python/src/ancilis/importers/github.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "github-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Default action patterns (mirrors the canonical _metadata.action_patterns in
# the JSON mapping table — used as a fallback if the JSON is missing).
_DEFAULT_ACTION_PATTERNS: tuple[dict[str, Any], ...] = (
    {"action": "git.push", "signal": "git_push", "result": "PASS", "control": "PR-05"},
    {"action": "pull_request.create", "signal": "pull_request_create",
     "result": "PASS", "control": "PR-05"},
    {"action": "pull_request.merge", "signal": "pull_request_merge",
     "result": "PASS", "control": "PR-05"},
    {"action": "pull_request.comment", "signal": "pull_request_comment",
     "result": "PASS", "control": "PR-05"},
    {"action": "pull_request.review", "signal": "pull_request_review",
     "result": "PASS", "control": "PR-05"},
    {"action": "issue.create", "signal": "issue_create",
     "result": "PASS", "control": "PR-05"},
    {"action": "issue.comment", "signal": "issue_comment",
     "result": "PASS", "control": "PR-05"},
    {"action": "branch.delete", "signal": "branch_delete",
     "result": "PASS", "control": "PR-05"},
    {"action": "repo.create", "signal": "repo_create",
     "result": "PASS", "control": "PR-05"},
    {"action": "repo.destroy", "signal": "repo_destroy",
     "result": "FAIL", "control": "PR-02"},
    {"action": "repo.access", "signal": "repo_access",
     "result": "PASS", "control": "PR-05"},
    {"action": "team.add_member", "signal": "team_add_member",
     "result": "PASS", "control": "PR-05"},
    {"action": "org.invite_member", "signal": "org_invite_member",
     "result": "PASS", "control": "PR-05"},
    {"action": "members.update_role", "signal": "members_update_role",
     "result": "PASS", "control": "PR-05"},
    {"action": "secret_scanning.alert.create", "signal": "secret_scanning_alert",
     "result": "FAIL", "control": "DE-01"},
    {"action": "secret_scanning.alert.*", "signal": "secret_scanning_lifecycle",
     "result": "PASS", "control": "PR-05"},
    {"action": "code_scanning.alert.dismiss", "signal": "code_scanning_dismiss",
     "result": "PASS", "control": "PR-05"},
    {"action": "workflow_run", "signal": "workflow_run",
     "result": "PASS", "control": "PR-05"},
    {"action": "personal_access_token.create", "signal": "pat_create",
     "result": "FLAG", "control": "PR-01"},
    {"action": "personal_access_token.*", "signal": "pat_lifecycle",
     "result": "PASS", "control": "PR-05"},
    {"action": "oauth_application.create", "signal": "oauth_app_create",
     "result": "FLAG", "control": "PR-01"},
    {"action": "deploy_key.create", "signal": "deploy_key_create",
     "result": "FLAG", "control": "PR-01"},
    {"action": "repository_secret.create", "signal": "repo_secret_create",
     "result": "PASS", "control": "PR-01"},
    {"action": "repository_secret.update", "signal": "repo_secret_update",
     "result": "PASS", "control": "PR-01"},
    {"action": "repository_environment.protection_rule.create",
     "signal": "env_protection_rule_create", "result": "PASS", "control": "PR-05"},
    {"action": "branch_protection.update", "signal": "branch_protection_update",
     "result": "PASS", "control": "PR-05"},
)

_DEFAULT_PROTECTED_BRANCH_PATTERNS: tuple[str, ...] = (
    "main", "master", "release/*", "prod*",
)
_DEFAULT_CROSS_REPO_THRESHOLD = 5
_DEFAULT_BOT_VELOCITY_THRESHOLD = 10
_DEFAULT_BOT_VELOCITY_WINDOW_SECONDS = 3600

# Org-allowlisted country codes default to a permissive set; an operator can
# narrow this via the importer kwarg.
_DEFAULT_ALLOWED_COUNTRIES: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the github-aksi-controls.json mapping; tolerate missing file."""
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


def _classify_actor_ip(actor_ip: str | None) -> str | None:
    """Reduce an actor_ip to a /16 IPv4 or /32-hextet IPv6 pattern."""
    if not actor_ip or not isinstance(actor_ip, str):
        return None
    ip = actor_ip.strip()
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
    """Capture first 80 chars + sha256 hash of full UA (no full token-bearing fingerprint)."""
    if not user_agent or not isinstance(user_agent, str):
        return None
    ua = user_agent.strip()
    if not ua:
        return None
    digest = hashlib.sha256(ua.encode("utf-8")).hexdigest()
    return {"prefix": ua[:80], "sha256": digest}


def _redact_email(email: str | None) -> str | None:
    """Reduce an email to ``@domain`` only."""
    if not email or not isinstance(email, str):
        return None
    em = email.strip()
    if "@" not in em:
        return None
    return "@" + em.rsplit("@", 1)[1]


def _matches_action(action: str, pattern: dict[str, Any]) -> bool:
    return fnmatch.fnmatchcase(action, str(pattern.get("action", "")))


def _is_protected_branch(ref: str, patterns: Iterable[str]) -> bool:
    """Match a git ref (e.g. ``refs/heads/main``) against branch glob patterns."""
    if not ref:
        return False
    branch = ref
    for prefix in ("refs/heads/", "refs/tags/"):
        if branch.startswith(prefix):
            branch = branch[len(prefix):]
            break
    return any(fnmatch.fnmatchcase(branch, p) for p in patterns)


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from int (epoch ms or s) or ISO 8601 string."""
    if value is None:
        return None
    # GitHub audit-log canonical timestamp is epoch ms (int).
    if isinstance(value, (int, float)):
        v = float(value)
        # Heuristic: > 1e12 → ms, else seconds.
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
        # Allow trailing Z.
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


class GitHubImporter:
    """Parse a GitHub audit-log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        protected_branch_patterns: Iterable[str] | None = None,
        cross_repo_threshold: int | None = None,
        bot_velocity_threshold: int | None = None,
        bot_velocity_window_seconds: int | None = None,
        org_domain: str | None = None,
        allowed_countries: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.org_domain = (org_domain or "").lower().strip() or None
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Action patterns: mapping table > built-in defaults.
        meta_patterns = meta.get("action_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._action_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._action_patterns = _DEFAULT_ACTION_PATTERNS
        # Protected-branch patterns: explicit arg > mapping metadata > default.
        if protected_branch_patterns is not None:
            self.protected_branch_patterns: tuple[str, ...] = tuple(
                str(p) for p in protected_branch_patterns
            )
        else:
            meta_protected = meta.get("protected_branch_patterns")
            if isinstance(meta_protected, list) and meta_protected:
                self.protected_branch_patterns = tuple(str(p) for p in meta_protected)
            else:
                self.protected_branch_patterns = _DEFAULT_PROTECTED_BRANCH_PATTERNS
        # Cross-repo threshold.
        if cross_repo_threshold is not None:
            self.cross_repo_threshold = int(cross_repo_threshold)
        else:
            self.cross_repo_threshold = int(
                meta.get("cross_repo_threshold", _DEFAULT_CROSS_REPO_THRESHOLD)
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
        # Allowed-country allowlist (operator-supplied).
        if allowed_countries is not None:
            self.allowed_countries: frozenset[str] = frozenset(
                str(c).upper() for c in allowed_countries
            )
        else:
            self.allowed_countries = _DEFAULT_ALLOWED_COUNTRIES

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a GitHub audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse GitHub audit-log content from a JSON or JSONL string."""
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
        """Build per-event EvaluationResults plus cross-repo / bot-velocity synthetics."""
        # Pass 1: aggregate (actor, repo) for cross-repo detection and (actor,
        # action, timestamp) for bot-velocity detection (PR-creates only).
        actor_repos: dict[str, set[str]] = {}
        actor_is_bot: dict[str, bool] = {}
        bot_pr_create_ts: dict[str, list[datetime]] = {}

        for ev in events:
            actor = ev.get("actor")
            if not isinstance(actor, str) or not actor:
                continue
            is_bot = bool(ev.get("actor_is_bot"))
            # Once a bot, always a bot for this export (any single bot record promotes).
            actor_is_bot[actor] = actor_is_bot.get(actor, False) or is_bot
            repo = ev.get("repo")
            if isinstance(repo, str) and repo:
                actor_repos.setdefault(actor, set()).add(repo)
            action = ev.get("action")
            if action == "pull_request.create" and is_bot:
                ts = _parse_iso_timestamp(ev.get("@timestamp"))
                if ts is not None:
                    bot_pr_create_ts.setdefault(actor, []).append(ts)

        cross_repo_actors: dict[str, list[str]] = {
            actor: sorted(repos)
            for actor, repos in actor_repos.items()
            if len(repos) > self.cross_repo_threshold
        }

        # Bot-velocity: any actor with > N PR-creates within the window.
        bot_velocity_actors: dict[str, int] = {}
        window = self.bot_velocity_window_seconds
        for actor, timestamps in bot_pr_create_ts.items():
            if len(timestamps) <= self.bot_velocity_threshold:
                continue
            sorted_ts = sorted(timestamps)
            # Sliding window: any sub-sequence of length > threshold within window.
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
                cross_repo_actors=cross_repo_actors,
                bot_velocity_actors=bot_velocity_actors,
            )
            for ev in events
        ]

        for actor, repos in sorted(cross_repo_actors.items()):
            results.append(
                self._synthetic_cross_repo_result(
                    actor=actor,
                    is_bot=actor_is_bot.get(actor, False),
                    repos=repos,
                    file_sha256=file_sha256,
                )
            )
        for actor, count in sorted(bot_velocity_actors.items()):
            results.append(
                self._synthetic_bot_velocity_result(
                    actor=actor,
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
            "source_format": "github_audit_log",
            "source_tool_name": "github",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_action(self, action: str) -> dict[str, Any] | None:
        """Find the first action-pattern that matches; ``None`` if no match."""
        for pattern in self._action_patterns:
            if _matches_action(action, pattern):
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
        cross_repo_actors: dict[str, list[str]],
        bot_velocity_actors: dict[str, int],
    ) -> EvaluationResult:
        event_id = str(event.get("_document_id") or uuid.uuid4())
        action = str(event.get("action") or "").strip()
        timestamp = _format_timestamp(event.get("@timestamp"))
        actor_raw = event.get("actor")
        actor = str(actor_raw) if isinstance(actor_raw, str) else ""
        actor_is_bot = bool(event.get("actor_is_bot"))
        actor_display = f"{actor}_bot" if actor_is_bot and actor else actor
        org = str(event.get("org") or "")
        repo = str(event.get("repo") or "")
        repo_id_raw = event.get("repo_id")
        repo_id = (
            int(repo_id_raw) if isinstance(repo_id_raw, (int, float)) else None
        )
        ref = str(event.get("ref") or "")
        transport_protocol_name = (
            event.get("transport_protocol_name")
            if isinstance(event.get("transport_protocol_name"), str)
            else None
        )
        branch_protection_evasion = event.get("branch_protection_evasion")
        # Pass through verbatim if it is a structured/string value, else None.
        if not isinstance(branch_protection_evasion, (str, dict)):
            branch_protection_evasion = None
        pull_request_id_raw = event.get("pull_request_id")
        pull_request_id = (
            int(pull_request_id_raw)
            if isinstance(pull_request_id_raw, (int, float))
            else None
        )
        merge_method = (
            event.get("merge_method")
            if isinstance(event.get("merge_method"), str)
            else None
        )
        is_ml_powered_action = bool(event.get("is_ml_powered_action"))
        external_app_name = (
            event.get("external_app_name")
            if isinstance(event.get("external_app_name"), str)
            else None
        )
        permission = (
            event.get("permission")
            if isinstance(event.get("permission"), str)
            else None
        )
        old_permission = (
            event.get("old_permission")
            if isinstance(event.get("old_permission"), str)
            else None
        )
        old_role = (
            event.get("old_role")
            if isinstance(event.get("old_role"), str)
            else None
        )
        new_role = (
            event.get("new_role")
            if isinstance(event.get("new_role"), str)
            else None
        )
        head_repository = (
            event.get("head_repository")
            if isinstance(event.get("head_repository"), str)
            else None
        )
        secret_scan_alert_state = (
            event.get("secret_scan_alert_state")
            if isinstance(event.get("secret_scan_alert_state"), str)
            else None
        )
        code_scan_alert_severity = (
            event.get("code_scan_alert_severity")
            if isinstance(event.get("code_scan_alert_severity"), str)
            else None
        )
        workflow_run_id = (
            event.get("workflow_run_id")
            if isinstance(event.get("workflow_run_id"), str)
            else None
        )
        team = event.get("team") if isinstance(event.get("team"), str) else None
        deploy_key_title = (
            event.get("deploy_key_title")
            if isinstance(event.get("deploy_key_title"), str)
            else None
        )
        is_via_oauth_app = (
            bool(event.get("is_via_oauth_app"))
            if event.get("is_via_oauth_app") is not None
            else None
        )
        actor_location = event.get("actor_location") or {}
        if not isinstance(actor_location, dict):
            actor_location = {}
        country_code = actor_location.get("country_code")
        country_code = (
            str(country_code).upper()
            if isinstance(country_code, str) and country_code
            else None
        )
        # Email (rarely present, but if so reduce to domain).
        invitee_email = event.get("invitee_email") or event.get("email")
        invitee_domain = _redact_email(
            invitee_email if isinstance(invitee_email, str) else None
        )
        # repo private flag (for repo.create).
        repo_visibility = event.get("visibility")
        repo_private_raw = event.get("private")
        if isinstance(repo_private_raw, bool):
            repo_private: bool | None = repo_private_raw
        elif isinstance(repo_visibility, str):
            repo_private = repo_visibility.lower() != "public"
        else:
            repo_private = None

        actor_ip_redacted = _classify_actor_ip(
            event.get("actor_ip") if isinstance(event.get("actor_ip"), str) else None
        )
        user_agent_redacted = _redact_user_agent(
            event.get("user_agent") if isinstance(event.get("user_agent"), str) else None
        )

        common_evidence: dict[str, Any] = {
            "github_event_id": event_id,
            "action": action,
            "actor": actor_display or None,
            "actor_is_bot": actor_is_bot,
            "org": org or None,
            "repo": repo or None,
            "repo_id": repo_id,
            "ref": ref or None,
            "transport_protocol_name": transport_protocol_name,
            "branch_protection_evasion": branch_protection_evasion,
            "pull_request_id": pull_request_id,
            "merge_method": merge_method,
            "is_ml_powered_action": is_ml_powered_action,
            "external_app_name": external_app_name,
            "permission": permission,
            "old_permission": old_permission,
            "old_role": old_role,
            "new_role": new_role,
            "head_repository": head_repository,
            "secret_scan_alert_state": secret_scan_alert_state,
            "code_scan_alert_severity": code_scan_alert_severity,
            "workflow_run_id": workflow_run_id,
            "team": team,
            "deploy_key_title": deploy_key_title,
            "is_via_oauth_app": is_via_oauth_app,
            "country_code": country_code,
            "invitee_domain": invitee_domain,
            "repo_private": repo_private,
            "actor_ip_redacted": actor_ip_redacted,
            "user_agent_redacted": user_agent_redacted,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "github",
        }

        control_results: list[ControlResult] = []
        is_protected = _is_protected_branch(ref, self.protected_branch_patterns)

        # ----------------------------------------------------------------
        # 1. Branch-protection evasion (CRITICAL — admin override of
        # branch protection). Applies to git.push and pull_request.merge.
        # We treat any non-null branch_protection_evasion as a FAIL.
        # ----------------------------------------------------------------
        if branch_protection_evasion and action in {
            "git.push", "pull_request.merge"
        }:
            signal = "branch_protection_evasion"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"GitHub event {event_id} {action} on {repo or 'unknown'}"
                        f"{(' ref=' + ref) if ref else ''} "
                        f"recorded branch_protection_evasion="
                        f"{branch_protection_evasion!r} — admin override of "
                        f"branch protection is a critical compliance violation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Primary action classification.
        # ----------------------------------------------------------------
        pattern = self._classify_action(action) if action else None

        if pattern is not None:
            signal = str(pattern.get("signal", "unknown_event"))
            control_id = _control_for(
                signal, self._mappings, str(pattern.get("control", "PR-05"))
            )
            result = str(pattern.get("result", "PASS"))
            # repo.destroy always FAIL — catch via pattern.
            # secret_scanning.alert.create always FAIL → leaked secret evidence.
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"GitHub event {event_id} action={action!r} "
                        f"on repo={repo or 'unknown'} "
                        f"actor={actor_display or 'unknown'} "
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
                        f"GitHub event {event_id} action={action!r} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Fork head_repository on git.push — untrusted source content.
        # A push whose head_repository is owned by someone other than the
        # upstream org is a code-supply-chain risk.
        # ----------------------------------------------------------------
        if (
            action == "git.push"
            and head_repository
            and "/" in head_repository
            and (not org or not head_repository.startswith(org + "/"))
            and (not repo or head_repository != repo)
        ):
            signal = "fork_head_push"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} git.push from forked "
                        f"head_repository={head_repository!r} into {repo!r} — "
                        f"untrusted source content"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Agent-authored PR — must be reviewed by a human.
        # Triggers on actor_is_bot, is_ml_powered_action, or external_app_name set.
        # ----------------------------------------------------------------
        if action == "pull_request.create" and (
            actor_is_bot or is_ml_powered_action or external_app_name
        ):
            signal = "agent_authored_pr"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} pull_request.create authored by "
                        f"agent (actor_is_bot={actor_is_bot}, "
                        f"is_ml_powered_action={is_ml_powered_action}, "
                        f"external_app_name={external_app_name!r}) — "
                        f"requires human review before merge"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Public repo creation — IP exposure surface.
        # ----------------------------------------------------------------
        if action == "repo.create" and repo_private is False:
            signal = "public_repo_create"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} repo.create created public "
                        f"repository {repo!r} — IP exposure surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 6. Org-owner role promotion — critical privilege escalation.
        # ----------------------------------------------------------------
        if action == "members.update_role" and (
            (new_role or "").lower() == "owner"
        ):
            signal = "owner_role_promotion"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"GitHub event {event_id} members.update_role promoted "
                        f"to owner (old_role={old_role!r}, new_role={new_role!r}) "
                        f"in org {org!r} — critical privilege change"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 7. Admin-team add — privilege grant FLAG.
        # ----------------------------------------------------------------
        if action == "team.add_member" and team and "admin" in team.lower():
            signal = "admin_team_add"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} team.add_member added member "
                        f"to admin team={team!r} — privilege grant"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 8. External invite — domain not in org-domain → FLAG.
        # ----------------------------------------------------------------
        if (
            action == "org.invite_member"
            and invitee_domain
            and self.org_domain
            and invitee_domain.lstrip("@").lower() != self.org_domain
        ):
            signal = "external_invite"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} org.invite_member to external "
                        f"domain={invitee_domain!r} (org domain={self.org_domain!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif action == "org.invite_member" and invitee_domain and not self.org_domain:
            # No org_domain configured — capture invitee domain but do not flag.
            signal = "external_invite"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} org.invite_member to "
                        f"domain={invitee_domain!r} — verify allowlist "
                        f"(no org_domain configured)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 9. Code-scanning dismiss critical/high → FAIL.
        # ----------------------------------------------------------------
        if action == "code_scanning.alert.dismiss" and (
            (code_scan_alert_severity or "").lower() in {"critical", "high"}
        ):
            signal = "code_scan_dismiss_critical"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"GitHub event {event_id} code_scanning.alert.dismiss "
                        f"dismissed severity={code_scan_alert_severity!r} alert "
                        f"in repo {repo!r} — high/critical alerts must not "
                        f"be silently dismissed"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 10. Branch-protection weakening — comparison of permissions.
        # If old_permission > new_permission (e.g. admin → write or write → read),
        # treat as a weakening of branch protection.
        # ----------------------------------------------------------------
        if action == "branch_protection.update":
            ranking = {"read": 0, "write": 1, "admin": 2}
            old_rank = ranking.get((old_permission or "").lower(), -1)
            new_rank = ranking.get((permission or "").lower(), -1)
            weakening = old_rank > new_rank and new_rank >= 0
            # Also flag explicit weakening signal in the event.
            weakening = weakening or bool(event.get("weakened_protection"))
            if weakening:
                signal = "branch_protection_weakening"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"GitHub event {event_id} branch_protection.update "
                            f"weakened (old_permission={old_permission!r}, "
                            f"permission={permission!r}) on repo {repo!r}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 11. Workflow run failed in protected workflow → DE-01 FLAG.
        # ----------------------------------------------------------------
        if action == "workflow_run":
            conclusion = str(event.get("conclusion") or "").lower()
            if conclusion == "failure" and is_protected:
                signal = "workflow_run_failed_protected"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"GitHub event {event_id} workflow_run failed on "
                            f"protected ref={ref!r} in repo {repo!r}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 12. Geographic anomaly — non-allowlisted country on repo.access.
        # ----------------------------------------------------------------
        if (
            action == "repo.access"
            and country_code
            and self.allowed_countries
            and country_code not in self.allowed_countries
        ):
            signal = "geographic_anomaly"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} repo.access from country "
                        f"{country_code!r} not in allowlist "
                        f"{sorted(self.allowed_countries)}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 13. Cross-repo pattern — informational marker on contributing events.
        # ----------------------------------------------------------------
        if actor and actor in cross_repo_actors:
            signal = "cross_repo_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} actor {actor_display or actor} "
                        f"is part of a cross-repo pattern "
                        f"({len(cross_repo_actors[actor])} repos > "
                        f"threshold {self.cross_repo_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_repo_repos": cross_repo_actors[actor],
                        "cross_repo_threshold": self.cross_repo_threshold,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 14. Bot-velocity pattern — informational marker on contributing events.
        # ----------------------------------------------------------------
        if actor and actor in bot_velocity_actors:
            signal = "bot_velocity_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"GitHub event {event_id} actor {actor_display or actor} "
                        f"is part of a bot-velocity pattern "
                        f"({bot_velocity_actors[actor]} PR-creates > "
                        f"threshold {self.bot_velocity_threshold} "
                        f"in {self.bot_velocity_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bot_velocity_count": bot_velocity_actors[actor],
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
            f"Imported from GitHub audit log: action={action} "
            f"actor={actor_display or 'unknown'} "
            f"repo={repo or 'unknown'} "
            f"ref={ref or 'none'} "
            f"branch_protection_evasion={branch_protection_evasion or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"github-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="github_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=str(workflow_run_id) if workflow_run_id else None,
        )

    def _synthetic_cross_repo_result(
        self,
        *,
        actor: str,
        is_bot: bool,
        repos: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor cross-repo pattern finding."""
        signal = "cross_repo_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"github-cross-repo-{actor}"
        actor_display = f"{actor}_bot" if is_bot else actor
        evidence: dict[str, Any] = {
            "github_event_id": synthetic_id,
            "actor": actor_display,
            "actor_is_bot": is_bot,
            "cross_repo_repos": repos,
            "cross_repo_repo_count": len(repos),
            "cross_repo_threshold": self.cross_repo_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "github",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"GitHub synthetic finding: actor {actor_display} touched "
                f"{len(repos)} repos in this export "
                f"({', '.join(repos)}) — exceeds cross-repo threshold "
                f"{self.cross_repo_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="github_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from GitHub audit log: synthetic cross-repo pattern "
                f"for actor={actor_display} repos={len(repos)}>threshold="
                f"{self.cross_repo_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
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
        synthetic_id = f"github-bot-velocity-{actor}"
        actor_display = f"{actor}_bot"
        evidence: dict[str, Any] = {
            "github_event_id": synthetic_id,
            "actor": actor_display,
            "actor_is_bot": True,
            "bot_velocity_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "github",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"GitHub synthetic finding: bot {actor_display} opened "
                f"{count} PRs in a {self.bot_velocity_window_seconds}s window "
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
            source_type="github_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from GitHub audit log: synthetic bot-velocity pattern "
                f"for bot={actor_display} count={count}>threshold="
                f"{self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
