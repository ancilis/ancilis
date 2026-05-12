# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Vercel audit-event importer — maps coding-agent and human Vercel activity to AKSI controls.

Vercel (https://vercel.com) is the dominant deployment platform for frontend
and serverless code, including AI-generated code shipped from v0, Lovable,
Bolt, and Replit. Coding agents push to Vercel hundreds of times daily — and
Vercel's ``/v1/teams/{team_id}/audit-logs`` endpoint, ``/v6/deployments``
endpoint, and webhook events are the durable evidence source for what an
agent actually deployed, where it landed, and who promoted it to production.

This importer ingests Vercel audit-log exports and webhook captures in three
on-disk shapes:

  1. ``{"events": [...]}`` — primary Vercel audit-log envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                  — one event per line

Signal mapping (see shared/mappings/vercel-aksi-controls.json):
  * ``deployment.created`` target=production source=git, human creator      → PR-05 PASS
  * ``deployment.created`` target=production with creator.is_bot OR
    via_template OR source=api                                              → PR-01 FLAG
    (agent-deployed to production — review)
  * ``deployment.created`` target=preview                                   → PR-05 PASS
    (preview environments are normal CI artifacts)
  * ``deployment.error`` build_error_count > 0                              → PR-03 FLAG
  * ``deployment.promoted`` to production by bot                            → PR-02 FAIL
    (autonomous prod promotion = approval-gate breach)
  * ``domain.added`` / ``alias.created``                                    → PR-04 FLAG
    (new public surface — exposure event)
  * ``domain.removed``                                                      → PR-05 PASS
  * ``env.created`` / ``env.updated`` with secret-pattern key in production → PR-01 FLAG
  * ``env.deleted``                                                         → PR-05 PASS
  * ``team.member.role.updated`` previous=VIEWER/DEVELOPER new=OWNER        → PR-02 FAIL
  * ``team.member.added``                                                   → PR-02 FLAG
  * ``team.transfer.requested``                                             → PR-02 FAIL
    (org-level transfer = highest-impact action)
  * ``team.sso.config.updated``                                             → PR-02 FLAG
  * ``integration.added``                                                   → PR-01 FLAG
  * ``secret.created``                                                      → PR-01 FLAG
  * ``project.deleted``                                                     → PR-02 FAIL
  * ``checks.created`` conclusion=failure blocking=true on production       → PR-03 FAIL
  * ``edge_config.updated``                                                 → PR-05 FLAG
  * bot-velocity: bot creator deploying > N times to production in 1h
    (default N=5)                                                           → PR-02 FLAG synthetic
  * cross-project: bot touching > N projects in export (default N=5)        → PR-02 FLAG synthetic

Sanitization (security-critical — Vercel audit logs can carry actor IPs,
full user-agents, deployment URLs, commit SHAs, commit author logins, and
environment-variable values that may include tenant identifiers and tokens):
  * ``deployment.url`` is reduced to host-only via ``urlsplit``; the full
    URL (which includes per-deployment slugs) is never persisted.
  * ``git_metadata.commit_sha`` is captured as the last 8 chars only.
  * ``git_metadata.commit_author_login`` is reduced to length + sha256
    (a login can carry email-style PII).
  * ``user.email`` is reduced to ``@domain`` only.
  * ``user.username`` is reduced to length + sha256.
  * ``ip`` is reduced to a /16 pattern (first two octets) for IPv4 and
    /32 hextet pattern for IPv6. RFC1918 private addresses preserved
    verbatim. Loopback / link-local preserved.
  * ``user_agent`` is captured as the first 80 characters plus a sha256
    hash of the full string (so identical agents collide while not
    retaining the full token-bearing fingerprint).
  * Environment-variable values are NEVER stored — only the key names are
    captured. If a key name itself matches a secret pattern (``API_KEY``,
    ``SECRET``, ``TOKEN``, ``PASSWORD``, ``CREDENTIAL``, ``PRIVATE_KEY``),
    the key is redacted to a 4-char prefix + sha256 of the full key.
  * Domains are stored verbatim — public DNS is by definition non-sensitive.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``vercel`` package; Vercel audit-log JSON
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
from urllib.parse import urlsplit

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at
#   <repo>/python/src/ancilis/importers/vercel.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "vercel-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Default type patterns (mirrors the canonical _metadata.type_patterns in
# the JSON mapping table — used as a fallback if the JSON is missing).
_DEFAULT_TYPE_PATTERNS: tuple[dict[str, Any], ...] = (
    {"type": "deployment.created", "signal": "deployment_created", "result": "PASS", "control": "PR-05"},
    {"type": "deployment.ready", "signal": "deployment_ready", "result": "PASS", "control": "PR-05"},
    {"type": "deployment.error", "signal": "deployment_error", "result": "PASS", "control": "PR-05"},
    {"type": "deployment.canceled", "signal": "deployment_canceled", "result": "PASS", "control": "PR-05"},
    {"type": "deployment.promoted", "signal": "deployment_promoted", "result": "PASS", "control": "PR-05"},
    {"type": "domain.added", "signal": "domain_added", "result": "FLAG", "control": "PR-04"},
    {"type": "domain.removed", "signal": "domain_removed", "result": "PASS", "control": "PR-05"},
    {"type": "alias.created", "signal": "alias_created", "result": "FLAG", "control": "PR-04"},
    {"type": "env.created", "signal": "env_created", "result": "PASS", "control": "PR-05"},
    {"type": "env.updated", "signal": "env_updated", "result": "PASS", "control": "PR-05"},
    {"type": "env.deleted", "signal": "env_deleted", "result": "PASS", "control": "PR-05"},
    {"type": "team.member.added", "signal": "team_member_added", "result": "FLAG", "control": "PR-02"},
    {"type": "team.member.removed", "signal": "team_member_removed", "result": "PASS", "control": "PR-05"},
    {"type": "team.member.role.updated", "signal": "team_member_role_updated", "result": "PASS", "control": "PR-05"},
    {"type": "team.transfer.requested", "signal": "team_transfer_requested", "result": "FAIL", "control": "PR-02"},
    {"type": "team.sso.config.updated", "signal": "team_sso_config_updated", "result": "FLAG", "control": "PR-02"},
    {"type": "project.created", "signal": "project_created", "result": "PASS", "control": "PR-05"},
    {"type": "project.deleted", "signal": "project_deleted", "result": "FAIL", "control": "PR-02"},
    {"type": "integration.added", "signal": "integration_added", "result": "FLAG", "control": "PR-01"},
    {"type": "integration.removed", "signal": "integration_removed", "result": "PASS", "control": "PR-05"},
    {"type": "secret.created", "signal": "secret_created", "result": "FLAG", "control": "PR-01"},
    {"type": "secret.removed", "signal": "secret_removed", "result": "PASS", "control": "PR-05"},
    {"type": "edge_config.updated", "signal": "edge_config_updated", "result": "FLAG", "control": "PR-05"},
    {"type": "checks.created", "signal": "checks_created", "result": "PASS", "control": "PR-05"},
)

_DEFAULT_SECRET_KEY_PATTERNS: tuple[str, ...] = (
    "*API_KEY*",
    "*SECRET*",
    "*TOKEN*",
    "*PASSWORD*",
    "*CREDENTIAL*",
    "*PRIVATE_KEY*",
)
_DEFAULT_BOT_VELOCITY_THRESHOLD = 5
_DEFAULT_BOT_VELOCITY_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_PROJECT_THRESHOLD = 5

_OWNER_ROLE = "OWNER"
_LOWER_ROLES: frozenset[str] = frozenset({"VIEWER", "DEVELOPER", "MEMBER", "BILLING"})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the vercel-aksi-controls.json mapping; tolerate missing file."""
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
    """Reduce an IP to a /16 IPv4 or /32-hextet IPv6 pattern."""
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
    """Capture first 80 chars + sha256 of full UA."""
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


def _redact_identifier(value: str | None) -> dict[str, Any] | None:
    """Reduce an identifier (e.g. username, login) to length + sha256."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    return {"length": len(v), "sha256": hashlib.sha256(v.encode("utf-8")).hexdigest()}


def _host_only(url: str | None) -> str | None:
    """Reduce a URL to its host component."""
    if not url or not isinstance(url, str):
        return None
    u = url.strip()
    if not u:
        return None
    try:
        parts = urlsplit(u if "://" in u else f"https://{u}")
    except ValueError:
        return None
    host = parts.hostname
    return host or None


def _last8_sha(sha: str | None) -> str | None:
    """Reduce a commit SHA to its last 8 characters."""
    if not sha or not isinstance(sha, str):
        return None
    s = sha.strip()
    if not s:
        return None
    return s[-8:]


def _matches_type(event_type: str, pattern: dict[str, Any]) -> bool:
    return fnmatch.fnmatchcase(event_type, str(pattern.get("type", "")))


def _key_is_secret(key: str, patterns: Iterable[str]) -> bool:
    upper = key.upper()
    return any(fnmatch.fnmatchcase(upper, p.upper()) for p in patterns)


def _redact_secret_key(key: str) -> str:
    """If a key name matches a secret pattern, retain only a short prefix
    plus a sha256 digest of the full key — never the full key.
    """
    prefix_len = min(4, len(key))
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"{key[:prefix_len]}...{digest[:16]}"


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
    dt = _parse_iso_timestamp(value)
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class VercelImporter:
    """Parse a Vercel audit-log export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        secret_key_patterns: Iterable[str] | None = None,
        bot_velocity_threshold: int | None = None,
        bot_velocity_window_seconds: int | None = None,
        cross_project_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        meta_patterns = meta.get("type_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._type_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._type_patterns = _DEFAULT_TYPE_PATTERNS
        # Secret key patterns: explicit arg > mapping metadata > default.
        if secret_key_patterns is not None:
            self.secret_key_patterns: tuple[str, ...] = tuple(
                str(p) for p in secret_key_patterns
            )
        else:
            meta_secret = meta.get("secret_key_patterns")
            if isinstance(meta_secret, list) and meta_secret:
                self.secret_key_patterns = tuple(str(p) for p in meta_secret)
            else:
                self.secret_key_patterns = _DEFAULT_SECRET_KEY_PATTERNS
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
        if cross_project_threshold is not None:
            self.cross_project_threshold = int(cross_project_threshold)
        else:
            self.cross_project_threshold = int(
                meta.get("cross_project_threshold", _DEFAULT_CROSS_PROJECT_THRESHOLD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Vercel audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Vercel audit-log content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
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
        # Pass 1: aggregate bot creator → projects (cross-project) and bot
        # creator → production-deployment timestamps (bot-velocity).
        bot_projects: dict[str, set[str]] = {}
        bot_prod_deploy_ts: dict[str, list[datetime]] = {}

        for ev in events:
            if not isinstance(ev, dict):
                continue
            ev_type = str(ev.get("type") or "")
            deployment = ev.get("deployment") or {}
            if not isinstance(deployment, dict):
                deployment = {}
            creator = deployment.get("creator") or {}
            if not isinstance(creator, dict):
                creator = {}
            creator_username = creator.get("username")
            is_bot = bool(creator.get("is_bot"))
            target = deployment.get("target")
            if not (
                ev_type == "deployment.created"
                and is_bot
                and isinstance(creator_username, str)
                and creator_username
            ):
                continue
            project = ev.get("project") or {}
            if isinstance(project, dict):
                project_id = project.get("id") or project.get("name")
                if isinstance(project_id, str) and project_id:
                    bot_projects.setdefault(creator_username, set()).add(project_id)
            if target == "production":
                ts = _parse_iso_timestamp(ev.get("createdAt"))
                if ts is not None:
                    bot_prod_deploy_ts.setdefault(creator_username, []).append(ts)

        cross_project_bots: dict[str, list[str]] = {
            bot: sorted(projects)
            for bot, projects in bot_projects.items()
            if len(projects) > self.cross_project_threshold
        }

        bot_velocity_bots: dict[str, int] = {}
        window = self.bot_velocity_window_seconds
        for bot, timestamps in bot_prod_deploy_ts.items():
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
                bot_velocity_bots[bot] = max_in_window

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                cross_project_bots=cross_project_bots,
                bot_velocity_bots=bot_velocity_bots,
            )
            for ev in events
        ]

        for bot, projects in sorted(cross_project_bots.items()):
            results.append(
                self._synthetic_cross_project_result(
                    bot=bot,
                    projects=projects,
                    file_sha256=file_sha256,
                )
            )
        for bot, count in sorted(bot_velocity_bots.items()):
            results.append(
                self._synthetic_bot_velocity_result(
                    bot=bot,
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
            "source_format": "vercel_audit_log",
            "source_tool_name": "vercel",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_type(self, event_type: str) -> dict[str, Any] | None:
        for pattern in self._type_patterns:
            if _matches_type(event_type, pattern):
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
        cross_project_bots: dict[str, list[str]],
        bot_velocity_bots: dict[str, int],
    ) -> EvaluationResult:
        event_id = str(event.get("id") or uuid.uuid4())
        event_type = str(event.get("type") or "").strip()
        timestamp = _format_timestamp(event.get("createdAt"))

        # Actor (top-level user).
        user = event.get("user") or {}
        if not isinstance(user, dict):
            user = {}
        user_email_domain = _redact_email(
            user.get("email") if isinstance(user.get("email"), str) else None
        )
        user_username_redacted = _redact_identifier(
            user.get("username") if isinstance(user.get("username"), str) else None
        )
        user_id = (
            str(user.get("id"))
            if isinstance(user.get("id"), (str, int))
            else None
        )

        # Team.
        team = event.get("team") or {}
        if not isinstance(team, dict):
            team = {}
        team_id = str(team.get("id")) if isinstance(team.get("id"), (str, int)) else None
        team_slug = str(team.get("slug")) if isinstance(team.get("slug"), str) else None

        # Project.
        project = event.get("project") or {}
        if not isinstance(project, dict):
            project = {}
        project_id = (
            str(project.get("id")) if isinstance(project.get("id"), (str, int)) else None
        )
        project_name = (
            str(project.get("name")) if isinstance(project.get("name"), str) else None
        )
        project_framework = (
            str(project.get("framework"))
            if isinstance(project.get("framework"), str)
            else None
        )

        # Deployment.
        deployment = event.get("deployment") or {}
        if not isinstance(deployment, dict):
            deployment = {}
        deployment_id = (
            str(deployment.get("id"))
            if isinstance(deployment.get("id"), (str, int))
            else None
        )
        deployment_url_host = _host_only(
            deployment.get("url") if isinstance(deployment.get("url"), str) else None
        )
        deployment_target = (
            str(deployment.get("target"))
            if isinstance(deployment.get("target"), str)
            else None
        )
        deployment_source = (
            str(deployment.get("source"))
            if isinstance(deployment.get("source"), str)
            else None
        )
        deployment_ready_state = (
            str(deployment.get("ready_state"))
            if isinstance(deployment.get("ready_state"), str)
            else None
        )
        build_skipped = bool(deployment.get("build_skipped")) if (
            "build_skipped" in deployment
        ) else None
        duration_ms_raw = deployment.get("duration_ms")
        duration_ms = (
            float(duration_ms_raw)
            if isinstance(duration_ms_raw, (int, float))
            else None
        )
        build_error_count_raw = deployment.get("build_error_count")
        build_error_count = (
            int(build_error_count_raw)
            if isinstance(build_error_count_raw, (int, float))
            else None
        )
        via_template = deployment.get("via_template")
        via_template = (
            str(via_template)
            if isinstance(via_template, str) and via_template.strip()
            else None
        )
        creator = deployment.get("creator") or {}
        if not isinstance(creator, dict):
            creator = {}
        creator_username = (
            str(creator.get("username"))
            if isinstance(creator.get("username"), str)
            else None
        )
        creator_is_bot = bool(creator.get("is_bot"))
        # Git metadata.
        git_metadata = deployment.get("git_metadata") or {}
        if not isinstance(git_metadata, dict):
            git_metadata = {}
        git_branch = (
            str(git_metadata.get("branch"))
            if isinstance(git_metadata.get("branch"), str)
            else None
        )
        git_provider = (
            str(git_metadata.get("provider"))
            if isinstance(git_metadata.get("provider"), str)
            else None
        )
        git_commit_sha = _last8_sha(
            git_metadata.get("commit_sha")
            if isinstance(git_metadata.get("commit_sha"), str)
            else None
        )
        git_commit_msg_len = (
            int(git_metadata.get("commit_message_length"))
            if isinstance(git_metadata.get("commit_message_length"), (int, float))
            else None
        )
        git_commit_author_login_redacted = _redact_identifier(
            git_metadata.get("commit_author_login")
            if isinstance(git_metadata.get("commit_author_login"), str)
            else None
        )
        git_repo = (
            str(git_metadata.get("repo"))
            if isinstance(git_metadata.get("repo"), str)
            else None
        )

        # env_var_changes (capture key-name + target only; redact secret keys).
        env_var_changes_raw = event.get("env_var_changes") or []
        env_var_changes_clean: list[dict[str, Any]] = []
        env_var_keys: list[str] = []
        env_var_secret_targets: list[str] = []
        production_secret_change = False
        if isinstance(env_var_changes_raw, list):
            for entry in env_var_changes_raw:
                if not isinstance(entry, dict):
                    continue
                key = entry.get("key") if isinstance(entry.get("key"), str) else None
                change = (
                    str(entry.get("change"))
                    if isinstance(entry.get("change"), str)
                    else None
                )
                target_raw = entry.get("target")
                target_list: list[str] = []
                if isinstance(target_raw, list):
                    target_list = [
                        str(t) for t in target_raw if isinstance(t, str)
                    ]
                elif isinstance(target_raw, str):
                    target_list = [target_raw]
                is_secret = bool(
                    key and _key_is_secret(key, self.secret_key_patterns)
                )
                stored_key = (
                    _redact_secret_key(key) if (is_secret and key) else key
                )
                env_var_changes_clean.append(
                    {
                        "key": stored_key,
                        "change": change,
                        "target": target_list,
                        "is_secret_key_pattern": is_secret,
                    }
                )
                if key:
                    env_var_keys.append(stored_key or "")
                if (
                    is_secret
                    and "production" in {t.lower() for t in target_list}
                    and change in {"created", "updated"}
                ):
                    production_secret_change = True
                    env_var_secret_targets.append(stored_key or "")

        # Domain (verbatim — public DNS).
        domain = event.get("domain") or {}
        if not isinstance(domain, dict):
            domain = {}
        domain_name = (
            str(domain.get("name"))
            if isinstance(domain.get("name"), str)
            else None
        )

        # Team-member role change.
        team_member = event.get("team_member") or {}
        if not isinstance(team_member, dict):
            team_member = {}
        role_changed_to = (
            str(team_member.get("role_changed_to"))
            if isinstance(team_member.get("role_changed_to"), str)
            else None
        )
        previous_role = (
            str(team_member.get("previous_role"))
            if isinstance(team_member.get("previous_role"), str)
            else None
        )

        # Secret event payload.
        secret_block = event.get("secret") or {}
        if not isinstance(secret_block, dict):
            secret_block = {}
        secret_name_raw = (
            str(secret_block.get("name"))
            if isinstance(secret_block.get("name"), str)
            else None
        )
        secret_name = secret_name_raw
        if secret_name_raw and _key_is_secret(secret_name_raw, self.secret_key_patterns):
            secret_name = _redact_secret_key(secret_name_raw)

        # Checks block.
        checks = event.get("checks") or {}
        if not isinstance(checks, dict):
            checks = {}
        check_name = (
            str(checks.get("name")) if isinstance(checks.get("name"), str) else None
        )
        check_status = (
            str(checks.get("status")) if isinstance(checks.get("status"), str) else None
        )
        check_conclusion = (
            str(checks.get("conclusion"))
            if isinstance(checks.get("conclusion"), str)
            else None
        )
        check_blocking = bool(checks.get("blocking")) if "blocking" in checks else False

        ip_redacted = _classify_actor_ip(
            event.get("ip") if isinstance(event.get("ip"), str) else None
        )
        user_agent_redacted = _redact_user_agent(
            event.get("user_agent") if isinstance(event.get("user_agent"), str) else None
        )

        common_evidence: dict[str, Any] = {
            "vercel_event_id": event_id,
            "type": event_type,
            "user_id": user_id,
            "user_email_domain": user_email_domain,
            "user_username_redacted": user_username_redacted,
            "team_id": team_id,
            "team_slug": team_slug,
            "project_id": project_id,
            "project_name": project_name,
            "project_framework": project_framework,
            "deployment_id": deployment_id,
            "deployment_url_host": deployment_url_host,
            "deployment_target": deployment_target,
            "deployment_source": deployment_source,
            "deployment_ready_state": deployment_ready_state,
            "deployment_build_skipped": build_skipped,
            "deployment_duration_ms": duration_ms,
            "deployment_build_error_count": build_error_count,
            "deployment_via_template": via_template,
            "deployment_creator_username": creator_username,
            "deployment_creator_is_bot": creator_is_bot,
            "git_branch": git_branch,
            "git_provider": git_provider,
            "git_commit_sha_last8": git_commit_sha,
            "git_commit_message_length": git_commit_msg_len,
            "git_commit_author_login_redacted": git_commit_author_login_redacted,
            "git_repo": git_repo,
            "env_var_changes": env_var_changes_clean or None,
            "env_var_change_count": len(env_var_changes_clean) or None,
            "env_var_keys": env_var_keys or None,
            "domain_name": domain_name,
            "team_member_role_changed_to": role_changed_to,
            "team_member_previous_role": previous_role,
            "secret_name": secret_name,
            "check_name": check_name,
            "check_status": check_status,
            "check_conclusion": check_conclusion,
            "check_blocking": check_blocking,
            "ip_redacted": ip_redacted,
            "user_agent_redacted": user_agent_redacted,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "vercel",
        }

        control_results: list[ControlResult] = []
        is_production = deployment_target == "production"
        is_preview = deployment_target == "preview"
        agent_indicator = (
            creator_is_bot
            or via_template is not None
            or deployment_source == "api"
        )

        # ----------------------------------------------------------------
        # 1. Primary type classification.
        # ----------------------------------------------------------------
        pattern = self._classify_type(event_type) if event_type else None

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
                        f"Vercel event {event_id} type={event_type!r} "
                        f"on project={project_name or project_id or 'unknown'} "
                        f"target={deployment_target or 'n/a'} "
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
                        f"Vercel event {event_id} type={event_type!r} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Agent-deployed-to-production overlay (FLAG).
        # creator.is_bot OR via_template set OR source=api on a production
        # deployment.created → PR-01 FLAG (review).
        # ----------------------------------------------------------------
        if event_type == "deployment.created" and is_production and agent_indicator:
            signal = "agent_production_deployment"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Vercel event {event_id} deployment.created to production "
                        f"by agent (creator_is_bot={creator_is_bot}, "
                        f"via_template={via_template!r}, source={deployment_source!r}) "
                        f"on project={project_name or project_id or 'unknown'} — "
                        f"requires human review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif event_type == "deployment.created" and is_production:
            signal = "production_deployment_audit"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Vercel event {event_id} human production deployment "
                        f"by {creator_username or 'unknown'} "
                        f"on {project_name or project_id or 'unknown'} "
                        f"(audit trail)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif event_type == "deployment.created" and is_preview:
            signal = "preview_deployment_audit"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Vercel event {event_id} preview deployment "
                        f"by {creator_username or 'unknown'} "
                        f"on {project_name or project_id or 'unknown'} "
                        f"(preview environments are normal CI artifacts)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. deployment.error with build_error_count > 0 → PR-03 FLAG.
        # ----------------------------------------------------------------
        if event_type == "deployment.error" and (build_error_count or 0) > 0:
            signal = "deployment_build_error"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Vercel event {event_id} deployment.error with "
                        f"build_error_count={build_error_count} on "
                        f"{project_name or project_id or 'unknown'} — "
                        f"build failure"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Autonomous production-promote — bot promoted a deployment to
        # production without a human in the loop. PR-02 FAIL.
        # ----------------------------------------------------------------
        if (
            event_type == "deployment.promoted"
            and is_production
            and creator_is_bot
        ):
            signal = "autonomous_production_promote"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Vercel event {event_id} deployment.promoted to "
                        f"production by bot creator={creator_username!r} on "
                        f"project={project_name or project_id or 'unknown'} — "
                        f"autonomous prod promotion is an approval-gate breach"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Production secret change overlay (PR-01 FLAG).
        # env.created / env.updated with a secret-pattern key in production.
        # ----------------------------------------------------------------
        if (
            event_type in {"env.created", "env.updated"}
            and production_secret_change
        ):
            signal = "production_secret_change"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Vercel event {event_id} {event_type} touched "
                        f"{len(env_var_secret_targets)} secret-pattern key(s) "
                        f"in production on "
                        f"{project_name or project_id or 'unknown'} — "
                        f"production secret change requires review"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "production_secret_keys": env_var_secret_targets,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 6. Owner promotion — previous role lower than OWNER, new=OWNER.
        # ----------------------------------------------------------------
        if (
            event_type == "team.member.role.updated"
            and (role_changed_to or "").upper() == _OWNER_ROLE
            and (previous_role or "").upper() in _LOWER_ROLES
        ):
            signal = "owner_role_promotion"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Vercel event {event_id} team.member.role.updated "
                        f"promoted to OWNER (previous_role={previous_role!r}) "
                        f"in team={team_slug or team_id or 'unknown'} — "
                        f"critical privilege change"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 7. Blocking check failure on production deployment → PR-03 FAIL.
        # ----------------------------------------------------------------
        if (
            event_type == "checks.created"
            and check_blocking
            and (check_conclusion or "").lower() == "failure"
            and is_production
        ):
            signal = "blocking_check_failure"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Vercel event {event_id} checks.created blocking "
                        f"check={check_name!r} failed (conclusion={check_conclusion!r}) "
                        f"on production deployment "
                        f"{deployment_id or 'unknown'} on "
                        f"{project_name or project_id or 'unknown'}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 8. Cross-project pattern marker on contributing events.
        # ----------------------------------------------------------------
        if creator_username and creator_username in cross_project_bots:
            signal = "cross_project_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Vercel event {event_id} bot creator={creator_username!r} "
                        f"is part of a cross-project pattern "
                        f"({len(cross_project_bots[creator_username])} projects > "
                        f"threshold {self.cross_project_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_project_projects": cross_project_bots[creator_username],
                        "cross_project_threshold": self.cross_project_threshold,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 9. Bot-velocity pattern marker on contributing events.
        # ----------------------------------------------------------------
        if creator_username and creator_username in bot_velocity_bots:
            signal = "bot_velocity_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Vercel event {event_id} bot creator={creator_username!r} "
                        f"is part of a bot-velocity pattern "
                        f"({bot_velocity_bots[creator_username]} production deploys "
                        f"> threshold {self.bot_velocity_threshold} in "
                        f"{self.bot_velocity_window_seconds}s window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bot_velocity_count": bot_velocity_bots[creator_username],
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
            f"Imported from Vercel audit log: type={event_type} "
            f"project={project_name or project_id or 'unknown'} "
            f"target={deployment_target or 'none'} "
            f"creator_is_bot={creator_is_bot}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"vercel-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="vercel_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=deployment_id,
        )

    def _synthetic_cross_project_result(
        self,
        *,
        bot: str,
        projects: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_project_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"vercel-cross-project-{bot}"
        evidence: dict[str, Any] = {
            "vercel_event_id": synthetic_id,
            "deployment_creator_username": bot,
            "deployment_creator_is_bot": True,
            "cross_project_projects": projects,
            "cross_project_project_count": len(projects),
            "cross_project_threshold": self.cross_project_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "vercel",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Vercel synthetic finding: bot {bot!r} touched {len(projects)} "
                f"projects in this export ({', '.join(projects)}) — exceeds "
                f"cross-project threshold {self.cross_project_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="vercel_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Vercel audit log: synthetic cross-project "
                f"pattern for bot={bot} projects={len(projects)}>threshold="
                f"{self.cross_project_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_bot_velocity_result(
        self,
        *,
        bot: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "bot_velocity_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"vercel-bot-velocity-{bot}"
        evidence: dict[str, Any] = {
            "vercel_event_id": synthetic_id,
            "deployment_creator_username": bot,
            "deployment_creator_is_bot": True,
            "bot_velocity_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "bot_velocity_window_seconds": self.bot_velocity_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "vercel",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Vercel synthetic finding: bot {bot!r} ran {count} production "
                f"deployments in a {self.bot_velocity_window_seconds}s window "
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
            source_type="vercel_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Vercel audit log: synthetic bot-velocity "
                f"pattern for bot={bot} count={count}>threshold="
                f"{self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
