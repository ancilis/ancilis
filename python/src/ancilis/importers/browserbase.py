"""Browserbase session-export importer — maps hosted browser-automation sessions to AKSI controls.

Browserbase (https://browserbase.com) is the leading hosted browser-automation
platform for AI agents — agents drive headless Chromium sessions to fill forms,
click buttons, log in to third-party SaaS, scrape pages, download files, and
evaluate arbitrary JavaScript. Each session is a credentialed third-party
action carrying massive PII and exfiltration risk: a single session may touch
dozens of distinct domains, log into authenticated surfaces, and pull files
out of those surfaces back to the agent runtime.

This importer ingests the ``/v1/sessions`` and ``/v1/sessions/{id}/logs``
payloads in four on-disk shapes:

  1. ``{"sessions": [...]}`` — primary sessions envelope
  2. ``{"data": [...]}``       — generic data envelope
  3. JSONL                      — one session per line
  4. single session object

Signal mapping (see shared/mappings/browserbase-aksi-controls.json):
  * ``status=COMPLETED``                                            → PR-05 PASS  (audit trail)
  * ``status=FAILED`` / ``status=ERROR``                            → DE-01 FAIL
  * ``status=TIMED_OUT``                                            → PR-02 FLAG  (capacity / unbounded session)
  * ``captcha_solver_used=true``                                    → PR-01 FLAG  (anti-bot circumvention)
  * ``stealth_mode=true`` AND visited high-trust domain             → PR-01 FLAG  (deception surface)
  * ``proxy_used=true`` AND ``proxy_country`` differs from project  → PR-01 FLAG  (geographic provenance)
  * ``downloads_count > 0``                                         → PR-04 FLAG  (data exfiltration surface)
  * ``is_logged_in_to`` non-empty                                   → PR-04 FLAG  (auth-bound exfil risk)
  * any action ``type=evaluate``                                    → PR-03 FLAG  (arbitrary JS execution)
  * any action ``type in {type, fill_form}`` on auth-domain URL    → PR-04 FLAG  (credential entry)
  * ``url_count > threshold`` (default 50)                          → PR-04 FLAG  (broad-crawl session)
  * ``duration_ms > threshold`` (default 5min = 300000)             → PR-02 FLAG  (long-running session)
  * cross-domain pattern: > N distinct second-level domains in one
    session (default 5)                                             → PR-04 FLAG  (synthetic finding)

Sanitization: action ``target_selector`` values, URL query strings, and
``action.text`` contents are NEVER stored. Only:
  - action types and per-type counts
  - URL hostnames (eTLD+1 second-level domains and full hostnames)
  - ``url_path_present`` booleans (was there a non-root path on this URL)
  - the ``is_logged_in_to`` hostname list (already hostnames, already public)
  - aggregate counts (events_count, url_count, downloads_count, errors_count)

URL sanitization uses ``urllib.parse.urlsplit`` / ``urlunsplit`` (not regex)
to drop query, fragment, and userinfo components before any hostname or
path-presence check. The original file is hashed (sha256) for source
provenance.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/browserbase-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/browserbase.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "browserbase-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_CROSS_DOMAIN_THRESHOLD = 5
_DEFAULT_URL_COUNT_THRESHOLD = 50
_DEFAULT_DURATION_THRESHOLD_MS = 300_000
_DEFAULT_AUTH_DOMAIN_PATTERNS: tuple[str, ...] = (
    "login", "signin", "signup", "auth", "sso",
)
_DEFAULT_HIGH_TRUST_DOMAINS: tuple[str, ...] = (
    "google.com", "github.com", "microsoft.com", "okta.com", "auth0.com",
    "salesforce.com", "linkedin.com", "facebook.com", "apple.com", "amazon.com",
)

_CREDENTIAL_ENTRY_ACTION_TYPES: frozenset[str] = frozenset({"type", "fill_form"})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the browserbase-aksi-controls.json mapping; tolerate missing file."""
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
# URL sanitization
# ---------------------------------------------------------------------------


def _sanitize_url(url: str) -> tuple[str, str, bool]:
    """Strip query/fragment/userinfo from ``url``.

    Returns ``(safe_url, hostname, path_present)`` where ``safe_url`` is the
    URL with query string, fragment, and userinfo removed; ``hostname`` is
    the lower-cased host; and ``path_present`` is True iff the path is a
    non-root, non-empty path. Uses ``urllib.parse.urlsplit`` / ``urlunsplit``
    rather than regex so edge cases (encoded characters, IPv6 hosts, ports)
    are handled by the standard library.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return ("", "", False)
    hostname = (parts.hostname or "").lower()
    # Reconstruct netloc without userinfo and without password.
    netloc = hostname
    if parts.port is not None:
        netloc = f"{hostname}:{parts.port}"
    safe = urlunsplit((parts.scheme, netloc, parts.path or "", "", ""))
    path_present = bool(parts.path) and parts.path not in ("", "/")
    return (safe, hostname, path_present)


def _second_level_domain(hostname: str) -> str:
    """Return the eTLD+1 approximation: last two dot-separated labels.

    This is a best-effort second-level-domain extraction. It does not consult
    the public-suffix list (which would be a heavy dep), so co.uk-style hosts
    will collapse to "something.co.uk" only if the hostname has 3+ labels —
    callers should treat this as a coarse cross-domain bucket, not a
    cryptographic identity. For the cross-domain pattern it is sufficient.
    """
    if not hostname:
        return ""
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    return ".".join(labels[-2:])


def _hostname_matches_any(hostname: str, patterns: Iterable[str]) -> bool:
    """True if any pattern is a substring of hostname or matches its eTLD+1."""
    if not hostname:
        return False
    sld = _second_level_domain(hostname)
    for pat in patterns:
        if not pat:
            continue
        if pat in hostname or pat == sld:
            return True
    return False


def _url_matches_auth_pattern(safe_url: str, hostname: str, patterns: Iterable[str]) -> bool:
    """True if a URL's hostname OR path contains any auth pattern as a substring.

    We check the sanitized URL (no query string, no fragment) and the
    hostname. Substring matching is intentional — "login.example.com",
    "example.com/login", and "auth.salesforce.com/sso" all qualify.
    """
    safe_lower = safe_url.lower()
    host_lower = hostname.lower()
    for pat in patterns:
        if not pat:
            continue
        if pat in host_lower or pat in safe_lower:
            return True
    return False


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class BrowserbaseImporter:
    """Parse a Browserbase session export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        project_country: str | None = None,
        cross_domain_threshold: int | None = None,
        url_count_threshold: int | None = None,
        duration_threshold_ms: int | None = None,
        auth_domain_patterns: Iterable[str] | None = None,
        high_trust_domain_patterns: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.project_country = (
            project_country.lower() if isinstance(project_country, str) else None
        )

        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # Threshold precedence: explicit arg > mapping metadata > module default.
        if cross_domain_threshold is not None:
            self.cross_domain_threshold = int(cross_domain_threshold)
        else:
            self.cross_domain_threshold = int(
                meta.get("cross_domain_threshold", _DEFAULT_CROSS_DOMAIN_THRESHOLD)
            )

        if url_count_threshold is not None:
            self.url_count_threshold = int(url_count_threshold)
        else:
            self.url_count_threshold = int(
                meta.get("default_url_count_threshold", _DEFAULT_URL_COUNT_THRESHOLD)
            )

        if duration_threshold_ms is not None:
            self.duration_threshold_ms = int(duration_threshold_ms)
        else:
            self.duration_threshold_ms = int(
                meta.get("default_duration_threshold_ms", _DEFAULT_DURATION_THRESHOLD_MS)
            )

        if auth_domain_patterns is not None:
            self.auth_domain_patterns = tuple(
                str(p).lower() for p in auth_domain_patterns
            )
        else:
            meta_auth = meta.get("auth_domain_patterns")
            if isinstance(meta_auth, list) and meta_auth:
                self.auth_domain_patterns = tuple(str(p).lower() for p in meta_auth)
            else:
                self.auth_domain_patterns = _DEFAULT_AUTH_DOMAIN_PATTERNS

        if high_trust_domain_patterns is not None:
            self.high_trust_domain_patterns = tuple(
                str(p).lower() for p in high_trust_domain_patterns
            )
        else:
            meta_ht = meta.get("high_trust_domain_patterns")
            if isinstance(meta_ht, list) and meta_ht:
                self.high_trust_domain_patterns = tuple(
                    str(p).lower() for p in meta_ht
                )
            else:
                self.high_trust_domain_patterns = _DEFAULT_HIGH_TRUST_DOMAINS

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Browserbase session export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        sessions = self._sessions_from_text(text)
        return self._build_results(sessions, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Browserbase export content from a JSON or JSONL string."""
        sessions = self._sessions_from_text(content)
        return self._build_results(sessions, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _sessions_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"sessions": [...]}`` / ``{"data": [...]}`` / single / JSONL."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [s for s in doc if isinstance(s, dict)]
            if isinstance(doc, dict):
                if "sessions" in doc and isinstance(doc["sessions"], list):
                    return [s for s in doc["sessions"] if isinstance(s, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [s for s in doc["data"] if isinstance(s, dict)]
                # Single session object.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        sessions: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-session EvaluationResults."""
        return [
            self._parse_session(session, file_sha256=file_sha256)
            for session in sessions
        ]

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "browserbase",
            "source_tool_name": "browserbase",
            "source_tool_version": "",
        }
        if session_id is not None:
            provenance["session_id"] = session_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _summarize_actions(
        self,
        actions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Aggregate per-action evidence WITHOUT storing selectors, query strings, or text.

        Returned dict contains only safe aggregates:
          - action_type_counts: {type: count}
          - hostnames: sorted list of unique hostnames touched
          - second_level_domains: sorted list of unique eTLD+1 buckets
          - has_evaluate: bool
          - credential_entry_hostnames: sorted list of hostnames where a
            type/fill_form action targeted an auth-pattern URL
          - any_url_path_present: bool (informational — does NOT include the path)
        """
        type_counts: dict[str, int] = {}
        hostnames: set[str] = set()
        slds: set[str] = set()
        cred_entry_hosts: set[str] = set()
        has_evaluate = False
        any_url_path_present = False

        for act in actions:
            if not isinstance(act, dict):
                continue
            atype = str(act.get("type") or "").strip().lower()
            if atype:
                type_counts[atype] = type_counts.get(atype, 0) + 1
                if atype == "evaluate":
                    has_evaluate = True

            url_raw = act.get("url")
            if isinstance(url_raw, str) and url_raw:
                _, host, path_present = _sanitize_url(url_raw)
                if host:
                    hostnames.add(host)
                    sld = _second_level_domain(host)
                    if sld:
                        slds.add(sld)
                if path_present:
                    any_url_path_present = True

                # Credential-entry detection: type/fill_form on an auth-pattern URL.
                if atype in _CREDENTIAL_ENTRY_ACTION_TYPES:
                    safe_url, host, _ = _sanitize_url(url_raw)
                    if host and _url_matches_auth_pattern(
                        safe_url, host, self.auth_domain_patterns
                    ):
                        cred_entry_hosts.add(host)

        return {
            "action_type_counts": type_counts,
            "hostnames": sorted(hostnames),
            "second_level_domains": sorted(slds),
            "has_evaluate": has_evaluate,
            "credential_entry_hostnames": sorted(cred_entry_hosts),
            "any_url_path_present": any_url_path_present,
        }

    def _parse_session(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        session_id = str(entry.get("id") or uuid.uuid4())
        project_id = str(entry.get("project_id") or "")
        status = str(entry.get("status") or "").strip().upper()
        started_at = entry.get("started_at") or ""
        ended_at = entry.get("ended_at") or ""
        try:
            duration_ms = int(entry.get("duration_ms") or 0)
        except (TypeError, ValueError):
            duration_ms = 0

        user_metadata_raw = entry.get("user_metadata") or {}
        user_metadata = (
            user_metadata_raw if isinstance(user_metadata_raw, dict) else {}
        )
        agent_id_observed = user_metadata.get("agent_id")
        task_id = user_metadata.get("task_id")

        proxy_used = bool(entry.get("proxy_used", False))
        proxy_country_raw = entry.get("proxy_country")
        proxy_country = (
            str(proxy_country_raw).lower()
            if isinstance(proxy_country_raw, str) and proxy_country_raw
            else None
        )
        captcha_solver_used = bool(entry.get("captcha_solver_used", False))
        stealth_mode = bool(entry.get("stealth_mode", False))

        try:
            memory_url_kb = int(entry.get("memory_url_kb") or 0)
        except (TypeError, ValueError):
            memory_url_kb = 0
        try:
            events_count = int(entry.get("events_count") or 0)
        except (TypeError, ValueError):
            events_count = 0
        try:
            url_count = int(entry.get("url_count") or 0)
        except (TypeError, ValueError):
            url_count = 0
        try:
            downloads_count = int(entry.get("downloads_count") or 0)
        except (TypeError, ValueError):
            downloads_count = 0
        try:
            errors_count = int(entry.get("errors_count") or 0)
        except (TypeError, ValueError):
            errors_count = 0

        context_id = str(entry.get("context_id") or "")

        is_logged_in_raw = entry.get("is_logged_in_to") or []
        is_logged_in_to: list[str] = []
        if isinstance(is_logged_in_raw, list):
            for host in is_logged_in_raw:
                if isinstance(host, str) and host:
                    is_logged_in_to.append(host.lower())

        # Browser settings: keep only viewport (numeric) and a fingerprint
        # presence flag — the fingerprint string itself is opaque and not
        # actionable, but its presence is interesting.
        bs_raw = entry.get("browser_settings") or {}
        browser_settings_safe: dict[str, Any] = {}
        if isinstance(bs_raw, dict):
            viewport = bs_raw.get("viewport")
            if isinstance(viewport, dict):
                vp_safe: dict[str, Any] = {}
                for key in ("width", "height"):
                    val = viewport.get(key)
                    try:
                        if val is not None:
                            vp_safe[key] = int(val)
                    except (TypeError, ValueError):
                        pass
                if vp_safe:
                    browser_settings_safe["viewport"] = vp_safe
            browser_settings_safe["fingerprint_present"] = bool(bs_raw.get("fingerprint"))

        actions_raw = entry.get("actions") or []
        actions = actions_raw if isinstance(actions_raw, list) else []
        action_summary = self._summarize_actions(actions)

        # Cross-domain pattern: count distinct second-level domains touched
        # by this session's actions plus its is_logged_in_to surfaces.
        sld_set: set[str] = set(action_summary["second_level_domains"])
        for host in is_logged_in_to:
            sld = _second_level_domain(host)
            if sld:
                sld_set.add(sld)
        cross_domain_count = len(sld_set)
        cross_domain_hit = cross_domain_count > self.cross_domain_threshold

        # Stealth-mode-on-high-trust-domain check.
        high_trust_visited = False
        for host in action_summary["hostnames"]:
            if _hostname_matches_any(host, self.high_trust_domain_patterns):
                high_trust_visited = True
                break
        if not high_trust_visited:
            for host in is_logged_in_to:
                if _hostname_matches_any(host, self.high_trust_domain_patterns):
                    high_trust_visited = True
                    break

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            session_id=session_id,
        )

        common_evidence: dict[str, Any] = {
            "browserbase_session_id": session_id,
            "project_id": project_id,
            "status": status,
            "started_at": str(started_at),
            "ended_at": str(ended_at),
            "duration_ms": duration_ms,
            "agent_id_observed": (
                str(agent_id_observed) if agent_id_observed is not None else None
            ),
            "task_id": str(task_id) if task_id is not None else None,
            "project_country": self.project_country,
            "proxy_used": proxy_used,
            "proxy_country": proxy_country,
            "captcha_solver_used": captcha_solver_used,
            "stealth_mode": stealth_mode,
            "memory_url_kb": memory_url_kb,
            "events_count": events_count,
            "url_count": url_count,
            "downloads_count": downloads_count,
            "errors_count": errors_count,
            "context_id": context_id,
            "is_logged_in_to": is_logged_in_to,
            "browser_settings": browser_settings_safe,
            "action_type_counts": action_summary["action_type_counts"],
            "action_hostnames": action_summary["hostnames"],
            "action_second_level_domains": action_summary["second_level_domains"],
            "any_url_path_present": action_summary["any_url_path_present"],
            "source_provenance": source_provenance,
            "source_tool": "browserbase",
        }

        control_results: list[ControlResult] = []

        # 1. Status — primary signal.
        if status == "COMPLETED":
            signal = "status_completed"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Browserbase session {session_id} on project {project_id} "
                        f"completed cleanly — audit trail recorded "
                        f"(duration_ms={duration_ms}, urls={url_count})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif status in ("FAILED", "ERROR"):
            signal = "status_failed" if status == "FAILED" else "status_error"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Browserbase session {session_id} on project {project_id} "
                        f"terminated with status={status} "
                        f"(errors_count={errors_count})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif status == "TIMED_OUT":
            signal = "status_timed_out"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} on project {project_id} "
                        f"timed out (capacity / unbounded session signal, "
                        f"duration_ms={duration_ms})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif status == "RUNNING":
            # Live session in the middle of execution — informational, not an alert.
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Browserbase session {session_id} is currently RUNNING — "
                        f"point-in-time audit trail snapshot"
                    ),
                    evidence_data={**common_evidence, "signal": "status_running"},
                )
            )
        else:
            # Unknown / missing status — surface as PR-02 FLAG so it does not silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} on project {project_id} "
                        f"has unrecognized status={entry.get('status')!r}"
                    ),
                    evidence_data={**common_evidence, "signal": "status_unknown"},
                )
            )

        # 2. CAPTCHA solver — anti-bot circumvention; legal/compliance flag.
        if captcha_solver_used:
            signal = "captcha_solver_used"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} used a captcha solver — "
                        f"anti-bot circumvention; review for legal/compliance "
                        f"implications on visited domains"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 3. Stealth-mode-on-high-trust-domain — deception surface.
        if stealth_mode and high_trust_visited:
            signal = "stealth_mode_high_trust"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} ran in stealth_mode while "
                        f"visiting a high-trust domain — deception surface, "
                        f"review terms-of-service posture"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "high_trust_domain_patterns": list(self.high_trust_domain_patterns),
                    },
                )
            )

        # 4. Proxy country mismatch — geographic provenance.
        if (
            proxy_used
            and proxy_country is not None
            and self.project_country is not None
            and proxy_country != self.project_country
        ):
            signal = "proxy_country_mismatch"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} used proxy in country="
                        f"{proxy_country!r} which differs from project_country="
                        f"{self.project_country!r} — geographic provenance signal"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 5. Downloads — data exfiltration surface.
        if downloads_count > 0:
            signal = "downloads_present"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} pulled "
                        f"{downloads_count} file(s) out of the browser session — "
                        f"data exfiltration surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 6. Logged-in surfaces — auth-bound exfil risk.
        if is_logged_in_to:
            signal = "logged_in_surfaces"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} is logged into "
                        f"{len(is_logged_in_to)} authenticated surface(s) "
                        f"({', '.join(is_logged_in_to)}) — auth-bound exfil risk"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "logged_in_domains": is_logged_in_to,
                    },
                )
            )

        # 7. Evaluate action — arbitrary JS execution surface.
        if action_summary["has_evaluate"]:
            signal = "evaluate_action"
            control_id = _control_for(signal, self._mappings, "PR-03")
            evaluate_count = action_summary["action_type_counts"].get("evaluate", 0)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} executed "
                        f"{evaluate_count} arbitrary JavaScript evaluate action(s) — "
                        f"input validation surface"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "evaluate_action_count": evaluate_count,
                    },
                )
            )

        # 8. Credential entry on auth domain.
        cred_entry_hosts = action_summary["credential_entry_hostnames"]
        if cred_entry_hosts:
            signal = "credential_entry_on_auth_domain"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} performed type/fill_form "
                        f"action(s) on auth-domain URL(s) at "
                        f"{', '.join(cred_entry_hosts)} — credential-entry sanity check"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "credential_entry_hostnames": cred_entry_hosts,
                        "auth_domain_patterns": list(self.auth_domain_patterns),
                    },
                )
            )

        # 9. URL count above threshold — broad-crawl session.
        if url_count > self.url_count_threshold:
            signal = "url_count_above_threshold"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} touched {url_count} URLs "
                        f"(> threshold {self.url_count_threshold}) — broad-crawl session"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "url_count_threshold": self.url_count_threshold,
                    },
                )
            )

        # 10. Duration above threshold — long-running session.
        if duration_ms > self.duration_threshold_ms:
            signal = "duration_above_threshold"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} ran for {duration_ms}ms "
                        f"(> threshold {self.duration_threshold_ms}ms) — "
                        f"long-running session"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "duration_threshold_ms": self.duration_threshold_ms,
                    },
                )
            )

        # 11. Cross-domain pattern (synthetic per-session finding).
        if cross_domain_hit:
            signal = "cross_domain_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Browserbase session {session_id} touched "
                        f"{cross_domain_count} distinct second-level domains "
                        f"(> threshold {self.cross_domain_threshold}) — "
                        f"cross-domain crawl pattern"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_domain_count": cross_domain_count,
                        "cross_domain_threshold": self.cross_domain_threshold,
                        "cross_domain_second_level_domains": sorted(sld_set),
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
            f"Imported from Browserbase: session={session_id} "
            f"project={project_id} status={status or 'unknown'} "
            f"duration_ms={duration_ms} urls={url_count} "
            f"downloads={downloads_count} logged_in={len(is_logged_in_to)}"
        )

        timestamp = (
            str(started_at)
            if started_at
            else datetime.now(timezone.utc).isoformat()
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"browserbase-{session_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="browserbase_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=float(duration_ms),
            session_id=session_id or None,
        )
