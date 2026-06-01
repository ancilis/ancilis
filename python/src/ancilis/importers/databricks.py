"""Databricks audit-log importer — maps Databricks Lakehouse audit events to
AKSI controls.

Databricks (https://docs.databricks.com/aws/en/admin/account-settings/audit-logs)
is the dominant unified analytics + ML platform. Agents on Databricks query
data via SQL warehouses, train models, deploy serving endpoints, register
models in Unity Catalog and MLflow, attach to GPU clusters, run notebooks,
publish features, and increasingly invoke Vector Search and Genie GenAI
workloads. The platform has a Databricks "Agent Bricks" + MLflow adapter for
agent-side instrumentation; this importer covers the **data-plane / control-
plane audit** side — the underlying API calls that the workspace + account
layer record in ``system.access.audit`` (or workspace-level audit log).

Each Databricks audit record carries:

  * ``event_id`` / ``event_time``
  * ``workspace_id`` / ``account_id``
  * ``service_name``  — workspace | jobs | clusters | sql | unityCatalog |
                        mlflow | notebook | genie | dlt | vectorSearch |
                        feature | sql/databases
  * ``action_name``   — login | runJobNow | createCluster | executeQuery |
                        createSchema | deleteTable | grantPermission |
                        createServingEndpoint | createModel | updateNotebook |
                        runCommand | transitionModelVersionStage | …
  * ``request_params`` — keys + values (we keep keys only; values can carry
                          access tokens, query text, cluster names, etc.)
  * ``response.status_code`` / ``response.error_message_length`` / ``response.result``
  * ``user_identity.email``  — DOMAIN ONLY
  * ``source_ip_address``    — masked /16
  * ``user_agent``           — first 80 chars + sha256
  * ``audit_level``          — WORKSPACE_LEVEL | ACCOUNT_LEVEL
  * ``is_compute_attached`` / ``compute_kind`` / ``is_genai_use_case``
  * ``request_id`` / ``session_id``  (last 8 of session_id only)

This importer accepts five on-disk shapes:

  1. ``{"events": [...]}``  — Databricks "audit log" envelope
  2. ``{"data":   [...]}``  — generic envelope
  3. ``[...]``               — bare array of records
  4. JSONL                   — one record per line
  5. Single record at top level

Mapping (see shared/mappings/databricks-aksi-controls.json):

  * service_name=workspace action_name=login response.status_code=200          → PR-01 PASS
  * service_name=workspace action_name=login response.status_code in {401,403} → PR-01 FLAG
  * service_name=jobs action_name=runJobNow                                    → PR-05 PASS
  * service_name=clusters action_name=createCluster + GPU node_type            → PR-04 FLAG
  * service_name=clusters action_name=createCluster cluster_source=API by SP   → captured (programmatic provisioning)
  * service_name=clusters action_name=permanentDelete                          → PR-05 PASS
  * service_name=sql action_name=executeQuery + destructive query patterns     → PR-02 FLAG
  * service_name=unityCatalog action_name=createSchema/createCatalog            → PR-05 PASS
  * service_name=unityCatalog action_name=deleteTable on managed table         → PR-02 FAIL
  * service_name=unityCatalog action_name=grantPermission with ALL_PRIVILEGES   → PR-02 FAIL
  * service_name=mlflow action_name=createModel                                 → PR-05 PASS
  * service_name=mlflow action_name=transitionModelVersionStage to Production
        with no approver                                                      → PR-02 FAIL
  * service_name=mlflow action_name=createServingEndpoint                       → PR-01 FLAG
  * service_name=notebook action_name=updateNotebook by service_principal       → captured
  * service_name=notebook action_name=runCommand response includes shell-out
        patterns ("dbutils.fs.put"|"%sh "|"os.system"|subprocess.*)              → PR-03 FAIL
  * service_name=genie OR is_genai_use_case=true                                → captured (GenAI workload)
  * service_name=vectorSearch action_name=query                                 → PR-04 PASS
  * service_name=feature action_name=publishFeature                             → PR-05 FLAG
  * service_name=dlt action_name=startUpdate                                     → PR-05 PASS
  * response.status_code=403                                                    → PR-02 PASS (correctly denied)
  * response.status_code=500                                                    → DE-01 FAIL
  * audit_level=ACCOUNT_LEVEL action_name in admin patterns                     → PR-02 FLAG
  * is_compute_attached=true on routine SELECT                                  → PR-05 PASS
  * source_ip_address external (not RFC1918) on production workspace            → PR-01 FLAG

Cross-record patterns:

  * Same user.email (DOMAIN ONLY group) touching > N workspace_ids in export   → PR-02 FLAG synthetic
  * Same user creating > N clusters in 1h                                       → PR-04 FLAG synthetic

Sanitization (security-critical — Databricks audit records can carry SQL
text via request_params, access tokens via header values, customer IDs in
notebook payloads, etc):

  * ``request_params`` values are **never stored** — only the sorted **key
    list** is kept. Params can carry secrets like ``access_token``,
    ``personal_access_token``, ``password``, full SQL via ``statement``, or
    customer-specific filter literals.
  * ``response.result`` raw is **never stored** — Databricks may surface
    statement output here. Only the boolean indicator ``result_present`` is
    captured. The shell-out classifier inspects the raw text in-memory only
    and surfaces a categorical signal — not the matched substring.
  * ``response.error_message`` raw is **never stored** — only the length
    integer (Databricks itself surfaces ``error_message_length`` in some
    schemas; we coerce-or-compute).
  * ``user_identity.email`` is reduced to **domain only** (everything after
    ``@``). The local-part is dropped — agent emails routinely include the
    end-customer name (e.g. ``acme-prod-bot@…``).
  * ``source_ip_address`` is masked to a /16 (or RFC1918 preserved).
  * ``user_agent`` is reduced to ``{"prefix": <first 80>, "sha256": <hex>}``.
  * ``session_id`` is reduced to the last 8 characters.
  * ``request_id`` is preserved (it is opaque + correlation-only).
  * ``query_text`` from request_params is **never stored**; the integer
    ``query_text_length`` from request_params (if present) is preserved.
  * The original file is hashed (sha256) for source provenance.

The SDK does **not** depend on ``databricks-sdk``; exports are parsed with
the standard library only.
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


# Mapping table lives at <repo>/shared/mappings/databricks-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/databricks.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "databricks-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Built-in fallbacks if the mapping JSON is missing or malformed.
_DEFAULT_GPU_NODE_PATTERNS: tuple[str, ...] = (
    "Standard_NV*",
    "Standard_NC*",
    "Standard_ND*",
    "g4dn.*",
    "g5.*",
    "p2.*",
    "p3.*",
    "p4d.*",
    "p4de.*",
    "p5.*",
)
_DEFAULT_ADMIN_ACTION_PATTERNS: tuple[str, ...] = (
    "createAccount*",
    "deleteAccount*",
    "addUserToAccount*",
    "removeUserFromAccount*",
    "createGroup",
    "deleteGroup",
    "patchGroup",
    "setAccountAdmin*",
    "updateAccountSettings*",
    "createServicePrincipal",
    "deleteServicePrincipal",
    "createMetastore",
    "deleteMetastore",
    "createWorkspace",
    "deleteWorkspace",
    "createIpAccessList",
    "deleteIpAccessList",
    "updatePrivateAccessSettings",
)
_DEFAULT_DESTRUCTIVE_QUERY_PATTERNS: tuple[str, ...] = (
    "DROP ", "TRUNCATE ", "DROP\t", "TRUNCATE\t",
)
_DEFAULT_SHELL_OUT_PATTERNS: tuple[str, ...] = (
    "dbutils.fs.put",
    "%sh ",
    "%sh\n",
    "os.system",
    "subprocess.",
    "subprocess(",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.call",
)
_DEFAULT_ADMIN_GRANT_KEYWORDS: tuple[str, ...] = (
    "ALL_PRIVILEGES",
    "MANAGE",
    "MANAGE_ALLOWLIST",
)
_DEFAULT_CROSS_WORKSPACE_THRESHOLD = 3
_DEFAULT_CLUSTER_CREATION_BURST = 10
_DEFAULT_CLUSTER_CREATION_WINDOW_SECONDS = 3600
_DEFAULT_USER_AGENT_PREFIX_LENGTH = 80


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the databricks-aksi-controls.json mapping; tolerate missing file."""
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


def _mask_source_ip(source_ip: str | None) -> str | None:
    """Mask a Databricks source_ip_address to a privacy-aware form.

    * RFC1918 / loopback / link-local preserved verbatim (already non-routable).
    * Public IPv4 reduced to ``X.Y.0.0/16``.
    * Public IPv6 reduced to ``HHHH:HHHH::/32``.
    * Hostnames / non-IP markers preserved verbatim.
    """
    if not source_ip or not isinstance(source_ip, str):
        return None
    ip = source_ip.strip()
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


def _is_external_ip(source_ip: str | None) -> bool:
    """Return True iff ``source_ip`` is a parseable public IP (not RFC1918)."""
    if not source_ip or not isinstance(source_ip, str):
        return False
    try:
        addr = ipaddress.ip_address(source_ip.strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def _redact_user_agent(
    value: str | None, prefix_length: int
) -> dict[str, Any] | None:
    """Return ``{"prefix": <first N chars>, "sha256": <hex>}`` or None."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    return {
        "prefix": s[:prefix_length],
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _email_domain(email: Any) -> str | None:
    """Reduce an email address to its **domain only** (everything after ``@``).

    The local-part is dropped — Databricks audit logs routinely carry agent
    emails that include end-customer or environment names (e.g.
    ``acme-prod-bot@example.com``) which leak tenant context.
    """
    if not isinstance(email, str):
        return None
    e = email.strip().lower()
    if "@" not in e:
        return None
    domain = e.split("@", 1)[1]
    return domain or None


def _short_session_id(session_id: Any) -> str | None:
    """Reduce a Databricks session_id to its last 8 characters."""
    if session_id is None:
        return None
    s = str(session_id).strip()
    if not s:
        return None
    if len(s) <= 8:
        return s
    return s[-8:]


def _request_params_keys(params: Any) -> list[str]:
    """Return the sorted **key list** of ``request_params``.

    The values are NEVER returned — params can carry access tokens,
    statement text, customer IDs, etc. The keys themselves are
    operationally useful (we want to know "this call carried a job_id",
    "this call carried a query_text") without leaking the values.
    """
    if not isinstance(params, dict):
        return []
    return sorted(str(k) for k in params)


def _query_text_length_from_params(params: Any) -> int:
    """Look up an explicit ``query_text_length`` integer in request_params.

    Databricks audit records sometimes carry the integer rather than the
    raw text (preferred). When the raw ``statement`` is present, we DO NOT
    fall back to ``len(statement)`` — see ``_inspect_statement_for_destructive``
    for the handling of statement content; the length is computed from
    the in-memory string but we do not store the text itself.
    """
    if not isinstance(params, dict):
        return 0
    v = params.get("query_text_length")
    try:
        return int(v) if v is not None else 0
    except (TypeError, ValueError):
        return 0


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pat) for pat in patterns)


def _matches_any_ci(value: str, patterns: tuple[str, ...]) -> bool:
    """Case-insensitive fnmatch — used for action_name patterns."""
    if not value:
        return False
    lower = value
    return any(
        fnmatch.fnmatchcase(lower, pat) or fnmatch.fnmatchcase(
            lower.lower(), pat.lower()
        )
        for pat in patterns
    )


def _parse_iso(ts: str) -> datetime | None:
    """Best-effort ISO-8601 parse. Returns None for unparseable inputs."""
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class DatabricksImporter:
    """Parse a Databricks audit-log export and convert each record to an
    ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_workspace_threshold: int | None = None,
        cluster_creation_burst: int | None = None,
        cluster_creation_window_seconds: int | None = None,
        gpu_node_patterns: Iterable[str] | None = None,
        admin_action_patterns: Iterable[str] | None = None,
        destructive_query_patterns: Iterable[str] | None = None,
        shell_out_patterns: Iterable[str] | None = None,
        admin_grant_keywords: Iterable[str] | None = None,
        user_agent_prefix_length: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # service::action(::status_code) → pattern.
        meta_sap = meta.get("service_action_patterns")
        if isinstance(meta_sap, dict) and meta_sap:
            self._service_action_patterns: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_sap.items()
                if isinstance(v, dict)
            }
        else:
            self._service_action_patterns = {}

        # GPU node patterns (fnmatch, case-sensitive — Databricks node_type
        # ids preserve the original cloud naming).
        if gpu_node_patterns is not None:
            self.gpu_node_patterns = tuple(str(p) for p in gpu_node_patterns)
        else:
            meta_gpu = meta.get("gpu_node_patterns")
            if isinstance(meta_gpu, list) and meta_gpu:
                self.gpu_node_patterns = tuple(str(p) for p in meta_gpu)
            else:
                self.gpu_node_patterns = _DEFAULT_GPU_NODE_PATTERNS

        # Admin action patterns.
        if admin_action_patterns is not None:
            self.admin_action_patterns = tuple(
                str(p) for p in admin_action_patterns
            )
        else:
            meta_admin = meta.get("admin_action_patterns")
            if isinstance(meta_admin, list) and meta_admin:
                self.admin_action_patterns = tuple(str(p) for p in meta_admin)
            else:
                self.admin_action_patterns = _DEFAULT_ADMIN_ACTION_PATTERNS

        # Destructive SQL substrings (case-insensitive contains check).
        if destructive_query_patterns is not None:
            self.destructive_query_patterns = tuple(
                str(p).upper() for p in destructive_query_patterns
            )
        else:
            meta_dq = meta.get("destructive_query_patterns")
            if isinstance(meta_dq, list) and meta_dq:
                self.destructive_query_patterns = tuple(
                    str(p).upper() for p in meta_dq
                )
            else:
                self.destructive_query_patterns = tuple(
                    p.upper() for p in _DEFAULT_DESTRUCTIVE_QUERY_PATTERNS
                )

        # Shell-out patterns (case-sensitive — Python keywords + magic markers).
        if shell_out_patterns is not None:
            self.shell_out_patterns = tuple(str(p) for p in shell_out_patterns)
        else:
            meta_sh = meta.get("shell_out_patterns")
            if isinstance(meta_sh, list) and meta_sh:
                self.shell_out_patterns = tuple(str(p) for p in meta_sh)
            else:
                self.shell_out_patterns = _DEFAULT_SHELL_OUT_PATTERNS

        # Admin grant keywords (case-insensitive contains check).
        if admin_grant_keywords is not None:
            self.admin_grant_keywords = tuple(
                str(k).upper() for k in admin_grant_keywords
            )
        else:
            meta_ag = meta.get("admin_grant_keywords")
            if isinstance(meta_ag, list) and meta_ag:
                self.admin_grant_keywords = tuple(
                    str(k).upper() for k in meta_ag
                )
            else:
                self.admin_grant_keywords = _DEFAULT_ADMIN_GRANT_KEYWORDS

        # Numeric thresholds — explicit > meta > default.
        def _resolve_int(arg: int | None, key: str, default: int) -> int:
            if arg is not None:
                return int(arg)
            v = meta.get(key)
            try:
                return int(v) if v is not None else default
            except (TypeError, ValueError):
                return default

        self.cross_workspace_threshold = _resolve_int(
            cross_workspace_threshold,
            "cross_workspace_threshold",
            _DEFAULT_CROSS_WORKSPACE_THRESHOLD,
        )
        self.cluster_creation_burst = _resolve_int(
            cluster_creation_burst,
            "cluster_creation_burst",
            _DEFAULT_CLUSTER_CREATION_BURST,
        )
        self.cluster_creation_window_seconds = _resolve_int(
            cluster_creation_window_seconds,
            "cluster_creation_window_seconds",
            _DEFAULT_CLUSTER_CREATION_WINDOW_SECONDS,
        )
        self.user_agent_prefix_length = _resolve_int(
            user_agent_prefix_length,
            "user_agent_prefix_length",
            _DEFAULT_USER_AGENT_PREFIX_LENGTH,
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Databricks audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._records_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a Databricks audit-log export from a JSON or JSONL string."""
        events = self._records_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events":[]}`` / ``{"data":[]}`` / array / single / JSONL."""
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
                if "events" in doc and isinstance(doc["events"], list):
                    return [r for r in doc["events"] if isinstance(r, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [r for r in doc["data"] if isinstance(r, dict)]
                # Single record at top level.
                return [doc]
            return []

        return list(_iter_jsonl(text))

    # -- Build phase --------------------------------------------------------

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # ---- First pass: aggregate cross-record patterns.
        # Cross-workspace: same email-domain-prefix (we use the *full* email
        # for grouping in the in-memory pass, but only emit the domain in the
        # synthetic finding evidence).
        email_workspaces: dict[str, set[str]] = {}
        # Cluster-creation burst: per-email timeline of createCluster events.
        email_cluster_creates: dict[str, list[datetime]] = {}

        for ev in events:
            email_full = self._extract_email(ev)
            workspace_id = str(ev.get("workspace_id") or "")
            service = str(ev.get("service_name") or "")
            action = str(ev.get("action_name") or "")

            if email_full and workspace_id:
                email_workspaces.setdefault(email_full, set()).add(workspace_id)
            if (
                email_full
                and service == "clusters"
                and action == "createCluster"
            ):
                ts = _parse_iso(str(ev.get("event_time") or ""))
                if ts is not None:
                    email_cluster_creates.setdefault(email_full, []).append(ts)

        cross_workspace_users = {
            u: sorted(ws)
            for u, ws in email_workspaces.items()
            if len(ws) > self.cross_workspace_threshold
        }

        cluster_burst_users: dict[str, int] = {}
        for user, times in email_cluster_creates.items():
            times.sort()
            max_count = 0
            j = 0
            for i in range(len(times)):
                while (
                    times[i] - times[j]
                ).total_seconds() > self.cluster_creation_window_seconds:
                    j += 1
                count = i - j + 1
                if count > max_count:
                    max_count = count
            if max_count > self.cluster_creation_burst:
                cluster_burst_users[user] = max_count

        # ---- Per-record results.
        results: list[EvaluationResult] = []
        for ev in events:
            results.append(
                self._parse_event(
                    ev,
                    file_sha256=file_sha256,
                    cross_workspace_users=cross_workspace_users,
                    cluster_burst_users=cluster_burst_users,
                )
            )

        # ---- Synthetic findings.
        for email_full, ws in sorted(cross_workspace_users.items()):
            results.append(
                self._synthetic_cross_workspace_result(
                    email_full=email_full,
                    workspaces=ws,
                    file_sha256=file_sha256,
                )
            )
        for email_full, count in sorted(cluster_burst_users.items()):
            results.append(
                self._synthetic_cluster_burst_result(
                    email_full=email_full,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        return results

    @staticmethod
    def _extract_email(record: dict[str, Any]) -> str | None:
        ui = record.get("user_identity")
        if isinstance(ui, dict):
            e = ui.get("email")
            if isinstance(e, str) and e.strip():
                return e.strip().lower()
        # Some exports surface ``userIdentity`` (camelCase) — be lenient.
        ui2 = record.get("userIdentity")
        if isinstance(ui2, dict):
            e = ui2.get("email")
            if isinstance(e, str) and e.strip():
                return e.strip().lower()
        return None

    # -- Provenance ---------------------------------------------------------

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
        record_kind: str = "event",
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "databricks",
            "source_tool_name": "databricks",
            "source_tool_version": "",
            "record_kind": record_kind,
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ----------------------------------------------------------------------
    # Per-record parsing
    # ----------------------------------------------------------------------

    def _parse_event(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_workspace_users: dict[str, list[str]],
        cluster_burst_users: dict[str, int],
    ) -> EvaluationResult:
        event_id = str(record.get("event_id") or uuid.uuid4().hex)
        event_time = str(
            record.get("event_time")
            or datetime.now(timezone.utc).isoformat()
        )
        service = str(record.get("service_name") or "").strip()
        action = str(record.get("action_name") or "").strip()
        workspace_id = str(record.get("workspace_id") or "")
        account_id = str(record.get("account_id") or "")
        audit_level = str(record.get("audit_level") or "").strip()
        request_id = str(record.get("request_id") or "")

        # is_compute_attached / compute_kind / is_genai_use_case.
        is_compute_attached = self._coerce_bool(record.get("is_compute_attached"))
        compute_kind = str(record.get("compute_kind") or "")
        is_genai_use_case = self._coerce_bool(record.get("is_genai_use_case"))

        # Response.
        response = record.get("response")
        if not isinstance(response, dict):
            response = {}
        try:
            status_code: int | None = (
                int(response["status_code"])
                if response.get("status_code") is not None
                else None
            )
        except (TypeError, ValueError):
            status_code = None
        try:
            error_message_length: int = int(
                response.get("error_message_length") or 0
            )
        except (TypeError, ValueError):
            error_message_length = 0
        # response.result raw is NEVER stored — capture only its presence and
        # an in-memory-only inspection result for shell-out detection on
        # notebook runCommand.
        response_result_raw = response.get("result")
        result_present = response_result_raw not in (None, "")
        if isinstance(response_result_raw, str) and not response_result_raw.strip():
            result_present = False

        # Request params — keys only.
        request_params = record.get("request_params")
        request_params_keys = _request_params_keys(request_params)
        query_text_length = _query_text_length_from_params(request_params)
        # Pick out a few high-signal scalars from request_params *without*
        # surfacing their raw values into evidence:
        #   * node_type_id  — for GPU classification
        #   * cluster_source — for service-principal API provisioning
        #   * permission    — for admin-grant detection
        #   * stage / new_stage — for MLflow promotion detection
        #   * approver / approved_by — for MLflow promotion approver presence
        node_type_id = ""
        cluster_source = ""
        grant_permission = ""
        new_stage = ""
        approver = ""
        statement_destructive = False
        if isinstance(request_params, dict):
            node_type_id = str(request_params.get("node_type_id") or "")
            cluster_source = str(
                request_params.get("cluster_source")
                or request_params.get("source")
                or ""
            )
            grant_permission = str(
                request_params.get("permission")
                or request_params.get("privilege")
                or request_params.get("privileges")
                or ""
            ).upper()
            new_stage = str(
                request_params.get("new_stage")
                or request_params.get("stage")
                or ""
            )
            approver = str(
                request_params.get("approver")
                or request_params.get("approved_by")
                or ""
            )
            stmt = request_params.get("statement")
            if isinstance(stmt, str) and stmt:
                upper = stmt.upper()
                if any(p in upper for p in self.destructive_query_patterns):
                    statement_destructive = True
                # Also surface a length-only datapoint; we do NOT store the
                # statement itself.
                if not query_text_length:
                    query_text_length = len(stmt)
        # action_name suffix override: some warehouses surface the variant
        # as a distinct action (executeQuery_DROP, etc).
        if not statement_destructive and action:
            upper_action = action.upper()
            if any(
                kw.strip() in upper_action
                for kw in ("DROP", "TRUNCATE")
            ) and action != "createTable" and action != "dropTable":
                # Only treat as destructive if the action itself is a SQL
                # variant — not the metadata-table createTable/dropTable
                # which we surface as a UC schema/table action.
                pass

        # Identity / network sanitization.
        email_full = self._extract_email(record) or ""
        email_domain = _email_domain(email_full)
        source_ip_raw = record.get("source_ip_address")
        source_ip = source_ip_raw if isinstance(source_ip_raw, str) else None
        source_ip_masked = _mask_source_ip(source_ip)
        source_ip_external = _is_external_ip(source_ip)
        user_agent_redacted = _redact_user_agent(
            record.get("user_agent")
            if isinstance(record.get("user_agent"), str)
            else None,
            self.user_agent_prefix_length,
        )
        session_id_short = _short_session_id(record.get("session_id"))

        # Notebook runCommand shell-out detection: inspect the raw
        # response.result text in-memory only and surface a categorical
        # signal — the matched substring is NEVER stored.
        shell_out_hits: list[str] = []
        if (
            service == "notebook"
            and action == "runCommand"
            and isinstance(response_result_raw, str)
            and response_result_raw
        ):
            for pat in self.shell_out_patterns:
                if pat in response_result_raw:
                    shell_out_hits.append(pat)
        # Also accept a list-shaped result that contains line strings.
        elif (
            service == "notebook"
            and action == "runCommand"
            and isinstance(response_result_raw, list)
        ):
            joined = "\n".join(
                str(x) for x in response_result_raw if isinstance(x, str)
            )
            for pat in self.shell_out_patterns:
                if pat in joined:
                    shell_out_hits.append(pat)

        # cluster_source by service principal? Identify by email containing
        # a service-principal marker OR an explicit user_identity.type field.
        ui = record.get("user_identity")
        identity_type = ""
        if isinstance(ui, dict):
            identity_type = str(ui.get("type") or "").lower()
        is_service_principal = (
            identity_type == "service_principal"
            or identity_type == "service-principal"
            or identity_type == "service principal"
            or "service-principal" in (email_full or "")
            or "servicePrincipal" in (email_full or "")
        )

        common_evidence: dict[str, Any] = {
            "databricks_event_id": event_id,
            "service_name": service,
            "action_name": action,
            "workspace_id": workspace_id,
            "account_id": account_id,
            "audit_level": audit_level,
            "request_id": request_id,
            "session_id_suffix": session_id_short,
            "response_status_code": status_code,
            "response_error_message_length": error_message_length,
            "response_result_present": result_present,
            "is_compute_attached": is_compute_attached,
            "compute_kind": compute_kind,
            "is_genai_use_case": is_genai_use_case,
            "request_params_keys": request_params_keys,
            "query_text_length": query_text_length,
            "node_type_id": node_type_id,
            "cluster_source": cluster_source,
            "is_service_principal": is_service_principal,
            "email_domain": email_domain,
            "source_ip_masked": source_ip_masked,
            "source_ip_external": source_ip_external,
            "user_agent_redacted": user_agent_redacted,
            "event_time": event_time,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=event_id,
                record_kind="event",
            ),
            "source_tool": "databricks",
        }

        control_results: list[ControlResult] = []

        # --------------------------------------------------------------
        # 1. status_code-driven precedence.
        #    500 → DE-01 FAIL (execution failure)
        #    403 → PR-02 PASS (correctly denied)
        # --------------------------------------------------------------
        handled_by_status = False
        if status_code == 500:
            signal = "execution_failure"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Databricks {service}.{action} returned HTTP 500 — "
                        f"execution failure on workspace {workspace_id}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            handled_by_status = True
        elif status_code == 403:
            signal = "access_denied"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks {service}.{action} correctly denied "
                        f"(HTTP 403) on workspace {workspace_id}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            handled_by_status = True

        # --------------------------------------------------------------
        # 2. Service + action primary classification (when not pre-empted
        #    by a 5xx/403). The login flow handles status_code in {200,
        #    401, 403} explicitly — we already routed 403 above; 401 is
        #    handled below.
        # --------------------------------------------------------------
        if not handled_by_status:
            self._append_service_action_signal(
                control_results,
                common_evidence=common_evidence,
                service=service,
                action=action,
                status_code=status_code,
                node_type_id=node_type_id,
                cluster_source=cluster_source,
                grant_permission=grant_permission,
                new_stage=new_stage,
                approver=approver,
                statement_destructive=statement_destructive,
                shell_out_hits=tuple(shell_out_hits),
                is_service_principal=is_service_principal,
                workspace_id=workspace_id,
            )

        # --------------------------------------------------------------
        # 3. Account-level admin actions (audit_level=ACCOUNT_LEVEL +
        #    action matches admin pattern) — additive PR-02 FLAG.
        # --------------------------------------------------------------
        if (
            audit_level == "ACCOUNT_LEVEL"
            and action
            and _matches_any(action, self.admin_action_patterns)
        ):
            signal = "account_admin_action"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Databricks account-level admin action {service}."
                        f"{action} on account {account_id} — surfaced for "
                        f"review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 4. External source IP on a workspace event — additive PR-01 FLAG.
        # --------------------------------------------------------------
        if source_ip_external and service == "workspace":
            signal = "external_source_ip"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Databricks workspace event {service}.{action} from "
                        f"external (non-RFC1918) source IP {source_ip_masked}"
                        f" on workspace {workspace_id} — review network "
                        f"posture"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 5. is_compute_attached=true on routine SQL SELECT → PR-05 PASS.
        # --------------------------------------------------------------
        if (
            is_compute_attached
            and service == "sql"
            and action == "executeQuery"
            and not statement_destructive
        ):
            signal = "compute_attached_routine"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks {service}.{action} executed with "
                        f"compute attached (compute_kind={compute_kind!r}) — "
                        f"reasonable scope"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 6. GenAI workload identifier — captured as additive PASS.
        # --------------------------------------------------------------
        if service == "genie" or is_genai_use_case is True:
            signal = "genai_workload"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks {service}.{action} identified as a "
                        f"GenAI workload (is_genai_use_case={is_genai_use_case}"
                        f", service={service!r}) — captured for evidence"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 7. Cross-record-pattern markers (informational; the synthetic
        #    finding is added separately).
        # --------------------------------------------------------------
        if email_full and email_full in cross_workspace_users:
            signal = "cross_workspace_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Databricks event {event_id} user (domain "
                        f"{email_domain or 'unknown'}) is part of a cross-"
                        f"workspace pattern "
                        f"({len(cross_workspace_users[email_full])} workspaces"
                        f" > threshold {self.cross_workspace_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_workspace_workspaces": (
                            cross_workspace_users[email_full]
                        ),
                        "cross_workspace_threshold": (
                            self.cross_workspace_threshold
                        ),
                    },
                )
            )
        if email_full and email_full in cluster_burst_users:
            signal = "cluster_creation_burst"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Databricks event {event_id} user (domain "
                        f"{email_domain or 'unknown'}) is part of a cluster-"
                        f"creation burst "
                        f"({cluster_burst_users[email_full]} createCluster "
                        f"events > threshold {self.cluster_creation_burst} "
                        f"in {self.cluster_creation_window_seconds}s)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cluster_burst_count": cluster_burst_users[email_full],
                        "cluster_burst_threshold": self.cluster_creation_burst,
                        "cluster_burst_window_seconds": (
                            self.cluster_creation_window_seconds
                        ),
                    },
                )
            )

        decision = _decision_for(control_results)
        decision_reason = (
            f"Imported from Databricks audit log: service={service} "
            f"action={action} workspace_id={workspace_id} "
            f"audit_level={audit_level or 'unknown'} "
            f"status={status_code if status_code is not None else 'none'}"
        )

        # action_id derived from the canonical event_id (Databricks event
        # ids are opaque UUIDs — we keep the full id since it has no PII).
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"databricks-{service or 'event'}-{event_id}",
            timestamp=event_time,
            agent_id=self.agent_id,
            source_type="databricks_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=session_id_short,
        )

    # ----------------------------------------------------------------------

    def _append_service_action_signal(
        self,
        control_results: list[ControlResult],
        *,
        common_evidence: dict[str, Any],
        service: str,
        action: str,
        status_code: int | None,
        node_type_id: str,
        cluster_source: str,
        grant_permission: str,
        new_stage: str,
        approver: str,
        statement_destructive: bool,
        shell_out_hits: tuple[str, ...],
        is_service_principal: bool,
        workspace_id: str,
    ) -> None:
        """Apply the service+action mapping with overlays.

        Overlays:
          * workspace.login + 401 → login_denied FLAG
          * workspace.login + 200 → login_success PASS
          * clusters.createCluster + GPU node_type → cluster_create_gpu FLAG
          * clusters.createCluster + cluster_source=API + service principal
                → cluster_create_api_sp PASS (programmatic provisioning, captured)
          * sql.executeQuery + destructive statement → sql_execute_destructive FLAG
          * unityCatalog.grantPermission + ALL_PRIVILEGES/MANAGE → uc_grant_admin FAIL
          * mlflow.transitionModelVersionStage to Production with no approver
                → mlflow_auto_promote_production FAIL (parallel to the
                  dedicated MLflow importer's pattern)
          * notebook.runCommand with shell-out hit → notebook_shell_out FAIL
          * notebook.updateNotebook by service principal → notebook_update_service_principal PASS
        """
        # workspace.login: status-code-aware
        if service == "workspace" and action == "login":
            if status_code == 200:
                signal = "login_success"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Databricks workspace.login succeeded on "
                            f"workspace {workspace_id} — identity confirmed"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            if status_code in (401, 403):
                signal = "login_denied"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Databricks workspace.login denied on workspace "
                            f"{workspace_id} (HTTP {status_code}) — review "
                            f"identity context"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            # Other status codes — still capture the login attempt as PASS.
            signal = "login_success"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks workspace.login on workspace "
                        f"{workspace_id} captured for audit trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # clusters.createCluster — GPU + service-principal overlays.
        if service == "clusters" and action == "createCluster":
            if node_type_id and _matches_any(
                node_type_id, self.gpu_node_patterns
            ):
                signal = "cluster_create_gpu"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Databricks clusters.createCluster on workspace "
                            f"{workspace_id} requested GPU node_type "
                            f"{node_type_id!r} — high-cost compute, surface "
                            f"for review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                # Also capture the API+SP overlay if applicable, additively.
                if (
                    cluster_source.upper() == "API" and is_service_principal
                ):
                    signal = "cluster_create_api_sp"
                    control_id = _control_for(signal, self._mappings, "PR-05")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="PASS",
                            detail=(
                                "Databricks clusters.createCluster via API "
                                "by service principal — programmatic "
                                "provisioning captured"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                return
            if cluster_source.upper() == "API" and is_service_principal:
                signal = "cluster_create_api_sp"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Databricks clusters.createCluster via API by "
                            f"service principal on workspace {workspace_id}"
                            f" — programmatic provisioning captured"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            signal = "cluster_create"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks clusters.createCluster on workspace "
                        f"{workspace_id} captured for audit trail"
                        + (f" (node_type={node_type_id!r})" if node_type_id else "")
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # sql.executeQuery — destructive-statement overlay.
        if service == "sql" and action == "executeQuery":
            if statement_destructive:
                signal = "sql_execute_destructive"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Databricks sql.executeQuery on workspace "
                            f"{workspace_id} carries a destructive statement "
                            f"pattern (DROP/TRUNCATE) — surface for review "
                            f"(query text not stored)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            signal = "sql_execute"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks sql.executeQuery on workspace "
                        f"{workspace_id} captured (query text not stored)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # unityCatalog grants — admin overlay.
        if service == "unityCatalog" and action in (
            "grantPermission",
            "updatePermissions",
        ):
            if grant_permission and any(
                kw in grant_permission for kw in self.admin_grant_keywords
            ):
                signal = "uc_grant_admin"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Databricks unityCatalog.{action} on workspace "
                            f"{workspace_id} grants admin-level permission "
                            f"({grant_permission!r}) — high-blast-radius "
                            f"privilege change"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            signal = "uc_grant"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Databricks unityCatalog.{action} on workspace "
                        f"{workspace_id} — privilege grant requires review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # mlflow.transitionModelVersionStage — auto-promote-to-Production.
        if service == "mlflow" and action == "transitionModelVersionStage":
            if new_stage == "Production" and not approver:
                signal = "mlflow_auto_promote_production"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Databricks mlflow.transitionModelVersionStage "
                            f"to Production on workspace {workspace_id} with "
                            f"NO approver in request_params — auto-promotion "
                            f"to production (parallel to dedicated MLflow "
                            f"importer's pattern)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            signal = "mlflow_transition_stage"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks mlflow.transitionModelVersionStage "
                        f"new_stage={new_stage!r} on workspace {workspace_id}"
                        f" captured for audit trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # notebook.runCommand — shell-out detection.
        if service == "notebook" and action == "runCommand":
            if shell_out_hits:
                signal = "notebook_shell_out"
                control_id = _control_for(signal, self._mappings, "PR-03")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Databricks notebook.runCommand on workspace "
                            f"{workspace_id} produced output containing "
                            f"shell-out patterns "
                            f"({len(shell_out_hits)} hit(s)) — SQL/Python -> "
                            f"OS gadget on Databricks (matched substrings "
                            f"NOT stored)"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            # Surface CATEGORY of hits, not raw text — the
                            # patterns themselves are short categorical
                            # markers (dbutils.fs.put, %sh, os.system, …)
                            # — they are safe to keep.
                            "shell_out_pattern_categories": sorted(
                                set(shell_out_hits)
                            ),
                        },
                    )
                )
                return
            signal = "notebook_run_command"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks notebook.runCommand on workspace "
                        f"{workspace_id} captured for audit trail "
                        f"(notebook content not stored)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # notebook.updateNotebook — service-principal overlay.
        if service == "notebook" and action == "updateNotebook":
            if is_service_principal:
                signal = "notebook_update_service_principal"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Databricks notebook.updateNotebook by service "
                            f"principal on workspace {workspace_id} — agent "
                            f"updating notebooks (captured)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            signal = "notebook_update"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Databricks notebook.updateNotebook on workspace "
                        f"{workspace_id} captured for audit trail "
                        f"(notebook content not stored)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # Generic mapping table lookup.
        key = f"{service}::{action}"
        pattern = self._service_action_patterns.get(key)
        if pattern is not None:
            signal = pattern.get("signal", "unknown_action")
            control_id = _control_for(
                signal, self._mappings, pattern.get("control", "PR-05")
            )
            result = pattern.get("result", "PASS")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Databricks {service}.{action} on workspace "
                        f"{workspace_id} classified as {signal} ({result})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # Fully unknown action — capture as PASS for the audit trail.
        signal = "unknown_action"
        control_id = _control_for(signal, self._mappings, "PR-05")
        control_results.append(
            ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result="PASS",
                detail=(
                    f"Databricks {service}.{action} on workspace "
                    f"{workspace_id} — unknown action, captured for audit "
                    f"trail"
                ),
                evidence_data={**common_evidence, "signal": signal},
            )
        )

    # ----------------------------------------------------------------------
    # Helper coercion
    # ----------------------------------------------------------------------

    @staticmethod
    def _coerce_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ("true", "yes", "1"):
                return True
            if v in ("false", "no", "0"):
                return False
        return None

    # ----------------------------------------------------------------------
    # Synthetic findings
    # ----------------------------------------------------------------------

    def _synthetic_cross_workspace_result(
        self,
        *,
        email_full: str,
        workspaces: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_workspace_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        domain = _email_domain(email_full) or "unknown"
        synthetic_id = f"databricks-cross-workspace-{domain}-{uuid.uuid4().hex[:8]}"
        evidence: dict[str, Any] = {
            "databricks_synthetic_id": synthetic_id,
            "email_domain": domain,
            "cross_workspace_workspaces": workspaces,
            "cross_workspace_workspace_count": len(workspaces),
            "cross_workspace_threshold": self.cross_workspace_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "databricks",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Databricks synthetic finding: a user (domain {domain}) "
                f"touched {len(workspaces)} workspaces in this export "
                f"({', '.join(workspaces)}) — exceeds cross-workspace "
                f"threshold {self.cross_workspace_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="databricks_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Databricks: synthetic cross-workspace "
                f"pattern for domain={domain} "
                f"workspaces={len(workspaces)}>threshold="
                f"{self.cross_workspace_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cluster_burst_result(
        self,
        *,
        email_full: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cluster_creation_burst"
        control_id = _control_for(signal, self._mappings, "PR-04")
        domain = _email_domain(email_full) or "unknown"
        synthetic_id = f"databricks-cluster-burst-{domain}-{uuid.uuid4().hex[:8]}"
        evidence: dict[str, Any] = {
            "databricks_synthetic_id": synthetic_id,
            "email_domain": domain,
            "cluster_burst_count": count,
            "cluster_burst_threshold": self.cluster_creation_burst,
            "cluster_burst_window_seconds": self.cluster_creation_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "databricks",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Databricks synthetic finding: a user (domain {domain}) "
                f"created {count} clusters in "
                f"{self.cluster_creation_window_seconds}s "
                f"(> threshold {self.cluster_creation_burst}) — high-volume "
                f"compute provisioning, surface for review"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="databricks_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Databricks: synthetic cluster-creation burst "
                f"pattern for domain={domain} count={count}>threshold="
                f"{self.cluster_creation_burst}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )


# ---------------------------------------------------------------------------
# Decision helper
# ---------------------------------------------------------------------------


def _decision_for(control_results: list[ControlResult]) -> str:
    """any FAIL → BLOCK; any FLAG → FLAG; else ALLOW."""
    if any(cr.result == "FAIL" for cr in control_results):
        return "BLOCK"
    if any(cr.result == "FLAG" for cr in control_results):
        return "FLAG"
    return "ALLOW"
