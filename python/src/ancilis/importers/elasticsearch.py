"""Elasticsearch X-Pack Security audit-log importer — converts Elastic security audit events to AKSI EvaluationResults.

Elasticsearch (https://www.elastic.co) is the dominant lexical+vector search
engine; agents increasingly query it for hybrid retrieval (BM25 + dense
vectors), log analysis, and security-data lookups. When X-Pack Security audit
logging is enabled each authentication, authorization, request-tampering,
run-as, connection, and system-access decision is captured as a structured
event referencing one or more indices and a cluster endpoint. This importer
turns each event into one ``EvaluationResult``.

Accepted on-disk shapes:

  1. Envelope with events:    ``{"events": [{...}, ...]}``
  2. Generic data envelope:   ``{"data": [{...}, ...]}``
  3. JSON array:              ``[{...}, {...}]``
  4. Single object:           ``{...}``  (treated as one event)
  5. JSONL stream:            one JSON object per line

Signal mapping (see shared/mappings/elasticsearch-aksi-controls.json):

  Authentication / connection
    * ``authentication_success``                      → PR-01 PASS
    * ``authentication_failed``                       → PR-01 FLAG
    * ``connection_denied``                           → PR-01 FLAG
    * ``run_as_granted`` (impersonation captured)     → PR-01 FLAG
    * ``API_KEY`` without expiration metadata         → PR-01 FLAG  (long-lived key)
    * ``client.ip`` non-RFC1918                       → PR-01 FLAG  (off-VPC)

  Authorization
    * ``anonymous_access_denied``                     → PR-02 PASS  (correctly denied)
    * ``access_denied``                               → PR-02 PASS  (governance audit-trail)
    * ``access_granted`` read on user index           → PR-04 PASS
    * ``access_granted`` read on sensitive index      → PR-04 FLAG  (sensitive-index access)
    * ``access_granted`` read on ``.security``        → PR-04 FAIL  (reading security index)
    * ``access_granted`` write/manage/all on .security→ PR-02 FAIL  (modifying security index)
    * ``access_granted`` manage/all on production     → PR-02 FLAG  (privileged on prod)
    * ``system_access_granted``                       → PR-02 FLAG  (system-level access)

  Request integrity / cluster ops
    * ``tampered_request``                            → DE-01 FAIL  (request integrity violation)
    * ``url.path=/_cluster/settings`` PUT             → PR-02 FAIL  (cluster setting change)
    * ``url.path=/_security/*`` PUT/DELETE            → PR-02 FAIL  (security config change)
    * ``url.path=/_security/role*`` PUT               → PR-02 FAIL  (role grant)
    * ``url.path=/_snapshot*``                        → PR-02 FLAG  (privileged backup)
    * ``url.path=/_reindex`` on sensitive index       → PR-04 FLAG  (data movement)
    * ``url.path=/_search`` wildcard_expansion=true
       and ``indices.count > 5``                      → PR-04 FLAG  (multi-index wildcard)
    * ``url.path=/_msearch`` and ``indices.count > 10``→ PR-04 FLAG  (multi-search across many)
    * ``tls.version`` ∈ {TLSv1.0, TLSv1.1}            → PR-04 FAIL  (legacy TLS)

  Synthetic findings (cross-event correlation, per-export)
    * Failed-auth burst (same client.ip > N failed)    → PR-01 FAIL
    * Cross-index access (same user > N indices)       → PR-02 FLAG
    * Sensitive-read burst (same user > N reads on
      sensitive indices)                                → PR-04 FAIL

Sanitization: the importer NEVER stores ``request.body`` raw bodies, raw
``url.query`` strings, full ``client.ip`` (masked to /16), full
``kibana.session_id`` (last 8 only), full ``request.id`` (last 8 only), or
full ``tls.client.certificate.serial_number`` (last 8 only). Only structural
metadata is captured: event.action, event.category, event.type, user.name,
user.realm, user.run_as.name, authentication.type, sanitized index name,
indices.0.privilege, indices.count, request.method, url.path,
wildcard_expansion, cluster.name, cluster.node, tls.version, tls.cipher,
request.body_length (length only — already structural). The original file's
sha256 is recorded in source_provenance for tamper evidence.

Why ``.security`` reads are FAIL (not just FLAG):
    The ``.security`` system index is the source of truth for users, roles,
    and API keys. A successful read of that index by a non-platform principal
    is a credential-harvesting precondition: even one such event in a normal
    agent's evidence stream warrants blocking the run, not a soft warning.
    Writes to ``.security`` (privilege ∈ write/manage/all) are routed through
    PR-02 because they are scope violations rather than data exposure.

Why ``tampered_request`` is FAIL (not FLAG):
    Elasticsearch emits ``tampered_request`` when the message-authentication
    check on a transport-layer request fails — i.e. the body or headers were
    altered between the client and the receiving node. This is unambiguously
    an integrity-control failure (DE-01) and, in production, almost always
    means an active MITM, replay, or proxy injection. We treat it as a hard
    FAIL so it cannot be silently down-graded.

Why ``wildcard_expansion`` over many indices is its own flag:
    A single ``GET /_search`` with ``wildcard_expansion=true`` resolving to
    >5 indices behaves more like an undeclared cross-index scan than a
    normal retrieval — the agent never named the indices it actually read.
    From a data-classification standpoint, an unscoped wildcard is the
    runtime equivalent of ``SELECT * FROM *``: the principal extracts data
    from indices it might not even know exist. We flag separately from
    ``msearch`` (which at least enumerates target indices in the request)
    so reviewers can distinguish "intentional fan-out" from "wildcard
    discovery."
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table.
# This file lives at <repo>/python/src/ancilis/importers/elasticsearch.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "elasticsearch-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_SENSITIVE_INDICES: tuple[str, ...] = (
    ".security",
    ".kibana",
    "*-pii",
    "*-customers",
    "*-audit*",
    "*-credentials",
    "*-secrets",
)
_DEFAULT_LEGACY_TLS: tuple[str, ...] = ("TLSv1.0", "TLSv1.1")
_DEFAULT_CROSS_INDEX_THRESHOLD = 10
_DEFAULT_FAILED_AUTH_BURST = 10
_DEFAULT_SENSITIVE_READ_THRESHOLD = 50
_DEFAULT_WILDCARD_INDICES_THRESHOLD = 5
_DEFAULT_MSEARCH_INDICES_THRESHOLD = 10

# Per-index "production-ish" detector: any non-system, non-dotfile index whose
# name contains "prod" or matches typical prod patterns. We treat manage/all on
# such indices as a privilege flag separate from write-on-.security.
_PROD_HINTS: tuple[str, ...] = ("prod", "production", "live")

_SYSTEM_INDICES: tuple[str, ...] = (".security", ".kibana", ".security-7", ".kibana_7")

_PRIVILEGED_WRITE_PRIVS: frozenset[str] = frozenset(
    {"write", "create", "delete", "index", "manage", "all"}
)
_MANAGE_PRIVS: frozenset[str] = frozenset({"manage", "all"})

_DEFAULT_OPERATION_CONTROLS: dict[str, str] = {
    "authentication_success": "PR-01",
    "authentication_failed": "PR-01",
    "anonymous_access_denied": "PR-02",
    "access_denied": "PR-02",
    "access_granted_read": "PR-04",
    "sensitive_index_access": "PR-04",
    "security_index_read": "PR-04",
    "security_index_write": "PR-02",
    "manage_privilege_on_prod": "PR-02",
    "tampered_request": "DE-01",
    "run_as_granted": "PR-01",
    "connection_denied": "PR-01",
    "system_access_granted": "PR-02",
    "long_lived_api_key": "PR-01",
    "wildcard_search_many": "PR-04",
    "msearch_many_indices": "PR-04",
    "reindex_sensitive": "PR-04",
    "snapshot_operation": "PR-02",
    "cluster_settings_modify": "PR-02",
    "security_config_change": "PR-02",
    "security_role_grant": "PR-02",
    "legacy_tls": "PR-04",
    "non_rfc1918_client": "PR-01",
    "failed_auth_burst": "PR-01",
    "cross_index_pattern": "PR-02",
    "sensitive_read_burst": "PR-04",
}


# ---------------------------------------------------------------------------
# Mapping loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load elasticsearch-aksi-controls.json; tolerate missing file."""
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


def _mask_ip(ip: str | None) -> str | None:
    """Mask a client IP to /16 (or /112 for v6); returns None on bad input."""
    if not ip or not isinstance(ip, str):
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.IPv4Network(f"{ip}/16", strict=False)
        return str(net)
    net6 = ipaddress.IPv6Network(f"{ip}/112", strict=False)
    return str(net6)


def _is_rfc1918(ip: str | None) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(getattr(addr, "is_private", False))


def _last8(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value)
    if not s:
        return None
    return s[-8:]


def _sanitize_index_name(name: str | None, sensitive_patterns: Iterable[str]) -> dict[str, Any]:
    """Return structural metadata about an index without leaking the raw name.

    We DO retain the raw index name in evidence_data because the index name
    is itself a governance signal (the same way we retain collection/class
    names in qdrant.py and weaviate.py). We additionally classify it as
    sensitive vs not and tag a coarse alias category so downstream consumers
    do not have to re-implement the matcher.
    """
    if not name or not isinstance(name, str):
        return {"index_name": None, "is_sensitive": False, "alias_category": "unknown"}
    is_sensitive = _matches_any(name, sensitive_patterns)
    if name.startswith(".security"):
        category = "security_system"
    elif name.startswith(".kibana"):
        category = "kibana_system"
    elif name.startswith("."):
        category = "dotted_system"
    elif _matches_any(name, ("*-pii", "*-customers")):
        category = "pii"
    elif _matches_any(name, ("*-audit*",)):
        category = "audit"
    elif _matches_any(name, ("*-credentials", "*-secrets")):
        category = "credentials"
    elif any(h in name for h in _PROD_HINTS):
        category = "production"
    else:
        category = "user"
    return {
        "index_name": name,
        "is_sensitive": is_sensitive,
        "alias_category": category,
    }


def _matches_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class ElasticsearchImporter:
    """Parse an Elasticsearch X-Pack security audit-log export and convert to ``EvaluationResult``.

    The importer is import-safe: it never imports the optional ``elasticsearch``
    client, so it works in environments where Elasticsearch is not installed.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_index_threshold: int | None = None,
        failed_auth_burst: int | None = None,
        sensitive_read_threshold: int | None = None,
        wildcard_indices_threshold: int | None = None,
        msearch_indices_threshold: int | None = None,
        sensitive_indices: Iterable[str] | None = None,
        legacy_tls_versions: Iterable[str] | None = None,
        detect_synthetic: bool = True,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        self.cross_index_threshold = int(
            cross_index_threshold
            if cross_index_threshold is not None
            else meta.get("cross_index_threshold", _DEFAULT_CROSS_INDEX_THRESHOLD)
        )
        self.failed_auth_burst = int(
            failed_auth_burst
            if failed_auth_burst is not None
            else meta.get("failed_auth_burst", _DEFAULT_FAILED_AUTH_BURST)
        )
        self.sensitive_read_threshold = int(
            sensitive_read_threshold
            if sensitive_read_threshold is not None
            else meta.get("sensitive_read_threshold", _DEFAULT_SENSITIVE_READ_THRESHOLD)
        )
        self.wildcard_indices_threshold = int(
            wildcard_indices_threshold
            if wildcard_indices_threshold is not None
            else _DEFAULT_WILDCARD_INDICES_THRESHOLD
        )
        self.msearch_indices_threshold = int(
            msearch_indices_threshold
            if msearch_indices_threshold is not None
            else _DEFAULT_MSEARCH_INDICES_THRESHOLD
        )
        if sensitive_indices is not None:
            self.sensitive_indices: tuple[str, ...] = tuple(sensitive_indices)
        else:
            self.sensitive_indices = tuple(
                meta.get("sensitive_indices", _DEFAULT_SENSITIVE_INDICES)
            )
        if legacy_tls_versions is not None:
            self.legacy_tls_versions: tuple[str, ...] = tuple(legacy_tls_versions)
        else:
            self.legacy_tls_versions = tuple(
                meta.get("legacy_tls_versions", _DEFAULT_LEGACY_TLS)
            )
        self.detect_synthetic = bool(detect_synthetic)

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an Elasticsearch audit export file from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Elasticsearch audit content from a JSON / JSONL string (no file hash)."""
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

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "elasticsearch",
            "source_tool_name": "elasticsearch",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = [
            self._parse_event(e, file_sha256=file_sha256) for e in events
        ]
        if self.detect_synthetic:
            results.extend(self._synthetic_findings(events, file_sha256=file_sha256))
        return results

    # -- Per-event parsing --------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        action = str(event.get("event.action") or "").strip().lower()
        categories_raw = event.get("event.category")
        categories: list[str] = []
        if isinstance(categories_raw, list):
            categories = [str(c) for c in categories_raw if isinstance(c, (str, int))]
        elif isinstance(categories_raw, str):
            categories = [categories_raw]
        types_raw = event.get("event.type")
        types: list[str] = []
        if isinstance(types_raw, list):
            types = [str(t) for t in types_raw if isinstance(t, (str, int))]
        elif isinstance(types_raw, str):
            types = [types_raw]

        user_name = event.get("user.name")
        user_realm = event.get("user.realm")
        run_as_name = event.get("user.run_as.name")
        auth_type = event.get("authentication.type")
        index_name_raw = event.get("indices.0.name")
        privilege = (
            str(event.get("indices.0.privilege") or "").strip().lower() or None
        )
        try:
            indices_count = (
                int(event.get("indices.count"))
                if event.get("indices.count") is not None
                else None
            )
        except (TypeError, ValueError):
            indices_count = None
        request_method = (
            str(event.get("request.method") or "").strip().upper() or None
        )
        url_path = event.get("url.path")
        try:
            url_query_count = (
                int(event.get("url.query_count"))
                if event.get("url.query_count") is not None
                else None
            )
        except (TypeError, ValueError):
            url_query_count = None
        client_ip_full = event.get("client.ip")
        try:
            request_body_length = (
                int(event.get("request.body_length"))
                if event.get("request.body_length") is not None
                else None
            )
        except (TypeError, ValueError):
            request_body_length = None
        wildcard_expansion = bool(event.get("wildcard_expansion"))
        cluster_name = event.get("elasticsearch.cluster.name")
        cluster_uuid = event.get("elasticsearch.cluster.uuid")
        node_name = event.get("elasticsearch.node.name")
        tls_version = event.get("tls.version")
        tls_cipher = event.get("tls.cipher")
        timestamp = (
            event.get("@timestamp")
            or event.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )
        request_id_full = event.get("request.id")
        kibana_session_full = event.get("kibana.session_id")
        tls_serial_full = event.get("tls.client.certificate.serial_number")
        api_key_metadata = event.get("authentication.api_key.metadata")
        api_key_expiration = event.get("authentication.api_key.expiration")
        transport_profile = event.get("transport.profile")
        trace_id = event.get("trace.id")

        index_meta = _sanitize_index_name(
            str(index_name_raw) if index_name_raw is not None else None,
            self.sensitive_indices,
        )

        # Common evidence — sanitized only.
        common_evidence: dict[str, Any] = {
            "event_action": action,
            "event_category": categories,
            "event_type": types,
            "user_name": str(user_name) if user_name else None,
            "user_realm": str(user_realm) if user_realm else None,
            "user_run_as_name": str(run_as_name) if run_as_name else None,
            "authentication_type": str(auth_type) if auth_type else None,
            "index_name": index_meta["index_name"],
            "index_is_sensitive": index_meta["is_sensitive"],
            "index_alias_category": index_meta["alias_category"],
            "indices_privilege": privilege,
            "indices_count": indices_count,
            "request_method": request_method,
            "request_body_length": request_body_length,
            "url_path": str(url_path) if url_path else None,
            "url_query_count": url_query_count,
            "wildcard_expansion": wildcard_expansion,
            "client_ip_masked": _mask_ip(
                str(client_ip_full) if client_ip_full else None
            ),
            "client_ip_is_rfc1918": _is_rfc1918(
                str(client_ip_full) if client_ip_full else None
            ),
            "elasticsearch_cluster_name": str(cluster_name) if cluster_name else None,
            "elasticsearch_cluster_uuid": str(cluster_uuid) if cluster_uuid else None,
            "elasticsearch_node_name": str(node_name) if node_name else None,
            "tls_version": str(tls_version) if tls_version else None,
            "tls_cipher": str(tls_cipher) if tls_cipher else None,
            "tls_client_cert_serial_last8": _last8(tls_serial_full),
            "request_id_last8": _last8(request_id_full),
            "kibana_session_id_last8": _last8(kibana_session_full),
            "transport_profile": str(transport_profile) if transport_profile else None,
            "trace_id": str(trace_id) if trace_id else None,
            "source_provenance": self._source_provenance(file_sha256=file_sha256),
            "source_tool": "elasticsearch",
        }

        control_results: list[ControlResult] = []

        # 1. event.action — primary signal.
        if action == "authentication_success":
            control_results.append(
                self._make_cr(
                    "authentication_success",
                    "PASS",
                    common_evidence,
                    f"Elasticsearch authentication succeeded for user={user_name!r} "
                    f"realm={user_realm!r} type={auth_type!r}",
                )
            )
            # API_KEY without expiration metadata → long-lived key flag.
            if (
                str(auth_type or "").upper() == "API_KEY"
                and not api_key_expiration
                and not api_key_metadata
            ):
                control_results.append(
                    self._make_cr(
                        "long_lived_api_key",
                        "FLAG",
                        common_evidence,
                        f"Elasticsearch API_KEY auth for user={user_name!r} has "
                        f"no expiration metadata (long-lived credential)",
                    )
                )
        elif action == "authentication_failed":
            control_results.append(
                self._make_cr(
                    "authentication_failed",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch authentication failed for user={user_name!r} "
                    f"realm={user_realm!r} from client.ip(masked)="
                    f"{common_evidence['client_ip_masked']}",
                )
            )
        elif action == "anonymous_access_denied":
            control_results.append(
                self._make_cr(
                    "anonymous_access_denied",
                    "PASS",
                    common_evidence,
                    "Elasticsearch correctly denied anonymous access "
                    f"(governance audit-trail; client.ip(masked)="
                    f"{common_evidence['client_ip_masked']})",
                )
            )
        elif action == "access_denied":
            control_results.append(
                self._make_cr(
                    "access_denied",
                    "PASS",
                    common_evidence,
                    f"Elasticsearch denied access to user={user_name!r} on "
                    f"index={index_meta['index_name']!r} "
                    f"privilege={privilege!r} (governance audit-trail)",
                )
            )
        elif action == "tampered_request":
            control_results.append(
                self._make_cr(
                    "tampered_request",
                    "FAIL",
                    common_evidence,
                    "Elasticsearch detected tampered_request — request integrity "
                    f"violation (possible MITM/replay); user={user_name!r} "
                    f"path={url_path!r}",
                )
            )
        elif action == "connection_denied":
            control_results.append(
                self._make_cr(
                    "connection_denied",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch denied transport-layer connection from "
                    f"client.ip(masked)={common_evidence['client_ip_masked']} "
                    f"profile={transport_profile!r}",
                )
            )
        elif action == "run_as_granted":
            control_results.append(
                self._make_cr(
                    "run_as_granted",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch run_as impersonation granted: "
                    f"user={user_name!r} → run_as={run_as_name!r} "
                    f"(impersonation captured)",
                )
            )
        elif action == "system_access_granted":
            control_results.append(
                self._make_cr(
                    "system_access_granted",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch granted system-level access for "
                    f"user={user_name!r} on path={url_path!r}",
                )
            )
        elif action == "access_granted":
            control_results.extend(
                self._access_granted_signals(
                    common_evidence,
                    user_name=user_name,
                    index_meta=index_meta,
                    privilege=privilege,
                )
            )

        # 2. URL-path signals — independent of action (the action is usually
        #    access_granted but we want the FAIL even if the export shape is
        #    slightly different).
        control_results.extend(
            self._url_path_signals(
                common_evidence,
                url_path=str(url_path) if url_path else None,
                request_method=request_method,
                indices_count=indices_count,
                wildcard_expansion=wildcard_expansion,
                index_meta=index_meta,
            )
        )

        # 3. TLS version signal.
        if tls_version and str(tls_version) in self.legacy_tls_versions:
            control_results.append(
                self._make_cr(
                    "legacy_tls",
                    "FAIL",
                    common_evidence,
                    f"Elasticsearch transport used legacy "
                    f"tls.version={tls_version!r} (insecure cipher channel)",
                )
            )

        # 4. Off-VPC / non-RFC1918 client IP on production cluster.
        if (
            client_ip_full
            and not _is_rfc1918(str(client_ip_full))
            and cluster_name
            and any(h in str(cluster_name).lower() for h in _PROD_HINTS)
        ):
            control_results.append(
                self._make_cr(
                    "non_rfc1918_client",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch production cluster={cluster_name!r} accessed "
                    f"from non-RFC1918 client.ip(masked)="
                    f"{common_evidence['client_ip_masked']}",
                )
            )

        # If no signals matched, surface the event as a generic ALLOW so
        # downstream consumers still get a record.
        if not control_results:
            control_results.append(
                self._make_cr(
                    "authentication_success",
                    "PASS",
                    common_evidence,
                    f"Elasticsearch event action={action!r} captured "
                    f"(no specific signal matched)",
                )
            )

        decision = _decision_for(control_results)
        decision_reason = (
            f"Imported from Elasticsearch: action={action!r} "
            f"user={user_name!r} index={index_meta['index_name']!r} "
            f"privilege={privilege!r} path={url_path!r}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"elasticsearch-{(_last8(request_id_full) or uuid.uuid4().hex)[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="elasticsearch_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=str(trace_id) if trace_id else None,
        )

    # -- Sub-routines -------------------------------------------------------

    def _access_granted_signals(
        self,
        common_evidence: dict[str, Any],
        *,
        user_name: Any,
        index_meta: dict[str, Any],
        privilege: str | None,
    ) -> list[ControlResult]:
        """Compute access_granted signals: read vs write × sensitive vs not."""
        results: list[ControlResult] = []
        index_name = index_meta["index_name"] or ""
        is_sensitive = bool(index_meta["is_sensitive"])
        is_security = index_name.startswith(".security")
        is_kibana = index_name.startswith(".kibana")
        priv = (privilege or "").lower()

        # --- .security index handling --------------------------------------
        if is_security:
            if priv == "read":
                results.append(
                    self._make_cr(
                        "security_index_read",
                        "FAIL",
                        common_evidence,
                        f"Elasticsearch user={user_name!r} read .security system "
                        f"index (privilege=read) — credential-store exposure",
                    )
                )
                return results
            if priv in _PRIVILEGED_WRITE_PRIVS:
                results.append(
                    self._make_cr(
                        "security_index_write",
                        "FAIL",
                        common_evidence,
                        f"Elasticsearch user={user_name!r} modified .security "
                        f"system index (privilege={privilege!r}) — security "
                        f"configuration tampering",
                    )
                )
                return results

        # --- manage/all on production index --------------------------------
        if (
            priv in _MANAGE_PRIVS
            and index_name
            and not index_name.startswith(".")
        ):
            results.append(
                self._make_cr(
                    "manage_privilege_on_prod",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch access_granted with privilege={privilege!r} "
                    f"on index={index_name!r} (privileged on production-style index)",
                )
            )

        # --- sensitive-but-not-.security read -----------------------------
        if is_sensitive and not is_security and priv == "read":
            results.append(
                self._make_cr(
                    "sensitive_index_access",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch user={user_name!r} read sensitive index "
                    f"{index_name!r} (category={index_meta['alias_category']})",
                )
            )
            return results

        # --- Kibana write (treated as system_access-style flag) -----------
        if is_kibana and priv in _PRIVILEGED_WRITE_PRIVS:
            results.append(
                self._make_cr(
                    "manage_privilege_on_prod",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch user={user_name!r} wrote to .kibana system "
                    f"index (privilege={privilege!r})",
                )
            )
            return results

        # --- Routine read on a normal index → PR-04 PASS ------------------
        if priv == "read" and not is_sensitive:
            results.append(
                self._make_cr(
                    "access_granted_read",
                    "PASS",
                    common_evidence,
                    f"Elasticsearch user={user_name!r} read index "
                    f"{index_name!r} (data-access governance)",
                )
            )
        return results

    def _url_path_signals(
        self,
        common_evidence: dict[str, Any],
        *,
        url_path: str | None,
        request_method: str | None,
        indices_count: int | None,
        wildcard_expansion: bool,
        index_meta: dict[str, Any],
    ) -> list[ControlResult]:
        """Compute URL-path-driven signals (cluster, security, snapshot, _search, _msearch, _reindex)."""
        results: list[ControlResult] = []
        if not url_path:
            return results
        path = url_path
        method = request_method or ""

        # /_cluster/settings PUT → FAIL
        if path.startswith("/_cluster/settings") and method == "PUT":
            results.append(
                self._make_cr(
                    "cluster_settings_modify",
                    "FAIL",
                    common_evidence,
                    f"Elasticsearch cluster-settings modification PUT {path}"
                    f" (cluster-wide configuration change)",
                )
            )

        # /_security/role* PUT → role grant FAIL
        if path.startswith("/_security/role") and method in ("PUT", "POST"):
            results.append(
                self._make_cr(
                    "security_role_grant",
                    "FAIL",
                    common_evidence,
                    f"Elasticsearch role grant via {method} {path}"
                    f" (RBAC configuration change)",
                )
            )
        # /_security/* PUT/DELETE → security config change FAIL
        elif path.startswith("/_security/") and method in ("PUT", "DELETE"):
            results.append(
                self._make_cr(
                    "security_config_change",
                    "FAIL",
                    common_evidence,
                    f"Elasticsearch security configuration {method} {path}"
                    f" (users / API keys / privileges modified)",
                )
            )

        # /_snapshot* → privileged backup FLAG
        if path.startswith("/_snapshot"):
            results.append(
                self._make_cr(
                    "snapshot_operation",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch snapshot operation {method} {path}"
                    f" (privileged backup/restore)",
                )
            )

        # /_reindex on sensitive index → FLAG
        if path.startswith("/_reindex") and index_meta.get("is_sensitive"):
            results.append(
                self._make_cr(
                    "reindex_sensitive",
                    "FLAG",
                    common_evidence,
                    f"Elasticsearch reindex involving sensitive "
                    f"index={index_meta['index_name']!r}"
                    f" (data movement)",
                )
            )

        # /_search wildcard_expansion=true on >threshold indices → FLAG
        if (
            path.startswith("/_search")
            and wildcard_expansion
            and indices_count is not None
            and indices_count > self.wildcard_indices_threshold
        ):
            results.append(
                self._make_cr(
                    "wildcard_search_many",
                    "FLAG",
                    {
                        **common_evidence,
                        "wildcard_indices_threshold": self.wildcard_indices_threshold,
                    },
                    f"Elasticsearch /_search with wildcard_expansion=true "
                    f"resolved to {indices_count} indices (> "
                    f"{self.wildcard_indices_threshold}) — undeclared cross-index scan",
                )
            )

        # /_msearch on >threshold indices → FLAG
        if (
            path.startswith("/_msearch")
            and indices_count is not None
            and indices_count > self.msearch_indices_threshold
        ):
            results.append(
                self._make_cr(
                    "msearch_many_indices",
                    "FLAG",
                    {
                        **common_evidence,
                        "msearch_indices_threshold": self.msearch_indices_threshold,
                    },
                    f"Elasticsearch /_msearch spanned {indices_count} indices "
                    f"(> {self.msearch_indices_threshold}) — broad multi-search",
                )
            )
        return results

    # -- Helpers ------------------------------------------------------------

    def _make_cr(
        self,
        signal: str,
        level: str,
        common_evidence: dict[str, Any],
        detail: str,
    ) -> ControlResult:
        control_id = _control_for(
            signal,
            self._mappings,
            _DEFAULT_OPERATION_CONTROLS.get(signal, "PR-02"),
        )
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=level,
            detail=detail,
            evidence_data={**common_evidence, "signal": signal},
        )

    # -- Synthetic findings -------------------------------------------------

    def _synthetic_findings(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Emit per-export synthetic findings: cross-index, failed-auth burst, sensitive-read burst."""
        if not events:
            return []
        findings: list[EvaluationResult] = []

        # 1. Failed-auth burst: same client.ip with > N authentication_failed.
        failed_by_ip: dict[str, int] = defaultdict(int)
        for e in events:
            if str(e.get("event.action") or "").lower() != "authentication_failed":
                continue
            ip = e.get("client.ip")
            if isinstance(ip, str) and ip:
                failed_by_ip[ip] += 1
        for ip, count in failed_by_ip.items():
            if count <= self.failed_auth_burst:
                continue
            cr = self._make_synthetic_cr(
                signal="failed_auth_burst",
                level="FAIL",
                detail=(
                    f"Elasticsearch detected {count} authentication_failed events "
                    f"from client.ip(masked)={_mask_ip(ip)} (> "
                    f"{self.failed_auth_burst} in export) — credential-stuffing pattern"
                ),
                evidence={
                    "client_ip_masked": _mask_ip(ip),
                    "failed_count": count,
                    "threshold": self.failed_auth_burst,
                    "source_provenance": self._source_provenance(file_sha256=file_sha256),
                    "source_tool": "elasticsearch",
                },
            )
            findings.append(self._wrap_synthetic(cr, action_id_hint=f"failed-auth-{_mask_ip(ip)}"))

        # 2. Cross-index: same user.name touched > N distinct indices.
        user_to_indices: dict[str, set[str]] = defaultdict(set)
        for e in events:
            user = e.get("user.name")
            idx = e.get("indices.0.name")
            if isinstance(user, str) and user and isinstance(idx, str) and idx:
                user_to_indices[user].add(idx)
        for user, idx_set in user_to_indices.items():
            if len(idx_set) <= self.cross_index_threshold:
                continue
            cr = self._make_synthetic_cr(
                signal="cross_index_pattern",
                level="FLAG",
                detail=(
                    f"Elasticsearch user={user!r} touched {len(idx_set)} distinct "
                    f"indices in export (> {self.cross_index_threshold}) — "
                    f"scope-expansion pattern"
                ),
                evidence={
                    "user_name": user,
                    "index_count": len(idx_set),
                    "threshold": self.cross_index_threshold,
                    "source_provenance": self._source_provenance(file_sha256=file_sha256),
                    "source_tool": "elasticsearch",
                },
            )
            findings.append(self._wrap_synthetic(cr, action_id_hint=f"cross-index-{user[:24]}"))

        # 3. Sensitive-read burst: same user > N reads of sensitive indices.
        sensitive_reads: dict[str, int] = defaultdict(int)
        for e in events:
            if str(e.get("event.action") or "").lower() != "access_granted":
                continue
            priv = str(e.get("indices.0.privilege") or "").lower()
            if priv != "read":
                continue
            idx = e.get("indices.0.name")
            user = e.get("user.name")
            if not (isinstance(user, str) and user and isinstance(idx, str) and idx):
                continue
            if _matches_any(idx, self.sensitive_indices):
                sensitive_reads[user] += 1
        for user, count in sensitive_reads.items():
            if count <= self.sensitive_read_threshold:
                continue
            cr = self._make_synthetic_cr(
                signal="sensitive_read_burst",
                level="FAIL",
                detail=(
                    f"Elasticsearch user={user!r} performed {count} reads on "
                    f"sensitive indices (> {self.sensitive_read_threshold}) — "
                    f"data-exfiltration pattern"
                ),
                evidence={
                    "user_name": user,
                    "sensitive_read_count": count,
                    "threshold": self.sensitive_read_threshold,
                    "source_provenance": self._source_provenance(file_sha256=file_sha256),
                    "source_tool": "elasticsearch",
                },
            )
            findings.append(self._wrap_synthetic(cr, action_id_hint=f"sensitive-read-{user[:24]}"))

        return findings

    def _make_synthetic_cr(
        self,
        *,
        signal: str,
        level: str,
        detail: str,
        evidence: dict[str, Any],
    ) -> ControlResult:
        control_id = _control_for(
            signal,
            self._mappings,
            _DEFAULT_OPERATION_CONTROLS.get(signal, "PR-02"),
        )
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=level,
            detail=detail,
            evidence_data={**evidence, "signal": signal},
        )

    def _wrap_synthetic(
        self,
        cr: ControlResult,
        *,
        action_id_hint: str,
    ) -> EvaluationResult:
        decision = "BLOCK" if cr.result == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"elasticsearch-synthetic-{action_id_hint[:48]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="elasticsearch_import_synthetic",
            mode=self.mode,
            control_results=[cr],
            decision=decision,
            decision_reason=cr.detail,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _decision_for(control_results: list[ControlResult]) -> str:
    if any(cr.result == "FAIL" for cr in control_results):
        return "BLOCK"
    if any(cr.result == "FLAG" for cr in control_results):
        return "FLAG"
    return "ALLOW"
