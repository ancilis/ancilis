"""Kubernetes apiserver audit-event importer — maps cluster-action audit events to AKSI controls.

The kube-apiserver (https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
is the single chokepoint for every cluster-mutating action: pod creation,
secret access, RBAC modification, exec into pods, port-forward, namespace
deletion. For agents that operate Kubernetes clusters (Devin's deploys,
AIOps, custom DevOps agents), audit logs are THE canonical evidence source
for who-did-what across cluster state — far broader than any application-
level trace.

This importer ingests audit-event exports in three on-disk shapes:

  1. ``{"items": [...]}`` — the canonical kubectl-export envelope (also the
     wire shape ``audit.k8s.io/v1`` events are batched in)
  2. ``{"data":  [...]}`` — generic data envelope
  3. JSONL                 — one event per line (the kube-apiserver native
     log-file shape when configured with ``--audit-log-format=json``)

Signal mapping (see shared/mappings/kubernetes-audit-aksi-controls.json):
  * verb=get/list/watch on pods/services/configmaps    → PR-04 PASS  (read)
  * verb=get on secrets                                → PR-04 FLAG  (review)
  * verb=list/watch on secrets                         → PR-04 FAIL  (mass enum)
  * verb=create/update/patch/delete on secrets         → PR-01 FLAG  (lifecycle)
  * verb=create on pods + privileged|hostNetwork|hostPID → PR-02 FAIL (escape risk)
  * verb=create on pods + image tag :latest            → PR-05 FLAG  (un-pinned)
  * verb=create on pods + non-allowlisted registry     → PR-04 FLAG  (untrusted)
  * verb=delete on namespaces                          → PR-02 FAIL  (bulk impact)
  * verb=delete on deployments/statefulsets in prod-ns → PR-02 FAIL
  * verb=exec / subresource=exec                       → PR-02 FAIL  (shell)
  * verb=attach / subresource=attach                   → PR-02 FAIL
  * verb=portforward                                   → PR-02 FAIL  (bypass mesh)
  * verb=create on rolebindings/clusterrolebindings    → PR-02 FAIL  (RBAC grant)
  * RBAC subjects include kind=Group system:authenticated → PR-02 FAIL (over-broad)
  * impersonatedUser non-null                          → PR-01 FLAG  (--as)
  * user.username == system:anonymous                  → PR-01 FAIL
  * unrecognized human user on prod namespace          → PR-01 FLAG
  * responseStatus.code=403 + decision=forbid          → PR-02 PASS  (RBAC denial)
  * responseStatus.code=500                            → DE-01 FAIL
  * verb=create on tokenrequests                       → PR-01 FLAG
  * cross-namespace pattern (one user > N namespaces)  → PR-02 FLAG synthetic
  * delete-burst pattern (one user > N deletes / 1h)   → PR-02 FLAG synthetic

Sanitization (security-critical — audit events at Request/RequestResponse
level can contain entire pod/secret manifests):
  * ``requestObject`` and ``responseObject`` BODIES are NEVER stored. Only
    extracted *features* are captured: privileged/hostNetwork/hostPID booleans,
    container image strings (the registry/tag is the security signal), and
    RBAC subject summaries (kind+name only — no metadata).
  * ``requestURI`` is stored *path-only* — query strings can carry watch
    selectors or fieldSelectors that may include identifying values.
  * ``user.username`` preserved verbatim (Kubernetes usernames are public
    identifiers — service-account names, OIDC subjects, etc.).
  * ``user.uid`` reduced to last-8 only.
  * ``sourceIPs`` normalized: RFC1918/loopback preserved verbatim, public
    IPv4 reduced to /16, public IPv6 reduced to /32.
  * ``userAgent`` — first 80 chars + sha256 of the full string.
  * Resource ``name`` field: pod names with random suffixes are usually safe,
    but custom-named resources may carry semantic data — names longer than
    16 chars are reduced to ``<first-16>...<sha256-prefix-8>``.
  * Original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``kubernetes`` package; audit-event JSON
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


# Path to the shared mapping table. Five .parent traversals reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "kubernetes-audit-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}


# Built-in fallbacks — mirror the canonical mapping JSON.
_DEFAULT_VERB_RESOURCE_PATTERNS: tuple[dict[str, Any], ...] = (
    {"verb": "get", "resource": "pods", "signal": "pod_read", "result": "PASS", "control": "PR-04"},
    {"verb": "list", "resource": "pods", "signal": "pod_read", "result": "PASS", "control": "PR-04"},
    {"verb": "watch", "resource": "pods", "signal": "pod_read", "result": "PASS", "control": "PR-04"},
    {"verb": "get", "resource": "services", "signal": "service_read", "result": "PASS", "control": "PR-04"},
    {"verb": "list", "resource": "services", "signal": "service_read", "result": "PASS", "control": "PR-04"},
    {"verb": "watch", "resource": "services", "signal": "service_read", "result": "PASS", "control": "PR-04"},
    {"verb": "get", "resource": "configmaps", "signal": "configmap_read", "result": "PASS", "control": "PR-04"},
    {"verb": "list", "resource": "configmaps", "signal": "configmap_read", "result": "PASS", "control": "PR-04"},
    {"verb": "watch", "resource": "configmaps", "signal": "configmap_read", "result": "PASS", "control": "PR-04"},
    {"verb": "get", "resource": "secrets", "signal": "secret_read", "result": "FLAG", "control": "PR-04"},
    {"verb": "list", "resource": "secrets", "signal": "secret_mass_enumeration", "result": "FAIL", "control": "PR-04"},
    {"verb": "watch", "resource": "secrets", "signal": "secret_mass_enumeration", "result": "FAIL", "control": "PR-04"},
    {"verb": "create", "resource": "secrets", "signal": "secret_lifecycle_change", "result": "FLAG", "control": "PR-01"},
    {"verb": "update", "resource": "secrets", "signal": "secret_lifecycle_change", "result": "FLAG", "control": "PR-01"},
    {"verb": "patch", "resource": "secrets", "signal": "secret_lifecycle_change", "result": "FLAG", "control": "PR-01"},
    {"verb": "delete", "resource": "secrets", "signal": "secret_lifecycle_change", "result": "FLAG", "control": "PR-01"},
    {"verb": "delete", "resource": "namespaces", "signal": "namespace_delete", "result": "FAIL", "control": "PR-02"},
    {"verb": "create", "resource": "rolebindings", "signal": "rbac_grant", "result": "FAIL", "control": "PR-02"},
    {"verb": "create", "resource": "clusterrolebindings", "signal": "rbac_grant", "result": "FAIL", "control": "PR-02"},
    {"verb": "create", "resource": "tokenrequests", "signal": "service_account_token_create", "result": "FLAG", "control": "PR-01"},
)

_DEFAULT_SUBRESOURCE_SIGNALS: dict[str, dict[str, str]] = {
    "exec":        {"signal": "pod_exec",        "result": "FAIL", "control": "PR-02"},
    "attach":      {"signal": "pod_attach",      "result": "FAIL", "control": "PR-02"},
    "portforward": {"signal": "pod_portforward", "result": "FAIL", "control": "PR-02"},
}

_DEFAULT_VERB_SIGNALS: dict[str, dict[str, str]] = {
    "exec":        {"signal": "pod_exec",        "result": "FAIL", "control": "PR-02"},
    "attach":      {"signal": "pod_attach",      "result": "FAIL", "control": "PR-02"},
    "portforward": {"signal": "pod_portforward", "result": "FAIL", "control": "PR-02"},
}

_DEFAULT_STATUS_CODE_SIGNALS: dict[str, dict[str, str]] = {
    "403": {"signal": "rbac_denied",              "result": "PASS", "control": "PR-02"},
    "500": {"signal": "apiserver_internal_error", "result": "FAIL", "control": "DE-01"},
}

_DEFAULT_IMAGE_REGISTRY_ALLOWLIST: frozenset[str] = frozenset(
    {"gcr.io", "docker.io", "quay.io", "public.ecr.aws", "ghcr.io",
     "registry.k8s.io", "k8s.gcr.io"}
)

_DEFAULT_PRODUCTION_NAMESPACE_PATTERNS: tuple[str, ...] = (
    "prod", "prod-*", "production", "production-*", "*-prod", "*-production",
)

_DEFAULT_CROSS_NAMESPACE_THRESHOLD = 5
_DEFAULT_DELETE_BURST_THRESHOLD = 10

# Resources that, when deleted from a production namespace, escalate to a
# bulk-impact PR-02 FAIL. Distinct from namespace deletion (always FAIL).
_PROD_DELETE_RESOURCES: frozenset[str] = frozenset({"deployments", "statefulsets"})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the kubernetes-audit-aksi-controls.json mapping; tolerate missing file."""
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


def _sanitize_resource_name(name: str | None) -> str | None:
    """Reduce a resource name to first-16 chars plus an 8-char sha256 fingerprint.

    Pod names with controller-generated random suffixes are typically safe,
    but custom-named resources (Secrets, ConfigMaps, custom CRs) can carry
    semantic data the org may consider sensitive. Names <= 16 chars are
    preserved verbatim; longer names are summarized.
    """
    if name is None or not isinstance(name, str):
        return None
    s = name.strip()
    if not s:
        return None
    if len(s) <= 16:
        return s
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
    return f"{s[:16]}...{digest}"


def _sanitize_uid(uid: str | None) -> str | None:
    """Reduce a Kubernetes UID to ``***<last-8>`` form."""
    if uid is None or not isinstance(uid, str):
        return None
    s = uid.strip()
    if not s:
        return None
    if len(s) <= 8:
        return f"***{s}"
    return f"***{s[-8:]}"


def _sanitize_user_agent(user_agent: str | None) -> str | None:
    """Reduce a userAgent to first-80 chars + sha256 of the full string."""
    if user_agent is None or not isinstance(user_agent, str):
        return None
    s = user_agent.strip()
    if not s:
        return None
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
    if len(s) <= 80:
        return f"{s}#{digest}"
    return f"{s[:80]}...#{digest}"


def _classify_source_ip(source_ip: str | None) -> str | None:
    """Normalize a sourceIPs entry to a privacy-aware form (mirrors CloudTrail)."""
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
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _request_path_only(request_uri: str | None) -> str | None:
    """Strip the query string from a requestURI — query selectors can leak data."""
    if not request_uri or not isinstance(request_uri, str):
        return None
    s = request_uri.strip()
    if not s:
        return None
    try:
        parts = urlsplit(s)
    except ValueError:
        return s
    return parts.path or s


def _extract_image_registry(image: str) -> str:
    """Return the registry component of a container image string.

    Heuristic identical to Docker's reference-parser: a registry is the part
    before the first ``/`` *only if* that part contains a ``.`` or ``:`` or
    is exactly ``localhost``. Otherwise the registry is the implicit
    ``docker.io`` (Docker Hub).
    """
    s = image.strip()
    if not s:
        return ""
    # Strip digest / tag for registry detection — registry is purely the
    # left-most segment before ``/``.
    head, _, _ = s.partition("/")
    if "/" not in s:
        return "docker.io"
    if "." in head or ":" in head or head == "localhost":
        return head
    return "docker.io"


def _extract_image_tag(image: str) -> str:
    """Return the tag portion of an image string (``""`` if no explicit tag)."""
    s = image.strip()
    if not s:
        return ""
    # Drop the registry/host segment — but only if the segment before the first
    # ``/`` looks like a registry (contains ``.`` / ``:`` / equals ``localhost``).
    rest = s
    head, sep, tail = s.partition("/")
    if sep and ("." in head or ":" in head or head == "localhost"):
        rest = tail
    # Drop digest if present.
    rest = rest.split("@", 1)[0]
    # Tag follows ``:`` in the LAST path segment.
    last_seg = rest.rsplit("/", 1)[-1]
    if ":" in last_seg:
        return last_seg.split(":", 1)[1]
    return ""


def _extract_pod_security_features(request_object: Any) -> dict[str, Any]:
    """Extract privileged/hostNetwork/hostPID flags + container images from a Pod spec.

    Operates on Pod or PodTemplate-shaped requestObjects (Deployment/StatefulSet
    requestObjects nest the pod spec under ``spec.template.spec``). Returns:
      * privileged: bool — any container has securityContext.privileged=true
      * host_network: bool — pod spec hostNetwork=true
      * host_pid: bool — pod spec hostPID=true
      * container_images: list[str] — collected from all containers and
        initContainers (no ephemeralContainers — those are exec-time only)
    """
    features: dict[str, Any] = {
        "privileged": False,
        "host_network": False,
        "host_pid": False,
        "container_images": [],
    }
    if not isinstance(request_object, dict):
        return features
    # Pod spec may live at .spec or .spec.template.spec (Deployment/StatefulSet).
    spec = request_object.get("spec")
    if not isinstance(spec, dict):
        return features
    pod_spec: dict[str, Any] = spec
    template = spec.get("template")
    if isinstance(template, dict):
        nested_spec = template.get("spec")
        if isinstance(nested_spec, dict):
            pod_spec = nested_spec
    if pod_spec.get("hostNetwork") is True:
        features["host_network"] = True
    if pod_spec.get("hostPID") is True:
        features["host_pid"] = True
    images: list[str] = []
    for container_field in ("containers", "initContainers"):
        containers = pod_spec.get(container_field)
        if not isinstance(containers, list):
            continue
        for c in containers:
            if not isinstance(c, dict):
                continue
            image = c.get("image")
            if isinstance(image, str) and image.strip():
                images.append(image.strip())
            sec_ctx = c.get("securityContext")
            if isinstance(sec_ctx, dict) and sec_ctx.get("privileged") is True:
                features["privileged"] = True
    features["container_images"] = images
    return features


def _extract_rbac_subjects(request_object: Any) -> list[dict[str, str]]:
    """Extract a SUMMARY of RBAC subjects (kind+name only — no metadata)."""
    if not isinstance(request_object, dict):
        return []
    subjects = request_object.get("subjects")
    if not isinstance(subjects, list):
        return []
    out: list[dict[str, str]] = []
    for s in subjects:
        if not isinstance(s, dict):
            continue
        kind = str(s.get("kind") or "")
        name = str(s.get("name") or "")
        ns = str(s.get("namespace") or "")
        entry = {"kind": kind, "name": name}
        if ns:
            entry["namespace"] = ns
        out.append(entry)
    return out


def _is_production_namespace(
    namespace: str | None, patterns: tuple[str, ...]
) -> bool:
    if not namespace:
        return False
    return any(fnmatch.fnmatchcase(namespace, pat) for pat in patterns)


def _matches_verb_resource(
    verb: str, resource: str, pattern: dict[str, Any]
) -> bool:
    return (
        fnmatch.fnmatchcase(verb, str(pattern.get("verb", "")))
        and fnmatch.fnmatchcase(resource, str(pattern.get("resource", "")))
    )


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class KubernetesAuditImporter:
    """Parse a kube-apiserver audit export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_namespace_threshold: int | None = None,
        delete_burst_threshold: int | None = None,
        image_registry_allowlist: Iterable[str] | None = None,
        production_namespace_patterns: Iterable[str] | None = None,
        known_users: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Verb/resource patterns precedence: mapping table > built-in defaults.
        meta_patterns = meta.get("verb_resource_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._verb_resource_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._verb_resource_patterns = _DEFAULT_VERB_RESOURCE_PATTERNS
        # Sub-resource signals (exec/attach/portforward).
        meta_subres = meta.get("subresource_signals")
        if isinstance(meta_subres, dict) and meta_subres:
            self._subresource_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_subres.items()
                if isinstance(v, dict)
            }
        else:
            self._subresource_signals = dict(_DEFAULT_SUBRESOURCE_SIGNALS)
        # Verb signals (exec / portforward as verbs).
        meta_verb = meta.get("verb_signals")
        if isinstance(meta_verb, dict) and meta_verb:
            self._verb_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_verb.items()
                if isinstance(v, dict)
            }
        else:
            self._verb_signals = dict(_DEFAULT_VERB_SIGNALS)
        # Status-code signals (403 / 500).
        meta_status = meta.get("status_code_signals")
        if isinstance(meta_status, dict) and meta_status:
            self._status_code_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_status.items()
                if isinstance(v, dict)
            }
        else:
            self._status_code_signals = dict(_DEFAULT_STATUS_CODE_SIGNALS)
        # Image registry allowlist.
        if image_registry_allowlist is not None:
            self._image_registry_allowlist: frozenset[str] = frozenset(
                str(s).lower() for s in image_registry_allowlist
            )
        else:
            meta_reg = meta.get("image_registry_allowlist")
            if isinstance(meta_reg, list) and meta_reg:
                self._image_registry_allowlist = frozenset(
                    str(s).lower() for s in meta_reg
                )
            else:
                self._image_registry_allowlist = _DEFAULT_IMAGE_REGISTRY_ALLOWLIST
        # Production-namespace patterns.
        if production_namespace_patterns is not None:
            self._prod_namespace_patterns: tuple[str, ...] = tuple(
                str(p) for p in production_namespace_patterns
            )
        else:
            meta_prod = meta.get("production_namespace_patterns")
            if isinstance(meta_prod, list) and meta_prod:
                self._prod_namespace_patterns = tuple(str(p) for p in meta_prod)
            else:
                self._prod_namespace_patterns = _DEFAULT_PRODUCTION_NAMESPACE_PATTERNS
        # Known-users list (for prod-namespace unrecognized-human-user FLAG).
        self._known_users: frozenset[str] = (
            frozenset(str(u) for u in known_users) if known_users else frozenset()
        )
        # Cross-namespace threshold precedence: explicit arg > meta > default.
        if cross_namespace_threshold is not None:
            self.cross_namespace_threshold = int(cross_namespace_threshold)
        else:
            self.cross_namespace_threshold = int(
                meta.get("cross_namespace_threshold", _DEFAULT_CROSS_NAMESPACE_THRESHOLD)
            )
        if delete_burst_threshold is not None:
            self.delete_burst_threshold = int(delete_burst_threshold)
        else:
            self.delete_burst_threshold = int(
                meta.get("delete_burst_threshold", _DEFAULT_DELETE_BURST_THRESHOLD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a kube-apiserver audit export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse audit-event content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"items":[]}`` / ``{"data":[]}`` / JSONL / single event."""
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
                if "items" in doc and isinstance(doc["items"], list):
                    return [r for r in doc["items"] if isinstance(r, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [r for r in doc["data"] if isinstance(r, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-event EvaluationResults plus synthetic findings."""
        # First pass — aggregate cross-namespace and delete-burst patterns
        # per username (impersonatedUser is preserved separately).
        user_namespaces: dict[str, set[str]] = {}
        user_deletes: dict[str, int] = {}
        for ev in events:
            user = ev.get("user") or {}
            if not isinstance(user, dict):
                continue
            uname = user.get("username")
            if not isinstance(uname, str) or not uname:
                continue
            obj_ref = ev.get("objectRef") or {}
            if isinstance(obj_ref, dict):
                ns = obj_ref.get("namespace")
                if isinstance(ns, str) and ns:
                    user_namespaces.setdefault(uname, set()).add(ns)
            verb = ev.get("verb")
            if isinstance(verb, str) and verb == "delete":
                user_deletes[uname] = user_deletes.get(uname, 0) + 1

        cross_namespace_users = {
            u: sorted(ns_set)
            for u, ns_set in user_namespaces.items()
            if len(ns_set) > self.cross_namespace_threshold
        }
        delete_burst_users = {
            u: count
            for u, count in user_deletes.items()
            if count > self.delete_burst_threshold
        }

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                cross_namespace_users=cross_namespace_users,
                delete_burst_users=delete_burst_users,
            )
            for ev in events
        ]

        # Synthetic per-user cross-namespace findings.
        for uname, ns_list in sorted(cross_namespace_users.items()):
            results.append(
                self._synthetic_cross_namespace_result(
                    username=uname,
                    namespaces=ns_list,
                    file_sha256=file_sha256,
                )
            )
        # Synthetic per-user delete-burst findings.
        for uname, count in sorted(delete_burst_users.items()):
            results.append(
                self._synthetic_delete_burst_result(
                    username=uname,
                    delete_count=count,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        audit_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "kubernetes_audit",
            "source_tool_name": "kubernetes_audit",
            "source_tool_version": "audit.k8s.io/v1",
        }
        if audit_id is not None:
            provenance["audit_id"] = audit_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_verb_resource(
        self, verb: str, resource: str
    ) -> dict[str, Any] | None:
        for pattern in self._verb_resource_patterns:
            if _matches_verb_resource(verb, resource, pattern):
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
        cross_namespace_users: dict[str, list[str]],
        delete_burst_users: dict[str, int],
    ) -> EvaluationResult:
        audit_id = str(event.get("auditID") or uuid.uuid4())
        level = str(event.get("level") or "")
        stage = str(event.get("stage") or "")
        verb = str(event.get("verb") or "").strip()
        request_uri_path = _request_path_only(event.get("requestURI"))
        request_received = str(event.get("requestReceivedTimestamp") or "")
        stage_timestamp = str(
            event.get("stageTimestamp")
            or request_received
            or datetime.now(timezone.utc).isoformat()
        )

        # ---- objectRef ----
        obj_ref = event.get("objectRef") or {}
        if not isinstance(obj_ref, dict):
            obj_ref = {}
        resource = str(obj_ref.get("resource") or "").strip()
        namespace = obj_ref.get("namespace") if isinstance(obj_ref.get("namespace"), str) else None
        raw_name = obj_ref.get("name") if isinstance(obj_ref.get("name"), str) else None
        sanitized_name = _sanitize_resource_name(raw_name)
        api_group = obj_ref.get("apiGroup") if isinstance(obj_ref.get("apiGroup"), str) else None
        api_version = obj_ref.get("apiVersion") if isinstance(obj_ref.get("apiVersion"), str) else None
        subresource_raw = obj_ref.get("subresource")
        subresource = (
            str(subresource_raw).strip()
            if isinstance(subresource_raw, str) and subresource_raw.strip()
            else None
        )

        # ---- user / impersonatedUser ----
        user = event.get("user") or {}
        if not isinstance(user, dict):
            user = {}
        username = user.get("username") if isinstance(user.get("username"), str) else None
        user_uid = _sanitize_uid(user.get("uid") if isinstance(user.get("uid"), str) else None)
        user_groups_raw = user.get("groups")
        user_groups: list[str] = (
            [str(g) for g in user_groups_raw if isinstance(g, str)]
            if isinstance(user_groups_raw, list)
            else []
        )
        impersonated = event.get("impersonatedUser") or {}
        if not isinstance(impersonated, dict):
            impersonated = {}
        impersonated_username = (
            impersonated.get("username")
            if isinstance(impersonated.get("username"), str)
            else None
        )

        # ---- sourceIPs ----
        source_ips_raw = event.get("sourceIPs")
        source_ips_redacted: list[str] = []
        if isinstance(source_ips_raw, list):
            for ip in source_ips_raw:
                normalized = _classify_source_ip(ip if isinstance(ip, str) else None)
                if normalized:
                    source_ips_redacted.append(normalized)

        user_agent_redacted = _sanitize_user_agent(
            event.get("userAgent") if isinstance(event.get("userAgent"), str) else None
        )

        # ---- responseStatus ----
        response_status = event.get("responseStatus") or {}
        if not isinstance(response_status, dict):
            response_status = {}
        status_code_raw = response_status.get("code")
        status_code: int | None = (
            int(status_code_raw)
            if isinstance(status_code_raw, (int, float)) and not isinstance(status_code_raw, bool)
            else None
        )

        # ---- annotations ----
        annotations = event.get("annotations") or {}
        if not isinstance(annotations, dict):
            annotations = {}
        auth_decision = annotations.get("authorization.k8s.io/decision")
        auth_decision = (
            str(auth_decision).strip()
            if isinstance(auth_decision, str) and auth_decision.strip()
            else None
        )

        # ---- requestObject features (NEVER store body) ----
        request_object = event.get("requestObject")
        pod_features = _extract_pod_security_features(request_object)
        rbac_subjects = _extract_rbac_subjects(request_object)

        common_evidence: dict[str, Any] = {
            "kubernetes_audit_id": audit_id,
            "level": level,
            "stage": stage,
            "verb": verb,
            "resource": resource,
            "namespace": namespace,
            "name_sanitized": sanitized_name,
            "api_group": api_group,
            "api_version": api_version,
            "subresource": subresource,
            "user_username": username,
            "user_groups": user_groups,
            "user_uid_redacted": user_uid,
            "impersonated_username": impersonated_username,
            "source_ips_redacted": source_ips_redacted,
            "user_agent_redacted": user_agent_redacted,
            "response_status_code": status_code,
            "annotations_authorization_decision": auth_decision,
            "request_uri_path": request_uri_path,
            "request_received_timestamp": request_received,
            "stage_timestamp": stage_timestamp,
            # Extracted features only — request/response BODIES never stored.
            "pod_privileged": pod_features["privileged"],
            "pod_host_network": pod_features["host_network"],
            "pod_host_pid": pod_features["host_pid"],
            "pod_container_images": pod_features["container_images"],
            "rbac_subjects": rbac_subjects,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, audit_id=audit_id
            ),
            "source_tool": "kubernetes_audit",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Anonymous identity — always FAIL (system:anonymous).
        # ----------------------------------------------------------------
        if isinstance(username, str) and username.startswith("system:anonymous"):
            signal = "anonymous_request"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Audit event {audit_id} verb={verb} resource={resource} "
                        f"performed by anonymous identity {username!r}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Status-code signals — 403 PASS (RBAC working) / 500 FAIL.
        # ----------------------------------------------------------------
        status_meta = (
            self._status_code_signals.get(str(status_code))
            if status_code is not None
            else None
        )

        # ----------------------------------------------------------------
        # 3. Primary classification: subresource > verb-signal > verb+resource.
        # exec/attach/portforward fire FAIL even via subresource form.
        # ----------------------------------------------------------------
        primary_meta: dict[str, Any] | None = None
        primary_origin: str = ""
        # Sub-resource (e.g. /pods/foo/exec).
        if subresource and subresource in self._subresource_signals:
            primary_meta = dict(self._subresource_signals[subresource])
            primary_origin = f"subresource={subresource}"
        # Verb form (some clusters surface ``exec``/``portforward`` as verbs).
        elif verb in self._verb_signals:
            primary_meta = dict(self._verb_signals[verb])
            primary_origin = f"verb={verb}"
        else:
            pattern = self._classify_verb_resource(verb, resource)
            if pattern is not None:
                primary_meta = dict(pattern)
                primary_origin = f"verb={verb} resource={resource}"

        if status_meta is not None:
            signal = str(status_meta["signal"])
            control_id = _control_for(
                signal, self._mappings, str(status_meta.get("control", "PR-02"))
            )
            result = str(status_meta.get("result", "FAIL"))
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Audit event {audit_id} verb={verb} resource={resource} "
                        f"responseStatus.code={status_code}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif primary_meta is not None:
            signal = str(primary_meta.get("signal", "unknown_event"))
            control_id = _control_for(
                signal, self._mappings, str(primary_meta.get("control", "PR-05"))
            )
            result = str(primary_meta.get("result", "FLAG"))
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Audit event {audit_id} {primary_origin} classified as "
                        f"{signal} ({result})"
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
                        f"Audit event {audit_id} verb={verb} resource={resource} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Pod-create overlays — privileged / un-pinned / untrusted-registry.
        # Privileged is a FAIL (container-escape risk). The other two FLAG.
        # ----------------------------------------------------------------
        if verb == "create" and resource == "pods":
            if (
                pod_features["privileged"]
                or pod_features["host_network"]
                or pod_features["host_pid"]
            ):
                signal = "privileged_pod"
                control_id = _control_for(signal, self._mappings, "PR-02")
                reasons: list[str] = []
                if pod_features["privileged"]:
                    reasons.append("privileged=true")
                if pod_features["host_network"]:
                    reasons.append("hostNetwork=true")
                if pod_features["host_pid"]:
                    reasons.append("hostPID=true")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Audit event {audit_id} pod-create with "
                            f"{', '.join(reasons)} — container-escape risk"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            for image in pod_features["container_images"]:
                tag = _extract_image_tag(image)
                if tag == "" or tag == "latest":
                    signal = "unpinned_image_tag"
                    control_id = _control_for(signal, self._mappings, "PR-05")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Audit event {audit_id} pod-create with un-pinned "
                                f"image tag {image!r} — un-reproducible deploy"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                                "image": image,
                                "image_tag": tag or "<missing>",
                            },
                        )
                    )
                registry = _extract_image_registry(image)
                if registry and registry.lower() not in self._image_registry_allowlist:
                    signal = "untrusted_registry"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FLAG",
                            detail=(
                                f"Audit event {audit_id} pod-create with image "
                                f"from non-allowlisted registry {registry!r}"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                                "image": image,
                                "image_registry": registry,
                            },
                        )
                    )

        # ----------------------------------------------------------------
        # 5. Production-namespace deployment/statefulset deletion → FAIL.
        # Note: namespace deletion itself is FAIL via primary classification
        # already; this layer covers in-namespace bulk-impact deletes.
        # ----------------------------------------------------------------
        if (
            verb == "delete"
            and resource in _PROD_DELETE_RESOURCES
            and _is_production_namespace(namespace, self._prod_namespace_patterns)
        ):
            signal = "production_workload_delete"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Audit event {audit_id} delete on {resource} in "
                        f"production namespace {namespace!r}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 6. RBAC-grant-to-system:authenticated overlay — over-broad RBAC.
        # ----------------------------------------------------------------
        if (
            verb == "create"
            and resource in {"rolebindings", "clusterrolebindings"}
            and any(
                s.get("kind") == "Group" and s.get("name") == "system:authenticated"
                for s in rbac_subjects
            )
        ):
            signal = "rbac_grant_to_authenticated"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Audit event {audit_id} {resource} grants to Group "
                        f"system:authenticated — over-broad RBAC"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 7. Impersonation — additive PR-01 FLAG (audit who impersonated whom).
        # ----------------------------------------------------------------
        if impersonated_username:
            signal = "impersonation"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Audit event {audit_id} user {username!r} impersonated "
                        f"{impersonated_username!r}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 8. Unrecognized human user on a production namespace → PR-01 FLAG.
        # Service accounts (system:* prefix) are NOT human users.
        # ----------------------------------------------------------------
        if (
            isinstance(username, str)
            and username
            and not username.startswith("system:")
            and self._known_users
            and username not in self._known_users
            and _is_production_namespace(namespace, self._prod_namespace_patterns)
        ):
            signal = "unrecognized_human_user"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Audit event {audit_id} unrecognized human user "
                        f"{username!r} acting on production namespace {namespace!r}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 9. Cross-namespace per-event marker (synthetic finding added in 2nd pass).
        # ----------------------------------------------------------------
        if isinstance(username, str) and username in cross_namespace_users:
            signal = "cross_namespace_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Audit event {audit_id} user {username!r} touched "
                        f"{len(cross_namespace_users[username])} namespaces > "
                        f"threshold {self.cross_namespace_threshold}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_namespace_namespaces": cross_namespace_users[username],
                        "cross_namespace_threshold": self.cross_namespace_threshold,
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
            f"Imported from Kubernetes apiserver audit: verb={verb} "
            f"resource={resource} "
            f"namespace={namespace or 'cluster-scoped'} "
            f"user={username or 'unknown'} "
            f"status={status_code if status_code is not None else 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"k8s-audit-{audit_id[:32]}",
            timestamp=stage_timestamp,
            agent_id=self.agent_id,
            source_type="kubernetes_audit_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=audit_id or None,
        )

    def _synthetic_cross_namespace_result(
        self,
        *,
        username: str,
        namespaces: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_namespace_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"k8s-cross-namespace-{username}"
        evidence: dict[str, Any] = {
            "kubernetes_audit_id": synthetic_id,
            "user_username": username,
            "cross_namespace_namespaces": namespaces,
            "cross_namespace_count": len(namespaces),
            "cross_namespace_threshold": self.cross_namespace_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                audit_id=synthetic_id,
            ),
            "source_tool": "kubernetes_audit",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Kubernetes audit synthetic finding: user {username!r} "
                f"touched {len(namespaces)} namespaces in this export "
                f"({', '.join(namespaces)}) — exceeds cross-namespace "
                f"threshold {self.cross_namespace_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="kubernetes_audit_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Kubernetes apiserver audit: synthetic "
                f"cross-namespace pattern user={username!r} "
                f"namespaces={len(namespaces)}>threshold="
                f"{self.cross_namespace_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_delete_burst_result(
        self,
        *,
        username: str,
        delete_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "delete_burst_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"k8s-delete-burst-{username}"
        evidence: dict[str, Any] = {
            "kubernetes_audit_id": synthetic_id,
            "user_username": username,
            "delete_count": delete_count,
            "delete_burst_threshold": self.delete_burst_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                audit_id=synthetic_id,
            ),
            "source_tool": "kubernetes_audit",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Kubernetes audit synthetic finding: user {username!r} "
                f"performed {delete_count} delete verbs in this export — "
                f"exceeds delete-burst threshold {self.delete_burst_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="kubernetes_audit_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Kubernetes apiserver audit: synthetic "
                f"delete-burst pattern user={username!r} "
                f"deletes={delete_count}>threshold="
                f"{self.delete_burst_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
