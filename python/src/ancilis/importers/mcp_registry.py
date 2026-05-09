"""MCP server registry catalog importer.

MCP (Model Context Protocol) server registries — including the upstream
``.well-known/mcp-registry`` endpoint and third-party catalogs such as
``smithery.ai`` — publish JSON catalogs describing the MCP servers an agent
may connect to. Discovery typically happens against one of these registries,
yet a connected agent has no native way to prove which servers were
registered, denied, or shadowed by a typosquat. This importer closes that
governance gap by converting a registry snapshot into Ancilis evidence.

For every registry entry we emit one :class:`EvaluationResult` carrying:

* a **trust-signal** :class:`ControlResult` (PR-01)
* a **scope-expansion** ``ControlResult`` (PR-02) when declared
  ``permissions_required`` contains write/exec/network keywords
* an **under-declared-permissions** ``ControlResult`` (PR-03) when a
  non-trivial server lists *no* permissions
* an **empty-tool-surface** ``ControlResult`` (PR-05) when ``tools`` is empty

After every entry has been parsed we additionally emit a single synthetic
``EvaluationResult`` describing any cross-entry **tool-name collisions**
(typosquatting / namespace-shadowing). Two servers that both expose a tool
named ``read_file`` are a strong signal that something is wrong, and the
importer surfaces the collision as PR-01 FLAG so reviewers can disambiguate.

The importer accepts both the upstream MCP shape (``servers[]`` with rich
fields) and the smithery shape (``data[]`` with ``qualifiedName``,
``displayName``, ``vendor``, etc.). Shape detection is heuristic and
tolerant: missing fields default to safe values and unknown shapes pass
through with best-effort key extraction.

The SDK does not import any MCP client package — this is a pure JSON
catalog reader.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# ---------------------------------------------------------------------------
# Mapping table resolution
# ---------------------------------------------------------------------------

_MAPPING_FILENAME = "mcp-registry-aksi-controls.json"


def _resolve_mapping_path() -> Path:
    """Walk up from this file to find ``shared/mappings/<filename>``.

    Mirrors the resolution strategy used by ``otel_genai`` so the importer
    keeps working from worktrees, editable installs, and site-packages
    layouts.
    """
    here = Path(__file__).resolve()
    for ancestor in [here.parent, *here.parents]:
        candidate = ancestor / "shared" / "mappings" / _MAPPING_FILENAME
        if candidate.is_file():
            return candidate
    return (
        here.parent.parent.parent.parent.parent.parent
        / "shared" / "mappings" / _MAPPING_FILENAME
    )


_MAPPING_PATH = _resolve_mapping_path()

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Default classification table — overridden by the mapping file's _metadata.
_DEFAULT_TRUST_TO_RESULT: dict[str, str] = {
    "verified": "PASS",
    "official": "PASS",
    "publisher_signed": "PASS",
    "community": "FLAG",
    "unverified": "FLAG",
    "untrusted": "FAIL",
    "missing": "FAIL",
}

_DEFAULT_SCOPE_KEYWORDS: tuple[str, ...] = (
    "write",
    "exec",
    "execute",
    "shell",
    "spawn",
    "network",
    "fetch",
    "send",
)

_DEFAULT_UNDER_DECLARED_THRESHOLD = 1
_DEFAULT_COLLISION_ACTION = "FLAG"

# Signal → control mapping defaults (used when the mapping file is missing).
_DEFAULT_SIGNAL_TO_CONTROL: dict[str, str] = {
    "trust_signal": "PR-01",
    "scope_expansion": "PR-02",
    "under_declared_permissions": "PR-03",
    "empty_tool_surface": "PR-05",
    "tool_name_collision": "PR-01",
}


def _load_mappings() -> tuple[dict[str, str], dict[str, Any]]:
    """Load the signal→control mapping plus the ``_metadata`` block."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_DEFAULT_SIGNAL_TO_CONTROL), {}
    if not isinstance(data, dict):
        return dict(_DEFAULT_SIGNAL_TO_CONTROL), {}
    raw = data.get("mappings", {})
    mappings: dict[str, str] = dict(_DEFAULT_SIGNAL_TO_CONTROL)
    if isinstance(raw, dict):
        for key, value in raw.items():
            mappings[str(key)] = str(value)
    meta = data.get("_metadata", {})
    if not isinstance(meta, dict):
        meta = {}
    return mappings, meta


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class McpRegistryImporter:
    """Parse an MCP server registry catalog and emit EvaluationResults.

    Parameters
    ----------
    agent_id:
        Identity recorded on every emitted ``EvaluationResult``.
    mode:
        ``"audit"`` (default) or ``"enforce"`` — recorded for downstream
        engine routing; the importer itself never blocks.
    aggregate:
        When ``True``, returns a single EvaluationResult containing the
        union of every entry's ControlResults. Default ``False`` (one
        EvaluationResult per server entry plus an optional collision
        synthetic result).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        aggregate: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.aggregate = aggregate
        self._mappings, meta = _load_mappings()

        trust_table = meta.get("trust_signal_to_result")
        self._trust_to_result: dict[str, str] = dict(_DEFAULT_TRUST_TO_RESULT)
        if isinstance(trust_table, dict):
            for k, v in trust_table.items():
                self._trust_to_result[str(k).lower()] = str(v).upper()

        keywords = meta.get("scope_expansion_permission_keywords")
        if isinstance(keywords, list) and keywords:
            self._scope_keywords: tuple[str, ...] = tuple(
                str(k).lower() for k in keywords
            )
        else:
            self._scope_keywords = _DEFAULT_SCOPE_KEYWORDS

        threshold = meta.get("under_declared_threshold_tool_count")
        try:
            self._under_declared_threshold = int(
                threshold if threshold is not None else _DEFAULT_UNDER_DECLARED_THRESHOLD
            )
        except (TypeError, ValueError):
            self._under_declared_threshold = _DEFAULT_UNDER_DECLARED_THRESHOLD

        action = str(meta.get("collision_action") or _DEFAULT_COLLISION_ACTION).upper()
        self._collision_action = action if action in ("FLAG", "FAIL") else _DEFAULT_COLLISION_ACTION

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a registry JSON document from disk."""
        content = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content).hexdigest()
        doc = json.loads(content.decode("utf-8"))
        return self._parse_doc(doc, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a registry JSON document from a string."""
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        doc = json.loads(content)
        return self._parse_doc(doc, file_sha256=digest)

    # -- Shape detection ----------------------------------------------------

    def _parse_doc(
        self,
        doc: Any,
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        entries, registry_shape, registry_version = _extract_entries(doc)

        source_provenance_base: dict[str, Any] = {
            "source_format": "mcp-registry",
            "source_tool_name": "mcp-registry",
            "source_tool_version": str(registry_version or ""),
            "registry_shape": registry_shape,
        }
        if file_sha256 is not None:
            source_provenance_base["original_file_sha256"] = file_sha256

        # Pre-pass: index tool-name occurrences to detect cross-entry
        # collisions / typosquats. We index *after* normalising entries so
        # both shapes feed the same collision detector.
        normalised: list[dict[str, Any]] = [
            _normalise_entry(e, registry_shape) for e in entries
        ]
        tool_owners: dict[str, list[str]] = defaultdict(list)
        for ne in normalised:
            for tname in ne["tool_names"]:
                tool_owners[tname].append(ne["server_id"])
        collisions = {
            tname: owners
            for tname, owners in tool_owners.items()
            if len(set(owners)) > 1
        }

        per_entry_results: list[EvaluationResult] = [
            self._entry_to_evaluation(
                ne,
                source_provenance_base=source_provenance_base,
                collisions=collisions,
            )
            for ne in normalised
        ]

        # Aggregate mode collapses every per-entry ControlResult into one
        # EvaluationResult so downstream evidence stores see a single record
        # for the whole catalog.
        if self.aggregate:
            aggregated = self._aggregate(
                per_entry_results,
                source_provenance_base=source_provenance_base,
                entry_count=len(normalised),
                collisions=collisions,
            )
            results: list[EvaluationResult] = [aggregated]
        else:
            results = list(per_entry_results)

        if collisions:
            results.append(
                self._collision_synthetic(
                    collisions=collisions,
                    source_provenance_base=source_provenance_base,
                    entry_count=len(normalised),
                )
            )
        return results

    # -- Per-entry evaluation ---------------------------------------------

    def _entry_to_evaluation(
        self,
        ne: dict[str, Any],
        *,
        source_provenance_base: dict[str, Any],
        collisions: dict[str, list[str]],
    ) -> EvaluationResult:
        server_id = ne["server_id"]
        provenance = dict(source_provenance_base)
        provenance["server_id"] = server_id

        common_evidence: dict[str, Any] = {
            "server_id": server_id,
            "server_name": ne["server_name"],
            "publisher": ne["publisher"],
            "version": ne["version"],
            "transports": ne["transports"],
            "auth_modes": ne["auth_modes"],
            "endpoints": ne["endpoints"],
            "permissions_required": ne["permissions_required"],
            "tool_names": ne["tool_names"],
            "resource_count": ne["resource_count"],
            "prompt_count": ne["prompt_count"],
            "homepage_url": ne["homepage_url"],
            "registry_shape": source_provenance_base["registry_shape"],
            "source_provenance": provenance,
            "source_tool": "mcp-registry",
        }

        control_results: list[ControlResult] = []

        # 1. Trust-signal — always emitted, drives the per-entry decision.
        control_results.append(self._trust_control(ne, common_evidence))

        # 2. Scope-expansion — additive when declared permissions look risky.
        scope_cr = self._scope_control(ne, common_evidence)
        if scope_cr is not None:
            control_results.append(scope_cr)

        # 3. Under-declared permissions — additive when permissions are empty
        #    but the server clearly does non-trivial work (>= threshold tools).
        under_cr = self._under_declared_control(ne, common_evidence)
        if under_cr is not None:
            control_results.append(under_cr)

        # 4. Empty tool surface — additive audit-trail concern.
        if not ne["tool_names"]:
            control_results.append(
                ControlResult(
                    control_id=self._mappings.get("empty_tool_surface", "PR-05"),
                    control_name=_CONTROL_NAMES.get(
                        self._mappings.get("empty_tool_surface", "PR-05"),
                        "PR-05",
                    ),
                    result="FLAG",
                    detail=(
                        f"Server '{server_id}' declares zero tools — audit trail "
                        f"cannot establish what the agent will actually invoke."
                    ),
                    evidence_data={**common_evidence, "signal": "empty_tool_surface"},
                )
            )

        # 5. Per-entry collision note. The synthetic catalog-level result
        #    summarises everything, but we also annotate the individual
        #    server so single-entry views surface the issue.
        entry_collisions = {
            tname: owners
            for tname, owners in collisions.items()
            if server_id in owners
        }
        if entry_collisions:
            control_results.append(
                ControlResult(
                    control_id=self._mappings.get("tool_name_collision", "PR-01"),
                    control_name=_CONTROL_NAMES.get(
                        self._mappings.get("tool_name_collision", "PR-01"),
                        "PR-01",
                    ),
                    result=self._collision_action,
                    detail=(
                        f"Server '{server_id}' shares tool name(s) with other "
                        f"registry entries: {sorted(entry_collisions.keys())}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "tool_name_collision",
                        "colliding_tools": {
                            tname: sorted(set(owners))
                            for tname, owners in entry_collisions.items()
                        },
                    },
                )
            )

        decision = _decision_from_results(control_results)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mcp-registry-{_safe_id_slug(server_id)}",
            timestamp=str(ne["registered_at"] or datetime.now(timezone.utc).isoformat()),
            agent_id=self.agent_id,
            source_type="mcp_registry_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=(
                f"Imported MCP registry entry '{server_id}' "
                f"(trust={ne['trust_signal']}, tools={len(ne['tool_names'])}, "
                f"permissions={len(ne['permissions_required'])})"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    # -- Individual control builders --------------------------------------

    def _trust_control(
        self,
        ne: dict[str, Any],
        common_evidence: dict[str, Any],
    ) -> ControlResult:
        raw_signal = ne["trust_signal"]
        signal_key = (raw_signal or "missing").lower()
        # Smithery vendors don't carry a trust_signal — treat verified=true
        # equivalents as PASS, otherwise default to "missing" → FAIL.
        result = self._trust_to_result.get(signal_key, "FAIL")
        control_id = self._mappings.get("trust_signal", "PR-01")
        if result == "PASS":
            detail = (
                f"Server '{ne['server_id']}' trust_signal='{raw_signal or signal_key}' — "
                f"provenance verified by registry."
            )
        elif result == "FLAG":
            detail = (
                f"Server '{ne['server_id']}' trust_signal='{raw_signal or signal_key}' — "
                f"provenance unclear; review before allow-listing."
            )
        else:  # FAIL
            detail = (
                f"Server '{ne['server_id']}' trust_signal='{raw_signal or 'missing'}' — "
                f"unverified provenance; block-by-default."
            )
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=result,
            detail=detail,
            evidence_data={
                **common_evidence,
                "signal": "trust_signal",
                "trust_signal": raw_signal or "missing",
            },
        )

    def _scope_control(
        self,
        ne: dict[str, Any],
        common_evidence: dict[str, Any],
    ) -> ControlResult | None:
        risky = sorted(
            {
                p
                for p in ne["permissions_required"]
                if any(kw in p.lower() for kw in self._scope_keywords)
            }
        )
        if not risky:
            return None
        control_id = self._mappings.get("scope_expansion", "PR-02")
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Server '{ne['server_id']}' requests scope-expanding "
                f"permissions: {risky}"
            ),
            evidence_data={
                **common_evidence,
                "signal": "scope_expansion",
                "risky_permissions": risky,
                "scope_keywords": list(self._scope_keywords),
            },
        )

    def _under_declared_control(
        self,
        ne: dict[str, Any],
        common_evidence: dict[str, Any],
    ) -> ControlResult | None:
        if ne["permissions_required"]:
            return None
        if len(ne["tool_names"]) < self._under_declared_threshold:
            return None
        control_id = self._mappings.get("under_declared_permissions", "PR-03")
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Server '{ne['server_id']}' declares {len(ne['tool_names'])} tool(s) "
                f"but no permissions_required — likely under-declared."
            ),
            evidence_data={
                **common_evidence,
                "signal": "under_declared_permissions",
                "tool_count": len(ne["tool_names"]),
                "under_declared_threshold": self._under_declared_threshold,
            },
        )

    # -- Collision synthetic result ---------------------------------------

    def _collision_synthetic(
        self,
        *,
        collisions: dict[str, list[str]],
        source_provenance_base: dict[str, Any],
        entry_count: int,
    ) -> EvaluationResult:
        provenance = dict(source_provenance_base)
        control_id = self._mappings.get("tool_name_collision", "PR-01")
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=self._collision_action,
            detail=(
                f"Detected {len(collisions)} tool-name collision(s) across "
                f"{entry_count} registry entries — possible typosquat / "
                f"namespace shadowing."
            ),
            evidence_data={
                "signal": "tool_name_collision",
                "collisions": {
                    tname: sorted(set(owners))
                    for tname, owners in collisions.items()
                },
                "entry_count": entry_count,
                "source_provenance": provenance,
                "source_tool": "mcp-registry",
            },
        )
        decision = "BLOCK" if cr.result == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mcp-registry-collision-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mcp_registry_import",
            mode=self.mode,
            control_results=[cr],
            decision=decision,
            decision_reason=(
                f"MCP registry tool-name collision check: {len(collisions)} "
                f"colliding name(s) across {entry_count} entries."
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    # -- Aggregate mode ---------------------------------------------------

    def _aggregate(
        self,
        per_entry: list[EvaluationResult],
        *,
        source_provenance_base: dict[str, Any],
        entry_count: int,
        collisions: dict[str, list[str]],
    ) -> EvaluationResult:
        merged: list[ControlResult] = []
        for ev in per_entry:
            merged.extend(ev.control_results)
        decision = _decision_from_results(merged) if merged else "ALLOW"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mcp-registry-catalog-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mcp_registry_import",
            mode=self.mode,
            control_results=merged,
            decision=decision,
            decision_reason=(
                f"Imported MCP registry catalog: {entry_count} server entr(ies), "
                f"{len(collisions)} tool-name collision(s)."
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )


# ---------------------------------------------------------------------------
# Shape extraction & normalisation
# ---------------------------------------------------------------------------


def _extract_entries(doc: Any) -> tuple[list[dict[str, Any]], str, str]:
    """Return (entries, registry_shape, registry_version) for any supported shape."""
    if isinstance(doc, list):
        return [e for e in doc if isinstance(e, dict)], "unknown-list", ""
    if not isinstance(doc, dict):
        return [], "unknown", ""
    version = str(doc.get("version") or doc.get("schemaVersion") or "")
    if isinstance(doc.get("servers"), list):
        return (
            [e for e in doc["servers"] if isinstance(e, dict)],
            "modelcontextprotocol",
            version,
        )
    if isinstance(doc.get("data"), list):
        # Smithery-style catalog: {"data": [...]}.
        return (
            [e for e in doc["data"] if isinstance(e, dict)],
            "smithery",
            version,
        )
    if isinstance(doc.get("entries"), list):
        return (
            [e for e in doc["entries"] if isinstance(e, dict)],
            "generic-entries",
            version,
        )
    # Bare single entry — wrap it.
    if "id" in doc or "qualifiedName" in doc:
        return [doc], "single-entry", version
    return [], "unknown", version


def _normalise_entry(entry: dict[str, Any], shape: str) -> dict[str, Any]:
    """Project a registry entry of either shape into a stable dict."""
    if shape == "smithery":
        return _normalise_smithery(entry)
    return _normalise_modelcontextprotocol(entry)


def _normalise_modelcontextprotocol(entry: dict[str, Any]) -> dict[str, Any]:
    server_id = str(
        entry.get("id")
        or entry.get("name")
        or f"unknown-{uuid.uuid4().hex[:8]}"
    )
    server_name = str(entry.get("name") or server_id)
    publisher = str(entry.get("publisher") or entry.get("vendor") or "")
    version = str(entry.get("version") or "")
    transports = _coerce_transports(entry.get("transport"))
    endpoints = _coerce_endpoints(entry.get("endpoints"))
    # Endpoints may carry their own transport/auth; merge in for completeness.
    for ep in endpoints:
        if isinstance(ep, dict):
            ep_transport = ep.get("transport")
            if isinstance(ep_transport, str) and ep_transport not in transports:
                transports.append(ep_transport)
    auth_modes = sorted(
        {
            str(ep.get("auth"))
            for ep in endpoints
            if isinstance(ep, dict) and ep.get("auth")
        }
    )
    permissions_required = _coerce_str_list(entry.get("permissions_required"))
    tools_raw = entry.get("tools") or []
    tool_names = _extract_tool_names(tools_raw)
    resources = entry.get("resources") or []
    prompts = entry.get("prompts") or []
    trust_signal = entry.get("trust_signal")
    if trust_signal is None:
        trust_signal = entry.get("trust")
    registered_at = entry.get("registered_at") or entry.get("registeredAt") or ""
    homepage_url = str(entry.get("homepage_url") or entry.get("homepageUrl") or "")
    return {
        "server_id": server_id,
        "server_name": server_name,
        "publisher": publisher,
        "version": version,
        "transports": transports,
        "auth_modes": auth_modes,
        "endpoints": endpoints,
        "permissions_required": permissions_required,
        "tool_names": tool_names,
        "resource_count": len(resources) if isinstance(resources, list) else 0,
        "prompt_count": len(prompts) if isinstance(prompts, list) else 0,
        "trust_signal": str(trust_signal) if trust_signal is not None else "",
        "registered_at": str(registered_at),
        "homepage_url": homepage_url,
    }


def _normalise_smithery(entry: dict[str, Any]) -> dict[str, Any]:
    server_id = str(
        entry.get("qualifiedName")
        or entry.get("id")
        or entry.get("name")
        or f"unknown-{uuid.uuid4().hex[:8]}"
    )
    server_name = str(entry.get("displayName") or entry.get("name") or server_id)
    publisher = str(entry.get("vendor") or entry.get("publisher") or "")
    version = str(entry.get("version") or "")
    # Smithery's per-entry shape doesn't expose a transport array; presence
    # of remoteSupported implies streamable-http reachability.
    transports: list[str] = []
    if entry.get("remoteSupported"):
        transports.append("streamable-http")
    if entry.get("stdio") or entry.get("localSupported"):
        transports.append("stdio")
    auth_modes: list[str] = []
    auth = entry.get("auth") or entry.get("authentication")
    if isinstance(auth, str):
        auth_modes.append(auth)
    elif isinstance(auth, list):
        auth_modes.extend(str(x) for x in auth if x)
    endpoints = _coerce_endpoints(entry.get("endpoints"))
    permissions_required = _coerce_str_list(
        entry.get("permissions_required") or entry.get("permissions")
    )
    tools_raw = entry.get("tools") or []
    tool_names = _extract_tool_names(tools_raw)
    resources = entry.get("resources") or []
    prompts = entry.get("prompts") or []
    # Smithery uses a boolean ``verified`` rather than a string trust_signal.
    if entry.get("verified") is True:
        trust_signal = "verified"
    elif entry.get("verified") is False:
        trust_signal = "community"
    else:
        trust_signal = str(entry.get("trust_signal") or "")
    homepage_url = str(entry.get("homepageUrl") or entry.get("homepage_url") or "")
    registered_at = entry.get("createdAt") or entry.get("registered_at") or ""
    return {
        "server_id": server_id,
        "server_name": server_name,
        "publisher": publisher,
        "version": version,
        "transports": sorted(set(transports)),
        "auth_modes": sorted(set(auth_modes)),
        "endpoints": endpoints,
        "permissions_required": permissions_required,
        "tool_names": tool_names,
        "resource_count": len(resources) if isinstance(resources, list) else 0,
        "prompt_count": len(prompts) if isinstance(prompts, list) else 0,
        "trust_signal": trust_signal,
        "registered_at": str(registered_at),
        "homepage_url": homepage_url,
    }


# ---------------------------------------------------------------------------
# Field coercion helpers
# ---------------------------------------------------------------------------


def _coerce_transports(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return []


def _coerce_endpoints(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for ep in value:
        if isinstance(ep, dict):
            out.append(ep)
        elif isinstance(ep, str):
            out.append({"url": ep})
    return out


def _coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return []


def _extract_tool_names(tools: Any) -> list[str]:
    """Return a stable list of declared tool names from a registry entry."""
    if not isinstance(tools, list):
        return []
    names: list[str] = []
    for t in tools:
        if isinstance(t, str):
            names.append(t)
        elif isinstance(t, dict):
            name = t.get("name") or t.get("id")
            if name:
                names.append(str(name))
    return names


def _safe_id_slug(server_id: str) -> str:
    """Slugify an identifier for use inside an ``action_id``."""
    keep = []
    for ch in server_id:
        if ch.isalnum() or ch in ("-", "_", "."):
            keep.append(ch)
        else:
            keep.append("_")
    slug = "".join(keep)[:48]
    return slug or uuid.uuid4().hex[:8]


_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _decision_from_results(results: Iterable[ControlResult]) -> str:
    """Roll up a list of ControlResults into ALLOW / FLAG / BLOCK."""
    worst = "PASS"
    for cr in results:
        if _RESULT_SEVERITY.get(cr.result, 0) > _RESULT_SEVERITY.get(worst, 0):
            worst = cr.result
    return {"PASS": "ALLOW", "FLAG": "FLAG", "FAIL": "BLOCK"}.get(worst, "ALLOW")
