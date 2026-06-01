"""n8n workflow-execution importer — maps AI-agent automation workflows to AKSI controls.

n8n (https://n8n.io) is the leading open-source workflow automation platform
with first-class AI-agent support: agents are built as n8n workflows that chain
LLMs (LangChain Agent, OpenAI, Anthropic, Google, Mistral, Ollama, ...), HTTP
requests, Code nodes (arbitrary JS), and database writes (postgres / mysql /
s3 / supabase / mongodb). Distinct from Composio (curated tool-calls) — n8n is
self-hostable and is widely deployed in regulated industries that cannot send
data through SaaS, which makes runtime evidence from these workflows
particularly load-bearing.

This importer ingests the ``/rest/executions`` audit payload in four shapes:

  1. ``{"data": [...]}``       — primary executions envelope
  2. ``{"executions": [...]}`` — alternate envelope
  3. JSONL                      — one execution per line
  4. Single execution object    — naked dict

Signal mapping (see shared/mappings/n8n-aksi-controls.json):

  * ``status=success``                                          → PR-05 PASS  (audit trail)
  * ``status=failed``                                           → DE-01 FAIL  (first errored node captured)
  * ``status=canceled``                                         → PR-05 PASS  (audit trail of cancellation)
  * ``status=waiting``                                          → PR-02 FLAG  (long-pending workflow)
  * ``mode=webhook`` & ``trigger_type=webhook``                 → PR-01 FLAG  (external trigger; signature
                                                                                verification is engine job)
  * ``mode=manual``                                             → PR-05 PASS  (operator-attested run)
  * Code-node usage (``n8n-nodes-base.code``, ``.function``,
    ``.functionItem``)                                          → PR-03 FLAG  (arbitrary JS surface)
  * HTTP-Request node to non-allowlisted host                   → PR-04 FLAG  (external data egress)
  * ``credentials_referenced`` count > threshold (default 5)    → PR-02 FLAG  (credential sprawl)
  * ``is_retry=true`` & ``errors_count`` > 0 in original        → PR-05 PASS, retry pattern in evidence_data
  * Database/storage write node executed with ``errored=false`` → PR-04 FLAG  (data write surface)
  * LangChain agent node (``@n8n/n8n-nodes-langchain.agent``)   → PR-01 PASS, surface model + tool count
  * AI Chat / OpenAI / Anthropic / Google / Mistral / Ollama
    LLM nodes executed                                          → PR-01 PASS
  * ``external_calls_count`` > threshold (default 20)           → PR-04 FLAG  (high external surface)

Sanitization (non-negotiable):

  * Node ``input``/``output`` VALUES are NEVER stored. Only top-level
    ``input_keys`` / ``output_keys`` arrays plus item counts are surfaced —
    raw payloads commonly carry PII (chat messages, customer records, ticket
    bodies, prompts, completions).
  * Raw ``error_message`` text is NEVER stored. Only ``error_message_length``
    and ``error_message_sha256`` are kept — enough to correlate identical
    errors across executions without leaking the message itself.
  * Credential VALUES are NEVER stored. Credential NAMES/IDs are safe to keep
    because in n8n they are already aliases that resolve to the encrypted
    secret out-of-band.

The original file is hashed (sha256) for source_provenance.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/n8n-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/n8n.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "n8n-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_CREDENTIALS_THRESHOLD = 5
_DEFAULT_EXTERNAL_CALLS_THRESHOLD = 20

_DEFAULT_DB_WRITE_NODES: tuple[str, ...] = (
    "n8n-nodes-base.postgres",
    "n8n-nodes-base.mysql",
    "n8n-nodes-base.s3",
    "n8n-nodes-base.awsS3",
    "n8n-nodes-base.supabase",
    "n8n-nodes-base.mongoDb",
    "n8n-nodes-base.mongodb",
)
_DEFAULT_LLM_NODES: tuple[str, ...] = (
    "@n8n/n8n-nodes-langchain.openAi",
    "@n8n/n8n-nodes-langchain.lmChatOpenAi",
    "@n8n/n8n-nodes-langchain.lmChatAnthropic",
    "@n8n/n8n-nodes-langchain.lmChatGoogle",
    "@n8n/n8n-nodes-langchain.lmChatMistralCloud",
    "@n8n/n8n-nodes-langchain.lmChatOllama",
    "@n8n/n8n-nodes-langchain.chainLlm",
    "n8n-nodes-base.openAi",
    "n8n-nodes-base.anthropic",
)
_DEFAULT_AGENT_NODES: tuple[str, ...] = (
    "@n8n/n8n-nodes-langchain.agent",
)
_DEFAULT_CODE_NODES: tuple[str, ...] = (
    "n8n-nodes-base.code",
    "n8n-nodes-base.function",
    "n8n-nodes-base.functionItem",
)
_DEFAULT_HTTP_NODES: tuple[str, ...] = (
    "n8n-nodes-base.httpRequest",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the n8n-aksi-controls.json mapping; tolerate missing file."""
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


def _node_type_matches(node_type: str, patterns: Iterable[str]) -> bool:
    """Return True if ``node_type`` matches any glob pattern (case-sensitive)."""
    return any(fnmatch.fnmatchcase(node_type, pattern) for pattern in patterns)


def _hostname_of(value: str) -> str:
    """Extract a hostname from a URL, host:port string, or bare host."""
    if not value:
        return ""
    candidate = value.strip()
    if "://" not in candidate:
        # Bare host or host:port — wrap so urlparse parses uniformly.
        candidate = "//" + candidate
    parsed = urlparse(candidate)
    host = parsed.hostname or ""
    return host.lower()


def _host_allowlisted(host: str, allowlist: Iterable[str]) -> bool:
    if not host:
        return True  # No host claim → not classifiable as external.
    for entry in allowlist:
        entry = (entry or "").strip().lower()
        if not entry:
            continue
        if fnmatch.fnmatchcase(host, entry):
            return True
    return False


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class N8nImporter:
    """Parse an n8n workflow-execution export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        credentials_threshold: int | None = None,
        external_calls_threshold: int | None = None,
        http_allowlist: Iterable[str] | None = None,
        db_write_nodes: Iterable[str] | None = None,
        llm_nodes: Iterable[str] | None = None,
        agent_nodes: Iterable[str] | None = None,
        code_nodes: Iterable[str] | None = None,
        http_nodes: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # Threshold precedence: explicit arg > mapping metadata > default.
        if credentials_threshold is not None:
            self.credentials_threshold = int(credentials_threshold)
        else:
            self.credentials_threshold = int(
                meta.get("credentials_referenced_threshold", _DEFAULT_CREDENTIALS_THRESHOLD)
            )
        if external_calls_threshold is not None:
            self.external_calls_threshold = int(external_calls_threshold)
        else:
            self.external_calls_threshold = int(
                meta.get("external_calls_threshold", _DEFAULT_EXTERNAL_CALLS_THRESHOLD)
            )

        # Node-type pattern lists. Precedence: explicit arg > metadata > default.
        self.db_write_nodes = self._resolve_pattern_list(
            db_write_nodes, meta.get("db_write_nodes"), _DEFAULT_DB_WRITE_NODES
        )
        self.llm_nodes = self._resolve_pattern_list(
            llm_nodes, meta.get("llm_nodes"), _DEFAULT_LLM_NODES
        )
        self.agent_nodes = self._resolve_pattern_list(
            agent_nodes, meta.get("agent_nodes"), _DEFAULT_AGENT_NODES
        )
        self.code_nodes = self._resolve_pattern_list(
            code_nodes, meta.get("code_nodes"), _DEFAULT_CODE_NODES
        )
        self.http_nodes = self._resolve_pattern_list(
            http_nodes, meta.get("http_nodes"), _DEFAULT_HTTP_NODES
        )

        # HTTP allowlist (empty default → every external host flags).
        if http_allowlist is not None:
            self.http_allowlist = tuple(str(p) for p in http_allowlist)
        else:
            meta_allow = meta.get("http_allowlist")
            if isinstance(meta_allow, list):
                self.http_allowlist = tuple(str(p) for p in meta_allow)
            else:
                self.http_allowlist = ()

    @staticmethod
    def _resolve_pattern_list(
        explicit: Iterable[str] | None,
        meta_value: Any,
        default: tuple[str, ...],
    ) -> tuple[str, ...]:
        if explicit is not None:
            return tuple(str(p) for p in explicit)
        if isinstance(meta_value, list) and meta_value:
            return tuple(str(p) for p in meta_value)
        return default

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an n8n export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        executions = self._executions_from_text(text)
        return [
            self._parse_execution(e, file_sha256=file_sha256)
            for e in executions
        ]

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse n8n export content from a JSON or JSONL string."""
        executions = self._executions_from_text(content)
        return [
            self._parse_execution(e, file_sha256=None)
            for e in executions
        ]

    # -- Internals ----------------------------------------------------------

    def _executions_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"data": [...]}`` / ``{"executions": [...]}`` / JSONL / single object."""
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
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                if "executions" in doc and isinstance(doc["executions"], list):
                    return [e for e in doc["executions"] if isinstance(e, dict)]
                # Single execution object.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        execution_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "n8n",
            "source_tool_name": "n8n",
            "source_tool_version": "",
        }
        if execution_id is not None:
            provenance["execution_id"] = execution_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _sanitize_node(self, node: dict[str, Any]) -> dict[str, Any]:
        """Strip raw payloads / error text from a node-execution record.

        Top-level input/output KEYS are kept (structural metadata). VALUES
        and error_message text are dropped — only length + sha256 of the
        error message is preserved so identical errors can be correlated
        without leaking content.
        """
        node_type = str(node.get("node_type") or "")
        node_name = str(node.get("node_name") or "")
        try:
            duration_ms = float(node.get("duration_ms") or 0.0)
        except (TypeError, ValueError):
            duration_ms = 0.0
        try:
            items_in = int(node.get("items_in") or 0)
        except (TypeError, ValueError):
            items_in = 0
        try:
            items_out = int(node.get("items_out") or 0)
        except (TypeError, ValueError):
            items_out = 0
        input_keys_raw = node.get("input_keys") or []
        input_keys = (
            [str(k) for k in input_keys_raw]
            if isinstance(input_keys_raw, list)
            else []
        )
        output_keys_raw = node.get("output_keys") or []
        output_keys = (
            [str(k) for k in output_keys_raw]
            if isinstance(output_keys_raw, list)
            else []
        )
        creds_raw = node.get("credentials_used") or []
        credentials_used = (
            [str(c) for c in creds_raw]
            if isinstance(creds_raw, list)
            else []
        )
        errored = bool(node.get("errored", False))
        error_message = node.get("error_message")
        if isinstance(error_message, str) and error_message:
            error_meta: dict[str, Any] = {
                "error_message_length": len(error_message),
                "error_message_sha256": hashlib.sha256(
                    error_message.encode("utf-8")
                ).hexdigest(),
            }
        else:
            error_meta = {
                "error_message_length": 0,
                "error_message_sha256": None,
            }

        return {
            "node_name": node_name,
            "node_type": node_type,
            "executed_at": str(node.get("executed_at") or ""),
            "duration_ms": duration_ms,
            "input_keys": input_keys,
            "output_keys": output_keys,
            "items_in": items_in,
            "items_out": items_out,
            "errored": errored,
            "credentials_used": credentials_used,
            **error_meta,
        }

    def _parse_execution(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        execution_id = str(entry.get("id") or uuid.uuid4())
        workflow_id = str(entry.get("workflow_id") or "")
        workflow_name = str(entry.get("workflow_name") or "unknown")
        status = str(entry.get("status") or "").strip().lower()
        exec_mode = str(entry.get("mode") or "").strip().lower()
        trigger_type_raw = entry.get("trigger_type")
        trigger_type = (
            str(trigger_type_raw).strip().lower()
            if isinstance(trigger_type_raw, str) and trigger_type_raw.strip()
            else None
        )
        try:
            duration_ms = float(entry.get("duration_ms") or 0.0)
        except (TypeError, ValueError):
            duration_ms = 0.0
        try:
            errors_count = int(entry.get("errors_count") or 0)
        except (TypeError, ValueError):
            errors_count = 0
        try:
            external_calls_count = int(entry.get("external_calls_count") or 0)
        except (TypeError, ValueError):
            external_calls_count = 0
        is_retry = bool(entry.get("is_retry", False))
        execution_url_host = str(entry.get("execution_url_host") or "")
        user_id = entry.get("user_id")
        started_at = (
            entry.get("started_at")
            or datetime.now(timezone.utc).isoformat()
        )
        finished_at = entry.get("finished_at")

        creds_raw = entry.get("credentials_referenced") or []
        credentials_referenced = (
            [str(c) for c in creds_raw]
            if isinstance(creds_raw, list)
            else []
        )

        node_executions_raw = entry.get("node_executions") or []
        if not isinstance(node_executions_raw, list):
            node_executions_raw = []
        sanitized_nodes = [
            self._sanitize_node(n)
            for n in node_executions_raw
            if isinstance(n, dict)
        ]

        # First errored node (used for status=failed detail).
        first_errored_node: dict[str, Any] | None = next(
            (n for n in sanitized_nodes if n["errored"]),
            None,
        )

        # Node-type fingerprints.
        code_node_hits = [
            n for n in sanitized_nodes
            if _node_type_matches(n["node_type"], self.code_nodes)
        ]
        http_node_hits = [
            n for n in sanitized_nodes
            if _node_type_matches(n["node_type"], self.http_nodes)
        ]
        db_write_hits = [
            n for n in sanitized_nodes
            if _node_type_matches(n["node_type"], self.db_write_nodes)
            and not n["errored"]
        ]
        agent_node_hits = [
            n for n in sanitized_nodes
            if _node_type_matches(n["node_type"], self.agent_nodes)
            and not n["errored"]
        ]
        llm_node_hits = [
            n for n in sanitized_nodes
            if _node_type_matches(n["node_type"], self.llm_nodes)
            and not n["errored"]
        ]
        primary_llm_node = (
            llm_node_hits[0]["node_type"]
            if llm_node_hits
            else (agent_node_hits[0]["node_type"] if agent_node_hits else None)
        )

        # External HTTP host detection — pull host from common fields.
        external_http_hosts: list[str] = []
        for n in http_node_hits:
            if n["errored"]:
                continue
            # n8n exposes external host info typically via a top-level
            # input key like "url" or via execution metadata. We do NOT
            # look at values — instead we look at original (non-sanitized)
            # to read just the URL/host structural field, mirroring how
            # other importers handle structural endpoint detection.
            original = next(
                (
                    raw for raw in node_executions_raw
                    if isinstance(raw, dict)
                    and str(raw.get("node_name") or "") == n["node_name"]
                ),
                {},
            )
            host_candidates: list[str] = []
            for key in ("url", "host", "request_host", "target_host"):
                value = original.get(key)
                if isinstance(value, str) and value:
                    host_candidates.append(value)
            for value in host_candidates:
                host = _hostname_of(value)
                if host and not _host_allowlisted(host, self.http_allowlist):
                    external_http_hosts.append(host)
        # De-duplicate, preserve order.
        seen: set[str] = set()
        external_http_hosts_unique: list[str] = []
        for h in external_http_hosts:
            if h not in seen:
                seen.add(h)
                external_http_hosts_unique.append(h)

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            execution_id=execution_id,
        )

        common_evidence: dict[str, Any] = {
            "n8n_execution_id": execution_id,
            "workflow_id": workflow_id,
            "workflow_name": workflow_name,
            "mode": exec_mode,
            "trigger_type": trigger_type,
            "status": status,
            "duration_ms": duration_ms,
            "errors_count": errors_count,
            "node_count": len(sanitized_nodes),
            "credentials_referenced": credentials_referenced,
            "external_calls_count": external_calls_count,
            "primary_llm_node": primary_llm_node,
            "execution_url_host": execution_url_host,
            "is_retry": is_retry,
            "user_id": str(user_id) if user_id is not None else None,
            "started_at": str(started_at),
            "finished_at": str(finished_at) if finished_at is not None else None,
            "node_executions": sanitized_nodes,
            "source_provenance": source_provenance,
            "source_tool": "n8n",
        }

        control_results: list[ControlResult] = []

        # 1. Status — primary signal.
        if status == "failed":
            signal = "status_failed"
            control_id = _control_for(signal, self._mappings, "DE-01")
            errored_summary = (
                f"node={first_errored_node['node_name']!r} "
                f"type={first_errored_node['node_type']!r}"
                if first_errored_node
                else "no errored node captured"
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"failed (errors_count={errors_count}, {errored_summary})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "first_errored_node": first_errored_node,
                    },
                )
            )
        elif status == "success":
            signal = "status_success"
            control_id = _control_for(signal, self._mappings, "PR-05")
            extra: dict[str, Any] = {"signal": signal}
            if is_retry and errors_count > 0:
                extra["retry_after_error"] = True
                extra["retry_errors_count"] = errors_count
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"succeeded (mode={exec_mode!r}, nodes={len(sanitized_nodes)}, "
                        f"duration_ms={duration_ms})"
                    ),
                    evidence_data={**common_evidence, **extra},
                )
            )
        elif status == "canceled":
            signal = "status_canceled"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"was canceled — audit trail of cancellation recorded"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif status == "waiting":
            signal = "status_waiting"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"is waiting (long-pending workflow — review for stuck state)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif status == "running":
            # Still in flight — surface as informational FLAG so it does not silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"is still running at export time"
                    ),
                    evidence_data={**common_evidence, "signal": "status_running"},
                )
            )
        else:
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"has unrecognized status={entry.get('status')!r}"
                    ),
                    evidence_data={**common_evidence, "signal": "status_unknown"},
                )
            )

        # 2. Trigger mode — webhook FLAG, manual PASS.
        if exec_mode == "webhook" and trigger_type == "webhook":
            signal = "trigger_webhook"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"was triggered by an external webhook — verify webhook "
                        f"signature provenance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif exec_mode == "manual":
            signal = "mode_manual"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"was manually triggered (operator-attested run)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 3. Code node — PR-03 FLAG (arbitrary JS surface).
        if code_node_hits:
            signal = "code_node_used"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"executed {len(code_node_hits)} code node(s) — arbitrary "
                        f"JavaScript execution surface"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "code_nodes_used": [n["node_name"] for n in code_node_hits],
                        "code_node_types": [n["node_type"] for n in code_node_hits],
                    },
                )
            )

        # 4. HTTP request to non-allowlisted external host — PR-04 FLAG.
        if external_http_hosts_unique:
            signal = "http_external_host"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"made HTTP request(s) to non-allowlisted host(s): "
                        f"{', '.join(external_http_hosts_unique)} (external data egress)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "external_http_hosts": external_http_hosts_unique,
                        "http_allowlist": list(self.http_allowlist),
                    },
                )
            )

        # 5. Credential sprawl — PR-02 FLAG.
        if len(credentials_referenced) > self.credentials_threshold:
            signal = "credential_sprawl"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"references {len(credentials_referenced)} credential(s) "
                        f"(> threshold {self.credentials_threshold}) — credential sprawl"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "credentials_threshold": self.credentials_threshold,
                    },
                )
            )

        # 6. DB write nodes — PR-04 FLAG (data write surface for audit).
        if db_write_hits:
            signal = "db_write_node"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"executed {len(db_write_hits)} database/storage write "
                        f"node(s) (data write surface for audit)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "db_write_nodes_used": [n["node_name"] for n in db_write_hits],
                        "db_write_node_types": [n["node_type"] for n in db_write_hits],
                    },
                )
            )

        # 7. LangChain Agent node — PR-01 PASS (surface model + tool count).
        if agent_node_hits:
            signal = "agent_node_used"
            control_id = _control_for(signal, self._mappings, "PR-01")
            tool_count = sum(
                len(n["input_keys"]) + len(n["output_keys"])
                for n in agent_node_hits
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"executed {len(agent_node_hits)} LangChain agent node(s) "
                        f"(primary_llm_node={primary_llm_node!r})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "agent_nodes_used": [n["node_name"] for n in agent_node_hits],
                        "agent_io_key_count": tool_count,
                    },
                )
            )

        # 8. LLM nodes (non-agent) — PR-01 PASS.
        if llm_node_hits:
            signal = "llm_node_used"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"executed {len(llm_node_hits)} LLM node(s) "
                        f"(types: {', '.join(sorted({n['node_type'] for n in llm_node_hits}))})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "llm_nodes_used": [n["node_name"] for n in llm_node_hits],
                        "llm_node_types": sorted(
                            {n["node_type"] for n in llm_node_hits}
                        ),
                    },
                )
            )

        # 9. High external-call surface — PR-04 FLAG.
        if external_calls_count > self.external_calls_threshold:
            signal = "external_calls_high"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"n8n execution {execution_id} workflow {workflow_name!r} "
                        f"made {external_calls_count} external call(s) "
                        f"(> threshold {self.external_calls_threshold}) — high "
                        f"external surface"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "external_calls_threshold": self.external_calls_threshold,
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
            f"Imported from n8n: workflow={workflow_name!r} "
            f"status={status or 'unknown'} mode={exec_mode or 'unknown'} "
            f"trigger_type={trigger_type or 'none'} "
            f"nodes={len(sanitized_nodes)} errors={errors_count} "
            f"credentials={len(credentials_referenced)} "
            f"external_calls={external_calls_count}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"n8n-{execution_id[:32]}",
            timestamp=str(started_at),
            agent_id=self.agent_id,
            source_type="n8n_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=workflow_id or None,
        )
