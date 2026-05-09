"""Portkey LLM gateway log importer — converts Portkey request logs to AKSI EvaluationResults.

Portkey (https://portkey.ai) is a popular LLM gateway alternative to LiteLLM /
OpenRouter, with first-class support for caching (simple + semantic), retries,
provider fallbacks, load balancing, and pre/post guardrails. Each upstream
call produces one entry in the ``GET /v1/logs`` export, regardless of which
underlying provider was selected (OpenAI, Anthropic, Bedrock, Vertex, Azure,
Groq, Google, ...).

This importer accepts three on-disk shapes:

  1. Logs envelope:                    ``{"data": [ {...}, ... ]}``
  2. JSON array:                        ``[ {...}, {...} ]``
  3. JSONL stream:                      one JSON object per line
  4. Single record:                     ``{...}`` — wrapped automatically

Signal mapping (see shared/mappings/portkey-aksi-controls.json):

  * status 2xx + no failed guardrail               → PR-01 PASS  (clean run)
  * status 4xx                                     → PR-02 FLAG  (scope/abuse)
  * status 5xx                                     → DE-01 FAIL  (provider failure)
  * guardrails.before contains failed verdict      → PR-03 FAIL  (input validation BLOCK)
  * guardrails.after contains failed verdict       → DE-01 FAIL  (output safety)
  * cache mode == "semantic" + cache_status hit    → PR-05 PASS  (audit trail of cache use)
  * response.fallback_used == true                 → PR-01 FLAG  (provenance verification)
  * response.retry_count > threshold (default 2)   → PR-02 FLAG  (capacity / abuse)
  * response.cost > threshold (default $1)         → PR-04 FLAG  (exposure)
  * user_feedback.value == -1                      → PR-05 FLAG  (negative feedback)
  * loadbalance with > 1 target                    → PR-01 FLAG  (multi-target routing)

Sanitization: Portkey already strips request/response bodies into ``body_keys``
and token counts at export time, but we defensively drop any raw ``body``
fields that some self-hosted exports include and strip query strings off all
``url`` values via ``urlsplit/urlunsplit``. Virtual key aliases (``vk-...``)
are recorded as-is — they are gateway-managed handles, not raw upstream
credentials.
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


# Path to the shared mapping table.
# This file lives at <repo>/python/src/ancilis/importers/portkey.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "portkey-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_COST_THRESHOLD_USD = 1.0
_DEFAULT_RETRY_THRESHOLD = 2

# Default control ids if mapping file is missing or stripped.
_DEFAULT_STATUS_2XX_CONTROL = "PR-01"
_DEFAULT_STATUS_4XX_CONTROL = "PR-02"
_DEFAULT_STATUS_5XX_CONTROL = "DE-01"
_DEFAULT_BEFORE_GUARDRAIL_CONTROL = "PR-03"
_DEFAULT_AFTER_GUARDRAIL_CONTROL = "DE-01"
_DEFAULT_SEMANTIC_CACHE_CONTROL = "PR-05"
_DEFAULT_FALLBACK_CONTROL = "PR-01"
_DEFAULT_RETRY_CONTROL = "PR-02"
_DEFAULT_COST_CONTROL = "PR-04"
_DEFAULT_NEG_FEEDBACK_CONTROL = "PR-05"
_DEFAULT_LOADBALANCE_CONTROL = "PR-01"

# cache_status header values that count as a hit.
_CACHE_HIT_VALUES: tuple[str, ...] = ("HIT", "SEMANTIC_HIT")


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------

def _load_mapping_table() -> dict[str, Any]:
    """Load the portkey-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------

def _coerce_int(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coerce_float(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# URL / sanitization helpers
# ---------------------------------------------------------------------------

def _strip_query(url: Any) -> str:
    """Strip query string + fragment from a URL via urlsplit/urlunsplit."""
    if not isinstance(url, str) or not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _scrub_metadata(metadata: Any) -> dict[str, Any]:
    """Return a shallow copy of metadata, dropping anything that smells like raw bodies."""
    if not isinstance(metadata, dict):
        return {}
    forbidden = {"body", "request_body", "response_body", "messages", "prompt", "completion"}
    return {
        str(k): v for k, v in metadata.items()
        if str(k).lower() not in forbidden
    }


# ---------------------------------------------------------------------------
# Guardrail helpers
# ---------------------------------------------------------------------------

def _failed_guardrails(checks: Any) -> list[dict[str, Any]]:
    """Return a list of failed guardrail descriptors from a before/after array."""
    if not isinstance(checks, list):
        return []
    failed: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        verdict = str(check.get("verdict") or "").lower()
        if verdict == "failed":
            failed.append({
                "id": str(check.get("id") or ""),
                "verdict": verdict,
            })
    return failed


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
# Importer
# ---------------------------------------------------------------------------

class PortkeyImporter:
    """Parse a Portkey ``/v1/logs`` export and convert to EvaluationResults."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cost_threshold_usd: float | None = None,
        retry_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        self.cost_threshold_usd = (
            float(cost_threshold_usd)
            if cost_threshold_usd is not None
            else float(meta.get("default_cost_threshold_usd", _DEFAULT_COST_THRESHOLD_USD))
        )
        self.retry_threshold = (
            int(retry_threshold)
            if retry_threshold is not None
            else int(meta.get("default_retry_threshold", _DEFAULT_RETRY_THRESHOLD))
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Portkey export file (JSON, JSONL, or logs envelope) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return [self._parse_entry(e, file_sha256=file_sha256) for e in entries]

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Portkey export content from a string."""
        entries = self._entries_from_text(content)
        return [self._parse_entry(e, file_sha256=None) for e in entries]

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON / JSONL / logs envelope and return entry dicts."""
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
                if "logs" in doc and isinstance(doc["logs"], list):
                    return [e for e in doc["logs"] if isinstance(e, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        log_id: str,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "portkey",
            "source_tool_name": "portkey",
            "source_tool_version": "",
            "log_id": log_id,
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        log_id = str(entry.get("id") or uuid.uuid4().hex[:16])
        trace_id = entry.get("trace_id")
        timestamp = (
            entry.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )

        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        guardrails = entry.get("guardrails") if isinstance(entry.get("guardrails"), dict) else {}
        user_feedback = (
            entry.get("user_feedback")
            if isinstance(entry.get("user_feedback"), dict)
            else {}
        )
        user_id = entry.get("user")

        model = str(request.get("model") or "unknown")
        provider = str(request.get("provider") or "unknown")
        method = str(request.get("method") or "")
        url = _strip_query(request.get("url"))

        config = request.get("config") if isinstance(request.get("config"), dict) else {}
        virtual_key = config.get("virtual_key")
        cfg_metadata = _scrub_metadata(config.get("metadata"))
        cache = config.get("cache") if isinstance(config.get("cache"), dict) else {}
        cache_mode = str(cache.get("mode") or "").lower() if cache else ""
        cache_max_age = _coerce_int(cache.get("max_age")) if cache else 0
        retry = config.get("retry") if isinstance(config.get("retry"), dict) else {}
        retry_attempts_cfg = _coerce_int(retry.get("attempts")) if retry else 0
        request_timeout_ms = _coerce_int(config.get("request_timeout"))

        fallback_targets = config.get("fallback_targets") or []
        if not isinstance(fallback_targets, list):
            fallback_targets = []
        fallback_target_count = len(fallback_targets)

        loadbalance = (
            config.get("loadbalance")
            if isinstance(config.get("loadbalance"), dict)
            else {}
        )
        lb_targets = loadbalance.get("targets") if loadbalance else None
        lb_target_count = len(lb_targets) if isinstance(lb_targets, list) else 0
        lb_target_summary: list[dict[str, Any]] = []
        if isinstance(lb_targets, list):
            for tgt in lb_targets:
                if isinstance(tgt, dict):
                    lb_target_summary.append({
                        "provider": str(tgt.get("provider") or ""),
                        "virtual_key": str(tgt.get("virtual_key") or ""),
                    })

        status_code = _coerce_int(response.get("status_code"))
        body_keys = response.get("body_keys") if isinstance(response.get("body_keys"), list) else []
        headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
        cache_status_raw = headers.get("x-portkey-cache-status") if headers else None
        cache_status = (
            str(cache_status_raw).upper() if isinstance(cache_status_raw, str) else ""
        )
        tokens = response.get("tokens") if isinstance(response.get("tokens"), dict) else {}
        prompt_tokens = _coerce_int(tokens.get("prompt_tokens"))
        completion_tokens = _coerce_int(tokens.get("completion_tokens"))
        total_tokens = _coerce_int(tokens.get("total_tokens")) or (
            prompt_tokens + completion_tokens
        )
        cost = _coerce_float(response.get("cost"))
        latency_ms = _coerce_float(response.get("latency_ms"))
        fallback_used = bool(response.get("fallback_used"))
        retry_count = _coerce_int(response.get("retry_count"))
        is_streaming = bool(response.get("is_streaming"))

        before_failed = _failed_guardrails(guardrails.get("before") if guardrails else None)
        after_failed = _failed_guardrails(guardrails.get("after") if guardrails else None)

        feedback_value = _coerce_int(user_feedback.get("value")) if user_feedback else 0
        feedback_weight = _coerce_float(user_feedback.get("weight")) if user_feedback else 0.0

        cache_hit_kind = ""
        if cache_mode == "semantic" and cache_status in _CACHE_HIT_VALUES:
            cache_hit_kind = "semantic"
        elif cache_status in _CACHE_HIT_VALUES:
            cache_hit_kind = "simple"

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            log_id=log_id,
        )

        common_evidence: dict[str, Any] = {
            "portkey_log_id": log_id,
            "trace_id": str(trace_id) if trace_id else None,
            "model": model,
            "provider": provider,
            "method": method,
            "url": url,
            "virtual_key": str(virtual_key) if virtual_key else None,
            "config_metadata": cfg_metadata,
            "cache_mode": cache_mode or None,
            "cache_max_age_s": cache_max_age,
            "cache_status": cache_status or None,
            "cache_hit_kind": cache_hit_kind or None,
            "retry_attempts_configured": retry_attempts_cfg,
            "retry_count": retry_count,
            "request_timeout_ms": request_timeout_ms,
            "fallback_target_count": fallback_target_count,
            "fallback_used": fallback_used,
            "loadbalance_target_count": lb_target_count,
            "loadbalance_targets": lb_target_summary,
            "status_code": status_code,
            "body_keys": list(body_keys),
            "tokens": {
                "prompt": prompt_tokens,
                "completion": completion_tokens,
                "total": total_tokens,
            },
            "cost_usd": cost,
            "latency_ms": latency_ms,
            "is_streaming": is_streaming,
            "user_id": str(user_id) if user_id else None,
            "user_feedback": {
                "value": feedback_value,
                "weight": feedback_weight,
            } if user_feedback else None,
            "source_provenance": source_provenance,
            "source_tool": "portkey",
        }

        control_results: list[ControlResult] = []

        # 1. Before-guardrail failure — input validation FAIL.
        if before_failed:
            control_id = _control_for(
                "before_guardrail_failed",
                self._mappings,
                _DEFAULT_BEFORE_GUARDRAIL_CONTROL,
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Portkey log {log_id} input guardrail rejected request "
                        f"({len(before_failed)} failure(s); provider={provider}, "
                        f"model={model})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "before_guardrail_failed",
                        "failed_guardrails": before_failed,
                    },
                )
            )

        # 2. After-guardrail failure — output safety FAIL.
        if after_failed:
            control_id = _control_for(
                "after_guardrail_failed",
                self._mappings,
                _DEFAULT_AFTER_GUARDRAIL_CONTROL,
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Portkey log {log_id} output guardrail rejected response "
                        f"({len(after_failed)} failure(s); provider={provider}, "
                        f"model={model})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "after_guardrail_failed",
                        "failed_guardrails": after_failed,
                    },
                )
            )

        # 3. Status code — primary signal. Skip PASS if a guardrail already failed.
        any_guardrail_failed = bool(before_failed or after_failed)
        if 500 <= status_code < 600:
            control_id = _control_for(
                "status_5xx", self._mappings, _DEFAULT_STATUS_5XX_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Portkey log {log_id} upstream {provider}/{model} returned "
                        f"5xx ({status_code})"
                    ),
                    evidence_data={**common_evidence, "signal": "status_5xx"},
                )
            )
        elif 400 <= status_code < 500:
            control_id = _control_for(
                "status_4xx", self._mappings, _DEFAULT_STATUS_4XX_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Portkey log {log_id} upstream {provider}/{model} returned "
                        f"4xx ({status_code})"
                    ),
                    evidence_data={**common_evidence, "signal": "status_4xx"},
                )
            )
        elif 200 <= status_code < 300 and not any_guardrail_failed:
            control_id = _control_for(
                "status_2xx", self._mappings, _DEFAULT_STATUS_2XX_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Portkey log {log_id} routed {provider}/{model} succeeded "
                        f"({status_code}, tokens={total_tokens}, cost=${cost:.4f}, "
                        f"latency_ms={latency_ms:.1f})"
                    ),
                    evidence_data={**common_evidence, "signal": "status_2xx"},
                )
            )

        # 4. Semantic cache hit — additive PASS audit-trail signal.
        if cache_hit_kind == "semantic":
            control_id = _control_for(
                "semantic_cache_hit",
                self._mappings,
                _DEFAULT_SEMANTIC_CACHE_CONTROL,
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Portkey log {log_id} served from semantic cache "
                        f"(cache_status={cache_status}, mode={cache_mode}, "
                        f"max_age={cache_max_age}s)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "semantic_cache_hit",
                        "cache_hit_kind": "semantic",
                    },
                )
            )

        # 5. Fallback fired — provider-provenance verification needed.
        if fallback_used:
            control_id = _control_for(
                "fallback_used", self._mappings, _DEFAULT_FALLBACK_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Portkey log {log_id} fell back to alternate provider "
                        f"(final={provider}, configured fallback_targets="
                        f"{fallback_target_count})"
                    ),
                    evidence_data={**common_evidence, "signal": "fallback_used"},
                )
            )

        # 6. Excessive retries — capacity / abuse signal.
        if retry_count > self.retry_threshold:
            control_id = _control_for(
                "retry_threshold_exceeded",
                self._mappings,
                _DEFAULT_RETRY_CONTROL,
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Portkey log {log_id} retried {retry_count} time(s) — "
                        f"exceeds threshold {self.retry_threshold}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "retry_threshold_exceeded",
                        "retry_threshold": self.retry_threshold,
                    },
                )
            )

        # 7. Cost threshold — exposure flag.
        if cost > self.cost_threshold_usd:
            control_id = _control_for(
                "cost_threshold_exceeded", self._mappings, _DEFAULT_COST_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Portkey log {log_id} cost ${cost:.4f} exceeds threshold "
                        f"${self.cost_threshold_usd:.4f} (exposure)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "cost_threshold_exceeded",
                        "cost_threshold_usd": self.cost_threshold_usd,
                    },
                )
            )

        # 8. Negative user feedback — audit-trail flag.
        if feedback_value == -1:
            control_id = _control_for(
                "negative_user_feedback",
                self._mappings,
                _DEFAULT_NEG_FEEDBACK_CONTROL,
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Portkey log {log_id} received negative user feedback "
                        f"(weight={feedback_weight:.2f})"
                    ),
                    evidence_data={**common_evidence, "signal": "negative_user_feedback"},
                )
            )

        # 9. Load balance with multiple targets — record routing decision.
        if lb_target_count > 1:
            control_id = _control_for(
                "loadbalance_multi_target",
                self._mappings,
                _DEFAULT_LOADBALANCE_CONTROL,
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Portkey log {log_id} routed via load-balanced pool "
                        f"({lb_target_count} targets); selected provider={provider}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "loadbalance_multi_target",
                        "selected_provider": provider,
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
            f"Imported from Portkey: {provider}/{model} status={status_code} "
            f"tokens={total_tokens} cost=${cost:.4f} "
            f"fallback_used={fallback_used} retry_count={retry_count}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"portkey-{log_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="portkey_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=latency_ms,
            session_id=str(trace_id) if trace_id else None,
        )
