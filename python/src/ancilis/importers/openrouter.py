"""OpenRouter generation-log importer — maps multi-provider router request records to AKSI controls.

OpenRouter (https://openrouter.ai) is a multi-provider LLM router. Agents send
OpenAI-shaped completion requests and OpenRouter routes each call to one of
200+ downstream providers (Anthropic, OpenAI, Mistral, Google, etc.). The
``GET /api/v1/generation/{id}`` endpoint returns a per-generation record with
the routed-to provider, model, token counts (both normalized and native),
latency components, and a ``finish_reason`` describing how the upstream
generation terminated. Bulk exports come as ``{"data": [...]}`` arrays or
JSONL streams of those same record shapes.

Signal mapping (see shared/mappings/openrouter-aksi-controls.json):
  - finish_reason in {"stop", "length"}  → PR-01 PASS  (identity / clean termination)
  - finish_reason == "content_filter"    → PR-02 FLAG  (provider moderation triggered)
  - finish_reason == "error"             → DE-01 FAIL  (provider failure surface)
  - cancelled is True                    → PR-05 FLAG  (audit-trail anomaly)
  - is_byok is True                      → PR-04 FLAG  (key-exposure consideration)
  - usage > cost_threshold_usd           → PR-04 FLAG  (exposure)

The actual upstream provider that handled the routed request is surfaced via
``evidence_data.provider_routed_to`` so downstream posture and lineage analysis
can answer "which provider actually saw this prompt?" — a question that is
unique to multi-provider routers.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/openrouter.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "openrouter-aksi-controls.json"
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

# finish_reason values that constitute a clean, allowed completion.
_CLEAN_FINISH_REASONS = {"stop", "length"}


def _load_mapping_table() -> dict[str, Any]:
    """Load the openrouter-aksi-controls.json mapping table; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for_signal(signal: str, mappings: dict[str, str], default: str) -> str:
    """Resolve a signal name to an AKSI control via the mapping table."""
    if signal in mappings:
        return mappings[signal]
    return default


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from a JSONL string, ignoring blank lines."""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        yield json.loads(line)


def _coerce_int(value: Any) -> int:
    """Best-effort int coercion; treat unparseable as 0."""
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coerce_float(value: Any) -> float:
    """Best-effort float coercion; treat unparseable as 0.0."""
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class OpenRouterImporter:
    """Parse an OpenRouter generation-log export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cost_threshold_usd: float | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Cost threshold precedence: explicit constructor arg > mapping metadata > default.
        if cost_threshold_usd is not None:
            self.cost_threshold_usd = float(cost_threshold_usd)
        else:
            self.cost_threshold_usd = float(
                meta.get("default_cost_threshold_usd", _DEFAULT_COST_THRESHOLD_USD)
            )

    # ------------------------------------------------------------------ public
    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an OpenRouter export file (JSON or JSONL) and return one EvaluationResult per generation."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return [self._parse_record(r, file_sha256=file_sha256) for r in records]

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse OpenRouter export content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return [self._parse_record(r, file_sha256=None) for r in records]

    # ----------------------------------------------------------------- private
    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON vs JSONL and return a flat list of generation records.

        Accepted shapes:
          * {"data": {...single generation...}}
          * {"data": [ {...}, {...} ]}
          * [ {...}, {...} ]                — bare list of records
          * JSONL — one record per line, each either a bare record or a {"data": ...} envelope.
        """
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                # Fall through to JSONL — some exports are line-delimited even if
                # the first line looks like a complete JSON object.
                return list(self._extract_records(_iter_jsonl(text)))
            return list(self._extract_records([doc]))
        # No leading JSON token — treat as JSONL.
        return list(self._extract_records(_iter_jsonl(text)))

    def _extract_records(self, items: Iterable[Any]) -> Iterable[dict[str, Any]]:
        """Normalize iterable of raw decoded values into individual generation dicts."""
        for item in items:
            if isinstance(item, dict):
                # {"data": single_obj} or {"data": [...]} envelope.
                if "data" in item and not _looks_like_record(item):
                    payload = item["data"]
                    if isinstance(payload, list):
                        for elem in payload:
                            if isinstance(elem, dict):
                                yield elem
                    elif isinstance(payload, dict):
                        yield payload
                    # else: envelope with non-record data — skip silently.
                else:
                    # Bare record.
                    yield item
            elif isinstance(item, list):
                for elem in item:
                    if isinstance(elem, dict):
                        yield elem

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        generation_id: str,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "openrouter",
            "source_tool_name": "openrouter",
            "source_tool_version": "",
            "generation_id": generation_id,
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _parse_record(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        generation_id = str(entry.get("id") or uuid.uuid4().hex[:16])
        model = str(entry.get("model") or "unknown")
        provider_name = entry.get("provider_name")
        provider_routed_to = str(provider_name) if provider_name else "unknown"

        streamed = bool(entry.get("streamed", False))
        cancelled = bool(entry.get("cancelled", False))
        is_byok = bool(entry.get("is_byok", False))

        # Normalized (router-side) token counts.
        tokens_prompt = _coerce_int(entry.get("tokens_prompt"))
        tokens_completion = _coerce_int(entry.get("tokens_completion"))
        tokens_total = tokens_prompt + tokens_completion

        # Native (raw provider) token counts — kept distinct for posture/billing lineage.
        native_tokens_prompt = _coerce_int(entry.get("native_tokens_prompt"))
        native_tokens_completion = _coerce_int(entry.get("native_tokens_completion"))
        native_tokens_total = native_tokens_prompt + native_tokens_completion

        num_media_prompt = _coerce_int(entry.get("num_media_prompt"))
        num_search_results = _coerce_int(entry.get("num_search_results"))

        usage_usd = _coerce_float(entry.get("usage"))
        latency_ms = _coerce_float(entry.get("latency"))
        generation_time_ms = _coerce_float(entry.get("generation_time"))
        moderation_latency_ms = _coerce_float(entry.get("moderation_latency"))

        finish_reason_raw = entry.get("finish_reason")
        finish_reason = (
            str(finish_reason_raw).lower() if finish_reason_raw is not None else ""
        )

        origin = entry.get("origin") or ""
        app_id = entry.get("app_id")
        external_user = entry.get("external_user")
        created_at = (
            entry.get("created_at")
            or datetime.now(timezone.utc).isoformat()
        )

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            generation_id=generation_id,
        )

        common_evidence: dict[str, Any] = {
            "openrouter_generation_id": generation_id,
            "model": model,
            "provider_routed_to": provider_routed_to,
            "streamed": streamed,
            "cancelled": cancelled,
            "is_byok": is_byok,
            "finish_reason": finish_reason,
            "tokens": {
                "prompt": tokens_prompt,
                "completion": tokens_completion,
                "total": tokens_total,
            },
            "native_tokens": {
                "prompt": native_tokens_prompt,
                "completion": native_tokens_completion,
                "total": native_tokens_total,
            },
            "num_media_prompt": num_media_prompt,
            "num_search_results": num_search_results,
            "usage_usd": usage_usd,
            "latency_ms": latency_ms,
            "generation_time_ms": generation_time_ms,
            "moderation_latency_ms": moderation_latency_ms,
            "origin": str(origin),
            "app_id": str(app_id) if app_id is not None else None,
            "external_user": str(external_user) if external_user is not None else None,
            "source_provenance": source_provenance,
            "source_tool": "openrouter",
        }

        control_results: list[ControlResult] = []

        # 1. finish_reason — primary signal, exactly one ControlResult per record.
        if finish_reason in _CLEAN_FINISH_REASONS:
            signal = f"finish_reason_{finish_reason}"
            control_id = _control_for_signal(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"OpenRouter generation {generation_id} routed to "
                        f"{provider_routed_to}/{model} terminated cleanly "
                        f"(finish_reason={finish_reason}, tokens={tokens_total}, "
                        f"cost=${usage_usd:.4f})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif finish_reason == "content_filter":
            signal = "finish_reason_content_filter"
            control_id = _control_for_signal(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"OpenRouter generation {generation_id} terminated by "
                        f"provider moderation (finish_reason=content_filter, "
                        f"provider={provider_routed_to}, "
                        f"moderation_latency_ms={moderation_latency_ms})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif finish_reason == "error":
            signal = "finish_reason_error"
            control_id = _control_for_signal(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"OpenRouter generation {generation_id} routed to "
                        f"{provider_routed_to}/{model} failed "
                        f"(finish_reason=error)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Unknown / missing finish_reason — surface as FLAG so it does not silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"OpenRouter generation {generation_id} has unrecognized "
                        f"finish_reason={finish_reason_raw!r}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "finish_reason_unknown",
                    },
                )
            )

        # 2. cancelled — additive audit-trail anomaly.
        if cancelled:
            signal = "cancelled"
            control_id = _control_for_signal(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"OpenRouter generation {generation_id} was cancelled "
                        f"mid-flight (audit-trail anomaly)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 3. is_byok — additive key-exposure consideration.
        if is_byok:
            signal = "is_byok"
            control_id = _control_for_signal(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"OpenRouter generation {generation_id} used a "
                        f"bring-your-own-key (BYOK) credential — review key "
                        f"handling and exposure surface for {provider_routed_to}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 4. cost-threshold exceeded — additive exposure flag.
        if usage_usd > self.cost_threshold_usd:
            signal = "cost_threshold_exceeded"
            control_id = _control_for_signal(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"OpenRouter generation {generation_id} cost "
                        f"${usage_usd:.4f} exceeds threshold "
                        f"${self.cost_threshold_usd:.4f} (exposure)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cost_threshold_usd": self.cost_threshold_usd,
                    },
                )
            )

        # Decision: BLOCK on any FAIL, FLAG on any FLAG, otherwise ALLOW.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from OpenRouter: routed to {provider_routed_to}/{model} "
            f"finish_reason={finish_reason or 'unknown'} tokens={tokens_total} "
            f"cost=${usage_usd:.4f}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"openrouter-{generation_id[:32]}",
            timestamp=str(created_at),
            agent_id=self.agent_id,
            source_type="openrouter_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=latency_ms,
            session_id=str(app_id) if app_id is not None else None,
        )


def _looks_like_record(obj: dict[str, Any]) -> bool:
    """Return True if obj already looks like a generation record (not a {"data": ...} envelope).

    Distinguishing characteristic: a raw record has fields like ``id`` /
    ``model`` / ``finish_reason`` / ``provider_name`` at the top level. An
    envelope is dominated by a ``data`` key. We treat any object whose only
    structural key is ``data`` (with optional metadata siblings) as an envelope.
    """
    return bool("id" in obj and ("model" in obj or "finish_reason" in obj or "provider_name" in obj))
