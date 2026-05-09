"""Helicone request/log export importer — maps proxied LLM call records to AKSI controls.

Helicone is a proxy/observability layer for LLM calls. Each entry in a Helicone export
represents one upstream LLM request (OpenAI/Anthropic/Azure/etc.) captured with
status, latency, tokens, cost, and user-supplied properties. This importer turns each
exported request into one EvaluationResult.

Signal mapping (see shared/mappings/helicone-aksi-controls.json):
  - status 2xx                 → PR-01 PASS  (identity / authorized call surface)
  - status 4xx                 → PR-02 FLAG  (scope / auth concern)
  - status 5xx                 → DE-01 FLAG  (provider failure surface)
  - feedback.rating=="negative" → PR-05 FLAG (audit-trail concern)
  - cost_usd > threshold       → PR-04 FLAG  (exposure)

Sanitization: prompt/response bodies are NEVER stored verbatim. We capture only the
top-level keys, token counts, and a sha256 of the JSON-encoded bodies for tamper
evidence.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


_MAPPING_PATH = (
    Path(__file__).parent.parent.parent.parent.parent.parent
    / "shared" / "mappings" / "helicone-aksi-controls.json"
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


def _load_mapping_table() -> dict[str, Any]:
    """Load the helicone-aksi-controls.json mapping table; tolerate missing file."""
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


def _sanitize_body(body: Any) -> dict[str, Any]:
    """Reduce a request_body / response_body blob to a non-sensitive summary.

    We never persist raw prompt or response text. Only top-level keys, byte-length,
    and a sha256 over the JSON-encoded body are kept so downstream evidence can
    prove a body existed and detect tampering without leaking content.
    """
    if body is None:
        return {"present": False}
    if not isinstance(body, dict):
        # primitives / lists — record type + size only
        encoded = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
        return {
            "present": True,
            "kind": type(body).__name__,
            "byte_length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    encoded = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    return {
        "present": True,
        "kind": "object",
        "body_keys": sorted(body.keys()),
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


class HeliconeImporter:
    """Parse a Helicone request/log JSON export and convert to EvaluationResults."""

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
        """Parse a Helicone export file and return one EvaluationResult per request."""
        content = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content).hexdigest()
        doc = json.loads(content.decode("utf-8"))
        return self._parse_doc(doc, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a Helicone export from a JSON string."""
        doc = json.loads(content)
        return self._parse_doc(doc, file_sha256=None)

    # ----------------------------------------------------------------- private
    def _parse_doc(
        self,
        doc: dict[str, Any] | list[Any],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # Helicone exports are typically {"data": [...]} but accept a bare list too.
        entries = doc if isinstance(doc, list) else doc.get("data", []) or []

        results: list[EvaluationResult] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            results.append(self._parse_entry(entry, file_sha256=file_sha256))
        return results

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "helicone",
            "source_tool_name": "helicone",
            "source_tool_version": "",
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
        request_id = str(entry.get("id") or entry.get("node_id") or uuid.uuid4())
        node_id = entry.get("node_id")
        provider = str(entry.get("provider", "")).upper() or "UNKNOWN"
        model = str(entry.get("model", "")) or "unknown"
        prompt_tokens = int(entry.get("prompt_tokens") or 0)
        completion_tokens = int(entry.get("completion_tokens") or 0)
        total_tokens = int(
            entry.get("total_tokens") or (prompt_tokens + completion_tokens)
        )
        cost_usd = float(entry.get("cost_usd") or 0.0)
        latency_ms = entry.get("latency_ms")
        user_id = entry.get("user_id")
        properties = entry.get("properties") or {}
        feedback = entry.get("feedback") or {}
        raw_status = entry.get("status")
        try:
            status = int(raw_status) if raw_status is not None else 0
        except (TypeError, ValueError):
            status = 0

        request_body_summary = _sanitize_body(entry.get("request_body"))
        response_body_summary = _sanitize_body(entry.get("response_body"))

        source_provenance = self._source_provenance(file_sha256=file_sha256)
        common_evidence: dict[str, Any] = {
            "helicone_request_id": request_id,
            "node_id": node_id,
            "provider": provider,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cost_usd": cost_usd,
            "latency_ms": latency_ms,
            "status": status,
            "user_id": user_id,
            "properties": properties,
            "request_body_summary": request_body_summary,
            "response_body_summary": response_body_summary,
            "source_provenance": source_provenance,
            "source_tool": "helicone",
        }

        control_results: list[ControlResult] = []

        # 1. Status-code signal — produces exactly one control result per request.
        if 200 <= status < 300:
            signal = "status_2xx"
            control_id = _control_for_signal(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Helicone request {request_id} {provider}/{model} "
                        f"status={status} tokens={total_tokens} cost=${cost_usd:.4f}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif 400 <= status < 500:
            signal = "status_4xx"
            control_id = _control_for_signal(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Helicone request {request_id} returned client error "
                        f"status={status} from {provider} (scope/auth concern)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif 500 <= status < 600:
            signal = "status_5xx"
            control_id = _control_for_signal(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Helicone request {request_id} provider {provider} "
                        f"returned server error status={status} (failure surface)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Unknown / 0 status — record as FLAG so it does not silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"Helicone request {request_id} has unrecognized status={raw_status!r}"
                    ),
                    evidence_data={**common_evidence, "signal": "status_unknown"},
                )
            )

        # 2. Negative feedback — additive.
        rating = str(feedback.get("rating", "")).lower() if isinstance(feedback, dict) else ""
        if rating == "negative":
            signal = "negative_feedback"
            control_id = _control_for_signal(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Helicone request {request_id} received negative user feedback "
                        f"(audit-trail concern)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "feedback": feedback,
                    },
                )
            )

        # 3. Cost-threshold exceeded — additive.
        if cost_usd > self.cost_threshold_usd:
            signal = "cost_threshold_exceeded"
            control_id = _control_for_signal(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Helicone request {request_id} cost ${cost_usd:.4f} exceeds "
                        f"threshold ${self.cost_threshold_usd:.4f} (exposure)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cost_threshold_usd": self.cost_threshold_usd,
                    },
                )
            )

        # Decision: ALLOW only if every control result is PASS.
        decision = "ALLOW" if all(cr.result == "PASS" for cr in control_results) else "FLAG"

        decision_reason = (
            f"Imported from Helicone: {provider}/{model} status={status} "
            f"tokens={total_tokens} cost=${cost_usd:.4f}"
        )

        # Use Helicone request timestamp if available, otherwise current UTC.
        ts = (
            entry.get("response_created_at")
            or entry.get("request_created_at")
            or datetime.now(timezone.utc).isoformat()
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"helicone-{request_id[:32]}",
            timestamp=str(ts),
            agent_id=self.agent_id,
            source_type="helicone_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=float(latency_ms) if isinstance(latency_ms, (int, float)) else 0.0,
            session_id=str(node_id) if node_id else None,
        )
