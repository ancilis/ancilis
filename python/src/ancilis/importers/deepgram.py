"""Deepgram speech-to-text request-log importer — voice-agent evidence for AKSI controls.

Voice agents (phone-call agents, meeting transcribers, voice customer-service
bots) are an explosive 2026 vertical, and Deepgram's ``/v1/listen`` endpoint is
the dominant speech-to-text path. Even chat-only agents that "just record
meeting notes" funnel raw audio through Deepgram. **Audio is the
highest-PII surface in agentic systems**: entire conversations are transcribed
verbatim, often including spoken account numbers, health information, internal
project names, and third-party voices captured without separate consent.

This importer accepts a Deepgram request-log export and emits one
``EvaluationResult`` per request, mapping per-call posture to AKSI controls.
Accepted on-disk shapes:

  * ``{"results": [...]}``  — official export envelope
  * ``{"data":    [...]}``  — alternate envelope used by some exporters
  * ``[ {...}, {...} ]``    — bare list of request records
  * single object           — one request record
  * JSONL                   — one request object per line

Signal mapping (see ``shared/mappings/deepgram-aksi-controls.json``):

  * ``status=completed``                                       → PR-04 PASS
    (data access governance for transcribed audio)
  * ``status=failed``                                          → DE-01 FAIL
    (transcription failure surface)
  * ``status=rejected``                                        → PR-02 FLAG
    (input rejected — quota/format/scope concern)
  * ``redact`` empty/missing AND ``duration_seconds`` > 60s    → PR-04 FAIL
    (long audio without PII redaction = high exfiltration risk)
  * ``diarize`` is False AND no ``speakers_count`` AND > 30s   → PR-05 FLAG
    (multi-speaker audio without separation = audit completeness concern)
  * ``callback_url`` set AND host NOT in allowlist             → PR-04 FLAG
    (async exfiltration to external endpoint)
  * ``input_source=stream``                                    → PR-05 PASS
    (audit: streaming session — captures transient audio)
  * ``input_source=url`` with ``input_url_host`` on public CDN → PR-04 FLAG
    (audio fetched from cloud storage)
  * ``sentiment=true`` OR ``topics=true`` OR ``intents=true``  → captured
    in ``evidence_data`` (analytics consent material — surface for auditors)
  * ``tier="base"`` AND ``characters_billed > 10000``          → PR-03 FLAG
    (low-tier model on production-volume traffic)

**Sanitization — never store raw audio content or full URLs.** Specifically:

  * The full ``callback_url`` is never persisted; only the URL host is kept
    via :func:`urllib.parse.urlsplit`.
  * ``input_url`` paths are never persisted; only the host is kept.
  * ``metadata`` values beyond ``customer_id`` and ``session_id`` are dropped
    (other metadata fields can contain raw PII or transcript fragments).
  * The ``redact`` list is preserved as a *structure* (which redaction modes
    were enabled) — the redaction config is itself non-sensitive.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ancilis.engine.result import ControlResult, EvaluationResult


# This file lives at <repo>/python/src/ancilis/importers/deepgram.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "deepgram-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_LONG_AUDIO_THRESHOLD_SECONDS = 60.0
_DEFAULT_MULTISPEAKER_AUDIT_THRESHOLD_SECONDS = 30.0
_DEFAULT_BASE_TIER_HIGH_VOLUME_CHARS = 10000

# Public cloud-storage / CDN hosts used when fetching audio via URL — these
# represent egress / cross-account exposure surfaces and are flagged so
# auditors can confirm authorized-source provenance.
_DEFAULT_PUBLIC_CDN_HOSTS: tuple[str, ...] = (
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "r2.cloudflarestorage.com",
    "cdn.jsdelivr.net",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the deepgram-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    """Resolve a signal name to an AKSI control via the mapping table."""
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from a JSONL string, ignoring blank lines."""
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
# Coercion helpers
# ---------------------------------------------------------------------------


def _coerce_float(value: Any) -> float:
    """Best-effort float coercion; treat unparseable as 0.0."""
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _coerce_int(value: Any) -> int:
    """Best-effort int coercion; treat unparseable as 0."""
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_host(url: Any) -> str:
    """Extract the host component of a URL using ``urlsplit``; never returns the path."""
    if not isinstance(url, str) or not url:
        return ""
    try:
        return urlsplit(url).hostname or ""
    except (ValueError, AttributeError):
        return ""


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class DeepgramImporter:
    """Parse a Deepgram ``/v1/listen`` request-log export and emit EvaluationResults.

    One ``EvaluationResult`` is produced per request entry. Each request is
    evaluated against several signals (see module docstring). Multiple
    ``ControlResult`` instances may attach to the same evaluation when more
    than one signal fires (e.g. completed AND no-redact-on-long-audio).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        long_audio_threshold_seconds: float | None = None,
        multispeaker_audit_threshold_seconds: float | None = None,
        base_tier_high_volume_chars: int | None = None,
        callback_host_allowlist: Iterable[str] | None = None,
        public_cdn_hosts: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # Threshold precedence: explicit constructor arg > mapping metadata > default.
        if long_audio_threshold_seconds is not None:
            self.long_audio_threshold_seconds = float(long_audio_threshold_seconds)
        else:
            self.long_audio_threshold_seconds = float(
                meta.get(
                    "default_long_audio_threshold_seconds",
                    _DEFAULT_LONG_AUDIO_THRESHOLD_SECONDS,
                )
            )

        if multispeaker_audit_threshold_seconds is not None:
            self.multispeaker_audit_threshold_seconds = float(
                multispeaker_audit_threshold_seconds
            )
        else:
            self.multispeaker_audit_threshold_seconds = float(
                meta.get(
                    "default_multispeaker_audit_threshold_seconds",
                    _DEFAULT_MULTISPEAKER_AUDIT_THRESHOLD_SECONDS,
                )
            )

        if base_tier_high_volume_chars is not None:
            self.base_tier_high_volume_chars = int(base_tier_high_volume_chars)
        else:
            self.base_tier_high_volume_chars = int(
                meta.get(
                    "default_base_tier_high_volume_chars",
                    _DEFAULT_BASE_TIER_HIGH_VOLUME_CHARS,
                )
            )

        # Callback allowlist: empty by default — every callback host fires
        # the unknown-host signal until the operator explicitly trusts hosts.
        if callback_host_allowlist is not None:
            allowlist_source: Iterable[str] = callback_host_allowlist
        else:
            meta_allow = meta.get("default_callback_host_allowlist", []) or []
            allowlist_source = meta_allow if isinstance(meta_allow, list) else []
        self.callback_host_allowlist: set[str] = {
            str(h).strip().lower() for h in allowlist_source if str(h).strip()
        }

        if public_cdn_hosts is not None:
            cdn_source: Iterable[str] = public_cdn_hosts
        else:
            meta_cdns = meta.get("public_cdn_hosts") or list(_DEFAULT_PUBLIC_CDN_HOSTS)
            cdn_source = meta_cdns if isinstance(meta_cdns, list) else list(
                _DEFAULT_PUBLIC_CDN_HOSTS
            )
        self.public_cdn_hosts: set[str] = {
            str(h).strip().lower() for h in cdn_source if str(h).strip()
        }

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Deepgram export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return [self._parse_entry(e, file_sha256=file_sha256) for e in entries]

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Deepgram export content from a JSON or JSONL string."""
        entries = self._entries_from_text(content)
        return [self._parse_entry(e, file_sha256=None) for e in entries]

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON vs JSONL and return a flat list of request records.

        Accepted shapes:
          * ``{"results": [...]}``       — official Deepgram envelope
          * ``{"data": [...]}``          — alternate envelope
          * ``[ {...}, {...} ]``         — bare list of records
          * single object                — one record
          * JSONL                        — one record per line
        """
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                # Some exports are line-delimited even when the first token
                # looks like a complete JSON object. Fall through to JSONL.
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [e for e in doc if isinstance(e, dict)]
            if isinstance(doc, dict):
                if "results" in doc and isinstance(doc["results"], list):
                    return [e for e in doc["results"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single record.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "deepgram",
            "source_tool_name": "deepgram",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _redact_structure(self, redact: Any) -> list[str]:
        """Normalize the ``redact`` field to a list[str] of mode names.

        The redact configuration is *structure*, not user data — the strings
        ("pci", "ssn", "numbers", ...) are Deepgram redaction-mode identifiers,
        not values pulled from the audio. Safe to persist.
        """
        if redact is None:
            return []
        if isinstance(redact, bool):
            return ["true"] if redact else []
        if isinstance(redact, str):
            stripped = redact.strip()
            return [stripped] if stripped else []
        if isinstance(redact, list):
            return [str(r).strip() for r in redact if str(r).strip()]
        return []

    def _safe_metadata(self, metadata: Any) -> dict[str, Any]:
        """Pick only customer_id and session_id from metadata.

        Deepgram metadata is operator-supplied free-form JSON; arbitrary keys
        could embed raw PII or transcript fragments. We deliberately surface
        only ``customer_id`` and ``session_id`` (operational identifiers
        commonly used for evidence correlation) and report the count of
        suppressed keys so auditors can detect missing context.
        """
        if not isinstance(metadata, dict):
            return {
                "customer_id": None,
                "session_id": None,
                "suppressed_metadata_keys": 0,
            }
        kept: dict[str, Any] = {
            "customer_id": metadata.get("customer_id"),
            "session_id": metadata.get("session_id"),
        }
        suppressed = sum(
            1 for k in metadata if k not in ("customer_id", "session_id")
        )
        kept["suppressed_metadata_keys"] = suppressed
        return kept

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        request_id = str(entry.get("request_id") or entry.get("id") or uuid.uuid4())
        started_at = entry.get("started_at")
        duration_seconds = _coerce_float(entry.get("duration_seconds"))
        model = str(entry.get("model") or "unknown")
        language = str(entry.get("language") or "")
        tier_raw = entry.get("tier")
        tier = str(tier_raw).strip().lower() if tier_raw is not None else ""
        channels = _coerce_int(entry.get("channels"))
        sample_rate = _coerce_int(entry.get("sample_rate"))
        diarize = bool(entry.get("diarize", False))
        smart_format = bool(entry.get("smart_format", False))
        summarize = entry.get("summarize")
        topics = bool(entry.get("topics", False))
        intents = bool(entry.get("intents", False))
        sentiment = bool(entry.get("sentiment", False))
        filler_words = bool(entry.get("filler_words", False))
        punctuate = bool(entry.get("punctuate", False))
        utterances_count = _coerce_int(entry.get("utterances_count"))
        speakers_raw = entry.get("speakers_count")
        speakers_count = (
            _coerce_int(speakers_raw) if speakers_raw is not None else None
        )
        audio_format = str(entry.get("audio_format") or "")
        input_source = str(entry.get("input_source") or "").strip().lower()
        input_url_host_raw = entry.get("input_url_host")
        # If the export included a full input_url instead of pre-extracted host,
        # be defensive and reduce to host only — never persist the path.
        input_url_host = (
            str(input_url_host_raw).strip().lower() if input_url_host_raw else ""
        )
        if not input_url_host and isinstance(entry.get("input_url"), str):
            input_url_host = _safe_host(entry["input_url"]).lower()
        size_bytes = _coerce_int(entry.get("size_bytes"))
        characters_billed = _coerce_int(entry.get("characters_billed"))
        status = str(entry.get("status") or "").strip().lower()
        error_code = entry.get("error_code")
        is_streaming = bool(entry.get("is_streaming", False))
        redact_modes = self._redact_structure(entry.get("redact"))

        # Callback URL: never store the full URL — extract host only.
        callback_url_raw = entry.get("callback_url")
        callback_host = _safe_host(callback_url_raw).lower()

        safe_metadata = self._safe_metadata(entry.get("metadata"))
        customer_id = safe_metadata.get("customer_id")
        session_id = safe_metadata.get("session_id")

        analytics_features = {
            "sentiment": sentiment,
            "topics": topics,
            "intents": intents,
            "summarize": summarize if isinstance(summarize, str) else bool(summarize),
        }

        source_provenance = self._source_provenance(file_sha256=file_sha256)

        common_evidence: dict[str, Any] = {
            "deepgram_request_id": request_id,
            "model": model,
            "language": language,
            "tier": tier,
            "duration_seconds": duration_seconds,
            "characters_billed": characters_billed,
            "audio_format": audio_format,
            "channels": channels,
            "sample_rate": sample_rate,
            "redact_modes": redact_modes,
            "diarize": diarize,
            "smart_format": smart_format,
            "punctuate": punctuate,
            "filler_words": filler_words,
            "utterances_count": utterances_count,
            "speakers_count": speakers_count,
            "input_source": input_source,
            "input_url_host": input_url_host,
            "callback_host": callback_host,
            "size_bytes": size_bytes,
            "is_streaming": is_streaming,
            "customer_id": str(customer_id) if customer_id is not None else None,
            "session_id": str(session_id) if session_id is not None else None,
            "suppressed_metadata_keys": safe_metadata.get(
                "suppressed_metadata_keys", 0
            ),
            "analytics_features": analytics_features,
            "source_provenance": source_provenance,
            "source_tool": "deepgram",
        }

        control_results: list[ControlResult] = []

        # 1. Status — primary signal, exactly one ControlResult.
        if status == "completed":
            signal = "status_completed"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Deepgram request {request_id} {model}/{language or 'unspec'} "
                        f"transcribed {duration_seconds:.1f}s of audio "
                        f"({characters_billed} chars billed)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif status == "failed":
            signal = "status_failed"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Deepgram request {request_id} failed "
                        f"(error_code={error_code!r}, model={model})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "error_code": str(error_code) if error_code is not None else None,
                    },
                )
            )
        elif status == "rejected":
            signal = "status_rejected"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Deepgram request {request_id} rejected "
                        f"(error_code={error_code!r}) — quota / format / scope concern"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "error_code": str(error_code) if error_code is not None else None,
                    },
                )
            )
        else:
            # Unknown / missing status — surface as FLAG so it does not
            # silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FLAG",
                    detail=(
                        f"Deepgram request {request_id} has unrecognized "
                        f"status={entry.get('status')!r}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "status_unknown",
                    },
                )
            )

        # 2. Long audio without PII redaction — FAIL (high exfiltration risk).
        if (
            not redact_modes
            and duration_seconds > self.long_audio_threshold_seconds
        ):
            signal = "long_audio_no_redact"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Deepgram request {request_id} transcribed "
                        f"{duration_seconds:.1f}s of audio with NO PII redaction "
                        f"configured (threshold={self.long_audio_threshold_seconds:.0f}s) "
                        f"— high exfiltration risk for spoken account/health/identity data"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "long_audio_threshold_seconds": self.long_audio_threshold_seconds,
                    },
                )
            )

        # 3. Multi-speaker audio without diarization — FLAG (audit completeness).
        if (
            not diarize
            and speakers_count is None
            and duration_seconds > self.multispeaker_audit_threshold_seconds
        ):
            signal = "diarize_off_multispeaker"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Deepgram request {request_id} transcribed "
                        f"{duration_seconds:.1f}s of audio with diarize=false and "
                        f"no speakers_count — audit-trail cannot attribute "
                        f"utterances to speakers"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "multispeaker_audit_threshold_seconds": (
                            self.multispeaker_audit_threshold_seconds
                        ),
                    },
                )
            )

        # 4. Callback URL to non-allowlisted host — FLAG (async exfiltration).
        if callback_host and callback_host not in self.callback_host_allowlist:
            signal = "callback_url_unknown_host"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Deepgram request {request_id} configured async callback "
                        f"to host {callback_host!r} not in operator allowlist "
                        f"(size={len(self.callback_host_allowlist)}) — async "
                        f"exfiltration surface"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "callback_host_allowlist_size": len(
                            self.callback_host_allowlist
                        ),
                    },
                )
            )

        # 5. URL-source audio fetched from public CDN — FLAG.
        if input_source == "url" and input_url_host in self.public_cdn_hosts:
            signal = "url_source_public_cdn"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Deepgram request {request_id} fetched audio from "
                        f"public cloud-storage host {input_url_host!r} — confirm "
                        f"authorized-source provenance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 6. Streaming source — PASS audit (transient capture, recorded for posture).
        if input_source == "stream":
            signal = "stream_source"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Deepgram request {request_id} streamed transient audio "
                        f"({duration_seconds:.1f}s, {utterances_count} utterances) "
                        f"— recorded for audit completeness"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 7. Base tier on production-volume traffic — PR-03 FLAG.
        if tier == "base" and characters_billed > self.base_tier_high_volume_chars:
            signal = "base_tier_high_volume"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Deepgram request {request_id} used tier=base on "
                        f"production-volume traffic ({characters_billed} chars > "
                        f"{self.base_tier_high_volume_chars}) — input-validation "
                        f"posture: low-tier model can degrade transcription "
                        f"reliability for downstream policy decisions"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "base_tier_high_volume_chars": self.base_tier_high_volume_chars,
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
            f"Imported from Deepgram: {model}/{language or 'unspec'} "
            f"status={status or 'unknown'} duration={duration_seconds:.1f}s "
            f"chars_billed={characters_billed} redact_modes={len(redact_modes)}"
        )

        timestamp = (
            started_at
            if isinstance(started_at, str) and started_at
            else datetime.now(timezone.utc).isoformat()
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"deepgram-{request_id[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="deepgram_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_seconds * 1000.0,
            session_id=str(session_id) if session_id else None,
        )
