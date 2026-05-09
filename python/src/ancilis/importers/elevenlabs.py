"""ElevenLabs TTS history importer — maps text-to-speech generation records to AKSI controls.

ElevenLabs is the dominant text-to-speech provider for voice agents. Every voice
agent that talks back to a user runs through ElevenLabs (or a direct competitor)
and the ``GET /v1/history`` endpoint exports a per-generation record describing
which voice was used, what model produced the audio, how long it was, whether
the voice was a clone (instant or professional), whether consent was recorded
for that clone, and so on. This importer turns each history item into one
``EvaluationResult``.

Voice cloning is the load-bearing risk surface here: a cloned voice without a
recorded consent timestamp is a direct legal-liability and impersonation
exposure, and is escalated to a hard FAIL. Sharing audio externally
(``share_link_id``), transforming a third-party speaker's voice
(``speech_to_speech``), or creating new voice identities
(``voice_clone`` / ``voice_design``) all surface as FLAGs that downstream
posture analysis can promote.

Signal mapping (see shared/mappings/elevenlabs-aksi-controls.json):
  - voice_category=premade                              → PR-01 PASS  (verified voice)
  - voice_category=professional                         → PR-01 PASS
  - voice_category=generated                            → PR-01 PASS  (synthetic voice)
  - voice_category=cloned + is_iv  + consent_signed_at  → PR-01 FLAG  (instant clone, consent recorded)
  - voice_category=cloned + is_pvc + consent_signed_at  → PR-01 FLAG  (professional clone, consent recorded)
  - voice_category=cloned WITHOUT consent_signed_at     → DE-01 FAIL  (clone without recorded consent)
  - status=failed                                       → DE-01 FAIL
  - request_method=voice_clone | voice_design           → PR-05 FLAG  (voice creation event)
  - request_method=speech_to_speech                     → PR-04 FLAG  (voice transformation)
  - share_link_id present                               → PR-04 FLAG  (shared audio = exfil surface)
  - text_length_chars > threshold (default 50000)       → PR-04 FLAG  (over-generation / corpus dump)

Sanitization rules:
  * ``feedback.feedback_text`` is NEVER stored verbatim — only its byte length and a
    sha256 are kept. User-supplied free text can carry PII.
  * Audio URLs are reduced to the host component via ``urllib.parse.urlsplit`` —
    full media URLs would be a content-leak risk.
  * Any free-text body is hashed, not retained.
  * ``consent_signed_at`` is stored verbatim — that timestamp is the audit trail.
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


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/elevenlabs.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "elevenlabs-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_TEXT_LENGTH_THRESHOLD = 50000

# voice_category values that constitute a verified, low-risk voice provenance.
_PASS_CATEGORIES = {"premade", "professional", "generated"}

_HIGH_IMPACT_CREATION_METHODS = {"voice_clone", "voice_design"}


def _load_mapping_table() -> dict[str, Any]:
    """Load the elevenlabs-aksi-controls.json mapping table; tolerate missing file."""
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


def _sanitize_feedback_text(text: Any) -> dict[str, Any]:
    """Reduce free-text feedback to a non-sensitive fingerprint.

    User-typed feedback could carry PII (names, account numbers, transcripts of
    a conversation the agent just had). We never persist the verbatim text;
    only its byte-length and a sha256 are kept so downstream evidence can prove
    the field existed and detect tampering without leaking content.
    """
    if text is None:
        return {"present": False}
    encoded = str(text).encode("utf-8")
    return {
        "present": True,
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _audio_url_host(url: Any) -> str | None:
    """Return only the host component of an audio URL (strips path/query)."""
    if not url:
        return None
    try:
        parsed = urlsplit(str(url))
    except (TypeError, ValueError):
        return None
    return parsed.hostname or None


class ElevenLabsImporter:
    """Parse an ElevenLabs ``/v1/history`` export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        text_length_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # text_length threshold precedence: explicit constructor arg > mapping metadata > default.
        if text_length_threshold is not None:
            self.text_length_threshold = int(text_length_threshold)
        else:
            self.text_length_threshold = int(
                meta.get(
                    "default_text_length_threshold_chars",
                    _DEFAULT_TEXT_LENGTH_THRESHOLD,
                )
            )
        self.consent_signed_required_for_clone = bool(
            meta.get("consent_signed_required_for_clone", True)
        )

    # ------------------------------------------------------------------ public
    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an ElevenLabs export file (JSON or JSONL) and return one EvaluationResult per history item."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return [self._parse_entry(r, file_sha256=file_sha256) for r in records]

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse ElevenLabs export content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return [self._parse_entry(r, file_sha256=None) for r in records]

    # ----------------------------------------------------------------- private
    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON vs JSONL and return a flat list of history items.

        Accepted shapes:
          * ``{"history": [ {...}, ... ]}``     — canonical /v1/history response
          * ``{"data":    [ {...}, ... ]}``     — alternate envelope
          * ``[ {...}, {...} ]``                — bare list of records
          * ``{ ...single record... }``         — bare object
          * JSONL — one record per line, each either a bare record or an envelope.
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
        """Normalize iterable of raw decoded values into individual history dicts."""
        for item in items:
            if isinstance(item, dict):
                if "history" in item and isinstance(item["history"], list):
                    for elem in item["history"]:
                        if isinstance(elem, dict):
                            yield elem
                elif "data" in item and isinstance(item["data"], list):
                    for elem in item["data"]:
                        if isinstance(elem, dict):
                            yield elem
                elif "data" in item and isinstance(item["data"], dict):
                    yield item["data"]
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
        history_item_id: str,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "elevenlabs",
            "source_tool_name": "elevenlabs",
            "source_tool_version": "",
            "history_item_id": history_item_id,
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
        history_item_id = str(
            entry.get("history_item_id") or entry.get("id") or uuid.uuid4().hex[:16]
        )
        request_id = str(entry.get("request_id") or "")
        voice_id = str(entry.get("voice_id") or "")
        voice_name = str(entry.get("voice_name") or "")
        voice_category = str(entry.get("voice_category") or "").lower()
        model_id = str(entry.get("model_id") or "")
        language = str(entry.get("language") or "")
        speaker_id = entry.get("speaker_id")
        is_pvc = bool(entry.get("is_pvc", False))
        is_iv = bool(entry.get("is_iv", False))
        share_link_id = entry.get("share_link_id")
        consent_signed_at = entry.get("consent_signed_at")
        request_method = str(entry.get("request_method") or "tts").lower()
        status = str(entry.get("status") or "").lower()
        error = entry.get("error")

        text_length_chars = _coerce_int(entry.get("text_length_chars"))
        char_count_from = _coerce_int(entry.get("character_count_change_from"))
        char_count_to = _coerce_int(entry.get("character_count_change_to"))
        duration_seconds = _coerce_float(entry.get("duration_seconds"))

        content_type = str(entry.get("content_type") or "")

        # Voice tuning settings — operationally useful, NOT sensitive content.
        voice_settings = entry.get("voice_settings") or {}
        if not isinstance(voice_settings, dict):
            voice_settings = {}

        # Feedback: thumbs_up is structural metadata, feedback_text is user-typed
        # free text and gets fingerprinted only.
        feedback_blob = entry.get("feedback") or {}
        if not isinstance(feedback_blob, dict):
            feedback_blob = {}
        feedback_thumbs_up = feedback_blob.get("thumbs_up")
        feedback_text_summary = _sanitize_feedback_text(feedback_blob.get("feedback_text"))

        # Strip audio URLs to host only; explicit ``audio_url_host`` key takes priority.
        audio_url_host = entry.get("audio_url_host")
        if audio_url_host:
            audio_url_host = str(audio_url_host)
        else:
            audio_url_host = (
                _audio_url_host(entry.get("audio_url"))
                or _audio_url_host(entry.get("audio_path"))
            )

        started_at = (
            entry.get("started_at")
            or entry.get("date_unix")
            or datetime.now(timezone.utc).isoformat()
        )

        source_provenance = self._source_provenance(
            file_sha256=file_sha256,
            history_item_id=history_item_id,
        )

        common_evidence: dict[str, Any] = {
            "elevenlabs_history_item_id": history_item_id,
            "request_id": request_id,
            "voice_id": voice_id,
            "voice_name": voice_name,
            "voice_category": voice_category,
            "model_id": model_id,
            "language": language,
            "speaker_id": str(speaker_id) if speaker_id is not None else None,
            "text_length_chars": text_length_chars,
            "character_count_change_from": char_count_from,
            "character_count_change_to": char_count_to,
            "duration_seconds": duration_seconds,
            "is_pvc": is_pvc,
            "is_iv": is_iv,
            "request_method": request_method,
            "voice_settings": voice_settings,
            "feedback_thumbs_up": (
                bool(feedback_thumbs_up) if feedback_thumbs_up is not None else None
            ),
            "feedback_text_summary": feedback_text_summary,
            "audio_url_host": audio_url_host,
            "content_type": content_type,
            "share_link_id": str(share_link_id) if share_link_id else None,
            # consent_signed_at is stored verbatim — that timestamp IS the audit trail.
            "consent_signed_at": consent_signed_at,
            "status": status,
            "source_provenance": source_provenance,
            "source_tool": "elevenlabs",
        }

        control_results: list[ControlResult] = []

        # 1. Primary signal — status / voice provenance / consent. Exactly one
        #    primary ControlResult per record.
        if status == "failed":
            signal = "status_failed"
            control_id = _control_for_signal(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"ElevenLabs history item {history_item_id} for "
                        f"voice {voice_name!r} ({voice_category}) failed"
                        + (f": {error}" if error else "")
                    ),
                    evidence_data={**common_evidence, "signal": signal, "error": error},
                )
            )
        elif voice_category == "cloned":
            has_consent = bool(consent_signed_at)
            if not has_consent and self.consent_signed_required_for_clone:
                signal = "cloned_voice_no_consent"
                control_id = _control_for_signal(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"ElevenLabs cloned voice {voice_name!r} "
                            f"(voice_id={voice_id}) used without recorded consent — "
                            f"legal liability and identity-impersonation exposure"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif is_pvc:
                signal = "cloned_voice_pvc_with_consent"
                control_id = _control_for_signal(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"ElevenLabs professional voice clone {voice_name!r} "
                            f"used with consent recorded at {consent_signed_at} — "
                            f"surface for periodic re-consent review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif is_iv:
                signal = "cloned_voice_iv_with_consent"
                control_id = _control_for_signal(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"ElevenLabs instant voice clone {voice_name!r} "
                            f"used with consent recorded at {consent_signed_at} — "
                            f"impersonation risk surface for review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                # Cloned but neither is_pvc nor is_iv flagged — still surface as FLAG
                # under the iv-with-consent signal as the conservative default.
                signal = "cloned_voice_iv_with_consent"
                control_id = _control_for_signal(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"ElevenLabs cloned voice {voice_name!r} used with "
                            f"consent recorded at {consent_signed_at}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        elif voice_category in _PASS_CATEGORIES:
            signal = f"voice_{voice_category}"
            control_id = _control_for_signal(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"ElevenLabs history item {history_item_id} used verified "
                        f"{voice_category} voice {voice_name!r} ({voice_id}) "
                        f"via {model_id} ({text_length_chars} chars, "
                        f"{duration_seconds:.1f}s)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Unknown / missing voice_category — surface as FLAG so it does not silently pass.
            control_results.append(
                ControlResult(
                    control_id="PR-01",
                    control_name=_CONTROL_NAMES["PR-01"],
                    result="FLAG",
                    detail=(
                        f"ElevenLabs history item {history_item_id} has "
                        f"unrecognized voice_category={voice_category!r}"
                    ),
                    evidence_data={**common_evidence, "signal": "voice_category_unknown"},
                )
            )

        # 2. Voice-creation events (voice_clone / voice_design) — additive, high-impact.
        if request_method in _HIGH_IMPACT_CREATION_METHODS:
            signal = f"{request_method}_method"
            control_id = _control_for_signal(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"ElevenLabs voice creation event ({request_method}) — "
                        f"new voice identity {voice_name!r} ({voice_id}) "
                        f"introduced; surface prominently in audit trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 3. Speech-to-speech voice transformation — additive exposure flag.
        if request_method == "speech_to_speech":
            signal = "speech_to_speech_method"
            control_id = _control_for_signal(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"ElevenLabs speech-to-speech transformation through voice "
                        f"{voice_name!r} ({voice_id}) — original speaker identity "
                        f"may be masked; review consent and downstream use"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 4. Externally-shared audio link — additive exfil-surface flag.
        if share_link_id:
            signal = "share_link_present"
            control_id = _control_for_signal(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"ElevenLabs history item {history_item_id} was published "
                        f"externally (share_link_id={share_link_id}) — "
                        f"audio exfiltration surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # 5. Over-generation: very long text-to-speech runs can be a covert
        #    exfil channel (dump a corpus into TTS, ship the audio out).
        if text_length_chars > self.text_length_threshold:
            signal = "long_text_overgeneration"
            control_id = _control_for_signal(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"ElevenLabs history item {history_item_id} synthesized "
                        f"{text_length_chars} characters (threshold "
                        f"{self.text_length_threshold}) — potential corpus "
                        f"exfiltration via voice channel"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "text_length_threshold": self.text_length_threshold,
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
            f"Imported from ElevenLabs: {request_method} via "
            f"{voice_category or 'unknown'} voice {voice_name!r} ({voice_id}) "
            f"model={model_id} chars={text_length_chars} status={status or 'succeeded'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"elevenlabs-{history_item_id[:32]}",
            timestamp=str(started_at),
            agent_id=self.agent_id,
            source_type="elevenlabs_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_seconds * 1000.0,
            session_id=request_id or None,
        )
