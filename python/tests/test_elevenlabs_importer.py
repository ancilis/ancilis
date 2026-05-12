"""Tests for the ElevenLabs TTS history evidence importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers.elevenlabs import (
    ElevenLabsImporter,
    _audio_url_host,
    _sanitize_feedback_text,
)


# ---------------------------------------------------------------------------
# Fixtures — inline ElevenLabs /v1/history records (no elevenlabs package required)
# ---------------------------------------------------------------------------


def _item(
    *,
    history_item_id: str = "hist-1",
    request_id: str = "req-1",
    voice_id: str = "21m00Tcm4TlvDq8ikWAM",
    voice_name: str = "Rachel",
    voice_category: str = "premade",
    model_id: str = "eleven_multilingual_v2",
    text_length_chars: int = 1234,
    duration_seconds: float = 24.5,
    request_method: str = "tts",
    status: str = "succeeded",
    is_pvc: bool = False,
    is_iv: bool = False,
    consent_signed_at: str | None = None,
    share_link_id: str | None = None,
    feedback: dict | None = None,
    audio_url: str | None = None,
    audio_url_host: str | None = "elevenlabs.io",
    error: str | None = None,
    started_at: str = "2026-04-01T12:00:00Z",
    language: str = "en",
    speaker_id: str | None = None,
    voice_settings: dict | None = None,
    content_type: str = "audio/mpeg",
    character_count_change_from: int = 0,
    character_count_change_to: int = 1234,
) -> dict:
    item: dict = {
        "history_item_id": history_item_id,
        "request_id": request_id,
        "voice_id": voice_id,
        "voice_name": voice_name,
        "voice_category": voice_category,
        "model_id": model_id,
        "text_length_chars": text_length_chars,
        "character_count_change_from": character_count_change_from,
        "character_count_change_to": character_count_change_to,
        "content_type": content_type,
        "language": language,
        "speaker_id": speaker_id,
        "is_pvc": is_pvc,
        "is_iv": is_iv,
        "consent_signed_at": consent_signed_at,
        "share_link_id": share_link_id,
        "started_at": started_at,
        "duration_seconds": duration_seconds,
        "request_method": request_method,
        "status": status,
        "feedback": feedback if feedback is not None else {"thumbs_up": True},
        "voice_settings": voice_settings if voice_settings is not None else {
            "stability": 0.5,
            "similarity_boost": 0.75,
            "style": 0,
            "use_speaker_boost": True,
        },
    }
    if audio_url is not None:
        item["audio_url"] = audio_url
    if audio_url_host is not None:
        item["audio_url_host"] = audio_url_host
    if error is not None:
        item["error"] = error
    return item


def _export(*items: dict, envelope: str = "history") -> str:
    return json.dumps({envelope: list(items)})


# ---------------------------------------------------------------------------
# Voice-provenance signal tests
# ---------------------------------------------------------------------------


def test_parse_premade_voice_passes() -> None:
    """A premade voice (verified ElevenLabs catalog voice) yields PR-01 PASS."""
    doc = _export(_item(voice_category="premade", voice_name="Rachel"))
    results = ElevenLabsImporter().parse_string(doc)

    assert len(results) == 1
    res = results[0]
    assert res.source_type == "elevenlabs_import"
    assert res.action_id == "elevenlabs-hist-1"
    assert res.decision == "ALLOW"
    assert len(res.control_results) == 1
    cr = res.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "voice_premade"
    assert cr.evidence_data["voice_name"] == "Rachel"
    assert cr.evidence_data["voice_category"] == "premade"


def test_cloned_voice_iv_with_consent_flags() -> None:
    """An instant voice clone WITH a consent timestamp yields PR-01 FLAG, not FAIL."""
    doc = _export(
        _item(
            voice_category="cloned",
            is_iv=True,
            voice_name="Custom Voice 1",
            consent_signed_at="2026-03-15T09:00:00Z",
        )
    )
    results = ElevenLabsImporter().parse_string(doc)

    assert len(results) == 1
    res = results[0]
    assert res.decision == "FLAG"
    cr = res.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cloned_voice_iv_with_consent"
    assert cr.evidence_data["consent_signed_at"] == "2026-03-15T09:00:00Z"
    assert cr.evidence_data["is_iv"] is True


def test_cloned_voice_pvc_with_consent_flags() -> None:
    """A professional voice clone WITH consent yields PR-01 FLAG."""
    doc = _export(
        _item(
            voice_category="cloned",
            is_pvc=True,
            voice_name="Pro Voice Alpha",
            consent_signed_at="2026-01-10T12:00:00Z",
        )
    )
    results = ElevenLabsImporter().parse_string(doc)

    res = results[0]
    assert res.decision == "FLAG"
    cr = res.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cloned_voice_pvc_with_consent"
    assert cr.evidence_data["is_pvc"] is True


def test_cloned_voice_no_consent_fails() -> None:
    """A cloned voice WITHOUT consent escalates to DE-01 FAIL — legal liability surface."""
    doc = _export(
        _item(
            voice_category="cloned",
            is_iv=True,
            voice_name="Suspect Clone",
            consent_signed_at=None,
        )
    )
    results = ElevenLabsImporter().parse_string(doc)

    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "cloned_voice_no_consent"
    assert cr.evidence_data["consent_signed_at"] is None


def test_professional_voice_passes() -> None:
    """A professional voice (ElevenLabs vetted) passes PR-01."""
    doc = _export(_item(voice_category="professional", voice_name="ProVoice"))
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "ALLOW"
    assert res.control_results[0].control_id == "PR-01"
    assert res.control_results[0].result == "PASS"
    assert res.control_results[0].evidence_data["signal"] == "voice_professional"


def test_generated_voice_passes() -> None:
    """A generated (synthetic) voice passes PR-01."""
    doc = _export(_item(voice_category="generated", voice_name="SynthOne"))
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "ALLOW"
    assert res.control_results[0].result == "PASS"
    assert res.control_results[0].evidence_data["signal"] == "voice_generated"


# ---------------------------------------------------------------------------
# Failure / status signal tests
# ---------------------------------------------------------------------------


def test_failed_status_marks_fail() -> None:
    """``status=failed`` yields DE-01 FAIL regardless of voice category."""
    doc = _export(
        _item(
            history_item_id="hist-fail",
            voice_category="premade",
            status="failed",
            error="upstream timeout",
        )
    )
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    cr = res.control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "status_failed"
    assert cr.evidence_data["error"] == "upstream timeout"


# ---------------------------------------------------------------------------
# request_method signals — voice creation, voice transformation, sharing
# ---------------------------------------------------------------------------


def test_voice_clone_method_flags() -> None:
    """``request_method=voice_clone`` adds a PR-05 FLAG audit-trail signal."""
    doc = _export(
        _item(
            request_method="voice_clone",
            voice_category="cloned",
            is_iv=True,
            consent_signed_at="2026-03-15T09:00:00Z",
        )
    )
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    pr05 = [cr for cr in res.control_results if cr.control_id == "PR-05"]
    assert len(pr05) == 1
    assert pr05[0].result == "FLAG"
    assert pr05[0].evidence_data["signal"] == "voice_clone_method"


def test_voice_design_method_flags() -> None:
    """``request_method=voice_design`` adds a PR-05 FLAG."""
    doc = _export(
        _item(
            request_method="voice_design",
            voice_category="generated",
            voice_name="DesignedVoice",
        )
    )
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    pr05 = [cr for cr in res.control_results if cr.control_id == "PR-05"]
    assert len(pr05) == 1
    assert pr05[0].evidence_data["signal"] == "voice_design_method"


def test_speech_to_speech_method_flags() -> None:
    """``request_method=speech_to_speech`` adds a PR-04 FLAG (voice transformation)."""
    doc = _export(
        _item(
            request_method="speech_to_speech",
            voice_category="premade",
            voice_name="Rachel",
        )
    )
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    pr04 = [
        cr for cr in res.control_results
        if cr.control_id == "PR-04"
        and cr.evidence_data.get("signal") == "speech_to_speech_method"
    ]
    assert len(pr04) == 1


def test_share_link_flags_exfiltration() -> None:
    """A ``share_link_id`` adds a PR-04 FLAG — exfiltration surface."""
    doc = _export(_item(share_link_id="share-abc-123"))
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    pr04 = [
        cr for cr in res.control_results
        if cr.control_id == "PR-04"
        and cr.evidence_data.get("signal") == "share_link_present"
    ]
    assert len(pr04) == 1
    assert pr04[0].evidence_data["share_link_id"] == "share-abc-123"


def test_long_text_flags_overgeneration() -> None:
    """``text_length_chars`` exceeding the threshold adds a PR-04 FLAG."""
    doc = _export(_item(text_length_chars=120000))
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    pr04 = [
        cr for cr in res.control_results
        if cr.control_id == "PR-04"
        and cr.evidence_data.get("signal") == "long_text_overgeneration"
    ]
    assert len(pr04) == 1
    assert pr04[0].evidence_data["text_length_threshold"] == 50000
    assert pr04[0].evidence_data["text_length_chars"] == 120000


def test_long_text_threshold_override() -> None:
    """Constructor ``text_length_threshold`` overrides the default."""
    doc = _export(_item(text_length_chars=8000))
    importer = ElevenLabsImporter(text_length_threshold=5000)
    res = importer.parse_string(doc)[0]
    pr04 = [
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "long_text_overgeneration"
    ]
    assert len(pr04) == 1


# ---------------------------------------------------------------------------
# Sanitization tests — ensure user-typed feedback and full audio URLs do NOT leak
# ---------------------------------------------------------------------------


def test_feedback_text_redacted() -> None:
    """``feedback.feedback_text`` is fingerprinted (length + sha256), never stored verbatim."""
    secret_text = "this contains john.doe@example.com and SSN 123-45-6789"
    doc = _export(
        _item(
            feedback={
                "thumbs_up": False,
                "feedback_text": secret_text,
            }
        )
    )
    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    summary = res.control_results[0].evidence_data["feedback_text_summary"]

    assert summary["present"] is True
    assert summary["byte_length"] == len(secret_text.encode("utf-8"))
    assert summary["sha256"] == hashlib.sha256(secret_text.encode("utf-8")).hexdigest()
    # The verbatim text must NEVER appear anywhere in serialized evidence.
    serialized = json.dumps(res.control_results[0].evidence_data, default=str)
    assert "john.doe@example.com" not in serialized
    assert "123-45-6789" not in serialized
    assert "feedback_text" not in summary

    # thumbs_up structural metadata is preserved.
    assert res.control_results[0].evidence_data["feedback_thumbs_up"] is False


def test_audio_url_only_host_stored() -> None:
    """A full ``audio_url`` is reduced to host only via urlsplit."""
    full_url = "https://elevenlabs.io/private/audio/abc123/secret.mp3?token=xyz"
    doc = json.dumps({"history": [_item(audio_url=full_url, audio_url_host=None)]})
    # Manually drop audio_url_host so importer falls back to parsing audio_url.
    parsed = json.loads(doc)
    parsed["history"][0].pop("audio_url_host", None)
    doc = json.dumps(parsed)

    results = ElevenLabsImporter().parse_string(doc)
    res = results[0]
    evidence = res.control_results[0].evidence_data
    assert evidence["audio_url_host"] == "elevenlabs.io"
    serialized = json.dumps(evidence, default=str)
    assert "/private/audio/abc123" not in serialized
    assert "token=xyz" not in serialized


# ---------------------------------------------------------------------------
# Shape parsing
# ---------------------------------------------------------------------------


def test_jsonl_stream() -> None:
    """A JSONL stream of bare records is parsed into one EvaluationResult per line."""
    jsonl = "\n".join(
        [
            json.dumps(_item(history_item_id="h1", voice_category="premade")),
            json.dumps(_item(history_item_id="h2", voice_category="generated")),
            json.dumps(
                _item(
                    history_item_id="h3",
                    voice_category="cloned",
                    is_iv=True,
                    consent_signed_at=None,
                )
            ),
            "",  # blank line tolerated
        ]
    )
    results = ElevenLabsImporter().parse_string(jsonl)
    assert len(results) == 3
    assert results[0].decision == "ALLOW"
    assert results[1].decision == "ALLOW"
    assert results[2].decision == "BLOCK"
    assert results[2].control_results[0].evidence_data["signal"] == "cloned_voice_no_consent"


# ---------------------------------------------------------------------------
# File-level provenance
# ---------------------------------------------------------------------------


class TestFileProvenance:
    def test_parse_records_file_sha256(self, tmp_path: Path) -> None:
        export_path = tmp_path / "elevenlabs_history.json"
        body = _export(_item())
        export_path.write_text(body)
        expected_sha = hashlib.sha256(body.encode("utf-8")).hexdigest()

        results = ElevenLabsImporter().parse(export_path)
        assert len(results) == 1
        sp = results[0].control_results[0].evidence_data["source_provenance"]
        assert sp["original_file_sha256"] == expected_sha
        assert sp["source_format"] == "elevenlabs"
        assert sp["history_item_id"] == "hist-1"


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://elevenlabs.io/private/foo.mp3", "elevenlabs.io"),
        ("https://api.elevenlabs.io/v1/history/abc/audio?x=1", "api.elevenlabs.io"),
        (None, None),
        ("", None),
    ],
)
def test_audio_url_host_helper(url, expected) -> None:
    assert _audio_url_host(url) == expected


def test_sanitize_feedback_text_none() -> None:
    assert _sanitize_feedback_text(None) == {"present": False}


def test_envelope_data_alias() -> None:
    """``{"data": [...]}`` envelope is accepted as an alternative to ``{"history": [...]}``."""
    doc = _export(_item(history_item_id="hist-data"), envelope="data")
    results = ElevenLabsImporter().parse_string(doc)
    assert len(results) == 1
    assert results[0].action_id == "elevenlabs-hist-data"


def test_bare_object_accepted() -> None:
    """A single bare record (no envelope) is parsed as one history item."""
    doc = json.dumps(_item(history_item_id="hist-bare"))
    results = ElevenLabsImporter().parse_string(doc)
    assert len(results) == 1
    assert results[0].action_id == "elevenlabs-hist-bare"
