"""Tests for the Deepgram speech-to-text request-log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers import DeepgramImporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _request(**overrides) -> dict:
    """Build a minimally-realistic Deepgram /v1/listen request log entry."""
    base: dict = {
        "request_id": "req-001",
        "started_at": "2026-04-15T12:00:00Z",
        "duration_seconds": 42.0,
        "model": "nova-3",
        "language": "en-US",
        "tier": "nova",
        "callback_url": None,
        "channels": 1,
        "sample_rate": 16000,
        "diarize": True,
        "redact": ["pci", "ssn", "numbers"],
        "smart_format": True,
        "summarize": None,
        "topics": False,
        "intents": False,
        "sentiment": False,
        "filler_words": False,
        "punctuate": True,
        "utterances_count": 12,
        "speakers_count": 2,
        "audio_format": "wav",
        "input_source": "buffer",
        "input_url_host": None,
        "size_bytes": 512000,
        "characters_billed": 4000,
        "status": "completed",
        "error_code": None,
        "is_streaming": False,
        "metadata": {"customer_id": "cust-1", "session_id": "sess-1"},
    }
    base.update(overrides)
    return base


def _envelope(*requests: dict) -> dict:
    return {"results": list(requests)}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_completed_request():
    """status=completed with redact configured → PR-04 PASS, ALLOW."""
    importer = DeepgramImporter()
    results = importer.parse_string(json.dumps(_envelope(_request())))

    assert len(results) == 1
    res = results[0]
    assert res.source_type == "deepgram_import"
    assert res.action_id == "deepgram-req-001"
    assert res.session_id == "sess-1"
    assert res.decision == "ALLOW"

    pass_crs = [cr for cr in res.control_results if cr.result == "PASS"]
    assert any(cr.control_id == "PR-04" for cr in pass_crs)
    completed_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "status_completed"
    )
    assert completed_cr.evidence_data["model"] == "nova-3"
    assert completed_cr.evidence_data["language"] == "en-US"
    assert completed_cr.evidence_data["duration_seconds"] == 42.0
    assert completed_cr.evidence_data["characters_billed"] == 4000
    assert completed_cr.evidence_data["audio_format"] == "wav"
    assert completed_cr.evidence_data["channels"] == 1
    assert completed_cr.evidence_data["sample_rate"] == 16000
    assert completed_cr.evidence_data["redact_modes"] == ["pci", "ssn", "numbers"]
    assert completed_cr.evidence_data["speakers_count"] == 2
    assert completed_cr.evidence_data["customer_id"] == "cust-1"
    assert completed_cr.evidence_data["session_id"] == "sess-1"


def test_failed_status_marks_fail():
    """status=failed → DE-01 FAIL → BLOCK."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(_envelope(_request(status="failed", error_code="upstream_timeout")))
    )
    res = results[0]
    assert res.decision == "BLOCK"
    fail_crs = [cr for cr in res.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "DE-01"
        and cr.evidence_data.get("signal") == "status_failed"
        for cr in fail_crs
    )
    failed_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "status_failed"
    )
    assert failed_cr.evidence_data["error_code"] == "upstream_timeout"


def test_rejected_status_flags():
    """status=rejected → PR-02 FLAG → FLAG."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(_envelope(_request(status="rejected", error_code="quota_exceeded")))
    )
    res = results[0]
    assert res.decision == "FLAG"
    flag_crs = [cr for cr in res.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-02"
        and cr.evidence_data.get("signal") == "status_rejected"
        for cr in flag_crs
    )


def test_long_audio_no_redact_fails_pii():
    """No redact configured AND duration > threshold → PR-04 FAIL → BLOCK."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(duration_seconds=180.5, redact=[], status="completed")
            )
        )
    )
    res = results[0]
    assert res.decision == "BLOCK"
    fail_crs = [cr for cr in res.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "PR-04"
        and cr.evidence_data.get("signal") == "long_audio_no_redact"
        for cr in fail_crs
    )

    # Below the threshold should NOT fire the PII signal.
    short = importer.parse_string(
        json.dumps(_envelope(_request(duration_seconds=10.0, redact=[])))
    )[0]
    assert not any(
        cr.evidence_data.get("signal") == "long_audio_no_redact"
        for cr in short.control_results
    )


def test_diarize_off_multispeaker_flags_audit():
    """diarize=false AND speakers_count=null AND duration > 30s → PR-05 FLAG."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(
                    diarize=False,
                    speakers_count=None,
                    duration_seconds=120.0,
                )
            )
        )
    )
    res = results[0]
    assert res.decision == "FLAG"
    assert any(
        cr.control_id == "PR-05"
        and cr.evidence_data.get("signal") == "diarize_off_multispeaker"
        for cr in res.control_results
    )

    # diarize=true should suppress the multispeaker flag.
    on = importer.parse_string(
        json.dumps(
            _envelope(
                _request(diarize=True, speakers_count=None, duration_seconds=120.0)
            )
        )
    )[0]
    assert not any(
        cr.evidence_data.get("signal") == "diarize_off_multispeaker"
        for cr in on.control_results
    )


def test_callback_url_unknown_host_flags():
    """callback_url with host not on allowlist → PR-04 FLAG; full URL never stored."""
    importer = DeepgramImporter()  # default empty allowlist
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(callback_url="https://evil.example.com/webhook?token=abc123")
            )
        )
    )
    res = results[0]
    assert res.decision == "FLAG"
    flagged = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "callback_url_unknown_host"
    )
    assert flagged.control_id == "PR-04"
    assert flagged.evidence_data["callback_host"] == "evil.example.com"


def test_callback_url_allowlisted_host_passes():
    """callback_url host on allowlist → no callback flag (only PASS controls)."""
    importer = DeepgramImporter(
        callback_host_allowlist=["webhooks.mycompany.internal"]
    )
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(callback_url="https://webhooks.mycompany.internal/dg/post")
            )
        )
    )
    res = results[0]
    assert res.decision == "ALLOW"
    assert not any(
        cr.evidence_data.get("signal") == "callback_url_unknown_host"
        for cr in res.control_results
    )
    completed_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "status_completed"
    )
    assert completed_cr.evidence_data["callback_host"] == "webhooks.mycompany.internal"


def test_streaming_source_logged_audit():
    """input_source=stream → PR-05 PASS audit ControlResult attached."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(input_source="stream", is_streaming=True, redact=["pci"])
            )
        )
    )
    res = results[0]
    stream_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "stream_source"
    )
    assert stream_cr.control_id == "PR-05"
    assert stream_cr.result == "PASS"
    assert res.decision == "ALLOW"


def test_url_source_public_cdn_flags():
    """input_source=url with public CDN host → PR-04 FLAG."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(
                    input_source="url",
                    input_url_host="s3.amazonaws.com",
                )
            )
        )
    )
    res = results[0]
    assert res.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.evidence_data.get("signal") == "url_source_public_cdn"
        for cr in res.control_results
    )

    # Private host should NOT fire the CDN signal.
    private = importer.parse_string(
        json.dumps(
            _envelope(
                _request(
                    input_source="url", input_url_host="audio.internal.corp"
                )
            )
        )
    )[0]
    assert not any(
        cr.evidence_data.get("signal") == "url_source_public_cdn"
        for cr in private.control_results
    )


def test_analytics_features_captured_in_evidence():
    """sentiment / topics / intents on → reflected in evidence_data.analytics_features."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(
                    sentiment=True,
                    topics=True,
                    intents=True,
                    summarize="v2",
                )
            )
        )
    )
    res = results[0]
    completed_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "status_completed"
    )
    feats = completed_cr.evidence_data["analytics_features"]
    assert feats["sentiment"] is True
    assert feats["topics"] is True
    assert feats["intents"] is True
    assert feats["summarize"] == "v2"


def test_base_tier_on_high_volume_flags():
    """tier=base on production-volume traffic → PR-03 FLAG."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(tier="base", characters_billed=42000)
            )
        )
    )
    res = results[0]
    assert res.decision == "FLAG"
    flagged = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "base_tier_high_volume"
    )
    assert flagged.control_id == "PR-03"
    assert flagged.evidence_data["base_tier_high_volume_chars"] == 10000

    # Base tier on LOW volume traffic should NOT fire.
    low_vol = importer.parse_string(
        json.dumps(_envelope(_request(tier="base", characters_billed=500)))
    )[0]
    assert not any(
        cr.evidence_data.get("signal") == "base_tier_high_volume"
        for cr in low_vol.control_results
    )

    # Nova tier on high volume should NOT fire either.
    nova_vol = importer.parse_string(
        json.dumps(_envelope(_request(tier="nova", characters_billed=42000)))
    )[0]
    assert not any(
        cr.evidence_data.get("signal") == "base_tier_high_volume"
        for cr in nova_vol.control_results
    )


def test_callback_url_full_value_not_stored():
    """The full callback_url (path + query) must NEVER appear anywhere in evidence."""
    importer = DeepgramImporter()
    secret_path = "/super-secret-webhook-path"
    secret_query = "?token=PII_TOKEN_DO_NOT_LEAK"
    full_url = f"https://attacker.example.com{secret_path}{secret_query}"
    results = importer.parse_string(
        json.dumps(_envelope(_request(callback_url=full_url)))
    )
    res = results[0]

    # Serialize entire evaluation to JSON and ensure neither the path nor the
    # query string is anywhere — only the host should survive.
    serialized = json.dumps(
        {
            "decision": res.decision,
            "control_results": [
                {
                    "control_id": cr.control_id,
                    "evidence_data": cr.evidence_data,
                    "detail": cr.detail,
                }
                for cr in res.control_results
            ],
        },
        default=str,
    )
    assert "super-secret-webhook-path" not in serialized
    assert "PII_TOKEN_DO_NOT_LEAK" not in serialized
    assert full_url not in serialized
    # But the host alone IS retained for audit lineage.
    assert "attacker.example.com" in serialized


def test_metadata_values_redacted():
    """Only customer_id and session_id from metadata survive — other keys dropped."""
    importer = DeepgramImporter()
    results = importer.parse_string(
        json.dumps(
            _envelope(
                _request(
                    metadata={
                        "customer_id": "cust-42",
                        "session_id": "sess-9",
                        # The next two are operator-supplied and could embed PII.
                        "patient_ssn": "123-45-6789",
                        "internal_note": "transcript fragment with names",
                    }
                )
            )
        )
    )
    res = results[0]
    completed_cr = next(
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "status_completed"
    )
    assert completed_cr.evidence_data["customer_id"] == "cust-42"
    assert completed_cr.evidence_data["session_id"] == "sess-9"
    assert completed_cr.evidence_data["suppressed_metadata_keys"] == 2

    # Confirm no PII metadata leaked into any field of any control result.
    serialized = json.dumps(
        [cr.evidence_data for cr in res.control_results], default=str
    )
    assert "123-45-6789" not in serialized
    assert "patient_ssn" not in serialized
    assert "internal_note" not in serialized
    assert "transcript fragment" not in serialized


def test_jsonl_stream():
    """JSONL: one Deepgram request object per line."""
    importer = DeepgramImporter()
    lines = [
        json.dumps(_request(request_id="req-A", status="completed")),
        json.dumps(_request(request_id="req-B", status="failed", error_code="oops")),
        json.dumps(_request(request_id="req-C", status="rejected")),
    ]
    results = importer.parse_string("\n".join(lines))
    assert len(results) == 3
    assert {r.action_id for r in results} == {
        "deepgram-req-A",
        "deepgram-req-B",
        "deepgram-req-C",
    }
    decisions = {r.action_id: r.decision for r in results}
    assert decisions["deepgram-req-A"] == "ALLOW"
    assert decisions["deepgram-req-B"] == "BLOCK"
    assert decisions["deepgram-req-C"] == "FLAG"


def test_source_provenance_includes_file_hash(tmp_path: Path):
    """parse(path) must hash the original file and include it in source_provenance."""
    payload = json.dumps(_envelope(_request()))
    p = tmp_path / "dg_export.json"
    p.write_text(payload, encoding="utf-8")
    expected_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    importer = DeepgramImporter()
    results = importer.parse(p)
    assert len(results) == 1
    cr = results[0].control_results[0]
    provenance = cr.evidence_data["source_provenance"]
    assert provenance["source_format"] == "deepgram"
    assert provenance["source_tool_name"] == "deepgram"
    assert provenance["original_file_sha256"] == expected_sha

    # parse_string must NOT include a file hash (no file involved).
    str_results = importer.parse_string(payload)
    str_provenance = str_results[0].control_results[0].evidence_data[
        "source_provenance"
    ]
    assert "original_file_sha256" not in str_provenance
