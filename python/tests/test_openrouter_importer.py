"""Tests for the OpenRouter generation-log evidence importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers.openrouter import OpenRouterImporter


# ---------------------------------------------------------------------------
# Fixtures — inline OpenRouter generation records (no openrouter package required)
# ---------------------------------------------------------------------------


def _gen(
    *,
    id: str = "gen-abc123",
    model: str = "anthropic/claude-3.5-sonnet",
    provider_name: str = "Anthropic",
    finish_reason: str = "stop",
    streamed: bool = True,
    cancelled: bool = False,
    is_byok: bool = False,
    usage: float = 0.001,
    tokens_prompt: int = 100,
    tokens_completion: int = 50,
    native_tokens_prompt: int = 100,
    native_tokens_completion: int = 50,
    moderation_latency: int = 50,
    generation_time: int = 1234,
    latency: int = 1500,
    created_at: str = "2026-04-01T12:00:00Z",
    app_id: str = "app-1",
    external_user: str = "user-42",
    origin: str = "https://example.com/agent",
    num_media_prompt: int = 0,
    num_search_results: int = 0,
) -> dict:
    return {
        "id": id,
        "model": model,
        "provider_name": provider_name,
        "streamed": streamed,
        "cancelled": cancelled,
        "tokens_prompt": tokens_prompt,
        "tokens_completion": tokens_completion,
        "native_tokens_prompt": native_tokens_prompt,
        "native_tokens_completion": native_tokens_completion,
        "num_media_prompt": num_media_prompt,
        "num_search_results": num_search_results,
        "origin": origin,
        "usage": usage,
        "is_byok": is_byok,
        "finish_reason": finish_reason,
        "moderation_latency": moderation_latency,
        "generation_time": generation_time,
        "latency": latency,
        "created_at": created_at,
        "app_id": app_id,
        "external_user": external_user,
    }


# ---------------------------------------------------------------------------
# Shape parsing
# ---------------------------------------------------------------------------


def test_parse_single_generation() -> None:
    """``{"data": single_obj}`` envelope yields exactly one EvaluationResult."""
    doc = json.dumps({"data": _gen(id="gen-single")})
    results = OpenRouterImporter().parse_string(doc)
    assert len(results) == 1
    assert results[0].source_type == "openrouter_import"
    assert results[0].action_id == "openrouter-gen-single"


def test_parse_data_array() -> None:
    """``{"data": [...]}`` array yields one EvaluationResult per record."""
    doc = json.dumps(
        {
            "data": [
                _gen(id="gen-1"),
                _gen(id="gen-2", finish_reason="length"),
                _gen(id="gen-3"),
            ]
        }
    )
    results = OpenRouterImporter().parse_string(doc)
    assert len(results) == 3
    assert {r.action_id for r in results} == {
        "openrouter-gen-1",
        "openrouter-gen-2",
        "openrouter-gen-3",
    }


def test_jsonl_stream() -> None:
    """JSONL — one record per line — is parsed as multiple records."""
    lines = [
        json.dumps(_gen(id="gen-jsonl-1")),
        json.dumps(_gen(id="gen-jsonl-2", finish_reason="length")),
        json.dumps({"data": _gen(id="gen-jsonl-3")}),  # envelope per line is OK
        "",  # blank lines tolerated
    ]
    results = OpenRouterImporter().parse_string("\n".join(lines))
    assert len(results) == 3
    assert {r.action_id for r in results} == {
        "openrouter-gen-jsonl-1",
        "openrouter-gen-jsonl-2",
        "openrouter-gen-jsonl-3",
    }


# ---------------------------------------------------------------------------
# finish_reason → control mapping
# ---------------------------------------------------------------------------


def test_finish_reason_stop_passes() -> None:
    """finish_reason='stop' produces a single PR-01 PASS and an ALLOW decision."""
    doc = json.dumps({"data": _gen(finish_reason="stop", usage=0.001)})
    [result] = OpenRouterImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert len(result.control_results) == 1
    cr = result.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "finish_reason_stop"
    assert cr.evidence_data["finish_reason"] == "stop"


def test_finish_reason_content_filter_flags() -> None:
    """finish_reason='content_filter' produces a PR-02 FLAG (moderation triggered)."""
    doc = json.dumps(
        {"data": _gen(finish_reason="content_filter", moderation_latency=200)}
    )
    [result] = OpenRouterImporter().parse_string(doc)
    assert result.decision == "FLAG"
    pr02 = [cr for cr in result.control_results if cr.control_id == "PR-02"]
    assert len(pr02) == 1
    assert pr02[0].result == "FLAG"
    assert pr02[0].evidence_data["signal"] == "finish_reason_content_filter"
    assert pr02[0].evidence_data["moderation_latency_ms"] == 200.0


def test_finish_reason_error_fails() -> None:
    """finish_reason='error' produces a DE-01 FAIL and a BLOCK decision."""
    doc = json.dumps({"data": _gen(finish_reason="error")})
    [result] = OpenRouterImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    de01 = [cr for cr in result.control_results if cr.control_id == "DE-01"]
    assert len(de01) == 1
    assert de01[0].result == "FAIL"
    assert de01[0].evidence_data["signal"] == "finish_reason_error"


# ---------------------------------------------------------------------------
# Additive flags
# ---------------------------------------------------------------------------


def test_cancelled_flags() -> None:
    """cancelled=True adds a PR-05 audit-trail FLAG even when finish_reason=stop."""
    doc = json.dumps({"data": _gen(finish_reason="stop", cancelled=True)})
    [result] = OpenRouterImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cancelled_flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "cancelled"
    ]
    assert len(cancelled_flags) == 1
    assert cancelled_flags[0].control_id == "PR-05"
    assert cancelled_flags[0].result == "FLAG"


def test_byok_flags() -> None:
    """is_byok=True adds a PR-04 key-exposure FLAG."""
    doc = json.dumps({"data": _gen(finish_reason="stop", is_byok=True)})
    [result] = OpenRouterImporter().parse_string(doc)
    assert result.decision == "FLAG"
    byok_flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "is_byok"
    ]
    assert len(byok_flags) == 1
    assert byok_flags[0].control_id == "PR-04"
    assert byok_flags[0].result == "FLAG"


def test_cost_threshold_flag() -> None:
    """usage above the configured threshold adds a PR-04 exposure FLAG."""
    # Default threshold is $1; use $5 to clear it.
    doc = json.dumps({"data": _gen(finish_reason="stop", usage=5.0)})
    [result] = OpenRouterImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cost_flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "cost_threshold_exceeded"
    ]
    assert len(cost_flags) == 1
    assert cost_flags[0].control_id == "PR-04"
    assert cost_flags[0].evidence_data["cost_threshold_usd"] == 1.0
    assert cost_flags[0].evidence_data["usage_usd"] == 5.0

    # And the threshold is configurable.
    [result_high] = OpenRouterImporter(cost_threshold_usd=10.0).parse_string(doc)
    cost_flags_high = [
        cr
        for cr in result_high.control_results
        if cr.evidence_data.get("signal") == "cost_threshold_exceeded"
    ]
    assert cost_flags_high == []
    assert result_high.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Provider routing & evidence shape
# ---------------------------------------------------------------------------


def test_provider_routing_captured() -> None:
    """provider_name is surfaced as evidence_data.provider_routed_to on every control."""
    doc = json.dumps(
        {
            "data": _gen(
                id="gen-routing",
                provider_name="Mistral",
                model="mistralai/mistral-large",
                finish_reason="stop",
            )
        }
    )
    [result] = OpenRouterImporter().parse_string(doc)
    assert all(
        cr.evidence_data["provider_routed_to"] == "Mistral"
        for cr in result.control_results
    )
    assert all(
        cr.evidence_data["model"] == "mistralai/mistral-large"
        for cr in result.control_results
    )
    # Native and normalized token counts both surface, distinct.
    cr = result.control_results[0]
    assert cr.evidence_data["tokens"] == {"prompt": 100, "completion": 50, "total": 150}
    assert cr.evidence_data["native_tokens"] == {
        "prompt": 100,
        "completion": 50,
        "total": 150,
    }
    assert cr.evidence_data["generation_time_ms"] == 1234.0
    assert cr.evidence_data["moderation_latency_ms"] == 50.0


def test_clean_export_yields_pass() -> None:
    """A whole array of clean stop/length generations produces only PASS / ALLOW."""
    doc = json.dumps(
        {
            "data": [
                _gen(id=f"gen-clean-{i}", finish_reason=("stop" if i % 2 == 0 else "length"))
                for i in range(4)
            ]
        }
    )
    results = OpenRouterImporter().parse_string(doc)
    assert len(results) == 4
    for r in results:
        assert r.decision == "ALLOW"
        assert len(r.control_results) == 1
        assert r.control_results[0].result == "PASS"
        assert r.control_results[0].control_id == "PR-01"


# ---------------------------------------------------------------------------
# Source provenance
# ---------------------------------------------------------------------------


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) hashes the file bytes and surfaces the hash in source_provenance."""
    payload = json.dumps({"data": [_gen(id="gen-prov")]}).encode("utf-8")
    expected_sha = hashlib.sha256(payload).hexdigest()
    file_path = tmp_path / "openrouter-export.json"
    file_path.write_bytes(payload)

    [result] = OpenRouterImporter().parse(file_path)
    cr = result.control_results[0]
    provenance = cr.evidence_data["source_provenance"]
    assert provenance["source_format"] == "openrouter"
    assert provenance["source_tool_name"] == "openrouter"
    assert provenance["generation_id"] == "gen-prov"
    assert provenance["original_file_sha256"] == expected_sha

    # parse_string omits original_file_sha256 — there is no on-disk file.
    [result_str] = OpenRouterImporter().parse_string(payload.decode("utf-8"))
    assert "original_file_sha256" not in result_str.control_results[0].evidence_data[
        "source_provenance"
    ]


# ---------------------------------------------------------------------------
# Extras — bare list shape, unknown finish_reason, mapping JSON validity
# ---------------------------------------------------------------------------


def test_bare_list_shape_is_supported() -> None:
    """A bare JSON array of records (no envelope) parses correctly."""
    doc = json.dumps([_gen(id="gen-bare-1"), _gen(id="gen-bare-2")])
    results = OpenRouterImporter().parse_string(doc)
    assert {r.action_id for r in results} == {
        "openrouter-gen-bare-1",
        "openrouter-gen-bare-2",
    }


def test_unknown_finish_reason_flags() -> None:
    """An unrecognized finish_reason surfaces as a PR-02 FLAG, not a silent PASS."""
    doc = json.dumps({"data": _gen(finish_reason="weird_new_reason")})
    [result] = OpenRouterImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = result.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "finish_reason_unknown"


def test_mapping_table_is_valid_json() -> None:
    """The shipped mapping table must be valid JSON with the required signals."""
    mapping_path = (
        Path(__file__).resolve().parent.parent.parent
        / "shared"
        / "mappings"
        / "openrouter-aksi-controls.json"
    )
    data = json.loads(mapping_path.read_text())
    assert data["_metadata"]["default_cost_threshold_usd"] == 1.0
    mappings = data["mappings"]
    assert mappings["finish_reason_stop"] == "PR-01"
    assert mappings["finish_reason_length"] == "PR-01"
    assert mappings["finish_reason_content_filter"] == "PR-02"
    assert mappings["finish_reason_error"] == "DE-01"
    assert mappings["cancelled"] == "PR-05"
    assert mappings["is_byok"] == "PR-04"
    assert mappings["cost_threshold_exceeded"] == "PR-04"


def test_importer_exported_from_package() -> None:
    """OpenRouterImporter is exported from ancilis.importers."""
    from ancilis.importers import OpenRouterImporter as Exported

    assert Exported is OpenRouterImporter
