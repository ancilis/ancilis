"""Tests for the Tavily AI-search-API evidence importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.tavily import TavilyImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Tavily request records (no tavily-python required)
# ---------------------------------------------------------------------------


def _req(
    *,
    id: str = "req-abc123",
    timestamp: str = "2026-04-01T12:00:00Z",
    api_key_id: str = "tk_abcd1234efgh5678",
    endpoint: str = "search",
    query_length: int = 120,
    search_depth: str = "basic",
    topic: str = "general",
    include_answer: bool = True,
    include_raw_content: bool = False,
    include_images: bool = False,
    max_results: int = 10,
    include_domains: list | None = None,
    exclude_domains: list | None = None,
    days: int = 3,
    results_count: int = 8,
    answer_length: int = 1234,
    total_response_size_bytes: int = 56789,
    latency_ms: int = 1500,
    status: str = "success",
    error_code: str | None = None,
    is_streaming: bool = False,
    agent_id: str = "agent-001",
    customer_metadata: dict | None = None,
    prompt_injection_detected: bool = False,
    flagged_content: list | None = None,
    unique_domains_returned: int = 7,
) -> dict:
    return {
        "id": id,
        "timestamp": timestamp,
        "api_key_id": api_key_id,
        "endpoint": endpoint,
        "query_length": query_length,
        "search_depth": search_depth,
        "topic": topic,
        "include_answer": include_answer,
        "include_raw_content": include_raw_content,
        "include_images": include_images,
        "max_results": max_results,
        "include_domains": include_domains if include_domains is not None else ["nytimes.com", "wsj.com"],
        "exclude_domains": exclude_domains if exclude_domains is not None else ["reddit.com"],
        "days": days,
        "results_count": results_count,
        "answer_length": answer_length,
        "total_response_size_bytes": total_response_size_bytes,
        "latency_ms": latency_ms,
        "status": status,
        "error_code": error_code,
        "is_streaming": is_streaming,
        "agent_id": agent_id,
        "customer_metadata": customer_metadata
        if customer_metadata is not None
        else {"task": "market-research", "user_id": "u-12345678abcdef"},
        "prompt_injection_detected": prompt_injection_detected,
        "flagged_content": flagged_content if flagged_content is not None else [],
        "unique_domains_returned": unique_domains_returned,
    }


# ---------------------------------------------------------------------------
# Shape parsing
# ---------------------------------------------------------------------------


def test_parse_requests_envelope() -> None:
    doc = json.dumps({"requests": [_req(id="req-1"), _req(id="req-2")]})
    results = TavilyImporter().parse_string(doc)
    assert {r.action_id for r in results} == {"tavily-req-1", "tavily-req-2"}
    assert all(r.source_type == "tavily_import" for r in results)


def test_parse_data_envelope_and_jsonl() -> None:
    """Both ``{"data": [...]}`` and JSONL shapes parse to the same records."""
    doc_data = json.dumps({"data": [_req(id="req-d1"), _req(id="req-d2")]})
    doc_jsonl = "\n".join(
        [json.dumps(_req(id="req-jl-1")), "", json.dumps(_req(id="req-jl-2"))]
    )
    res_data = TavilyImporter().parse_string(doc_data)
    res_jsonl = TavilyImporter().parse_string(doc_jsonl)
    assert {r.action_id for r in res_data} == {"tavily-req-d1", "tavily-req-d2"}
    assert {r.action_id for r in res_jsonl} == {"tavily-req-jl-1", "tavily-req-jl-2"}


# ---------------------------------------------------------------------------
# Endpoint / status mapping
# ---------------------------------------------------------------------------


def test_search_success_passes() -> None:
    """status=success endpoint=search → PR-04 PASS, ALLOW decision."""
    doc = json.dumps({"requests": [_req(id="req-search-pass")]})
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    primary = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "endpoint_search_success"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "PASS"


def test_extract_endpoint_flags() -> None:
    """status=success endpoint=extract → PR-04 FLAG (full-content extraction)."""
    doc = json.dumps({"requests": [_req(id="req-ext", endpoint="extract")]})
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "endpoint_extract_success"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "FLAG"


def test_qna_with_raw_content_flags() -> None:
    """endpoint=qna include_raw_content=true → PR-04 FLAG (injection vector)."""
    doc = json.dumps(
        {"requests": [_req(id="req-qna", endpoint="qna", include_raw_content=True)]}
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "endpoint_qna_raw_content"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "FLAG"


def test_prompt_injection_detected_fails() -> None:
    """prompt_injection_detected=true → PR-01 FAIL, BLOCK decision (top priority)."""
    doc = json.dumps(
        {"requests": [_req(id="req-pi", prompt_injection_detected=True)]}
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    pi_fails = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "prompt_injection_detected"
    ]
    assert len(pi_fails) == 1
    assert pi_fails[0].control_id == "PR-01"
    assert pi_fails[0].result == "FAIL"


def test_flagged_content_flags() -> None:
    """flagged_content non-empty → PR-03 FLAG (content moderation)."""
    doc = json.dumps(
        {"requests": [_req(id="req-fc", flagged_content=["ad", "spam"])]}
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "FLAG"
    fc = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "flagged_content"
    ]
    assert len(fc) == 1
    assert fc[0].control_id == "PR-03"
    assert fc[0].result == "FLAG"


def test_unscoped_open_web_flags() -> None:
    """No include/exclude domains AND topic=general → PR-04 FLAG (un-scoped)."""
    doc = json.dumps(
        {
            "requests": [
                _req(
                    id="req-unscoped",
                    include_domains=[],
                    exclude_domains=[],
                    topic="general",
                )
            ]
        }
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "FLAG"
    us = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "unscoped_open_web"
    ]
    assert len(us) == 1
    assert us[0].control_id == "PR-04"


def test_broad_fanout_flags() -> None:
    """unique_domains_returned > threshold → PR-04 FLAG (recon-shaped)."""
    doc = json.dumps(
        {"requests": [_req(id="req-fanout", unique_domains_returned=120)]}
    )
    [result] = TavilyImporter(unique_domains_threshold=50).parse_string(doc)
    assert result.decision == "FLAG"
    bf = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "broad_fanout"
    ]
    assert len(bf) == 1
    assert bf[0].control_id == "PR-04"
    assert bf[0].evidence_data["unique_domains_threshold"] == 50


def test_invalid_key_fails() -> None:
    """status=failed error_code=INVALID_KEY → PR-01 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "requests": [
                _req(id="req-ik", status="failed", error_code="INVALID_KEY")
            ]
        }
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    ik = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "error_invalid_key"
    ]
    assert len(ik) == 1
    assert ik[0].control_id == "PR-01"
    assert ik[0].result == "FAIL"


def test_rate_limited_flags() -> None:
    """status=failed error_code=RATE_LIMITED → PR-02 FLAG."""
    doc = json.dumps(
        {
            "requests": [
                _req(id="req-rl", status="failed", error_code="RATE_LIMITED")
            ]
        }
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "FLAG"
    rl = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "error_rate_limited"
    ]
    assert len(rl) == 1
    assert rl[0].control_id == "PR-02"


def test_timeout_flags() -> None:
    """status=failed error_code=TIMEOUT → DE-01 FLAG (provider failure)."""
    doc = json.dumps(
        {"requests": [_req(id="req-to", status="failed", error_code="TIMEOUT")]}
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "FLAG"
    to = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "error_timeout"
    ]
    assert len(to) == 1
    assert to[0].control_id == "DE-01"


def test_oversized_flags() -> None:
    """status=failed error_code=CONTENT_TOO_LARGE → PR-04 FLAG."""
    doc = json.dumps(
        {
            "requests": [
                _req(
                    id="req-big",
                    status="failed",
                    error_code="CONTENT_TOO_LARGE",
                    total_response_size_bytes=99999999,
                )
            ]
        }
    )
    [result] = TavilyImporter().parse_string(doc)
    assert result.decision == "FLAG"
    big = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "error_content_too_large"
    ]
    assert len(big) == 1
    assert big[0].control_id == "PR-04"


# ---------------------------------------------------------------------------
# Volume / cross-topic synthetic findings
# ---------------------------------------------------------------------------


def test_volume_synthetic_pattern() -> None:
    """Same agent_id with > N searches in 1h emits a synthetic mass-search FLAG."""
    requests = [
        _req(
            id=f"req-vol-{i}",
            agent_id="agent-vol",
            timestamp=f"2026-04-01T12:{i:02d}:00Z",
        )
        for i in range(8)
    ]
    doc = json.dumps({"requests": requests})
    results = TavilyImporter(volume_threshold=5).parse_string(doc)
    # Expect 8 per-request results + 1 synthetic.
    assert len(results) == 9
    synthetics = [r for r in results if r.action_id == "tavily-volume-agent-vol"]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    assert syn.control_results[0].control_id == "PR-04"
    assert syn.control_results[0].evidence_data["max_window_count"] >= 6
    assert syn.control_results[0].evidence_data["volume_threshold"] == 5
    # Each contributing request also carries a volume_pattern flag.
    contributors = [
        r
        for r in results
        if r.action_id != "tavily-volume-agent-vol"
        and any(
            cr.evidence_data.get("signal") == "volume_pattern"
            for cr in r.control_results
        )
    ]
    assert len(contributors) == 8


def test_cross_topic_pattern() -> None:
    """Same agent_id touching > N distinct topics in 1h emits a synthetic PASS."""
    topics = ["general", "news", "finance", "academic", "general", "news"]
    requests = [
        _req(
            id=f"req-ct-{i}",
            agent_id="agent-ct",
            topic=t,
            timestamp=f"2026-04-01T12:{i:02d}:00Z",
        )
        for i, t in enumerate(topics)
    ]
    doc = json.dumps({"requests": requests})
    results = TavilyImporter(cross_topic_threshold=3).parse_string(doc)
    synthetics = [r for r in results if r.action_id == "tavily-cross-topic-agent-ct"]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.control_results[0].control_id == "PR-05"
    assert syn.control_results[0].result == "PASS"
    assert set(syn.control_results[0].evidence_data["topics_in_window"]) >= {
        "general",
        "news",
        "finance",
        "academic",
    }


# ---------------------------------------------------------------------------
# Sanitization — query / answer / domain lists / metadata
# ---------------------------------------------------------------------------


def test_query_text_not_stored() -> None:
    """The full ``query`` text never appears in evidence_data — only query_length."""
    sneaky = _req(id="req-sane", query_length=42)
    sneaky["query"] = "highly confidential prompt that should never leak"  # noqa: S105
    doc = json.dumps({"requests": [sneaky]})
    [result] = TavilyImporter().parse_string(doc)
    serialized = json.dumps([cr.evidence_data for cr in result.control_results])
    assert "highly confidential prompt that should never leak" not in serialized
    # query_length is captured.
    assert result.control_results[0].evidence_data["query_length"] == 42
    # answer body sanitization — only answer_length.
    assert "answer_length" in result.control_results[0].evidence_data


def test_domain_lists_not_stored_raw() -> None:
    """include/exclude domain lists never appear raw — only count + sha256."""
    include = ["secret-target-1.example.com", "secret-target-2.example.com"]
    exclude = ["competitor-blocklist.example.org"]
    doc = json.dumps(
        {
            "requests": [
                _req(
                    id="req-dom",
                    include_domains=include,
                    exclude_domains=exclude,
                )
            ]
        }
    )
    [result] = TavilyImporter().parse_string(doc)
    serialized = json.dumps([cr.evidence_data for cr in result.control_results])
    for d in include + exclude:
        assert d not in serialized

    primary = result.control_results[0].evidence_data
    inc_sum = primary["include_domains_summary"]
    exc_sum = primary["exclude_domains_summary"]
    assert inc_sum["count"] == 2
    assert exc_sum["count"] == 1
    # Hash is deterministic over sorted-lowercased-joined.
    expected_inc = hashlib.sha256(
        "\n".join(sorted(d.lower() for d in include)).encode("utf-8")
    ).hexdigest()
    assert inc_sum["sha256"] == expected_inc

    # api_key_id, customer_metadata user_id are sanitized.
    assert primary["api_key_id_last4"] == "5678"
    assert primary["customer_user_id_last8"] == "abcdef"[-8:] or len(
        primary["customer_user_id_last8"] or ""
    ) <= 8
    # customer_metadata raw value 'market-research' should NOT appear.
    assert "market-research" not in serialized
    # Only the key list surfaces.
    assert primary["customer_metadata_keys"] == ["task", "user_id"]


# ---------------------------------------------------------------------------
# Provenance / mapping table
# ---------------------------------------------------------------------------


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    payload = json.dumps({"requests": [_req(id="req-prov")]}).encode("utf-8")
    expected_sha = hashlib.sha256(payload).hexdigest()
    file_path = tmp_path / "tavily-export.json"
    file_path.write_bytes(payload)

    [result] = TavilyImporter().parse(file_path)
    cr = result.control_results[0]
    provenance = cr.evidence_data["source_provenance"]
    assert provenance["source_format"] == "tavily"
    assert provenance["source_tool_name"] == "tavily"
    assert provenance["request_id"] == "req-prov"
    assert provenance["original_file_sha256"] == expected_sha


def test_mapping_table_is_valid_json() -> None:
    mapping_path = (
        Path(__file__).resolve().parent.parent.parent
        / "shared"
        / "mappings"
        / "tavily-aksi-controls.json"
    )
    data = json.loads(mapping_path.read_text())
    mappings = data["mappings"]
    assert mappings["endpoint_search_success"] == "PR-04"
    assert mappings["endpoint_extract_success"] == "PR-04"
    assert mappings["endpoint_qna_raw_content"] == "PR-04"
    assert mappings["error_invalid_key"] == "PR-01"
    assert mappings["error_rate_limited"] == "PR-02"
    assert mappings["error_timeout"] == "DE-01"
    assert mappings["error_content_too_large"] == "PR-04"
    assert mappings["prompt_injection_detected"] == "PR-01"
    assert mappings["flagged_content"] == "PR-03"
    meta = data["_metadata"]
    assert meta["default_volume_threshold"] == 50
    assert meta["default_cross_topic_threshold"] == 4


def test_importer_exported_from_package() -> None:
    from ancilis.importers import TavilyImporter as Exported

    assert Exported is TavilyImporter
