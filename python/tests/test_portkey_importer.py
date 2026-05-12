"""Tests for the Portkey LLM gateway log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.portkey import PortkeyImporter


# ---------------------------------------------------------------------------
# Fixture builders — inline Portkey /v1/logs entries.
# ---------------------------------------------------------------------------

def _log_entry(
    *,
    id: str = "log-1",
    trace_id: str = "trace-abc",
    timestamp: str = "2026-04-01T12:00:00Z",
    model: str = "gpt-4o",
    provider: str = "openai",
    url: str = "https://api.openai.com/v1/chat/completions",
    virtual_key: str = "vk-prod-openai",
    status_code: int = 200,
    cache_mode: str | None = None,
    cache_status: str | None = None,
    fallback_used: bool = False,
    retry_count: int = 0,
    cost: float = 0.001,
    latency_ms: float = 45.0,
    is_streaming: bool = False,
    before_guardrails: list | None = None,
    after_guardrails: list | None = None,
    user_feedback: dict | None = None,
    loadbalance_targets: list | None = None,
    fallback_targets: list | None = None,
    extra_request: dict | None = None,
    extra_response: dict | None = None,
) -> dict:
    config: dict = {
        "virtual_key": virtual_key,
        "metadata": {"_user": "user-42", "_environment": "prod", "_org_id": "org-x"},
        "retry": {"attempts": 3, "on_status_codes": [429, 500]},
        "request_timeout": 30000,
        "fallback_targets": fallback_targets if fallback_targets is not None else [],
    }
    if cache_mode is not None:
        config["cache"] = {"mode": cache_mode, "max_age": 3600}
    if loadbalance_targets is not None:
        config["loadbalance"] = {
            "targets": loadbalance_targets,
            "weights": [1] * len(loadbalance_targets),
        }

    request = {
        "model": model,
        "provider": provider,
        "method": "POST",
        "url": url,
        "config": config,
    }
    if extra_request:
        request.update(extra_request)

    headers: dict = {}
    if cache_status is not None:
        headers["x-portkey-cache-status"] = cache_status

    response = {
        "status_code": status_code,
        "body_keys": ["choices", "usage", "id", "model"],
        "headers": headers,
        "tokens": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        "cost": cost,
        "latency_ms": latency_ms,
        "fallback_used": fallback_used,
        "retry_count": retry_count,
        "is_streaming": is_streaming,
    }
    if extra_response:
        response.update(extra_response)

    entry: dict = {
        "id": id,
        "trace_id": trace_id,
        "timestamp": timestamp,
        "request": request,
        "response": response,
        "guardrails": {
            "before": before_guardrails or [],
            "after": after_guardrails or [],
        },
        "user": "user-42",
    }
    if user_feedback is not None:
        entry["user_feedback"] = user_feedback
    return entry


# ---------------------------------------------------------------------------
# Importer behaviour tests
# ---------------------------------------------------------------------------

class TestPortkeyImporter:
    def test_parse_success(self):
        imp = PortkeyImporter(agent_id="ci")
        export = json.dumps({"data": [_log_entry()]})
        results = imp.parse_string(export)

        assert len(results) == 1
        ev = results[0]
        assert ev.source_type == "portkey_import"
        assert ev.agent_id == "ci"
        assert ev.decision == "ALLOW"
        assert len(ev.control_results) == 1
        cr = ev.control_results[0]
        assert cr.result == "PASS"
        assert cr.control_id == "PR-01"
        assert cr.evidence_data["signal"] == "status_2xx"
        assert cr.evidence_data["status_code"] == 200
        assert cr.evidence_data["provider"] == "openai"
        assert cr.evidence_data["tokens"]["total"] == 150
        assert cr.evidence_data["virtual_key"] == "vk-prod-openai"

    def test_4xx_flags(self):
        imp = PortkeyImporter()
        ev = imp.parse_string(json.dumps([_log_entry(status_code=429)]))[0]

        assert ev.decision == "FLAG"
        cr = ev.control_results[0]
        assert cr.result == "FLAG"
        assert cr.control_id == "PR-02"
        assert cr.evidence_data["signal"] == "status_4xx"
        assert cr.evidence_data["status_code"] == 429

    def test_5xx_fails(self):
        imp = PortkeyImporter()
        ev = imp.parse_string(json.dumps([_log_entry(status_code=503)]))[0]

        assert ev.decision == "BLOCK"
        cr = ev.control_results[0]
        assert cr.result == "FAIL"
        assert cr.control_id == "DE-01"
        assert cr.evidence_data["signal"] == "status_5xx"

    def test_before_guardrail_failure_fails_input(self):
        imp = PortkeyImporter()
        entry = _log_entry(
            status_code=200,
            before_guardrails=[
                {"id": "pii", "verdict": "failed", "data": {"matched": ["ssn"]}},
                {"id": "moderation", "verdict": "passed", "data": {}},
            ],
        )
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "BLOCK"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "before_guardrail_failed" in signals
        # Successful 2xx PASS must NOT be added when an input guardrail failed.
        assert "status_2xx" not in signals
        guard_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "before_guardrail_failed"
        )
        assert guard_cr.result == "FAIL"
        assert guard_cr.control_id == "PR-03"
        assert any(g["id"] == "pii" for g in guard_cr.evidence_data["failed_guardrails"])

    def test_after_guardrail_failure_fails_output(self):
        imp = PortkeyImporter()
        entry = _log_entry(
            status_code=200,
            after_guardrails=[
                {"id": "toxicity", "verdict": "failed", "data": {"score": 0.92}},
            ],
        )
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "BLOCK"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "after_guardrail_failed" in signals
        assert "status_2xx" not in signals
        guard_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "after_guardrail_failed"
        )
        assert guard_cr.result == "FAIL"
        assert guard_cr.control_id == "DE-01"

    def test_semantic_cache_hit_logged_audit(self):
        imp = PortkeyImporter()
        entry = _log_entry(
            cache_mode="semantic",
            cache_status="SEMANTIC_HIT",
        )
        ev = imp.parse_string(json.dumps([entry]))[0]

        # 2xx PASS + semantic-cache PASS → still ALLOW.
        assert ev.decision == "ALLOW"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "semantic_cache_hit" in signals
        cache_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "semantic_cache_hit"
        )
        assert cache_cr.result == "PASS"
        assert cache_cr.control_id == "PR-05"
        assert cache_cr.evidence_data["cache_hit_kind"] == "semantic"
        assert cache_cr.evidence_data["cache_mode"] == "semantic"
        assert cache_cr.evidence_data["cache_status"] == "SEMANTIC_HIT"

    def test_fallback_used_flags_provenance(self):
        imp = PortkeyImporter()
        entry = _log_entry(
            fallback_used=True,
            fallback_targets=[
                {"provider": "anthropic", "virtual_key": "vk-anthropic"},
                {"provider": "azure-openai", "virtual_key": "vk-azure"},
            ],
            provider="anthropic",
            model="claude-3-5-sonnet-20241022",
        )
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "fallback_used" in signals
        fb_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "fallback_used"
        )
        assert fb_cr.result == "FLAG"
        assert fb_cr.control_id == "PR-01"
        assert fb_cr.evidence_data["fallback_used"] is True
        assert fb_cr.evidence_data["fallback_target_count"] == 2
        # Provider-routed-to surfaced in evidence.
        assert fb_cr.evidence_data["provider"] == "anthropic"

    def test_retry_count_above_threshold_flags(self):
        imp = PortkeyImporter()  # default retry_threshold=2
        entry = _log_entry(retry_count=3)
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "retry_threshold_exceeded" in signals
        retry_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "retry_threshold_exceeded"
        )
        assert retry_cr.result == "FLAG"
        assert retry_cr.control_id == "PR-02"
        assert retry_cr.evidence_data["retry_count"] == 3
        assert retry_cr.evidence_data["retry_threshold"] == 2

        # Threshold tweak suppresses the flag.
        lenient = PortkeyImporter(retry_threshold=5)
        ev2 = lenient.parse_string(json.dumps([entry]))[0]
        assert ev2.decision == "ALLOW"
        signals2 = {cr.evidence_data.get("signal") for cr in ev2.control_results}
        assert "retry_threshold_exceeded" not in signals2

    def test_cost_above_threshold_flags(self):
        imp = PortkeyImporter()  # default cost threshold = $1
        entry = _log_entry(cost=2.75)
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "cost_threshold_exceeded" in signals
        cost_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "cost_threshold_exceeded"
        )
        assert cost_cr.result == "FLAG"
        assert cost_cr.control_id == "PR-04"
        assert cost_cr.evidence_data["cost_usd"] == 2.75
        assert cost_cr.evidence_data["cost_threshold_usd"] == 1.0

        # Higher threshold suppresses the flag.
        lenient = PortkeyImporter(cost_threshold_usd=10.0)
        ev2 = lenient.parse_string(json.dumps([entry]))[0]
        assert ev2.decision == "ALLOW"

    def test_negative_user_feedback_flags(self):
        imp = PortkeyImporter()
        entry = _log_entry(user_feedback={"value": -1, "weight": 1.0})
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "negative_user_feedback" in signals
        fb_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "negative_user_feedback"
        )
        assert fb_cr.result == "FLAG"
        assert fb_cr.control_id == "PR-05"

        # Positive feedback does NOT raise the flag.
        pos = _log_entry(id="log-2", user_feedback={"value": 1, "weight": 1.0})
        ev_pos = imp.parse_string(json.dumps([pos]))[0]
        assert ev_pos.decision == "ALLOW"
        sigs_pos = {cr.evidence_data.get("signal") for cr in ev_pos.control_results}
        assert "negative_user_feedback" not in sigs_pos

    def test_loadbalance_multi_target_flags(self):
        imp = PortkeyImporter()
        entry = _log_entry(
            loadbalance_targets=[
                {"provider": "openai", "virtual_key": "vk-openai-1"},
                {"provider": "openai", "virtual_key": "vk-openai-2"},
                {"provider": "azure-openai", "virtual_key": "vk-azure"},
            ],
            provider="openai",
        )
        ev = imp.parse_string(json.dumps([entry]))[0]

        assert ev.decision == "FLAG"
        signals = {cr.evidence_data.get("signal") for cr in ev.control_results}
        assert "loadbalance_multi_target" in signals
        lb_cr = next(
            cr for cr in ev.control_results
            if cr.evidence_data.get("signal") == "loadbalance_multi_target"
        )
        assert lb_cr.result == "FLAG"
        assert lb_cr.control_id == "PR-01"
        assert lb_cr.evidence_data["loadbalance_target_count"] == 3
        assert lb_cr.evidence_data["selected_provider"] == "openai"
        # Targets recorded so we know which pool the request used.
        assert len(lb_cr.evidence_data["loadbalance_targets"]) == 3

        # Single-target loadbalance does NOT trigger the flag.
        single = _log_entry(
            id="log-2",
            loadbalance_targets=[
                {"provider": "openai", "virtual_key": "vk-openai-1"},
            ],
        )
        ev_single = imp.parse_string(json.dumps([single]))[0]
        sigs_single = {cr.evidence_data.get("signal") for cr in ev_single.control_results}
        assert "loadbalance_multi_target" not in sigs_single

    def test_request_body_not_stored(self):
        """Raw prompt / response bodies must NEVER appear in evidence_data."""
        secret_prompt = "DO NOT LEAK: super-secret-customer-data"
        secret_response = "DO NOT LEAK: confidential-answer"
        entry = _log_entry(
            extra_request={
                "body": {"messages": [{"role": "user", "content": secret_prompt}]},
            },
            extra_response={
                "body": {"choices": [{"message": {"content": secret_response}}]},
            },
        )
        # Self-hosted Portkey deployments occasionally include raw body in
        # config.metadata — make sure those get scrubbed too.
        entry["request"]["config"]["metadata"]["body"] = secret_prompt
        entry["request"]["config"]["metadata"]["request_body"] = secret_response

        imp = PortkeyImporter()
        ev = imp.parse_string(json.dumps([entry]))[0]
        serialized = json.dumps(
            [
                {
                    "control_id": c.control_id,
                    "detail": c.detail,
                    "evidence_data": c.evidence_data,
                }
                for c in ev.control_results
            ],
            default=str,
        )
        assert secret_prompt not in serialized
        assert secret_response not in serialized

        cr = ev.control_results[0]
        # body_keys is captured but raw body fields are not.
        assert cr.evidence_data["body_keys"] == ["choices", "usage", "id", "model"]
        cfg_meta = cr.evidence_data["config_metadata"]
        for forbidden in ("body", "request_body", "response_body", "messages", "prompt"):
            assert forbidden not in cfg_meta

    def test_url_query_strings_stripped(self):
        imp = PortkeyImporter()
        entry = _log_entry(
            url="https://api.openai.com/v1/chat/completions?api_key=sk-leak&trace=secret#frag",
        )
        ev = imp.parse_string(json.dumps([entry]))[0]
        cr = ev.control_results[0]
        url = cr.evidence_data["url"]
        assert url == "https://api.openai.com/v1/chat/completions"
        assert "api_key" not in url
        assert "sk-leak" not in url
        assert "#" not in url

    def test_jsonl_stream(self):
        """JSONL: one JSON object per line, blank lines tolerated."""
        lines = [
            json.dumps(_log_entry(id="log-a")),
            "",
            json.dumps(_log_entry(id="log-b", status_code=429)),
            json.dumps(_log_entry(id="log-c", status_code=503)),
        ]
        content = "\n".join(lines) + "\n"

        imp = PortkeyImporter()
        results = imp.parse_string(content)
        assert len(results) == 3
        decisions = [ev.decision for ev in results]
        assert decisions == ["ALLOW", "FLAG", "BLOCK"]

    def test_source_provenance_includes_file_hash(self, tmp_path: Path):
        entry = _log_entry()
        payload = json.dumps({"data": [entry]}).encode("utf-8")
        log_file = tmp_path / "portkey-export.json"
        log_file.write_bytes(payload)
        expected_sha = hashlib.sha256(payload).hexdigest()

        imp = PortkeyImporter()
        results = imp.parse(log_file)
        assert len(results) == 1
        ev = results[0]
        cr = ev.control_results[0]
        sp = cr.evidence_data["source_provenance"]
        assert sp["source_format"] == "portkey"
        assert sp["source_tool_name"] == "portkey"
        assert sp["original_file_sha256"] == expected_sha
        assert sp["log_id"] == "log-1"

        # parse_string omits file hash since there is no on-disk artifact.
        sp2 = imp.parse_string(json.dumps([entry]))[0].control_results[0].evidence_data[
            "source_provenance"
        ]
        assert "original_file_sha256" not in sp2
