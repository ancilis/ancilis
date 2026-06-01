"""Tests for the Browserbase session-export importer."""

from __future__ import annotations

import json

from ancilis.importers.browserbase import BrowserbaseImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Browserbase session records (no browserbase package required)
# ---------------------------------------------------------------------------


def _action(
    *,
    id: str = "act-1",
    type: str = "goto",
    target_selector: str = "",
    url: str = "https://example.com/",
    text_length: int = 0,
    succeeded: bool = True,
    duration_ms: int = 100,
    timestamp: str = "2026-04-01T12:00:00Z",
) -> dict:
    return {
        "id": id,
        "type": type,
        "target_selector": target_selector,
        "url": url,
        "text_length": text_length,
        "succeeded": succeeded,
        "duration_ms": duration_ms,
        "timestamp": timestamp,
    }


def _session(
    *,
    id: str = "sess-abc123",
    project_id: str = "proj-1",
    status: str = "COMPLETED",
    started_at: str = "2026-04-01T12:00:00Z",
    ended_at: str = "2026-04-01T12:01:00Z",
    duration_ms: int = 60_000,
    user_metadata: dict | None = None,
    proxy_used: bool = False,
    proxy_country: str | None = None,
    captcha_solver_used: bool = False,
    stealth_mode: bool = False,
    memory_url_kb: int = 100,
    browser_settings: dict | None = None,
    events_count: int = 5,
    url_count: int = 3,
    downloads_count: int = 0,
    actions: list | None = None,
    context_id: str = "ctx-1",
    errors_count: int = 0,
    is_logged_in_to: list | None = None,
) -> dict:
    if user_metadata is None:
        user_metadata = {"agent_id": "agent-1", "task_id": "task-1"}
    if browser_settings is None:
        browser_settings = {
            "viewport": {"width": 1280, "height": 720},
            "fingerprint": "fp-xyz",
        }
    if actions is None:
        actions = [_action()]
    if is_logged_in_to is None:
        is_logged_in_to = []
    return {
        "id": id,
        "project_id": project_id,
        "status": status,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "user_metadata": user_metadata,
        "proxy_used": proxy_used,
        "proxy_country": proxy_country,
        "captcha_solver_used": captcha_solver_used,
        "stealth_mode": stealth_mode,
        "memory_url_kb": memory_url_kb,
        "browser_settings": browser_settings,
        "events_count": events_count,
        "url_count": url_count,
        "downloads_count": downloads_count,
        "actions": actions,
        "context_id": context_id,
        "errors_count": errors_count,
        "is_logged_in_to": is_logged_in_to,
    }


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


# ---------------------------------------------------------------------------
# Status semantics
# ---------------------------------------------------------------------------


def test_parse_completed_session() -> None:
    """status=COMPLETED → PR-05 PASS, ALLOW decision."""
    doc = json.dumps({"sessions": [_session(id="sess-ok", status="COMPLETED")]})
    [result] = BrowserbaseImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "browserbase_import"
    assert result.action_id == "browserbase-sess-ok"
    pass_crs = [cr for cr in result.control_results if cr.result == "PASS"]
    assert len(pass_crs) == 1
    assert pass_crs[0].control_id == "PR-05"
    assert pass_crs[0].evidence_data["signal"] == "status_completed"
    assert pass_crs[0].evidence_data["project_id"] == "proj-1"
    assert pass_crs[0].evidence_data["agent_id_observed"] == "agent-1"


def test_failed_status_marks_fail() -> None:
    """status=FAILED → DE-01 FAIL, BLOCK decision."""
    doc = json.dumps({"sessions": [_session(id="sess-bad", status="FAILED", errors_count=2)]})
    [result] = BrowserbaseImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert len(fails) == 1
    assert fails[0].control_id == "DE-01"
    assert fails[0].evidence_data["signal"] == "status_failed"


def test_error_status_marks_fail() -> None:
    """status=ERROR → DE-01 FAIL."""
    doc = json.dumps({"sessions": [_session(id="sess-err", status="ERROR")]})
    [result] = BrowserbaseImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert fails[0].evidence_data["signal"] == "status_error"


def test_timed_out_flags_capacity() -> None:
    """status=TIMED_OUT → PR-02 FLAG (capacity)."""
    doc = json.dumps({"sessions": [_session(id="sess-tmo", status="TIMED_OUT")]})
    [result] = BrowserbaseImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-02" and cr.evidence_data["signal"] == "status_timed_out"
        for cr in flags
    )


# ---------------------------------------------------------------------------
# Captcha / stealth / proxy
# ---------------------------------------------------------------------------


def test_captcha_solver_flags() -> None:
    """captcha_solver_used=true → PR-01 FLAG."""
    doc = json.dumps({"sessions": [_session(captcha_solver_used=True)]})
    [result] = BrowserbaseImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "captcha_solver_used"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-01"
    assert flags[0].result == "FLAG"


def test_stealth_mode_high_trust_flags() -> None:
    """stealth_mode=true on session that visited high-trust domain → PR-01 FLAG."""
    doc = json.dumps(
        {
            "sessions": [
                _session(
                    stealth_mode=True,
                    actions=[
                        _action(type="goto", url="https://www.github.com/repo"),
                    ],
                )
            ]
        }
    )
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "stealth_mode_high_trust"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-01"

    # And NOT flagged if stealth_mode is on but no high-trust domain visited.
    doc2 = json.dumps(
        {
            "sessions": [
                _session(
                    stealth_mode=True,
                    actions=[_action(type="goto", url="https://random-blog.example/")],
                )
            ]
        }
    )
    [result2] = BrowserbaseImporter().parse_string(doc2)
    assert "stealth_mode_high_trust" not in _signals(result2)


def test_proxy_country_mismatch_flags() -> None:
    """proxy_used=true with proxy_country differing from project_country → PR-01 FLAG."""
    doc = json.dumps(
        {
            "sessions": [
                _session(proxy_used=True, proxy_country="ru"),
            ]
        }
    )
    importer = BrowserbaseImporter(project_country="us")
    [result] = importer.parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "proxy_country_mismatch"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-01"

    # No mismatch when countries match.
    doc2 = json.dumps(
        {"sessions": [_session(proxy_used=True, proxy_country="us")]}
    )
    [result2] = importer.parse_string(doc2)
    assert "proxy_country_mismatch" not in _signals(result2)


# ---------------------------------------------------------------------------
# Exfiltration surfaces
# ---------------------------------------------------------------------------


def test_downloads_flag_exfiltration() -> None:
    """downloads_count > 0 → PR-04 FLAG."""
    doc = json.dumps({"sessions": [_session(downloads_count=3)]})
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "downloads_present"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-04"
    assert flags[0].evidence_data["downloads_count"] == 3


def test_logged_in_domains_flag() -> None:
    """is_logged_in_to non-empty → PR-04 FLAG, with hostnames captured."""
    doc = json.dumps(
        {
            "sessions": [
                _session(is_logged_in_to=["github.com", "google.com"]),
            ]
        }
    )
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "logged_in_surfaces"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-04"
    assert flags[0].evidence_data["logged_in_domains"] == ["github.com", "google.com"]


def test_evaluate_action_flags_arbitrary_js() -> None:
    """action.type=evaluate → PR-03 FLAG."""
    doc = json.dumps(
        {
            "sessions": [
                _session(
                    actions=[
                        _action(type="goto", url="https://example.com/"),
                        _action(id="act-2", type="evaluate", url="https://example.com/dashboard"),
                        _action(id="act-3", type="evaluate", url="https://example.com/"),
                    ]
                )
            ]
        }
    )
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "evaluate_action"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-03"
    assert flags[0].evidence_data["evaluate_action_count"] == 2


def test_credential_entry_action_flags() -> None:
    """type/fill_form on auth-domain URL → PR-04 FLAG."""
    doc = json.dumps(
        {
            "sessions": [
                _session(
                    id="sess-cred",
                    actions=[
                        _action(type="goto", url="https://example.com/login"),
                        _action(
                            id="act-2",
                            type="type",
                            url="https://example.com/login",
                            text_length=42,
                        ),
                        _action(
                            id="act-3",
                            type="fill_form",
                            url="https://accounts.google.com/signin/v2/identifier",
                        ),
                        # type action on a non-auth URL — should NOT trip credential detection.
                        _action(
                            id="act-4",
                            type="type",
                            url="https://example.com/dashboard",
                            text_length=10,
                        ),
                    ],
                )
            ]
        }
    )
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "credential_entry_on_auth_domain"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-04"
    hosts = flags[0].evidence_data["credential_entry_hostnames"]
    assert "example.com" in hosts
    assert "accounts.google.com" in hosts


def test_url_count_above_threshold_flags() -> None:
    """url_count > threshold → PR-04 FLAG."""
    doc = json.dumps({"sessions": [_session(url_count=120)]})
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "url_count_above_threshold"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-04"
    assert flags[0].evidence_data["url_count"] == 120
    assert flags[0].evidence_data["url_count_threshold"] == 50

    # Custom threshold via constructor argument.
    importer = BrowserbaseImporter(url_count_threshold=200)
    [result2] = importer.parse_string(doc)
    assert "url_count_above_threshold" not in _signals(result2)


def test_duration_above_threshold_flags() -> None:
    """duration_ms > threshold → PR-02 FLAG."""
    # Default threshold is 5 minutes (300_000 ms); 600_000 = 10 minutes.
    doc = json.dumps({"sessions": [_session(duration_ms=600_000)]})
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "duration_above_threshold"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-02"
    assert flags[0].evidence_data["duration_ms"] == 600_000


def test_cross_domain_pattern_synthetic_finding() -> None:
    """Cross-domain pattern: > N distinct second-level domains → PR-04 FLAG."""
    actions = [
        _action(id=f"act-{i}", type="goto", url=f"https://www.example{i}.com/")
        for i in range(7)
    ]
    doc = json.dumps({"sessions": [_session(id="sess-broad", actions=actions)]})
    [result] = BrowserbaseImporter().parse_string(doc)
    flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "cross_domain_pattern"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-04"
    assert flags[0].evidence_data["cross_domain_count"] >= 7
    assert flags[0].evidence_data["cross_domain_threshold"] == 5
    assert len(flags[0].evidence_data["cross_domain_second_level_domains"]) >= 7

    # Below threshold: no synthetic finding.
    actions2 = [
        _action(id=f"act-{i}", type="goto", url=f"https://www.example{i}.com/")
        for i in range(3)
    ]
    doc2 = json.dumps({"sessions": [_session(actions=actions2)]})
    [result2] = BrowserbaseImporter().parse_string(doc2)
    assert "cross_domain_pattern" not in _signals(result2)


# ---------------------------------------------------------------------------
# Sanitization invariants
# ---------------------------------------------------------------------------


def test_url_query_strings_stripped() -> None:
    """URL query strings and fragments are stripped from any captured hostname/url."""
    doc = json.dumps(
        {
            "sessions": [
                _session(
                    actions=[
                        _action(
                            type="goto",
                            url="https://shop.example.com/checkout?token=SECRET&cc=4111111111111111#frag",
                        ),
                    ]
                )
            ]
        }
    )
    [result] = BrowserbaseImporter().parse_string(doc)
    # Walk the entire serialized evidence — no query value, fragment, or
    # selector value should be present anywhere.
    blob = json.dumps([cr.evidence_data for cr in result.control_results])
    assert "token=SECRET" not in blob
    assert "cc=4111111111111111" not in blob
    assert "frag" not in blob
    assert "?" not in blob
    assert "#" not in blob
    # But the hostname IS captured.
    found_host = False
    for cr in result.control_results:
        if "shop.example.com" in cr.evidence_data.get("action_hostnames", []):
            found_host = True
    assert found_host


def test_action_text_never_stored() -> None:
    """action.text content / target_selector are NEVER stored in evidence."""
    doc = json.dumps(
        {
            "sessions": [
                _session(
                    actions=[
                        {
                            "id": "act-secret",
                            "type": "type",
                            "target_selector": "#password-field",
                            "url": "https://app.example.com/login",
                            "text_length": 12,
                            "text": "hunter2-PASS",
                            "succeeded": True,
                            "duration_ms": 50,
                            "timestamp": "2026-04-01T12:00:00Z",
                        },
                        {
                            "id": "act-fill",
                            "type": "fill_form",
                            "target_selector": "form#login-form input[name='cc']",
                            "url": "https://app.example.com/auth/sso",
                            "text_length": 16,
                            "text": "4111111111111111",
                            "succeeded": True,
                            "duration_ms": 50,
                            "timestamp": "2026-04-01T12:00:00Z",
                        },
                    ]
                )
            ]
        }
    )
    [result] = BrowserbaseImporter().parse_string(doc)
    blob = json.dumps([cr.evidence_data for cr in result.control_results])
    # Sensitive text content must NEVER appear in evidence.
    assert "hunter2-PASS" not in blob
    assert "4111111111111111" not in blob
    # target_selector values must NEVER appear in evidence.
    assert "#password-field" not in blob
    assert "input[name=" not in blob
    assert "login-form" not in blob


# ---------------------------------------------------------------------------
# Envelope variants & misc
# ---------------------------------------------------------------------------


def test_data_envelope_and_jsonl_and_single_object() -> None:
    """Importer accepts {"data":[...]}, JSONL, and single-object payloads."""
    # data envelope
    doc_data = json.dumps({"data": [_session(id="sess-d1"), _session(id="sess-d2")]})
    results = BrowserbaseImporter().parse_string(doc_data)
    assert {r.action_id for r in results} == {
        "browserbase-sess-d1",
        "browserbase-sess-d2",
    }

    # JSONL
    jsonl = "\n".join(
        [json.dumps(_session(id="sess-l1")), json.dumps(_session(id="sess-l2"))]
    )
    results2 = BrowserbaseImporter().parse_string(jsonl)
    assert len(results2) == 2

    # single object
    single = json.dumps(_session(id="sess-solo"))
    [result3] = BrowserbaseImporter().parse_string(single)
    assert result3.action_id == "browserbase-sess-solo"


def test_combined_high_risk_session_blocks_with_multiple_flags() -> None:
    """A session that fails AND has multiple flag signals should still BLOCK with all signals captured."""
    doc = json.dumps(
        {
            "sessions": [
                _session(
                    id="sess-multi",
                    status="FAILED",
                    captcha_solver_used=True,
                    stealth_mode=True,
                    proxy_used=True,
                    proxy_country="ru",
                    downloads_count=5,
                    is_logged_in_to=["github.com"],
                    actions=[
                        _action(type="goto", url="https://github.com/repo"),
                        _action(id="a2", type="evaluate", url="https://github.com/"),
                    ],
                )
            ]
        }
    )
    [result] = BrowserbaseImporter(project_country="us").parse_string(doc)
    sigs = _signals(result)
    assert "status_failed" in sigs
    assert "captcha_solver_used" in sigs
    assert "stealth_mode_high_trust" in sigs
    assert "proxy_country_mismatch" in sigs
    assert "downloads_present" in sigs
    assert "logged_in_surfaces" in sigs
    assert "evaluate_action" in sigs
    assert result.decision == "BLOCK"
