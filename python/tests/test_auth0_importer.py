"""Tests for the Auth0 tenant log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers.auth0 import Auth0Importer


# ---------------------------------------------------------------------------
# Fixtures — inline Auth0 tenant log entries (no auth0-python SDK required)
# ---------------------------------------------------------------------------


def _log(
    *,
    log_id: str = "log-001",
    type_code: str = "s",
    date: str = "2026-04-01T12:00:00.000Z",
    description: str | None = "Successful login",
    connection: str | None = "Username-Password-Authentication",
    connection_id: str | None = "con_abc",
    client_id: str | None = "client_xyz",
    client_name: str | None = "Production App",
    ip: str | None = "203.0.113.42",
    user_agent: str | None = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    user_id: str | None = "auth0|abc123",
    user_name: str | None = "Alice Example",
    user_email: str | None = "alice@corp.example.com",
    audience: str | None = "https://api.example.com/",
    scope: str | None = "openid profile email",
    strategy: str | None = "auth0",
    strategy_type: str | None = "database",
    hostname: str | None = "tenant.auth0.com",
    tenant_name: str | None = "tenant",
    is_mobile: bool | None = False,
    country_code: str | None = "US",
    country_name: str | None = "United States",
    city_name: str | None = "San Francisco",
    latitude: str | None = "37.7749",
    longitude: str | None = "-122.4194",
    session_id: str | None = "sess-abc",
    logins_count: int | None = 42,
    extra_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "request": {"method": "POST", "path": "/oauth/token"},
        "response": {"status_code": 200},
    }
    if session_id is not None:
        details["session_id"] = session_id
    if scope is not None:
        details["scope"] = scope
    auth: dict[str, Any] = {}
    if user_email is not None or user_name is not None:
        user_obj: dict[str, Any] = {}
        if user_email is not None:
            user_obj["email"] = user_email
        if user_name is not None:
            user_obj["name"] = user_name
        auth["user"] = user_obj
    if auth:
        details["auth"] = auth
    stats: dict[str, Any] = {}
    if logins_count is not None:
        stats["loginsCount"] = logins_count
    if stats:
        details["stats"] = stats
    if extra_details:
        details.update(extra_details)

    location: dict[str, Any] = {}
    if country_code is not None:
        location["country_code"] = country_code
    if country_name is not None:
        location["country_name"] = country_name
    if city_name is not None:
        location["city_name"] = city_name
    if latitude is not None:
        location["latitude"] = latitude
    if longitude is not None:
        location["longitude"] = longitude

    log: dict[str, Any] = {
        "log_id": log_id,
        "_id": log_id,
        "date": date,
        "type": type_code,
        "details": details,
        "location_info": location,
    }
    if description is not None:
        log["description"] = description
    if connection is not None:
        log["connection"] = connection
    if connection_id is not None:
        log["connection_id"] = connection_id
    if client_id is not None:
        log["client_id"] = client_id
    if client_name is not None:
        log["client_name"] = client_name
    if ip is not None:
        log["ip"] = ip
    if user_agent is not None:
        log["user_agent"] = user_agent
    if user_id is not None:
        log["user_id"] = user_id
    if user_name is not None:
        log["user_name"] = user_name
    if audience is not None:
        log["audience"] = audience
    if scope is not None:
        log["scope"] = scope
    if strategy is not None:
        log["strategy"] = strategy
    if strategy_type is not None:
        log["strategy_type"] = strategy_type
    if hostname is not None:
        log["hostname"] = hostname
    if tenant_name is not None:
        log["tenant_name"] = tenant_name
    if is_mobile is not None:
        log["isMobile"] = is_mobile
    return log


def _envelope(*logs: dict[str, Any]) -> dict[str, Any]:
    return {"logs": list(logs)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _control_results_by_signal(result: Any) -> dict[str, Any]:
    return {
        cr.evidence_data.get("signal"): cr
        for cr in result.control_results
        if cr.evidence_data.get("signal")
    }


# ---------------------------------------------------------------------------
# Required tests (14)
# ---------------------------------------------------------------------------


def test_parse_successful_login() -> None:
    importer = Auth0Importer(agent_id="agent-1")
    raw = json.dumps(_envelope(_log(type_code="s", logins_count=42)))
    results = importer.parse_string(raw)
    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    by_sig = _control_results_by_signal(res)
    assert "login_success" in by_sig
    assert by_sig["login_success"].result == "PASS"
    assert by_sig["login_success"].control_id == "PR-01"
    assert res.source_type == "auth0_tenant_logs_import"
    # Type-code → human-readable mapping captured.
    assert by_sig["login_success"].evidence_data["type_code"] == "s"
    assert by_sig["login_success"].evidence_data["type_human"] == "login_success"


def test_failed_login_flags() -> None:
    importer = Auth0Importer()
    # Cover all three failure variants.
    raw = json.dumps(
        _envelope(
            _log(log_id="log-f", type_code="f", description="Failed Login"),
            _log(log_id="log-fp", type_code="fp", description="Failed Password"),
            _log(log_id="log-fu", type_code="fu", description="Failed User"),
        )
    )
    results = importer.parse_string(raw)
    assert len(results) == 3
    for res in results:
        assert res.decision == "FLAG"
        sigs = {cr.evidence_data.get("signal") for cr in res.control_results}
        assert sigs & {
            "login_failure",
            "login_failure_password",
            "login_failure_user",
        }
        for cr in res.control_results:
            if cr.evidence_data.get("signal", "").startswith("login_failure"):
                assert cr.result == "FLAG"
                assert cr.control_id == "PR-01"


def test_user_blocked_fails() -> None:
    importer = Auth0Importer()
    raw = json.dumps(_envelope(_log(type_code="ublkd", description="User blocked")))
    results = importer.parse_string(raw)
    assert len(results) == 1
    res = results[0]
    assert res.decision == "BLOCK"
    by_sig = _control_results_by_signal(res)
    assert by_sig["user_blocked"].result == "FAIL"
    assert by_sig["user_blocked"].control_id == "PR-01"


def test_rate_limit_flags() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(_log(type_code="limit_wc", description="Rate limit reached"))
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    by_sig = _control_results_by_signal(res)
    assert by_sig["rate_limit_reached"].result == "FLAG"
    assert by_sig["rate_limit_reached"].control_id == "PR-02"


def test_successful_signup() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(_log(type_code="ss", description="Successful signup"))
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "ALLOW"
    by_sig = _control_results_by_signal(res)
    assert by_sig["signup_success"].result == "PASS"
    assert by_sig["signup_success"].control_id == "PR-01"
    # Capture marker — type code AND human-readable form preserved in evidence.
    assert by_sig["signup_success"].evidence_data["type_code"] == "ss"
    assert by_sig["signup_success"].evidence_data["type_human"] == "signup_success"


def test_connection_update_flags() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(
            _log(
                log_id="log-scu",
                type_code="scu",
                description="Successful connection update",
            ),
            _log(
                log_id="log-fcu",
                type_code="fcu",
                description="Failed connection update",
            ),
        )
    )
    results = importer.parse_string(raw)
    assert len(results) == 2
    by_log = {res.action_id: res for res in results}
    scu_res = by_log["auth0-log-scu"]
    fcu_res = by_log["auth0-log-fcu"]
    # scu → PR-02 FLAG (connection config change is sensitive).
    assert scu_res.decision == "FLAG"
    by_sig = _control_results_by_signal(scu_res)
    assert by_sig["connection_update_success"].result == "FLAG"
    assert by_sig["connection_update_success"].control_id == "PR-02"
    # fcu → PR-02 PASS (audit trail of denial).
    assert fcu_res.decision == "ALLOW"
    by_sig = _control_results_by_signal(fcu_res)
    assert by_sig["connection_update_failure"].result == "PASS"
    assert by_sig["connection_update_failure"].control_id == "PR-02"


def test_token_exchange_admin_scope_flags() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(
            _log(
                type_code="sece",
                description="Successful exchange",
                scope="openid profile admin",
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    by_sig = _control_results_by_signal(res)
    # Both the privileged-scope and admin-token-exchange signals fire.
    assert "admin_token_exchange" in by_sig
    assert by_sig["admin_token_exchange"].result == "FLAG"
    assert by_sig["admin_token_exchange"].control_id == "PR-01"
    assert "privileged_scope" in by_sig
    assert by_sig["privileged_scope"].result == "FLAG"
    assert by_sig["privileged_scope"].control_id == "PR-02"
    # The base sece signal is still PASS.
    assert by_sig["token_exchange_success"].result == "PASS"


def test_consent_granted_passes() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(
            _log(
                log_id="log-scoa",
                type_code="scoa",
                description="Consent granted",
                scope="openid profile email",
            ),
            _log(
                log_id="log-fcoa",
                type_code="fcoa",
                description="Consent denied",
                scope="openid profile email",
            ),
        )
    )
    results = importer.parse_string(raw)
    by_log = {res.action_id: res for res in results}
    scoa_res = by_log["auth0-log-scoa"]
    fcoa_res = by_log["auth0-log-fcoa"]
    # Both consent signals are PR-04 PASS — they are audit-trail records.
    assert scoa_res.decision == "ALLOW"
    by_sig = _control_results_by_signal(scoa_res)
    assert by_sig["consent_granted"].result == "PASS"
    assert by_sig["consent_granted"].control_id == "PR-04"
    assert fcoa_res.decision == "ALLOW"
    by_sig = _control_results_by_signal(fcoa_res)
    assert by_sig["consent_denied"].result == "PASS"
    assert by_sig["consent_denied"].control_id == "PR-04"


def test_privileged_scope_flags() -> None:
    importer = Auth0Importer()
    # A successful login carrying read:users in scope — privileged grant.
    raw = json.dumps(
        _envelope(
            _log(
                type_code="s",
                scope="openid profile read:users",
                logins_count=42,
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    by_sig = _control_results_by_signal(res)
    assert "privileged_scope" in by_sig
    assert by_sig["privileged_scope"].result == "FLAG"
    assert by_sig["privileged_scope"].control_id == "PR-02"
    assert by_sig["privileged_scope"].evidence_data["privileged_scope_match"] == "read:users"


def test_first_ever_login_captured() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(_log(type_code="s", logins_count=1))
    )
    results = importer.parse_string(raw)
    res = results[0]
    by_sig = _control_results_by_signal(res)
    assert "first_ever_login" in by_sig
    assert by_sig["first_ever_login"].result == "PASS"
    assert by_sig["first_ever_login"].control_id == "PR-01"
    # loginsCount=1 still ALLOW since both signals are PASS.
    assert res.decision == "ALLOW"


def test_cross_country_pattern_synthetic() -> None:
    importer = Auth0Importer(cross_country_threshold=2)  # 3 distinct countries > 2.
    same_user = "auth0|globe-trotter"
    logs = [
        _log(log_id=f"log-{idx}", type_code="s", user_id=same_user, country_code=cc)
        for idx, cc in enumerate(("US", "DE", "JP", "BR"))
    ]
    raw = json.dumps(_envelope(*logs))
    results = importer.parse_string(raw)
    # 4 per-event + 1 synthetic = 5 results.
    assert len(results) == 5
    synthetic = next(
        res for res in results
        if res.action_id.startswith("auth0-cross-country-")
    )
    cr = synthetic.control_results[0]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-01"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["user_id"] == same_user
    assert cr.evidence_data["cross_country_country_count"] == 4
    assert cr.evidence_data["cross_country_country_codes"] == ["BR", "DE", "JP", "US"]
    # Per-event records also carry the cross_country_pattern marker.
    per_event = [
        res for res in results
        if not res.action_id.startswith("auth0-cross-country-")
    ]
    for res in per_event:
        sigs = {cr.evidence_data.get("signal") for cr in res.control_results}
        assert "cross_country_pattern" in sigs


def test_email_domain_only_stored() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(_log(type_code="s", user_email="alice@corp.example.com"))
    )
    results = importer.parse_string(raw)
    res = results[0]
    # Domain stored.
    found_domain = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("details_auth_user_email_domain") is not None:
            assert ev["details_auth_user_email_domain"] == "@corp.example.com"
            found_domain = True
        # Plaintext email never stored anywhere in evidence.
        for v in ev.values():
            if isinstance(v, str):
                assert "alice@corp.example.com" not in v
    assert found_domain


def test_user_agent_redacted() -> None:
    importer = Auth0Importer()
    long_ua = "Mozilla/5.0 " + ("X" * 200) + " End"
    raw = json.dumps(_envelope(_log(type_code="s", user_agent=long_ua)))
    results = importer.parse_string(raw)
    res = results[0]
    expected_sha = hashlib.sha256(long_ua.encode("utf-8")).hexdigest()
    found = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("client_user_agent_truncated") is not None:
            assert len(ev["client_user_agent_truncated"]) == 80
            assert ev["client_user_agent_truncated"] == long_ua[:80]
            assert ev["client_user_agent_sha256"] == expected_sha
            found = True
    assert found


def test_ip_redacted() -> None:
    importer = Auth0Importer()
    # 198.51.100.0/24 is a documentation range that ipaddress flags as
    # reserved/private; use a routable address so the /16 mask path is exercised.
    raw = json.dumps(_envelope(_log(type_code="s", ip="8.8.8.8")))
    results = importer.parse_string(raw)
    res = results[0]
    found = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("client_ip_redacted") is not None:
            assert ev["client_ip_redacted"] == "8.8.0.0/16"
            found = True
        # Full IP never stored.
        for v in ev.values():
            if isinstance(v, str):
                assert v != "8.8.8.8"
    assert found


def test_city_location_dropped() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(
            _log(
                type_code="s",
                country_code="US",
                country_name="United States",
                city_name="San Francisco",
                latitude="37.7749",
                longitude="-122.4194",
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    for cr in res.control_results:
        ev = cr.evidence_data
        # Country preserved.
        if ev.get("country_code") is not None:
            assert ev["country_code"] == "US"
        # City / lat / lon NEVER appear under any key, value, or nested form.
        flat = json.dumps(ev)
        assert "San Francisco" not in flat
        assert "37.7749" not in flat
        assert "-122.4194" not in flat
        assert "city_name" not in ev
        assert "latitude" not in ev
        assert "longitude" not in ev


# ---------------------------------------------------------------------------
# Additional coverage — file IO, JSONL, format variants, sanitization edges
# ---------------------------------------------------------------------------


def test_parse_jsonl_format(tmp_path: Path) -> None:
    importer = Auth0Importer()
    lines = [
        json.dumps(_log(log_id="log-a", type_code="s")),
        json.dumps(_log(log_id="log-b", type_code="f")),
        "",  # blank line tolerated.
        json.dumps(_log(log_id="log-c", type_code="ublkd")),
    ]
    p = tmp_path / "auth0.jsonl"
    p.write_text("\n".join(lines))
    results = importer.parse(p)
    assert len(results) == 3
    decisions = {res.action_id: res.decision for res in results}
    assert decisions["auth0-log-a"] == "ALLOW"
    assert decisions["auth0-log-b"] == "FLAG"
    assert decisions["auth0-log-c"] == "BLOCK"
    # File hash captured in source_provenance.
    expected_sha = hashlib.sha256(p.read_bytes()).hexdigest()
    for res in results:
        for cr in res.control_results:
            sp = cr.evidence_data.get("source_provenance", {})
            assert sp.get("original_file_sha256") == expected_sha
            assert sp.get("source_format") == "auth0_tenant_logs"


def test_parse_data_envelope() -> None:
    importer = Auth0Importer()
    raw = json.dumps({"data": [_log(type_code="s")]})
    results = importer.parse_string(raw)
    assert len(results) == 1
    assert results[0].decision == "ALLOW"


def test_parse_single_log_object() -> None:
    importer = Auth0Importer()
    raw = json.dumps(_log(type_code="s"))
    results = importer.parse_string(raw)
    assert len(results) == 1


def test_unknown_type_code_flags() -> None:
    importer = Auth0Importer()
    raw = json.dumps(_envelope(_log(type_code="zzzzz", description="Mystery event")))
    results = importer.parse_string(raw)
    res = results[0]
    by_sig = _control_results_by_signal(res)
    assert "unknown_event" in by_sig
    assert by_sig["unknown_event"].result == "FLAG"
    assert by_sig["unknown_event"].control_id == "PR-05"
    assert res.decision == "FLAG"


def test_user_name_stored_as_length_and_hash_only() -> None:
    importer = Auth0Importer()
    raw = json.dumps(_envelope(_log(type_code="s", user_name="Alice Example")))
    results = importer.parse_string(raw)
    res = results[0]
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("details_auth_user_name_sha256") is not None:
            assert ev["details_auth_user_name_length"] == len("Alice Example")
            assert ev["details_auth_user_name_sha256"] == hashlib.sha256(
                "Alice Example".encode("utf-8")
            ).hexdigest()
        # Plaintext name never stored.
        flat = json.dumps(ev)
        assert "Alice Example" not in flat


def test_federation_session_marker() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(
            _log(type_code="s", connection="saml", strategy_type="enterprise")
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    by_sig = _control_results_by_signal(res)
    assert "federation_session" in by_sig
    assert by_sig["federation_session"].result == "PASS"


def test_mobile_session_marker() -> None:
    importer = Auth0Importer()
    raw = json.dumps(_envelope(_log(type_code="s", is_mobile=True)))
    results = importer.parse_string(raw)
    res = results[0]
    by_sig = _control_results_by_signal(res)
    assert "mobile_session" in by_sig
    assert by_sig["mobile_session"].result == "PASS"


def test_unknown_oauth_client_when_allowlist_set() -> None:
    importer = Auth0Importer(client_name_allowlist=["Production App"])
    raw = json.dumps(
        _envelope(
            _log(log_id="ok", type_code="s", client_name="Production App"),
            _log(log_id="bad", type_code="s", client_name="Sketchy Tool"),
        )
    )
    results = importer.parse_string(raw)
    by_log = {res.action_id: res for res in results}
    ok_sigs = {
        cr.evidence_data.get("signal")
        for cr in by_log["auth0-ok"].control_results
    }
    bad_sigs = {
        cr.evidence_data.get("signal")
        for cr in by_log["auth0-bad"].control_results
    }
    assert "unknown_oauth_client" not in ok_sigs
    assert "unknown_oauth_client" in bad_sigs
    assert by_log["auth0-bad"].decision == "FLAG"


def test_description_truncated_to_safe_length() -> None:
    importer = Auth0Importer()
    long_desc = "A" * 500
    raw = json.dumps(_envelope(_log(type_code="s", description=long_desc)))
    results = importer.parse_string(raw)
    res = results[0]
    found = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("description") is not None:
            assert len(ev["description"]) <= 200
            found = True
    assert found


def test_request_response_keys_only() -> None:
    importer = Auth0Importer()
    raw = json.dumps(
        _envelope(
            _log(
                type_code="s",
                extra_details={
                    "request": {"method": "POST", "secret_token": "leak-me"},
                    "response": {"status_code": 200, "session_token": "leak-me-too"},
                },
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    for cr in res.control_results:
        ev = cr.evidence_data
        assert ev.get("details_request_keys") is not None
        assert ev.get("details_response_keys") is not None
        # Values never captured.
        flat = json.dumps(ev)
        assert "leak-me" not in flat
