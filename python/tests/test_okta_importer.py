"""Tests for the Okta SystemLog importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers.okta import OktaImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Okta SystemLog event records (no okta SDK required)
# ---------------------------------------------------------------------------


def _event(
    *,
    uuid: str = "evt-okta-001",
    event_type: str = "user.session.start",
    published: str = "2026-04-01T12:00:00.000Z",
    severity: str = "INFO",
    legacy_event_type: str = "core.user.signon.login_success",
    display_message: str = "User login to Okta",
    actor_id: str = "00u1abcd23efgh45ijkl",
    actor_type: str = "User",
    actor_alternate_id: str = "alice@example.com",
    actor_display_name: str = "Alice Example",
    ip_address: str = "203.0.113.42",
    raw_user_agent: str = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    ua_os: str = "Mac OS X",
    ua_browser: str = "Chrome",
    device: str = "Computer",
    zone: str = "null",
    country: str = "United States",
    outcome_result: str | None = "SUCCESS",
    outcome_reason: str | None = None,
    targets: list[dict[str, Any]] | None = None,
    transaction_type: str = "WEB",
    transaction_id: str = "txn-abc",
    request_uri: str = "/api/v1/sessions/me?expand=true&token=secret",
    auth_provider: str = "OKTA_AUTHENTICATION_PROVIDER",
    is_proxy: bool | None = False,
    as_org: str | None = "Example ISP Inc",
    as_number: int | None = 64500,
) -> dict[str, Any]:
    if targets is None:
        targets = []
    outcome: dict[str, Any] = {}
    if outcome_result is not None:
        outcome["result"] = outcome_result
    if outcome_reason is not None:
        outcome["reason"] = outcome_reason
    security_context: dict[str, Any] = {}
    if is_proxy is not None:
        security_context["isProxy"] = is_proxy
    if as_org is not None:
        security_context["asOrg"] = as_org
    if as_number is not None:
        security_context["asNumber"] = as_number
    return {
        "uuid": uuid,
        "published": published,
        "eventType": event_type,
        "version": "0",
        "severity": severity,
        "legacyEventType": legacy_event_type,
        "displayMessage": display_message,
        "actor": {
            "id": actor_id,
            "type": actor_type,
            "alternateId": actor_alternate_id,
            "displayName": actor_display_name,
        },
        "client": {
            "userAgent": {
                "rawUserAgent": raw_user_agent,
                "os": ua_os,
                "browser": ua_browser,
            },
            "zone": zone,
            "device": device,
            "ipAddress": ip_address,
            "geographicalContext": {
                "city": "San Francisco",
                "state": "California",
                "country": country,
                "postalCode": "94103",
            },
        },
        "outcome": outcome,
        "target": targets,
        "transaction": {"type": transaction_type, "id": transaction_id, "detail": {}},
        "debugContext": {"debugData": {"requestUri": request_uri, "url": request_uri}},
        "authenticationContext": {"authenticationProvider": auth_provider},
        "securityContext": security_context,
    }


def _findings_for_event(results: list, event_uuid: str) -> list:
    """Return EvaluationResults whose action_id matches a given event uuid."""
    return [r for r in results if r.action_id == f"okta-{event_uuid}"]


def _signals_in(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


# ---------------------------------------------------------------------------
# Authentication / session
# ---------------------------------------------------------------------------


def test_parse_successful_login() -> None:
    """user.authentication.auth_via_mfa SUCCESS → PR-01 PASS, ALLOW."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-auth-ok",
                    event_type="user.authentication.auth_via_mfa",
                    outcome_result="SUCCESS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    matches = _findings_for_event(results, "evt-auth-ok")
    assert len(matches) == 1
    res = matches[0]
    assert res.decision == "ALLOW"
    crs = res.control_results
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "auth_success"
        for cr in crs
    )


def test_failed_login_flags() -> None:
    """user.authentication.* FAILURE → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-auth-fail",
                    event_type="user.authentication.auth_via_mfa",
                    outcome_result="FAILURE",
                    outcome_reason="INVALID_CREDENTIALS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    matches = _findings_for_event(results, "evt-auth-fail")
    assert len(matches) == 1
    res = matches[0]
    assert res.decision == "FLAG"
    assert "auth_failure" in _signals_in(res)
    assert any(
        cr.control_id == "PR-01" and cr.result == "FLAG"
        for cr in res.control_results
    )


def test_proxy_originated_session_flags() -> None:
    """user.session.start with isProxy=true (benign asOrg) → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-proxy",
                    event_type="user.session.start",
                    outcome_result="SUCCESS",
                    is_proxy=True,
                    as_org="Cloudflare Inc",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-proxy")[0]
    assert res.decision == "FLAG"
    assert "proxy_session" in _signals_in(res)
    assert "anonymizer_session" not in _signals_in(res)


def test_admin_app_access_flags() -> None:
    """user.session.access_admin_app → PR-02 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-admin",
                    event_type="user.session.access_admin_app",
                    outcome_result="SUCCESS",
                    targets=[
                        {
                            "id": "0oa1adminapp",
                            "type": "AppInstance",
                            "alternateId": "Okta Admin Console",
                            "displayName": "Okta Admin Console",
                        }
                    ],
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-admin")[0]
    assert res.decision == "FLAG"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "admin_app_access"
        for cr in res.control_results
    )


def test_privilege_grant_fails() -> None:
    """user.account.privilege.grant → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-priv",
                    event_type="user.account.privilege.grant",
                    outcome_result="SUCCESS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-priv")[0]
    assert res.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "privilege_grant"
        for cr in res.control_results
    )


def test_api_token_create_flags() -> None:
    """system.api_token.create → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-token-create",
                    event_type="system.api_token.create",
                    outcome_result="SUCCESS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-token-create")[0]
    assert res.decision == "FLAG"
    assert "api_token_create" in _signals_in(res)
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "api_token_create"
        for cr in res.control_results
    )


def test_api_token_revoke_audit() -> None:
    """system.api_token.revoke → PR-05 PASS (audit trail)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-token-revoke",
                    event_type="system.api_token.revoke",
                    outcome_result="SUCCESS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-token-revoke")[0]
    assert res.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-05"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "api_token_revoke"
        for cr in res.control_results
    )


def test_policy_deactivate_fails() -> None:
    """policy.lifecycle.deactivate → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-policy-off",
                    event_type="policy.lifecycle.deactivate",
                    outcome_result="SUCCESS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-policy-off")[0]
    assert res.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "policy_deactivate"
        for cr in res.control_results
    )


def test_iwa_exempt_flags() -> None:
    """iwa.exempt.windows_login_success → PR-01 FLAG (auth bypass surface)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-iwa",
                    event_type="iwa.exempt.windows_login_success",
                    outcome_result="SUCCESS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-iwa")[0]
    assert res.decision == "FLAG"
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "iwa_exempt"
        for cr in res.control_results
    )


def test_mfa_deactivate_fails() -> None:
    """user.mfa.factor.deactivate → PR-01 FAIL (security degradation)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-mfa-off",
                    event_type="user.mfa.factor.deactivate",
                    outcome_result="SUCCESS",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-mfa-off")[0]
    assert res.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "mfa_factor_deactivate"
        for cr in res.control_results
    )


def test_anonymizer_origin_fails() -> None:
    """isProxy=true + asOrg matches anonymizer pattern → PR-01 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-tor",
                    event_type="user.session.start",
                    outcome_result="SUCCESS",
                    is_proxy=True,
                    as_org="Tor Exit Node Organization",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-tor")[0]
    assert res.decision == "BLOCK"
    assert "anonymizer_session" in _signals_in(res)
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "anonymizer_session"
        for cr in res.control_results
    )
    # The plain proxy_session signal should NOT also fire (anonymizer
    # supersedes plain-proxy classification).
    assert "proxy_session" not in _signals_in(res)


def test_cross_country_pattern_synthetic_finding() -> None:
    """Same actor.id touching > threshold countries → synthetic PR-01 FLAG."""
    actor_id = "00u9travel1234567890"
    events = [
        _event(
            uuid=f"evt-geo-{i}",
            event_type="user.session.start",
            outcome_result="SUCCESS",
            actor_id=actor_id,
            country=country,
        )
        for i, country in enumerate(
            ["United States", "Germany", "Brazil", "Japan"]
        )
    ]
    doc = json.dumps({"events": events})
    importer = OktaImporter(cross_country_threshold=3)
    results = importer.parse_string(doc)

    # Synthetic finding action_id pattern.
    synth = [r for r in results if r.action_id == f"okta-cross-country-{actor_id}"]
    assert len(synth) == 1
    sr = synth[0]
    assert sr.decision == "FLAG"
    assert sr.control_results[0].control_id == "PR-01"
    assert sr.control_results[0].result == "FLAG"
    assert sr.control_results[0].evidence_data["cross_country_country_count"] == 4
    assert sorted(
        sr.control_results[0].evidence_data["cross_country_countries"]
    ) == ["Brazil", "Germany", "Japan", "United States"]
    # The actor_id_redacted preserves the 00u prefix and last-4.
    assert sr.control_results[0].evidence_data["actor_id_redacted"].startswith("00u9")
    assert sr.control_results[0].evidence_data["actor_id_redacted"].endswith("7890")
    # Per-event control entries should also carry the cross_country_pattern signal.
    per_event = [r for r in results if r.action_id != f"okta-cross-country-{actor_id}"]
    assert all(
        "cross_country_pattern" in _signals_in(r) for r in per_event
    )


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_ip_address_redacted_to_slash16() -> None:
    """client.ipAddress public IPv4 is masked to /16."""
    # 8.8.4.4 is a clearly-public address (Google DNS); 203.0.113.x is
    # RFC5737 TEST-NET-3 which Python's ipaddress treats as is_private.
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-ip",
                    event_type="user.session.start",
                    outcome_result="SUCCESS",
                    ip_address="8.8.4.4",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-ip")[0]
    redacted = res.control_results[0].evidence_data["client_ip_redacted"]
    assert redacted == "8.8.0.0/16"
    # And the original full IP must not appear anywhere in any evidence_data.
    serialized = json.dumps([cr.evidence_data for cr in res.control_results])
    assert "8.8.4.4" not in serialized
    # RFC1918 private addresses are preserved verbatim (already non-routable).
    doc_private = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-ip-priv",
                    event_type="user.session.start",
                    outcome_result="SUCCESS",
                    ip_address="10.0.0.1",
                )
            ]
        }
    )
    res_priv = _findings_for_event(
        OktaImporter().parse_string(doc_private), "evt-ip-priv"
    )[0]
    assert (
        res_priv.control_results[0].evidence_data["client_ip_redacted"]
        == "10.0.0.1"
    )


def test_user_agent_redacted() -> None:
    """rawUserAgent is truncated to first 80 chars + sha256 of full UA captured."""
    long_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
        "ExtraFingerprintToken/abcdefghijklmnopqrstuvwxyz0123456789"
    )
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-ua",
                    event_type="user.session.start",
                    outcome_result="SUCCESS",
                    raw_user_agent=long_ua,
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-ua")[0]
    ed = res.control_results[0].evidence_data
    assert ed["client_user_agent_truncated"] == long_ua[:80]
    assert len(ed["client_user_agent_truncated"]) == 80
    assert ed["client_user_agent_sha256"] == hashlib.sha256(
        long_ua.encode("utf-8")
    ).hexdigest()
    # Fingerprint token must not survive in any evidence dict.
    serialized = json.dumps([cr.evidence_data for cr in res.control_results])
    assert "ExtraFingerprintToken" not in serialized


def test_alternateId_only_domain_stored() -> None:  # noqa: N802 — required test name
    """actor.alternateId reduced to ``"@<domain>"`` — local part never stored."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-pii",
                    event_type="user.session.start",
                    outcome_result="SUCCESS",
                    actor_alternate_id="alice.example@corp.example.com",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-pii")[0]
    ed = res.control_results[0].evidence_data
    assert ed["actor_alternate_id_domain"] == "@corp.example.com"
    serialized = json.dumps([cr.evidence_data for cr in res.control_results])
    assert "alice.example" not in serialized
    assert "alice.example@corp.example.com" not in serialized
    # Also: requestUri query string must be stripped.
    assert "?" not in (ed["debug_request_uri_path"] or "")
    assert "token=" not in serialized
    # And the actor.id must be redacted, never raw.
    assert ed["actor_id_redacted"].startswith("00u1")
    assert ed["actor_id_redacted"].endswith("ijkl")
    assert "00u1abcd23efgh45ijkl" not in serialized


def test_jsonl_stream() -> None:
    """JSONL: one event per line, mixed event types parse correctly."""
    lines = [
        json.dumps(
            _event(
                uuid="evt-jsonl-1",
                event_type="user.authentication.auth_via_mfa",
                outcome_result="SUCCESS",
            )
        ),
        json.dumps(
            _event(
                uuid="evt-jsonl-2",
                event_type="user.session.start",
                outcome_result="SUCCESS",
                is_proxy=True,
                as_org="VPN Provider Corp",
            )
        ),
        "",  # blank line tolerated
        json.dumps(
            _event(
                uuid="evt-jsonl-3",
                event_type="system.api_token.revoke",
                outcome_result="SUCCESS",
            )
        ),
    ]
    content = "\n".join(lines)
    results = OktaImporter().parse_string(content)
    uuids = {r.action_id for r in results}
    assert "okta-evt-jsonl-1" in uuids
    assert "okta-evt-jsonl-2" in uuids
    assert "okta-evt-jsonl-3" in uuids
    # Anonymizer detection on jsonl row 2 (asOrg contains "VPN").
    res2 = _findings_for_event(results, "evt-jsonl-2")[0]
    assert res2.decision == "BLOCK"
    assert "anonymizer_session" in _signals_in(res2)


# ---------------------------------------------------------------------------
# Bonus coverage: outcome=DENY, file provenance, missing okta package
# ---------------------------------------------------------------------------


def test_outcome_deny_audit_pass() -> None:
    """outcome=DENY → PR-02 PASS (audit trail of correct denial)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-deny",
                    event_type="user.session.access_admin_app",
                    outcome_result="DENY",
                )
            ]
        }
    )
    results = OktaImporter().parse_string(doc)
    res = _findings_for_event(results, "evt-deny")[0]
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "outcome_deny"
        for cr in res.control_results
    )


def test_parse_file_captures_sha256(tmp_path: Path) -> None:
    """parse(path) records the original-file sha256 in source_provenance."""
    payload = json.dumps(
        {
            "events": [
                _event(
                    uuid="evt-file",
                    event_type="user.authentication.auth_via_mfa",
                    outcome_result="SUCCESS",
                )
            ]
        }
    ).encode("utf-8")
    p = tmp_path / "okta-export.json"
    p.write_bytes(payload)
    results = OktaImporter().parse(p)
    expected_sha = hashlib.sha256(payload).hexdigest()
    res = _findings_for_event(results, "evt-file")[0]
    prov = res.control_results[0].evidence_data["source_provenance"]
    assert prov["original_file_sha256"] == expected_sha
    assert prov["source_format"] == "okta_systemlog"


def test_sdk_importable_without_okta_package() -> None:
    """OktaImporter must import even when the third-party 'okta' package is absent."""
    import importlib
    import sys

    # Simulate absence of the okta package.
    sentinel = object()
    saved = sys.modules.pop("okta", sentinel)
    try:
        mod = importlib.import_module("ancilis.importers.okta")
        assert hasattr(mod, "OktaImporter")
    finally:
        if saved is not sentinel:
            sys.modules["okta"] = saved  # type: ignore[assignment]
