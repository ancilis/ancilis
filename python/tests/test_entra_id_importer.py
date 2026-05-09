"""Tests for the Azure Entra ID sign-in importer."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ancilis.importers.entra_id import EntraIDImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Microsoft Graph sign-in events (no msgraph SDK required)
# ---------------------------------------------------------------------------


def _signin(
    *,
    event_id: str = "evt-001",
    created_date_time: str = "2026-04-01T12:00:00Z",
    user_principal_name: str | None = "alice@corp.example.com",
    user_display_name: str | None = "Alice Example",
    user_id: str | None = "00000000-0000-0000-0000-000000000001",
    app_id: str | None = "00000003-0000-0000-c000-000000000000",
    app_display_name: str | None = "Microsoft Office 365",
    ip_address: str | None = "203.0.113.42",
    client_app_used: str | None = "Browser",
    correlation_id: str | None = "corr-1",
    conditional_access_status: str | None = "success",
    original_request_id: str | None = "req-1",
    is_interactive: bool | None = True,
    token_issuer_type: str | None = "AzureAD",
    token_issuer_name: str | None = "",
    processing_time_ms: int | None = 500,
    risk_detail: str | None = "none",
    risk_level_aggregated: str | None = "none",
    risk_level_during_signin: str | None = "none",
    risk_state: str | None = "none",
    risk_event_types: list[str] | None = None,
    device_id: str | None = "device-id-1234567890abcdef",
    device_display_name: str | None = "ALICE-LAPTOP",
    device_os: str | None = "Windows 11",
    device_browser: str | None = "Edge 110",
    device_is_compliant: bool | None = True,
    device_is_managed: bool | None = True,
    device_trust_type: str | None = "AzureAD",
    location_country: str | None = "US",
    location_state: str | None = "California",
    location_city: str | None = "San Francisco",
    location_lat: float | None = 37.7749,
    location_lon: float | None = -122.4194,
    applied_ca_policies: list[dict[str, Any]] | None = None,
    authentication_methods: list[str] | None = None,
    network_location_details: list[dict[str, Any]] | None = None,
    status_error_code: int | None = 0,
    status_failure_reason: str | None = None,
    status_additional_details: str | None = None,
    sign_in_identifier_type: str | None = "userPrincipalName",
    resource_display_name: str | None = "Microsoft Graph",
    resource_id: str | None = "00000003-0000-0000-c000-000000000000",
) -> dict[str, Any]:
    evt: dict[str, Any] = {
        "id": event_id,
        "createdDateTime": created_date_time,
        "isInteractive": is_interactive,
        "processingTimeInMilliseconds": processing_time_ms,
    }
    if user_principal_name is not None:
        evt["userPrincipalName"] = user_principal_name
    if user_display_name is not None:
        evt["userDisplayName"] = user_display_name
    if user_id is not None:
        evt["userId"] = user_id
    if app_id is not None:
        evt["appId"] = app_id
    if app_display_name is not None:
        evt["appDisplayName"] = app_display_name
    if ip_address is not None:
        evt["ipAddress"] = ip_address
    if client_app_used is not None:
        evt["clientAppUsed"] = client_app_used
    if correlation_id is not None:
        evt["correlationId"] = correlation_id
    if conditional_access_status is not None:
        evt["conditionalAccessStatus"] = conditional_access_status
    if original_request_id is not None:
        evt["originalRequestId"] = original_request_id
    if token_issuer_type is not None:
        evt["tokenIssuerType"] = token_issuer_type
    if token_issuer_name is not None:
        evt["tokenIssuerName"] = token_issuer_name
    if risk_detail is not None:
        evt["riskDetail"] = risk_detail
    if risk_level_aggregated is not None:
        evt["riskLevelAggregated"] = risk_level_aggregated
    if risk_level_during_signin is not None:
        evt["riskLevelDuringSignIn"] = risk_level_during_signin
    if risk_state is not None:
        evt["riskState"] = risk_state
    if risk_event_types is not None:
        evt["riskEventTypes_v2"] = risk_event_types
    if sign_in_identifier_type is not None:
        evt["signInIdentifierType"] = sign_in_identifier_type
    if resource_display_name is not None:
        evt["resourceDisplayName"] = resource_display_name
    if resource_id is not None:
        evt["resourceId"] = resource_id

    # deviceDetail
    device_detail: dict[str, Any] = {}
    if device_id is not None:
        device_detail["deviceId"] = device_id
    if device_display_name is not None:
        device_detail["displayName"] = device_display_name
    if device_os is not None:
        device_detail["operatingSystem"] = device_os
    if device_browser is not None:
        device_detail["browser"] = device_browser
    if device_is_compliant is not None:
        device_detail["isCompliant"] = device_is_compliant
    if device_is_managed is not None:
        device_detail["isManaged"] = device_is_managed
    if device_trust_type is not None:
        device_detail["trustType"] = device_trust_type
    if device_detail:
        evt["deviceDetail"] = device_detail

    # location
    location: dict[str, Any] = {}
    if location_country is not None:
        location["countryOrRegion"] = location_country
    if location_state is not None:
        location["state"] = location_state
    if location_city is not None:
        location["city"] = location_city
    if location_lat is not None or location_lon is not None:
        location["geoCoordinates"] = {
            "latitude": location_lat,
            "longitude": location_lon,
        }
    if location:
        evt["location"] = location

    # appliedConditionalAccessPolicies
    if applied_ca_policies is not None:
        evt["appliedConditionalAccessPolicies"] = applied_ca_policies

    # authenticationDetails
    if authentication_methods is not None:
        evt["authenticationDetails"] = [
            {
                "authenticationStepDateTime": created_date_time,
                "authenticationMethod": method,
                "authenticationStepResultDetail": "success",
                "authenticationStepRequirement": "required",
            }
            for method in authentication_methods
        ]

    # networkLocationDetails
    if network_location_details is not None:
        evt["networkLocationDetails"] = network_location_details

    # status
    status: dict[str, Any] = {}
    if status_error_code is not None:
        status["errorCode"] = status_error_code
    if status_failure_reason is not None:
        status["failureReason"] = status_failure_reason
    if status_additional_details is not None:
        status["additionalDetails"] = status_additional_details
    evt["status"] = status

    return evt


def _envelope(*events: dict[str, Any]) -> dict[str, Any]:
    return {"value": list(events)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _signals(result: Any) -> dict[str, Any]:
    return {
        cr.evidence_data.get("signal"): cr
        for cr in result.control_results
        if cr.evidence_data.get("signal")
    }


# ---------------------------------------------------------------------------
# Required tests (16)
# ---------------------------------------------------------------------------


def test_successful_signin_passes() -> None:
    importer = EntraIDImporter(agent_id="agent-1")
    raw = json.dumps(
        _envelope(
            _signin(
                authentication_methods=[
                    "Password", "Mobile app notification",
                ],
                network_location_details=[
                    {"networkType": "namedNetwork", "networkNames": ["Corp HQ"]}
                ],
            )
        )
    )
    results = importer.parse_string(raw)
    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    sigs = _signals(res)
    assert "signin_success" in sigs
    assert sigs["signin_success"].result == "PASS"
    assert sigs["signin_success"].control_id == "PR-01"
    assert res.source_type == "entra_id_signins_import"


def test_failed_signin_flags() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-fail",
                conditional_access_status="notApplied",
                status_error_code=50053,
                status_failure_reason="IDS_LOCKED_OUT",
                authentication_methods=["Password"],
                network_location_details=[],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    sigs = _signals(res)
    assert "signin_failure" in sigs
    assert sigs["signin_failure"].result == "FLAG"
    assert sigs["signin_failure"].control_id == "PR-01"


def test_high_risk_fails() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-hi",
                risk_level_during_signin="high",
                authentication_methods=["Password"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "BLOCK"
    sigs = _signals(res)
    assert "high_risk_signin" in sigs
    assert sigs["high_risk_signin"].result == "FAIL"
    assert sigs["high_risk_signin"].control_id == "PR-01"


def test_confirmed_compromised_fails() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-cc",
                risk_state="confirmedCompromised",
                authentication_methods=["Password"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "BLOCK"
    sigs = _signals(res)
    assert "confirmed_compromised" in sigs
    assert sigs["confirmed_compromised"].result == "FAIL"
    assert sigs["confirmed_compromised"].control_id == "PR-01"


def test_leaked_credentials_fails() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-lc",
                risk_event_types=["leakedCredentials"],
                authentication_methods=["Password"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "BLOCK"
    sigs = _signals(res)
    assert "leaked_credentials" in sigs
    assert sigs["leaked_credentials"].result == "FAIL"
    assert sigs["leaked_credentials"].control_id == "PR-01"
    assert (
        sigs["leaked_credentials"].evidence_data["risk_event_type"]
        == "leakedCredentials"
    )


def test_password_spray_fails() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-ps",
                risk_event_types=["passwordSpray"],
                authentication_methods=["Password"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "BLOCK"
    sigs = _signals(res)
    assert "password_spray" in sigs
    assert sigs["password_spray"].result == "FAIL"
    assert sigs["password_spray"].control_id == "PR-01"


def test_atypical_travel_flags() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-at",
                risk_event_types=["atypicalTravel"],
                authentication_methods=["Password", "Mobile app notification"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    sigs = _signals(res)
    assert "atypical_travel" in sigs
    assert sigs["atypical_travel"].result == "FLAG"
    assert sigs["atypical_travel"].control_id == "PR-01"


def test_legacy_auth_client_flags() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-imap",
                client_app_used="IMAP",
                authentication_methods=["Password"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    sigs = _signals(res)
    assert "legacy_auth_client" in sigs
    assert sigs["legacy_auth_client"].result == "FLAG"
    assert sigs["legacy_auth_client"].control_id == "PR-01"


def test_non_compliant_device_flags() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-nc",
                device_is_compliant=False,
                authentication_methods=["Password", "Mobile app notification"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    sigs = _signals(res)
    assert "non_compliant_device" in sigs
    assert sigs["non_compliant_device"].result == "FLAG"
    assert sigs["non_compliant_device"].control_id == "PR-02"


def test_password_only_on_privileged_flags() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-popriv",
                authentication_methods=["Password"],
                resource_display_name="Microsoft Graph",
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    sigs = _signals(res)
    assert "password_only_privileged" in sigs
    assert sigs["password_only_privileged"].result == "FLAG"
    assert sigs["password_only_privileged"].control_id == "PR-01"


def test_ca_policy_block_audit() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-cab",
                conditional_access_status="failure",
                applied_ca_policies=[
                    {
                        "id": "pol-1",
                        "displayName": "Block legacy auth",
                        "enforcedGrantControls": ["block"],
                        "enforcedSessionControls": [],
                        "result": "block",
                    },
                ],
                authentication_methods=["Password"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    sigs = _signals(res)
    assert "ca_block_audit" in sigs
    assert sigs["ca_block_audit"].result == "PASS"
    assert sigs["ca_block_audit"].control_id == "PR-02"
    # ca_status=failure also fires.
    assert "ca_failure" in sigs
    assert sigs["ca_failure"].result == "FLAG"
    assert sigs["ca_failure"].control_id == "PR-02"
    # Decision is FLAG because of ca_failure (no FAIL signals).
    assert res.decision == "FLAG"


def test_unknown_app_flags() -> None:
    allowlist = {"00000003-0000-0000-c000-000000000000"}  # Microsoft Graph only.
    importer = EntraIDImporter(app_id_allowlist=allowlist)
    raw = json.dumps(
        _envelope(
            _signin(
                event_id="evt-ua",
                app_id="bad-app-id",
                app_display_name="Suspicious App",
                authentication_methods=["Password", "FIDO security key"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    assert res.decision == "FLAG"
    sigs = _signals(res)
    assert "unknown_app" in sigs
    assert sigs["unknown_app"].result == "FLAG"
    assert sigs["unknown_app"].control_id == "PR-01"


def test_cross_country_pattern_synthetic() -> None:
    importer = EntraIDImporter(cross_country_threshold=2)
    same_user = "00000000-0000-0000-0000-globe-trotter"
    events = [
        _signin(
            event_id=f"evt-{idx}",
            user_id=same_user,
            location_country=cc,
            authentication_methods=["Password", "Mobile app notification"],
        )
        for idx, cc in enumerate(("US", "DE", "JP", "BR"))
    ]
    raw = json.dumps(_envelope(*events))
    results = importer.parse_string(raw)
    # 4 per-event + 1 cross-country synthetic = 5 (no multi-app trigger).
    assert len(results) == 5
    synthetic = next(
        res for res in results
        if res.action_id.startswith("entra-id-cross-country-")
    )
    cr = synthetic.control_results[0]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-01"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["user_id"] == same_user
    assert cr.evidence_data["cross_country_country_count"] == 4
    assert cr.evidence_data["cross_country_countries"] == ["BR", "DE", "JP", "US"]
    # Per-event records also carry the cross_country_pattern marker.
    per_event = [
        res for res in results
        if not res.action_id.startswith("entra-id-cross-country-")
    ]
    for res in per_event:
        sigs = {cr.evidence_data.get("signal") for cr in res.control_results}
        assert "cross_country_pattern" in sigs


def test_userPrincipalName_only_domain_stored() -> None:  # noqa: N802 — required test name
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                user_principal_name="alice@corp.example.com",
                authentication_methods=["Password", "Mobile app notification"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    found_domain = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("user_principal_name_domain") is not None:
            assert ev["user_principal_name_domain"] == "@corp.example.com"
            found_domain = True
        # Plaintext UPN never stored anywhere in evidence.
        for v in ev.values():
            if isinstance(v, str):
                assert "alice@corp.example.com" not in v
    assert found_domain


def test_ip_redacted() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                ip_address="8.8.8.8",
                authentication_methods=["Password", "Mobile app notification"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    found = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("client_ip_redacted") is not None:
            assert ev["client_ip_redacted"] == "8.8.0.0/16"
            found = True
        # Full IP never stored anywhere in evidence.
        for v in ev.values():
            if isinstance(v, str):
                assert v != "8.8.8.8"
    assert found


def test_city_location_dropped() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                location_country="US",
                location_state="California",
                location_city="San Francisco",
                location_lat=37.7749,
                location_lon=-122.4194,
                authentication_methods=["Password", "Mobile app notification"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    found_country = False
    # Disallowed substrings that should never appear as strings in evidence.
    disallowed_strings = ("San Francisco", "California", "37.7749", "-122.4194")
    # Evidence keys that may contain "state"/"city"/etc as part of legitimate
    # field names (e.g. risk_state, status_*) are explicitly allowed.
    location_specific_keys = (
        "city", "city_name", "state_name", "geo_coordinates",
        "geographical", "latitude", "longitude", "coordinates",
    )
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("country_or_region") is not None:
            assert ev["country_or_region"] == "US"
            found_country = True
        for k, v in ev.items():
            if isinstance(v, str):
                for bad in disallowed_strings:
                    assert bad not in v, f"{bad!r} leaked into evidence key {k!r}"
            kl = k.lower()
            for bad_key in location_specific_keys:
                assert bad_key not in kl, (
                    f"location-specific key {k!r} should not be in evidence"
                )
    assert found_country


# ---------------------------------------------------------------------------
# Additional smoke tests
# ---------------------------------------------------------------------------


def test_parse_jsonl() -> None:
    importer = EntraIDImporter()
    lines = [
        json.dumps(
            _signin(
                event_id="jsonl-1",
                authentication_methods=["Password", "Mobile app notification"],
            )
        ),
        json.dumps(
            _signin(
                event_id="jsonl-2",
                client_app_used="POP",
                authentication_methods=["Password"],
            )
        ),
    ]
    results = importer.parse_string("\n".join(lines))
    assert len(results) == 2
    by_id = {res.action_id: res for res in results}
    assert "entra-id-jsonl-1" in by_id
    assert "entra-id-jsonl-2" in by_id
    # Second one (POP legacy auth) flags.
    assert by_id["entra-id-jsonl-2"].decision == "FLAG"


def test_user_display_name_hashed_not_plaintext() -> None:
    importer = EntraIDImporter()
    name = "Alice Confidential Example"
    raw = json.dumps(
        _envelope(
            _signin(
                user_display_name=name,
                authentication_methods=["Password", "Mobile app notification"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    expected_sha = hashlib.sha256(name.encode("utf-8")).hexdigest()
    found = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("user_display_name_sha256") is not None:
            assert ev["user_display_name_sha256"] == expected_sha
            assert ev["user_display_name_length"] == len(name)
            found = True
        for v in ev.values():
            if isinstance(v, str):
                assert name not in v
    assert found


def test_device_id_truncated() -> None:
    importer = EntraIDImporter()
    raw = json.dumps(
        _envelope(
            _signin(
                device_id="device-id-1234567890abcdef",
                authentication_methods=["Password", "Mobile app notification"],
            )
        )
    )
    results = importer.parse_string(raw)
    res = results[0]
    found = False
    for cr in res.control_results:
        ev = cr.evidence_data
        if ev.get("device_id_redacted") is not None:
            # Last 8 chars, prefixed with "..."
            assert ev["device_id_redacted"] == "...90abcdef"
            found = True
    assert found
