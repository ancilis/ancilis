"""Tests for the Microsoft Sentinel incidents importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers import MicrosoftSentinelImporter


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _alert(
    *,
    alert_id: str = "alert-1",
    name: str = "Anomalous Azure Active Directory sign-in",
    severity: str = "High",
    category: str = "Initial Access",
    kill_chain: list[str] | None = None,
    techniques: list[str] | None = None,
    vendor_name: str = "Microsoft 365 Defender",
    product_name: str = "Microsoft Defender for Endpoint",
    entities_count: int = 3,
) -> dict[str, Any]:
    return {
        "id": alert_id,
        "name": name,
        "severity": severity,
        "category": category,
        "kill_chain": list(kill_chain or []),
        "techniques": list(techniques or []),
        "vendor_name": vendor_name,
        "product_name": product_name,
        "entities_count": entities_count,
    }


def _incident(
    *,
    incident_id: str = "inc-001",
    incident_number: int = 1234,
    title: str = "Suspicious Sign-in",
    description_length: int = 200,
    severity: str = "High",
    status: str = "New",
    classification: str | None = None,
    classification_comment_length: int = 0,
    owner_email: str | None = "sec-team@example.com",
    owner_name: str | None = "SecTeam",
    owner_object_id: str | None = "obj-1",
    alerts: list[dict[str, Any]] | None = None,
    labels: list[str] | None = None,
    tags: list[str] | None = None,
    automated_response: dict[str, Any] | None = None,
    additional_data: dict[str, Any] | None = None,
    created: str = "2026-05-09T12:00:00Z",
    updated: str = "2026-05-09T12:00:01Z",
    alert_count: int | None = None,
) -> dict[str, Any]:
    if alerts is None:
        alerts = [_alert()]
    if alert_count is None:
        alert_count = len(alerts)
    return {
        "id": incident_id,
        "incidentNumber": incident_number,
        "title": title,
        "description_length": description_length,
        "createdTimeUtc": created,
        "lastUpdatedTimeUtc": updated,
        "severity": severity,
        "status": status,
        "classification": classification,
        "classificationComment_length": classification_comment_length,
        "owner": {
            "objectId": owner_object_id,
            "email": owner_email,
            "name": owner_name,
        },
        "alerts": alerts,
        "labels": list(labels or []),
        "alertCount": alert_count,
        "automatedResponse": automated_response
        or {
            "playbook_executed": False,
            "playbook_name": None,
            "actions_taken": [],
            "approval_required": False,
            "approved_by": None,
        },
        "additionalData": additional_data
        or {
            "alertProductNames": ["Microsoft Defender for Endpoint"],
            "alertsCount": alert_count,
            "bookmarksCount": 0,
            "commentsCount": 0,
        },
        "tags": list(tags or []),
    }


def _envelope(incidents: list[dict[str, Any]]) -> str:
    return json.dumps({"incidents": incidents})


def _has_signal(result: Any, signal: str) -> bool:
    return any(
        cr.evidence_data.get("signal") == signal for cr in result.control_results
    )


def _signal_result(result: Any, signal: str) -> Any:
    for cr in result.control_results:
        if cr.evidence_data.get("signal") == signal:
            return cr
    return None


def _per_incident(results: list[Any]) -> list[Any]:
    """Return only per-incident results (filter out synthetics)."""
    return [
        r
        for r in results
        if not any(cr.evidence_data.get("synthetic") for cr in r.control_results)
    ]


# ---------------------------------------------------------------------------
# Severity / status / classification tests
# ---------------------------------------------------------------------------


def test_high_open_fails() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope([_incident(severity="High", status="New")])
    )
    incidents = _per_incident(results)
    assert len(incidents) == 1
    r = incidents[0]
    assert _has_signal(r, "high_open")
    cr = _signal_result(r, "high_open")
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert r.decision == "FLAG"


def test_high_resolved_true_positive_audit_fail() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="High",
                    status="Resolved",
                    classification="TruePositive",
                )
            ]
        )
    )
    incidents = _per_incident(results)
    r = incidents[0]
    assert _has_signal(r, "high_resolved_true_positive")
    cr = _signal_result(r, "high_resolved_true_positive")
    assert cr.control_id == "PR-05"
    assert cr.result == "FAIL"


def test_high_closed_false_positive_passes() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="High",
                    status="Closed",
                    classification="FalsePositive",
                    alerts=[
                        _alert(category="Discovery", kill_chain=[], techniques=[])
                    ],
                )
            ]
        )
    )
    incidents = _per_incident(results)
    r = incidents[0]
    assert _has_signal(r, "high_closed_false_positive")
    cr = _signal_result(r, "high_closed_false_positive")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


# ---------------------------------------------------------------------------
# Category-based controls
# ---------------------------------------------------------------------------


def test_exfiltration_category_fails() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="Medium",
                    status="Active",
                    alerts=[
                        _alert(
                            category="Exfiltration",
                            kill_chain=["Exfiltration"],
                            techniques=["T1567"],
                        )
                    ],
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    assert _has_signal(r, "category_exfiltration")
    cr = _signal_result(r, "category_exfiltration")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_credential_access_category_fails() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="High",
                    status="Active",
                    alerts=[
                        _alert(
                            category="CredentialAccess",
                            kill_chain=["CredentialAccess"],
                            techniques=["T1110"],
                        )
                    ],
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    assert _has_signal(r, "category_credential_access")
    cr = _signal_result(r, "category_credential_access")
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_initial_access_with_severity_fails() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="High",
                    status="Active",
                    alerts=[
                        _alert(
                            category="Initial Access",
                            kill_chain=["InitialAccess", "CredentialAccess"],
                            techniques=["T1078"],
                        )
                    ],
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    assert _has_signal(r, "kill_chain_initial_access")
    cr = _signal_result(r, "kill_chain_initial_access")
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# AI-related labels
# ---------------------------------------------------------------------------


def test_ai_related_label_captured() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="Medium",
                    status="Active",
                    labels=["AI-related", "prompt-injection"],
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    assert _has_signal(r, "ai_related_label")
    cr = _signal_result(r, "ai_related_label")
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"
    assert "ai-related" in cr.evidence_data["ai_labels_matched"]
    assert "prompt-injection" in cr.evidence_data["ai_labels_matched"]


# ---------------------------------------------------------------------------
# Automated response governance
# ---------------------------------------------------------------------------


def test_auto_response_no_approval_fails() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="Medium",
                    status="Active",
                    automated_response={
                        "playbook_executed": True,
                        "playbook_name": "Auto-Notify-Owner",
                        "actions_taken": ["send_email"],
                        "approval_required": True,
                        "approved_by": None,
                    },
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    assert _has_signal(r, "auto_response_no_approval")
    cr = _signal_result(r, "auto_response_no_approval")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_high_impact_action_no_approval_fails() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="Medium",
                    status="Active",
                    automated_response={
                        "playbook_executed": True,
                        "playbook_name": "Block-User-On-Risky-Sign-In",
                        "actions_taken": ["disable_user", "reset_password"],
                        "approval_required": True,
                        "approved_by": None,
                    },
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    assert _has_signal(r, "high_impact_action_no_approval")
    cr = _signal_result(r, "high_impact_action_no_approval")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert "disable_user" in cr.evidence_data["high_impact_actions_executed"]


def test_customer_impacting_open_fails() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="Medium",
                    status="Active",
                    tags=["production", "customer-impacting"],
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    assert _has_signal(r, "customer_impacting_open")
    cr = _signal_result(r, "customer_impacting_open")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Synthetic cross-incident signals
# ---------------------------------------------------------------------------


def test_recurring_attack_synthetic() -> None:
    importer = MicrosoftSentinelImporter(recurring_attack_threshold=2)
    incidents = [
        _incident(
            incident_id=f"inc-{i}",
            incident_number=2000 + i,
            severity="High",
            status="Resolved",
            classification="TruePositive",
            alerts=[
                _alert(
                    alert_id=f"a-{i}",
                    name=f"Detected attack {i}",
                    product_name="Microsoft Defender for Endpoint",
                )
            ],
            created="2026-05-09T12:00:00Z",
        )
        for i in range(4)
    ]
    results = importer.parse_string(_envelope(incidents))
    synthetics = [
        r
        for r in results
        if any(cr.evidence_data.get("synthetic") for cr in r.control_results)
    ]
    recurring = [
        r
        for r in synthetics
        if any(
            cr.evidence_data.get("signal") == "recurring_attack_synthetic"
            for cr in r.control_results
        )
    ]
    assert len(recurring) == 1
    cr = recurring[0].control_results[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FLAG"
    assert (
        cr.evidence_data["alert_product_name"] == "Microsoft Defender for Endpoint"
    )
    assert cr.evidence_data["true_positive_count"] == 4


def test_repeated_fp_synthetic() -> None:
    importer = MicrosoftSentinelImporter(repeated_fp_threshold=2)
    incidents = [
        _incident(
            incident_id=f"inc-fp-{i}",
            incident_number=3000 + i,
            severity="Low",
            status="Closed",
            classification="FalsePositive",
            alerts=[
                _alert(
                    alert_id=f"a-fp-{i}",
                    name="Noisy Detection Rule",
                    product_name="Azure Sentinel",
                    category="Discovery",
                )
            ],
            created="2026-05-09T12:00:00Z",
        )
        for i in range(4)
    ]
    results = importer.parse_string(_envelope(incidents))
    synthetics = [
        r
        for r in results
        if any(cr.evidence_data.get("synthetic") for cr in r.control_results)
    ]
    fp_synthetics = [
        r
        for r in synthetics
        if any(
            cr.evidence_data.get("signal") == "repeated_fp_synthetic"
            for cr in r.control_results
        )
    ]
    assert len(fp_synthetics) == 1
    cr = fp_synthetics[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["false_positive_count"] == 4
    # Ensure the alert name was redacted (not stored verbatim).
    name_redacted = cr.evidence_data["alert_name_redacted"]
    assert "preview" in name_redacted
    assert "sha256" in name_redacted
    assert name_redacted["sha256"]


# ---------------------------------------------------------------------------
# Sanitization tests
# ---------------------------------------------------------------------------


def test_title_redacted() -> None:
    importer = MicrosoftSentinelImporter()
    long_title = (
        "Sensitive customer data exfil from CFO mailbox at AcmeCorp Q2 2026 "
        "containing internal credentials and PII"
    )
    results = importer.parse_string(
        _envelope([_incident(title=long_title, severity="Medium", status="Active")])
    )
    r = _per_incident(results)[0]
    cr = r.control_results[0]
    title_redacted = cr.evidence_data["title_redacted"]
    assert title_redacted["sha256"]
    assert title_redacted["length"] == len(long_title)
    assert title_redacted["truncated"] is True
    assert len(title_redacted["preview"]) <= 80
    # The full title must NEVER appear in the evidence.
    serialized = json.dumps(cr.evidence_data, default=str)
    assert long_title not in serialized


def test_owner_email_only_domain_stored() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="Medium",
                    status="Active",
                    owner_email="alice.smith@example.com",
                    owner_name="Alice Smith",
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    cr = r.control_results[0]
    owner = cr.evidence_data["owner"]
    assert owner["email_domain"] == "@example.com"
    # Local part of email must NOT appear.
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "alice.smith" not in serialized
    # Owner name is hashed, not stored verbatim.
    assert "Alice Smith" not in serialized
    assert owner["name_redacted"]["present"] is True
    assert owner["name_redacted"]["sha256"]
    assert owner["name_redacted"]["length"] == len("Alice Smith")


def test_mitre_techniques_captured() -> None:
    importer = MicrosoftSentinelImporter()
    results = importer.parse_string(
        _envelope(
            [
                _incident(
                    severity="High",
                    status="Active",
                    alerts=[
                        _alert(
                            category="Initial Access",
                            kill_chain=["InitialAccess"],
                            techniques=["T1078", "T1110"],
                            product_name="Azure AD Identity Protection",
                        ),
                        _alert(
                            alert_id="alert-2",
                            name="Data exfiltration over channel",
                            category="Exfiltration",
                            kill_chain=["Exfiltration"],
                            techniques=["T1041"],
                            product_name="Microsoft Defender for Cloud Apps",
                        ),
                    ],
                )
            ]
        )
    )
    r = _per_incident(results)[0]
    # Techniques captured in evidence on every control result.
    cr0 = r.control_results[0]
    techs = cr0.evidence_data["mitre_techniques"]
    assert "T1078" in techs
    assert "T1110" in techs
    assert "T1041" in techs
    # PR-01 technique signal emitted (T1078, T1110 → PR-01).
    assert _has_signal(r, "mitre_technique_pr01")
    pr01 = _signal_result(r, "mitre_technique_pr01")
    assert pr01.control_id == "PR-01"
    assert pr01.result == "FAIL"
    # PR-04 technique signal emitted (T1041 → PR-04).
    assert _has_signal(r, "mitre_technique_pr04")
    pr04 = _signal_result(r, "mitre_technique_pr04")
    assert pr04.control_id == "PR-04"
    assert pr04.result == "FAIL"
    # Aggregated alert categories captured.
    assert "Exfiltration" in cr0.evidence_data["alert_categories"]
    assert "Initial Access" in cr0.evidence_data["alert_categories"]
