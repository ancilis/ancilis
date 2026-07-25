"""OSCAL Assessment Results renderer."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, cast

from ancilis._shared import shared_path
from ancilis.evidence.record import EvidenceRecord

ANCILIS_OSCAL_NS = "https://ancilis.ai/ns/oscal"
RUNTIME_CONTROL_PREFIXES = ("PR-", "DE-")
POSTURE_CONTROL_PREFIXES = ("GOV-", "ID-", "RS-", "RC-")
RESULT_TO_STATE = {
    "PASS": "satisfied",
    # SKIP means "no evaluator evidence collected in period", i.e. pending —
    # not "not-applicable" (which asserts the control does not apply).
    "FAIL": "not-satisfied",
    "SKIP": "not-satisfied",
    "ERROR": "not-satisfied",
    "FLAG": "not-satisfied",
}
SKIP_REMARKS = "no evaluator evidence collected in period (pending)"


def load_oscal_mapping() -> dict[str, Any]:
    """Load the shared AKSI to NIST SP 800-53 Rev 5 OSCAL mapping."""
    mapping_path = shared_path("mappings", "oscal-sp800-53.json")
    data = json.loads(mapping_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("OSCAL mapping must be a JSON object")
    return cast(dict[str, Any], data)


def render_oscal(records: list[EvidenceRecord]) -> str:
    """Render evidence records as OSCAL Assessment Results JSON."""
    mapping = load_oscal_mapping()
    generated_at = datetime.now(timezone.utc).isoformat()
    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    reviewed_controls: dict[str, None] = {}

    for record in records:
        for control_result in record.control_results:
            control_id = str(control_result.get("control_id", ""))
            nist_controls = _nist_controls_for(mapping, control_id)
            if not nist_controls:
                continue
            for nist_control_id in nist_controls:
                reviewed_controls[nist_control_id] = None

                if control_id.startswith(RUNTIME_CONTROL_PREFIXES):
                    observations.append(
                        _observation(record, control_result, control_id, nist_control_id)
                    )
                elif control_id.startswith(POSTURE_CONTROL_PREFIXES):
                    findings.append(_finding(record, control_result, control_id, nist_control_id))

    assessment_results = {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "Ancilis Runtime Evidence Export",
                "last-modified": generated_at,
                "version": "1.0.0",
                "oscal-version": mapping["oscal_version"],
                "props": [
                    _prop("framework", mapping["framework"]),
                    _prop("source", "ancilis-sdk"),
                ],
            },
            "import-ap": {
                "href": mapping["catalog_href"],
            },
            "results": [
                {
                    "uuid": str(uuid.uuid4()),
                    "title": "Ancilis Assessment Results",
                    "description": "Assessment results generated from Ancilis hash-chained evidence.",
                    "start": _first_timestamp(records) or generated_at,
                    "end": _last_timestamp(records) or generated_at,
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "include-controls": [
                                    {"control-id": control_id}
                                    for control_id in sorted(reviewed_controls)
                                ]
                            }
                        ]
                    },
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }
    return json.dumps(assessment_results, indent=2, sort_keys=True) + "\n"


def _nist_controls_for(mapping: dict[str, Any], control_id: str) -> list[str]:
    raw_controls = mapping["mappings"].get(control_id, [])
    return [str(control).lower() for control in raw_controls]


def _observation(
    record: EvidenceRecord,
    control_result: dict[str, Any],
    control_id: str,
    nist_control_id: str,
) -> dict[str, Any]:
    observation: dict[str, Any] = {
        "uuid": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{record.record_id}:{control_id}:{nist_control_id}:observation",
            )
        ),
        "title": f"{control_id} runtime evidence",
        "description": str(control_result.get("detail") or control_result.get("control_name") or control_id),
        "methods": ["TEST"],
        "collected": record.timestamp,
        "props": _shared_props(record, control_result, control_id, nist_control_id),
        "relevant-evidence": [
            {
                "href": f"#evidence-{record.record_id}",
                "description": f"Ancilis evidence record {record.record_id}",
            }
        ],
    }
    if str(control_result.get("result", "SKIP")).upper() == "SKIP":
        observation["remarks"] = SKIP_REMARKS
    return observation


def _finding(
    record: EvidenceRecord,
    control_result: dict[str, Any],
    control_id: str,
    nist_control_id: str,
) -> dict[str, Any]:
    result = str(control_result.get("result", "SKIP")).upper()
    status: dict[str, str] = {
        "state": _assessment_state(control_result),
        "reason": str(control_result.get("result", "SKIP")),
    }
    if result == "SKIP":
        status["remarks"] = SKIP_REMARKS
    return {
        "uuid": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{record.record_id}:{control_id}:{nist_control_id}:finding",
            )
        ),
        "title": f"{control_id} posture finding",
        "description": str(control_result.get("detail") or control_result.get("control_name") or control_id),
        "props": _shared_props(record, control_result, control_id, nist_control_id),
        "target": {
            "type": "control-id",
            "target-id": nist_control_id,
            "status": status,
        },
    }


def _shared_props(
    record: EvidenceRecord,
    control_result: dict[str, Any],
    control_id: str,
    nist_control_id: str,
) -> list[dict[str, str]]:
    props = [
        _prop("aksi-control-id", control_id),
        _prop("nist-sp800-53-control-id", nist_control_id),
        _prop("evidence-record-id", record.record_id),
        _prop("evidence-record-hash", record.record_hash),
        _prop("evidence-previous-hash", record.previous_hash),
        _prop("assessment-state", _assessment_state(control_result)),
    ]
    if record.session_id is not None:
        props.append(_prop("evidence-session-id", record.session_id))
    if record.tenant_id is not None:
        props.append(_prop("evidence-tenant-id", record.tenant_id))
    if record.detected_data_types:
        props.append(_prop("detected-data-types", json.dumps(record.detected_data_types)))
    if record.sdk_version is not None:
        props.append(_prop("sdk-version", record.sdk_version))
    if record.framework_version is not None:
        props.append(_prop("aksi-framework-version", record.framework_version))
    if record.classification_context:
        props.append(_prop("classification-context", json.dumps(record.classification_context, sort_keys=True)))
    return props


def _assessment_state(control_result: dict[str, Any]) -> str:
    result = str(control_result.get("result", "SKIP")).upper()
    return RESULT_TO_STATE.get(result, "not-satisfied")


def _prop(name: str, value: str) -> dict[str, str]:
    return {"name": name, "ns": ANCILIS_OSCAL_NS, "value": value}


def _first_timestamp(records: list[EvidenceRecord]) -> str | None:
    if not records:
        return None
    return min(record.timestamp for record in records)


def _last_timestamp(records: list[EvidenceRecord]) -> str | None:
    if not records:
        return None
    return max(record.timestamp for record in records)
