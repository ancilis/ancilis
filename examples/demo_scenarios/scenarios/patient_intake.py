"""Patient intake MCP demo scenario."""

from __future__ import annotations

from scenarios.common import DemoCall, DemoScenario


def scenario() -> DemoScenario:
    return DemoScenario(
        agent_id="patient_intake_agent",
        display_name="Patient Intake Agent",
        architecture="MCP",
        agent_owner="Maya Patel, RN",
        llm_provider="anthropic/claude-3.7-sonnet",
        handles=("health_records", "personal_info"),
        allowed_tools=(
            "read_patient_record",
            "update_care_notes",
            "send_provider_message",
        ),
        blocked_tools=("export_patient_csv",),
        calls=(
            DemoCall(
                tool_name="read_patient_record",
                arguments={
                    "patient_id": "MRN-88291",
                    "name": "J. Doe",
                    "visit_reason": "A1C follow-up",
                    "destination": "ehr.internal.ancilis-demo",
                },
                response="Retrieved intake summary for J. Doe, MRN-88291.",
                detected_data_types=("DC-PHI", "DC-PII"),
                description="Read a patient chart through an internal EHR MCP server.",
            ),
            DemoCall(
                tool_name="update_care_notes",
                arguments={
                    "patient_id": "MRN-88291",
                    "note": "Patient reported dizziness after metformin dose change.",
                    "icd10": "E11.9",
                    "destination": "ehr.internal.ancilis-demo",
                },
                response="Care note appended with medication follow-up flag.",
                detected_data_types=("DC-PHI",),
                description="Append structured clinical notes to the chart.",
            ),
            DemoCall(
                tool_name="send_provider_message",
                arguments={
                    "to": "dr.nguyen@clinic.example",
                    "patient": "J. Doe",
                    "phone": "415-555-0198",
                    "message": "Please review glucose trend before Friday visit.",
                    "destination": "secure-provider-message",
                },
                response="Provider message queued for secure delivery.",
                outcome="FLAG",
                detected_data_types=("DC-PHI", "DC-PII"),
                reason="Flagged for privacy confirmation before provider messaging.",
                description="Send a provider handoff containing patient contact details.",
            ),
            DemoCall(
                tool_name="export_patient_csv",
                arguments={
                    "cohort": "diabetes-follow-up",
                    "fields": ["name", "dob", "mrn", "diagnosis"],
                    "destination": "s3://marketing-export",
                },
                response="Export blocked before PHI left the care environment.",
                outcome="BLOCK",
                detected_data_types=("DC-PHI", "DC-PII"),
                reason="Blocked because bulk PHI export is outside the approved MCP scope.",
                description="Attempt to export patient cohort data to an unapproved bucket.",
            ),
        ),
    )
