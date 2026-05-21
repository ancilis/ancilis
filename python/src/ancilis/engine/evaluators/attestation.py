"""Manual attestation evaluators for built-in AKSI controls."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import time
import uuid
from typing import Any, Protocol

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.record import EvidenceRecord


class AttestationEvidenceStore(Protocol):
    def get_records(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        tool_name: str | None = None,
        decision: str | None = None,
        since: str | None = None,
        limit: int | None = 100,
    ) -> list[EvidenceRecord]: ...

    def store(
        self,
        evaluation: EvaluationResult,
        tool_name: str,
        output_summary: str | None = None,
    ) -> EvidenceRecord: ...


@dataclass(frozen=True)
class AttestationSpec:
    control_id: str
    control_name: str
    required_evidence_fields: tuple[str, ...]
    optional_evidence_fields: tuple[str, ...] = ()
    staleness_days: int = 365
    per_agent: bool = False


@dataclass(frozen=True)
class AttestationState:
    control_id: str
    status: str
    required_fields: tuple[str, ...]
    optional_fields: tuple[str, ...]
    record_id: str | None = None
    attested_at: str | None = None
    attested_by: str | None = None
    fields: dict[str, str] | None = None
    missing_fields: tuple[str, ...] = ()
    revoked: bool = False
    revoked_record_id: str | None = None


@dataclass(frozen=True)
class _AttestationEvent:
    record: EvidenceRecord
    result: dict[str, Any]
    data: dict[str, Any]


ATTESTATION_CONTROL_SPECS: dict[str, AttestationSpec] = {
    "GOV-04": AttestationSpec(
        control_id="GOV-04",
        control_name="Human Oversight and Decision Accountability",
        required_evidence_fields=(
            "oversight_policy_url",
            "approval_workflow_id",
            "reviewer_role",
            "exception_log_location",
            "responsible_party",
            "last_review_date",
        ),
        staleness_days=365,
    ),
    "GOV-05": AttestationSpec(
        control_id="GOV-05",
        control_name="Purpose, Legal Basis and Data-Use Authority",
        required_evidence_fields=(
            "data_use_policy_url",
            "legal_basis",
            "consent_source",
            "contract_reference",
            "prohibited_use_review",
            "accountable_owner",
        ),
        staleness_days=180,
    ),
    "GOV-06": AttestationSpec(
        control_id="GOV-06",
        control_name="External Obligation Registry and Posture Reporting",
        required_evidence_fields=(
            "obligation_register_url",
            "mapped_frameworks",
            "customer_commitments",
            "reporting_owner",
            "reporting_cadence",
            "posture_report_location",
        ),
        staleness_days=180,
    ),
    "GOV-07": AttestationSpec(
        control_id="GOV-07",
        control_name="Transparency, Instructions and Affected-Party Feedback",
        required_evidence_fields=(
            "disclosure_url",
            "instruction_set_version",
            "feedback_channel",
            "privacy_request_routing",
            "intervention_channel",
            "review_owner",
        ),
        staleness_days=365,
    ),
    "DE-05": AttestationSpec(
        control_id="DE-05",
        control_name="AI Outcome Evaluation and Harm Monitoring",
        required_evidence_fields=(
            "evaluation_report_url",
            "evaluation_method",
            "monitored_risks",
            "latest_evaluation_date",
            "owner",
        ),
        staleness_days=90,
    ),
    "DE-06": AttestationSpec(
        control_id="DE-06",
        control_name="Assurance Testing and Vulnerability Evidence Ingestion",
        required_evidence_fields=(
            "assurance_report_url",
            "test_scope",
            "finding_tracker",
            "latest_test_date",
            "remediation_owner",
        ),
        staleness_days=180,
    ),
    "ID-02": AttestationSpec(
        control_id="ID-02",
        control_name="Tool, Model and Integration Registry",
        required_evidence_fields=(
            "registry_url",
            "integration_inventory_export",
            "approval_metadata",
            "provenance_source",
            "last_sync_at",
            "owner",
        ),
        staleness_days=90,
    ),
    "ID-03": AttestationSpec(
        control_id="ID-03",
        control_name="Data Flow Mapping and Classification",
        required_evidence_fields=(
            "data_flow_map_url",
            "classification_inventory",
            "source_destination_matrix",
            "last_review_date",
            "owner",
        ),
        staleness_days=180,
    ),
    "ID-04": AttestationSpec(
        control_id="ID-04",
        control_name="Supply Chain and Dependency Risk",
        required_evidence_fields=(
            "sbom_location",
            "dependency_scan_report",
            "model_provenance_register",
            "approval_record",
            "last_review_date",
        ),
        staleness_days=90,
    ),
    "ID-05": AttestationSpec(
        control_id="ID-05",
        control_name="Agent Risk Profiling and Purpose Scoping",
        required_evidence_fields=(
            "agent_id",
            "risk_profile_url",
            "purpose_statement",
            "autonomy_level",
            "data_sensitivity",
            "action_authority",
            "impact_tier",
            "owner",
            "review_date",
        ),
        staleness_days=365,
        per_agent=True,
    ),
    "PAY-01": AttestationSpec(
        control_id="PAY-01",
        control_name="Agent Payment Authorization and Sanctions Screening",
        required_evidence_fields=(
            "payment_policy_id",
            "spend_limit",
            "approval_workflow_id",
            "sanctions_screening_provider",
            "wallet_policy_id",
            "owner",
        ),
        staleness_days=180,
    ),
    "PAY-02": AttestationSpec(
        control_id="PAY-02",
        control_name="Payment Settlement Reconciliation and Irreversibility Control",
        required_evidence_fields=(
            "ledger_reconciliation_url",
            "receipt_retention_location",
            "irreversibility_policy",
            "reversal_escalation_route",
            "owner",
        ),
        staleness_days=180,
    ),
    "PR-10": AttestationSpec(
        control_id="PR-10",
        control_name="Memory and Context Integrity",
        required_evidence_fields=(
            "memory_store_inventory",
            "context_integrity_policy",
            "quarantine_process",
            "hashing_or_signing_scheme",
            "last_review_date",
        ),
        staleness_days=180,
    ),
    "PR-11": AttestationSpec(
        control_id="PR-11",
        control_name="Retention, Deletion and Memory Disposal",
        required_evidence_fields=(
            "retention_policy_url",
            "data_store_inventory",
            "deletion_log_location",
            "eviction_policy",
            "legal_hold_process",
            "last_disposal_test",
            "owner",
        ),
        staleness_days=365,
    ),
    "PR-12": AttestationSpec(
        control_id="PR-12",
        control_name="Secrets, Credential and Wallet Key Custody",
        required_evidence_fields=(
            "secret_manager_policy",
            "credential_rotation_record",
            "key_scope_inventory",
            "wallet_key_custody_policy",
            "last_review_date",
        ),
        staleness_days=180,
    ),
    "RC-01": AttestationSpec(
        control_id="RC-01",
        control_name="Rollback and Recovery Planning",
        required_evidence_fields=(
            "recovery_plan_url",
            "rollback_runbook_url",
            "dependency_inventory",
            "test_record",
            "responsible_party",
            "last_review_date",
        ),
        staleness_days=365,
    ),
    "RC-02": AttestationSpec(
        control_id="RC-02",
        control_name="Post-Incident Review and Communications",
        required_evidence_fields=(
            "pir_template_or_runbook",
            "incident_ticket_examples",
            "corrective_action_tracker",
            "communication_plan",
            "owner",
            "last_exercise_or_review_date",
        ),
        staleness_days=365,
    ),
    "RC-03": AttestationSpec(
        control_id="RC-03",
        control_name="Resilience Exercise and Recovery Test Evidence",
        required_evidence_fields=(
            "exercise_plan_url",
            "exercise_date",
            "scenario",
            "participants",
            "results",
            "open_findings",
            "remediation_owner",
            "next_test_due",
        ),
        staleness_days=365,
    ),
    "RS-01": AttestationSpec(
        control_id="RS-01",
        control_name="Automated Compliance Response",
        required_evidence_fields=(
            "response_playbook_url",
            "trigger_thresholds",
            "automation_owner",
            "latest_response_test",
            "exception_process",
        ),
        staleness_days=180,
    ),
    "RS-03": AttestationSpec(
        control_id="RS-03",
        control_name="Human Escalation and Incident Reporting",
        required_evidence_fields=(
            "escalation_policy_url",
            "severity_matrix",
            "incident_system_queue",
            "responder_group",
            "notification_evidence",
            "last_review_date",
        ),
        staleness_days=365,
    ),
    "RS-04": AttestationSpec(
        control_id="RS-04",
        control_name="Cascade Containment and Blast-Radius Control",
        required_evidence_fields=(
            "workflow_topology_url",
            "circuit_breaker_policy",
            "failure_domain_inventory",
            "latest_containment_test",
            "owner",
        ),
        staleness_days=180,
    ),
    "RS-05": AttestationSpec(
        control_id="RS-05",
        control_name="Regulated Notification Clock and Authority Routing",
        required_evidence_fields=(
            "notification_policy_url",
            "jurisdiction_matrix",
            "clock_start_rules",
            "authority_customer_routing",
            "preservation_procedure",
            "owner",
        ),
        staleness_days=365,
    ),
    "RS-06": AttestationSpec(
        control_id="RS-06",
        control_name="Coordinated Vulnerability Disclosure and Security Update Handling",
        required_evidence_fields=(
            "disclosure_policy_url",
            "intake_channel",
            "support_period",
            "advisory_template",
            "update_release_process",
            "remediation_tracker",
            "owner",
        ),
        staleness_days=365,
    ),
}


class ManualAttestationEvaluator:
    """Evaluator backed by immutable manual attestation evidence records."""

    def __init__(
        self,
        control_id: str,
        required_evidence_fields: list[str],
        optional_evidence_fields: list[str],
        staleness_days: int,
        evidence_store: AttestationEvidenceStore | None = None,
        *,
        control_name: str | None = None,
        per_agent: bool = False,
    ) -> None:
        self.control_id = control_id
        self.control_name = control_name or control_id
        self.required_evidence_fields = tuple(required_evidence_fields)
        self.optional_evidence_fields = tuple(optional_evidence_fields)
        self.staleness_days = staleness_days
        self.evidence_store = evidence_store
        self.per_agent = per_agent

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        state = get_attestation_state(
            self.evidence_store,
            AttestationSpec(
                control_id=self.control_id,
                control_name=self.control_name,
                required_evidence_fields=self.required_evidence_fields,
                optional_evidence_fields=self.optional_evidence_fields,
                staleness_days=self.staleness_days,
                per_agent=self.per_agent,
            ),
            agent_id=action.agent_id if self.per_agent else None,
        )
        evidence = _state_evidence(state)

        if state.status == "none":
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="SKIP",
                detail="MANUAL: attestation required",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        if state.status == "missing_fields":
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=(
                    "Manual attestation missing required fields: "
                    + ", ".join(state.missing_fields)
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        if state.status == "stale":
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=f"attestation stale, last attested {state.attested_at}",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail=f"Fresh manual attestation recorded at {state.attested_at}.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


def make_attestation_evaluators(
    evidence_store: AttestationEvidenceStore | None,
) -> dict[str, ManualAttestationEvaluator]:
    return {
        control_id: ManualAttestationEvaluator(
            spec.control_id,
            required_evidence_fields=list(spec.required_evidence_fields),
            optional_evidence_fields=list(spec.optional_evidence_fields),
            staleness_days=spec.staleness_days,
            evidence_store=evidence_store,
            control_name=spec.control_name,
            per_agent=spec.per_agent,
        )
        for control_id, spec in ATTESTATION_CONTROL_SPECS.items()
    }


def get_attestation_state(
    evidence_store: AttestationEvidenceStore | None,
    spec: AttestationSpec,
    *,
    agent_id: str | None = None,
    now: datetime | None = None,
) -> AttestationState:
    event = latest_attestation_event(
        evidence_store,
        spec.control_id,
        agent_id=agent_id,
        per_agent=spec.per_agent,
    )
    if event is None:
        return _empty_state(spec)

    data = event.data
    fields = _string_fields(data.get("fields", {}))
    attested_at = str(data.get("attested_at") or event.record.timestamp)
    attested_by = str(data.get("attested_by") or "")
    if bool(data.get("revoked")):
        return AttestationState(
            control_id=spec.control_id,
            status="none",
            required_fields=spec.required_evidence_fields,
            optional_fields=spec.optional_evidence_fields,
            record_id=event.record.record_id,
            attested_at=attested_at,
            attested_by=attested_by,
            fields=fields,
            revoked=True,
            revoked_record_id=str(data.get("revoked_record_id") or ""),
        )

    missing = tuple(
        field
        for field in spec.required_evidence_fields
        if not str(fields.get(field, "")).strip()
    )
    if missing:
        return AttestationState(
            control_id=spec.control_id,
            status="missing_fields",
            required_fields=spec.required_evidence_fields,
            optional_fields=spec.optional_evidence_fields,
            record_id=event.record.record_id,
            attested_at=attested_at,
            attested_by=attested_by,
            fields=fields,
            missing_fields=missing,
        )

    if _is_stale(attested_at, spec.staleness_days, now=now):
        return AttestationState(
            control_id=spec.control_id,
            status="stale",
            required_fields=spec.required_evidence_fields,
            optional_fields=spec.optional_evidence_fields,
            record_id=event.record.record_id,
            attested_at=attested_at,
            attested_by=attested_by,
            fields=fields,
        )

    return AttestationState(
        control_id=spec.control_id,
        status="fresh",
        required_fields=spec.required_evidence_fields,
        optional_fields=spec.optional_evidence_fields,
        record_id=event.record.record_id,
        attested_at=attested_at,
        attested_by=attested_by,
        fields=fields,
    )


def latest_attestation_event(
    evidence_store: AttestationEvidenceStore | None,
    control_id: str,
    *,
    agent_id: str | None = None,
    per_agent: bool = False,
) -> _AttestationEvent | None:
    if evidence_store is None:
        return None
    get_records = getattr(evidence_store, "get_records", None)
    if not callable(get_records):
        return None
    events: list[_AttestationEvent] = []
    for record in get_records(limit=None):
        if record.source_type != "attestation":
            continue
        for result in record.control_results:
            if result.get("control_id") != control_id:
                continue
            data = result.get("evidence_data", {}).get("attestation", {})
            if not isinstance(data, dict):
                continue
            if per_agent and agent_id and not _attestation_matches_agent(record, data, agent_id):
                continue
            events.append(_AttestationEvent(record=record, result=result, data=data))
    if not events:
        return None
    return max(events, key=lambda event: _parse_iso8601(event.record.timestamp))


def record_attestation(
    store: AttestationEvidenceStore,
    config: ResolvedConfig,
    spec: AttestationSpec,
    *,
    fields: dict[str, str],
    attested_by: str,
    agent_id: str,
    revoked: bool = False,
    revoked_record_id: str | None = None,
    attested_at: str | None = None,
) -> EvidenceRecord:
    now = attested_at or datetime.now(timezone.utc).isoformat()
    effective_fields = dict(fields)
    if spec.per_agent and "agent_id" not in effective_fields:
        effective_fields["agent_id"] = agent_id
    evidence_data = {
        "attestation": {
            "control_id": spec.control_id,
            "fields": effective_fields,
            "attested_at": now,
            "attested_by": attested_by,
            "required_fields": list(spec.required_evidence_fields),
            "optional_fields": list(spec.optional_evidence_fields),
            "staleness_days": spec.staleness_days,
            "revoked": revoked,
            "revoked_record_id": revoked_record_id,
        }
    }
    result = ControlResult(
        control_id=spec.control_id,
        control_name=spec.control_name,
        result="SKIP" if revoked else "PASS",
        detail="Manual attestation revoked." if revoked else "Manual attestation recorded.",
        evidence_data=evidence_data,
        duration_ms=0.0,
    )
    evaluation = EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        action_id=f"attest-{uuid.uuid4()}",
        timestamp=now,
        agent_id=agent_id,
        source_type="attestation",
        mode="audit",
        control_results=[result],
        decision="ALLOW",
        decision_reason="Manual attestation evidence recorded.",
        active_overlays=list(config.active_overlays.keys()),
        data_classifications=[
            code
            for codes in config.data_classifications.values()
            for code in codes
        ],
        total_duration_ms=0.0,
    )
    return store.store(
        evaluation,
        tool_name="ancilis attest",
        output_summary=f"Attestation event for {spec.control_id}",
    )


def _empty_state(spec: AttestationSpec) -> AttestationState:
    return AttestationState(
        control_id=spec.control_id,
        status="none",
        required_fields=spec.required_evidence_fields,
        optional_fields=spec.optional_evidence_fields,
    )


def _state_evidence(state: AttestationState) -> dict[str, Any]:
    return {
        "required_fields": list(state.required_fields),
        "optional_fields": list(state.optional_fields),
        "command": f"ancilis attest {state.control_id}",
        "record_id": state.record_id,
        "attested_at": state.attested_at,
        "attested_by": state.attested_by,
        "missing_fields": list(state.missing_fields),
        "status": state.status,
        "revoked": state.revoked,
        "revoked_record_id": state.revoked_record_id,
    }


def _string_fields(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def _attestation_matches_agent(
    record: EvidenceRecord,
    attestation: dict[str, Any],
    agent_id: str,
) -> bool:
    fields = _string_fields(attestation.get("fields", {}))
    return (
        fields.get("agent_id") == agent_id
        or str(attestation.get("agent_id") or "") == agent_id
        or record.agent_id == agent_id
    )


def _is_stale(
    attested_at: str,
    staleness_days: int,
    *,
    now: datetime | None = None,
) -> bool:
    attested = _parse_iso8601(attested_at)
    effective_now = now or datetime.now(timezone.utc)
    if attested.tzinfo is None:
        attested = attested.replace(tzinfo=timezone.utc)
    return (effective_now - attested).days > staleness_days


def _parse_iso8601(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
