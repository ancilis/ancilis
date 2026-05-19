"""Higher-level evidence querying helpers used by the CLI."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ancilis.activation.loader import load_certification_profile, load_overlay_profiles
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore


MIN_SHORT_EVIDENCE_ID_LENGTH = 7


def _parse_iso8601(timestamp: str) -> datetime:
    normalized = timestamp.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


@dataclass(frozen=True)
class EvidenceListRow:
    timestamp: str
    evidence_id: str
    agent_id: str
    source_type: str
    classification: str
    control_id: str
    status: str


@dataclass(frozen=True)
class FrameworkMapping:
    source_id: str
    source_name: str
    references: list[str]


@dataclass(frozen=True)
class CertifyTarget:
    target: str
    target_id: str
    target_name: str
    control_refs: dict[str, str]


@dataclass(frozen=True)
class CertificationCoverageRow:
    control_id: str
    framework_ref: str
    coverage_status: str
    evidence_count: int
    last_evidence_at: str | None


_CERTIFY_TARGET_IDS = {
    "soc2": ("overlay", "soc2"),
    "hipaa": ("overlay", "hipaa"),
    "pci": ("overlay", "pci-dss-v4"),
    "aiuc1": ("certification", "aiuc-1"),
    "eu_ai_act": ("overlay", "eu-ai-act"),
}


def query_records(
    store: EvidenceStore,
    *,
    agent_id: str | None = None,
    since: str | None = None,
    classification: str | None = None,
    control_id: str | None = None,
    limit: int | None = None,
) -> list[EvidenceRecord]:
    """Return evidence records sorted newest-first with CLI-friendly filters."""
    records = store.get_records(agent_id=agent_id, since=since, limit=None)
    filtered: list[EvidenceRecord] = []

    for record in records:
        if classification is not None and classification not in record.data_classifications:
            continue
        if control_id is not None and not any(
            result.get("control_id") == control_id for result in record.control_results
        ):
            continue
        filtered.append(record)

    filtered.sort(key=lambda record: _parse_iso8601(record.timestamp), reverse=True)
    if limit is not None:
        return filtered[:limit]
    return filtered


def list_rows_for_records(
    records: list[EvidenceRecord],
    *,
    control_id: str | None = None,
) -> list[EvidenceListRow]:
    """Flatten evidence records into table rows keyed by control result."""
    rows: list[EvidenceListRow] = []

    for record in records:
        classification = ", ".join(record.data_classifications) if record.data_classifications else "-"
        for result in record.control_results:
            current_control_id = str(result.get("control_id", ""))
            if control_id is not None and current_control_id != control_id:
                continue
            rows.append(
                EvidenceListRow(
                    timestamp=record.timestamp,
                    evidence_id=record.record_id,
                    agent_id=record.agent_id,
                    source_type=record.source_type,
                    classification=classification,
                    control_id=current_control_id,
                    status=str(result.get("result", "UNKNOWN")),
                )
            )

    return rows


def find_record(store: EvidenceStore, evidence_id: str) -> EvidenceRecord:
    """Resolve an evidence record by full ID or short prefix."""
    records = store.get_records(limit=None)

    for record in records:
        if record.record_id == evidence_id:
            return record

    if len(evidence_id) < MIN_SHORT_EVIDENCE_ID_LENGTH:
        raise ValueError(
            f"Evidence ID prefixes must be at least {MIN_SHORT_EVIDENCE_ID_LENGTH} characters."
        )

    matches = [record for record in records if record.record_id.startswith(evidence_id)]
    if not matches:
        raise LookupError(f"No evidence record found for '{evidence_id}'.")
    if len(matches) > 1:
        match_list = "\n".join(f"- {record.record_id}" for record in matches)
        raise ValueError(
            "Ambiguous evidence ID prefix "
            f"'{evidence_id}' matched {len(matches)} records:\n{match_list}"
        )
    return matches[0]


def framework_mappings_for_record(record: EvidenceRecord) -> dict[str, list[FrameworkMapping]]:
    """Return framework references relevant to each control result in a record."""
    overlays = load_overlay_profiles()
    mappings: dict[str, list[FrameworkMapping]] = {}

    for result in record.control_results:
        control_id = str(result.get("control_id", ""))
        control_mappings: list[FrameworkMapping] = []

        for overlay_id in record.active_overlays:
            profile = overlays.get(overlay_id)
            if not profile:
                continue
            control_data = profile.get("controls", {}).get(control_id, {})
            reference = control_data.get("framework_reference", "")
            if not reference:
                continue
            control_mappings.append(
                FrameworkMapping(
                    source_id=overlay_id,
                    source_name=str(profile.get("name", overlay_id)),
                    references=[part.strip() for part in reference.split(",") if part.strip()],
                )
            )

        for cert_id in record.active_certifications:
            profile = load_certification_profile(cert_id)
            if not profile:
                continue
            requirement_ids = profile.get("aksi_to_requirement_map", {}).get(control_id, [])
            if not requirement_ids:
                continue
            control_mappings.append(
                FrameworkMapping(
                    source_id=cert_id,
                    source_name=str(profile.get("name", cert_id)),
                    references=[str(requirement_id) for requirement_id in requirement_ids],
                )
            )

        if control_mappings:
            mappings[control_id] = control_mappings

    return mappings


def resolve_certify_target(target: str) -> CertifyTarget:
    """Resolve a CLI `certify` target into internal IDs and control references."""
    kind, internal_id = _CERTIFY_TARGET_IDS[target]
    if kind == "overlay":
        profile = load_overlay_profiles()[internal_id]
        control_refs = {
            control_id: str(control_data.get("framework_reference", ""))
            for control_id, control_data in profile.get("controls", {}).items()
            if control_data.get("applicable", True)
        }
        return CertifyTarget(
            target=target,
            target_id=internal_id,
            target_name=str(profile.get("name", internal_id)),
            control_refs=dict(sorted(control_refs.items())),
        )

    profile = load_certification_profile(internal_id)
    if profile is None:
        raise LookupError(f"Certification profile not found for '{internal_id}'.")
    requirement_map = profile.get("aksi_to_requirement_map", {})
    control_refs = {
        control_id: ", ".join(str(requirement_id) for requirement_id in requirement_map.get(control_id, []))
        for control_id in profile.get("required_aksi_controls", [])
    }
    return CertifyTarget(
        target=target,
        target_id=internal_id,
        target_name=str(profile.get("name", internal_id)),
        control_refs=dict(sorted(control_refs.items())),
    )


def certification_coverage(
    store: EvidenceStore,
    *,
    target: str,
) -> tuple[CertifyTarget, list[CertificationCoverageRow]]:
    """Compute evidence coverage for a CLI certification target."""
    resolved_target = resolve_certify_target(target)
    records = store.get_records(limit=None)
    stats: dict[str, dict[str, Any]] = {
        control_id: {
            "evidence_count": 0,
            "passed": 0,
            "failed": 0,
            "flagged": 0,
            "last_evidence_at": None,
        }
        for control_id in resolved_target.control_refs
    }

    for record in records:
        record_time = _parse_iso8601(record.timestamp)
        for result in record.control_results:
            control_id = str(result.get("control_id", ""))
            if control_id not in stats:
                continue
            row = stats[control_id]
            row["evidence_count"] += 1
            current = str(result.get("result", ""))
            if current == "PASS":
                row["passed"] += 1
            elif current in {"FAIL", "ERROR"}:
                row["failed"] += 1
            elif current == "FLAG":
                row["flagged"] += 1

            if row["last_evidence_at"] is None or record_time > _parse_iso8601(row["last_evidence_at"]):
                row["last_evidence_at"] = record.timestamp

    rows: list[CertificationCoverageRow] = []
    for control_id, framework_ref in resolved_target.control_refs.items():
        row = stats[control_id]
        if row["evidence_count"] == 0:
            coverage_status = "gap"
        elif row["failed"] > 0 or row["flagged"] > 0:
            coverage_status = "partial"
        else:
            coverage_status = "covered"
        rows.append(
            CertificationCoverageRow(
                control_id=control_id,
                framework_ref=framework_ref,
                coverage_status=coverage_status,
                evidence_count=int(row["evidence_count"]),
                last_evidence_at=row["last_evidence_at"],
            )
        )

    return resolved_target, rows
