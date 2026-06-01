"""SARIF v2.1.0 importer — parses findings and maps them to AKSI controls."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis._shared import shared_path
from ancilis.engine.result import ControlResult, EvaluationResult


_MAPPING_PATH = shared_path("mappings", "sarif-aksi-controls.json")

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Action Authorization",
    "PR-02": "Permission Scope Enforcement",
    "PR-03": "Tool/Model Integrity & Provenance",
    "PR-04": "Data Exposure Prevention",
    "PR-05": "Context & Tenant Isolation",
    "PR-08": "Input Validation & Injection Resistance",
    "PR-09": "Controlled Code Execution & Sandbox Enforcement",
    "DE-01": "Behavioral Anomaly Detection",
}

_UNMAPPED_CONTROL = "PR-03"  # default fallback


def _load_mappings() -> list[dict[str, str]]:
    """Load SARIF rule ID → AKSI control mapping from the shared table."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        mappings = data.get("mappings", {})
        if isinstance(mappings, list):
            return [
                {
                    "rule_id": str(entry["rule_id"]),
                    "control_id": str(entry["control_id"]),
                    "match": str(entry.get("match", "exact")),
                }
                for entry in mappings
                if isinstance(entry, dict) and entry.get("rule_id") and entry.get("control_id")
            ]
        if isinstance(mappings, dict):
            return [
                {
                    "rule_id": str(rule_id),
                    "control_id": str(control_id),
                    "match": "glob" if "*" in str(rule_id) or "?" in str(rule_id) else "exact",
                }
                for rule_id, control_id in mappings.items()
            ]
        return []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _normalize_mapping_entries(
    mappings: list[dict[str, str]] | dict[str, str],
) -> list[dict[str, str]]:
    if isinstance(mappings, dict):
        return [
            {
                "rule_id": str(rule),
                "control_id": str(control),
                "match": "glob" if "*" in str(rule) or "?" in str(rule) else "exact",
            }
            for rule, control in mappings.items()
        ]
    return mappings


def _map_rule_to_control(rule_id: str, mappings: list[dict[str, str]] | dict[str, str]) -> str:
    """Return the AKSI control ID for a SARIF rule ID (first match wins)."""
    entries = _normalize_mapping_entries(mappings)
    for entry in entries:
        if entry.get("match", "exact") != "glob" and entry["rule_id"] == rule_id:
            return entry["control_id"]
    for entry in entries:
        if entry.get("match", "exact") == "glob" and fnmatch.fnmatch(rule_id, entry["rule_id"]):
            return entry["control_id"]
    return _UNMAPPED_CONTROL


class SarifImporter:
    """Parse a SARIF v2.1.0 file and convert findings to EvaluationResults."""

    def __init__(self, agent_id: str = "import", mode: str = "audit") -> None:
        self.agent_id = agent_id
        self.mode = mode
        self._mappings = _load_mappings()

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a SARIF file and return one EvaluationResult per run."""
        content = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content).hexdigest()
        doc = json.loads(content.decode("utf-8"))

        results: list[EvaluationResult] = []
        for run in doc.get("runs", []):
            results.append(self._parse_run(run, file_sha256=file_sha256))
        return results

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse SARIF JSON from a string (useful for tests)."""
        doc = json.loads(content)
        return [self._parse_run(run) for run in doc.get("runs", [])]

    def _parse_run(
        self,
        run: dict[str, Any],
        *,
        file_sha256: str | None = None,
    ) -> EvaluationResult:
        tool_name = (
            run.get("tool", {})
            .get("driver", {})
            .get("name", "unknown-sarif-tool")
        )
        tool_version = (
            run.get("tool", {})
            .get("driver", {})
            .get("version", "")
        )
        source_tool = f"{tool_name}/{tool_version}" if tool_version else tool_name
        source_provenance = _source_provenance(
            tool_name=tool_name,
            tool_version=tool_version,
            file_sha256=file_sha256,
        )

        # Build a rule-id → rule-metadata index from the run
        rule_index: dict[str, dict[str, Any]] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_index[rule.get("id", "")] = rule

        control_results: list[ControlResult] = []
        findings = run.get("results", [])

        for finding in findings:
            rule_id = finding.get("ruleId", "")
            control_id = _map_rule_to_control(rule_id, self._mappings)
            control_name = _CONTROL_NAMES.get(control_id, control_id)

            rule_meta = rule_index.get(rule_id, {})
            short_desc = (
                rule_meta.get("shortDescription", {}).get("text", "")
                or rule_meta.get("name", rule_id)
            )

            # Location summary
            locations = finding.get("locations", [])
            loc_summary = _format_location(locations[0]) if locations else ""
            detail = f"{rule_id}: {short_desc}" + (f" [{loc_summary}]" if loc_summary else "")

            result_level = finding.get("level", "warning")
            cr_result = "FAIL" if result_level in ("error", "warning") else "FLAG"

            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=control_name,
                    result=cr_result,
                    detail=detail,
                    evidence_data={
                        "rule_id": rule_id,
                        "level": result_level,
                        "source_tool": source_tool,
                        "source_provenance": source_provenance,
                        "message": finding.get("message", {}).get("text", ""),
                    },
                )
            )

        # If no findings, record a PASS to represent clean scan evidence
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-01",
                    control_name=_CONTROL_NAMES["PR-01"],
                    result="PASS",
                    detail=f"No findings reported by {source_tool}",
                    evidence_data={
                        "source_tool": source_tool,
                        "source_provenance": source_provenance,
                    },
                )
            )

        overall_decision = "ALLOW" if all(cr.result == "PASS" for cr in control_results) else "FLAG"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sarif-import-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sarif_import",
            mode=self.mode,
            control_results=control_results,
            decision=overall_decision,
            decision_reason=f"Imported from SARIF ({source_tool}): {len(findings)} finding(s)",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )


def _format_location(location: dict[str, Any]) -> str:
    """Return 'file.ext:line' for the first physical location in a SARIF result."""
    phys = location.get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {})
    line = region.get("startLine", "")
    if uri and line:
        return f"{uri}:{line}"
    return uri or str(line)


def _source_provenance(
    *,
    tool_name: str,
    tool_version: str,
    file_sha256: str | None,
) -> dict[str, Any]:
    provenance: dict[str, Any] = {
        "source_format": "sarif",
        "source_tool_name": tool_name,
        "source_tool_version": tool_version,
    }
    if file_sha256 is not None:
        provenance["original_file_sha256"] = file_sha256
    return provenance
