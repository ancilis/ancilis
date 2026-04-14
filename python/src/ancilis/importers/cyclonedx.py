"""CycloneDX v1.5+ SBOM importer — maps components and vulnerabilities to AKSI controls."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# CWE → AKSI control mapping (subset covering most common SBOM vulnerability categories)
_CWE_CONTROL_MAP: dict[str, str] = {
    # Injection
    "CWE-89": "PR-03",   # SQL Injection
    "CWE-79": "PR-03",   # XSS
    "CWE-78": "PR-03",   # OS Command Injection
    "CWE-94": "PR-03",   # Code Injection
    "CWE-611": "PR-03",  # XXE
    "CWE-918": "PR-01",  # SSRF
    # Cryptography
    "CWE-326": "PR-04",  # Inadequate Encryption Strength
    "CWE-327": "PR-04",  # Use of Broken/Risky Algorithm
    "CWE-330": "PR-04",  # Insufficient Random Values
    "CWE-338": "PR-04",  # Weak PRNG
    # Secrets / Credentials
    "CWE-798": "PR-05",  # Hard-coded Credentials
    "CWE-259": "PR-05",  # Hard-coded Password
    "CWE-312": "PR-05",  # Cleartext Storage of Sensitive Data
    # Auth / Access
    "CWE-287": "PR-01",  # Improper Authentication
    "CWE-306": "PR-01",  # Missing Auth for Critical Function
    "CWE-862": "PR-01",  # Missing Authorization
    # Data Exfiltration
    "CWE-200": "DE-01",  # Exposure of Sensitive Information
    "CWE-359": "DE-01",  # Exposure of Private Personal Information
}

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_CONTROL = "PR-03"


def _cwe_to_control(cwes: list[str]) -> str:
    """Return the most specific AKSI control for a list of CWE IDs."""
    for cwe in cwes:
        cwe_key = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
        if cwe_key in _CWE_CONTROL_MAP:
            return _CWE_CONTROL_MAP[cwe_key]
    return _DEFAULT_CONTROL


def _extract_cwes(vulnerability: dict[str, Any]) -> list[str]:
    """Pull CWE IDs from a CycloneDX vulnerability object."""
    cwes: list[str] = []
    for cwe in vulnerability.get("cwes", []):
        if isinstance(cwe, int):
            cwes.append(f"CWE-{cwe}")
        elif isinstance(cwe, str):
            cwes.append(cwe if cwe.startswith("CWE-") else f"CWE-{cwe}")
    return cwes


class CycloneDxImporter:
    """Parse a CycloneDX v1.5+ SBOM JSON and convert to EvaluationResults."""

    def __init__(self, agent_id: str = "import", mode: str = "audit") -> None:
        self.agent_id = agent_id
        self.mode = mode

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a CycloneDX SBOM file and return EvaluationResults."""
        content = Path(path).read_bytes()
        doc = json.loads(content.decode("utf-8"))
        return self._parse_doc(doc, file_sha256=hashlib.sha256(content).hexdigest())

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse CycloneDX SBOM JSON from a string."""
        doc = json.loads(content)
        return self._parse_doc(doc)

    def _parse_doc(
        self,
        doc: dict[str, Any],
        *,
        file_sha256: str | None = None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []

        # One EvaluationResult for component metadata (provenance evidence)
        results.append(self._build_component_result(doc, file_sha256=file_sha256))

        # One EvaluationResult per vulnerability (if any)
        vulns = doc.get("vulnerabilities", [])
        for vuln in vulns:
            results.append(self._build_vuln_result(doc, vuln, file_sha256=file_sha256))

        return results

    def _source_tool_metadata(self, doc: dict[str, Any]) -> tuple[str, str]:
        meta = doc.get("metadata", {})
        tools = meta.get("tools", [])
        if tools:
            t = tools[0]
            return t.get("name", "cyclonedx-tool"), t.get("version", "")
        return "cyclonedx-import", ""

    def _source_tool(self, doc: dict[str, Any]) -> str:
        name, version = self._source_tool_metadata(doc)
        return f"{name}/{version}" if version else name

    def _source_provenance(
        self,
        doc: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        name, version = self._source_tool_metadata(doc)
        provenance: dict[str, Any] = {
            "source_format": "cyclonedx",
            "source_tool_name": name,
            "source_tool_version": version,
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_component_result(
        self,
        doc: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Produce a PASS evidence record representing component inventory."""
        source_tool = self._source_tool(doc)
        source_provenance = self._source_provenance(doc, file_sha256=file_sha256)
        components = doc.get("components", [])
        meta = doc.get("metadata", {})
        serial = doc.get("serialNumber", "")
        spec_version = doc.get("specVersion", "")

        summary_parts = [f"{len(components)} component(s) inventoried"]
        if serial:
            summary_parts.append(f"serialNumber={serial}")

        control_results = [
            ControlResult(
                control_id="PR-05",
                control_name=_CONTROL_NAMES["PR-05"],
                result="PASS",
                detail=f"SBOM component inventory ingested from {source_tool}. {', '.join(summary_parts)}.",
                evidence_data={
                    "source_tool": source_tool,
                    "source_provenance": source_provenance,
                    "spec_version": spec_version,
                    "serial_number": serial,
                    "component_count": len(components),
                    "components": [
                        {
                            "name": c.get("name", ""),
                            "version": c.get("version", ""),
                            "purl": c.get("purl", ""),
                            "type": c.get("type", ""),
                        }
                        for c in components
                    ],
                    "metadata": {
                        "timestamp": meta.get("timestamp", ""),
                        "component": meta.get("component", {}).get("name", ""),
                    },
                },
            )
        ]

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"cdx-components-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="cyclonedx_import",
            mode=self.mode,
            control_results=control_results,
            decision="ALLOW",
            decision_reason=f"CycloneDX SBOM component inventory from {source_tool}",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _build_vuln_result(
        self,
        doc: dict[str, Any],
        vuln: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Produce a FLAG/FAIL evidence record for one vulnerability."""
        source_tool = self._source_tool(doc)
        source_provenance = self._source_provenance(doc, file_sha256=file_sha256)
        vuln_id = vuln.get("id", "UNKNOWN")
        description = vuln.get("description", "")
        cwes = _extract_cwes(vuln)
        control_id = _cwe_to_control(cwes)
        control_name = _CONTROL_NAMES.get(control_id, control_id)

        # Severity from ratings
        ratings = vuln.get("ratings", [])
        severity = ratings[0].get("severity", "unknown") if ratings else "unknown"
        score = ratings[0].get("score", None) if ratings else None

        detail = f"{vuln_id}: {description[:200]}" if description else vuln_id
        if cwes:
            detail += f" ({', '.join(cwes)})"

        cr_result = "FAIL" if severity in ("critical", "high") else "FLAG"

        control_results = [
            ControlResult(
                control_id=control_id,
                control_name=control_name,
                result=cr_result,
                detail=detail,
                evidence_data={
                    "vuln_id": vuln_id,
                    "severity": severity,
                    "score": score,
                    "cwes": cwes,
                    "source_tool": source_tool,
                    "source_provenance": source_provenance,
                    "affects": [
                        {"ref": a.get("ref", ""), "versions": a.get("versions", [])}
                        for a in vuln.get("affects", [])
                    ],
                },
            )
        ]

        overall_decision = "BLOCK" if cr_result == "FAIL" else "FLAG"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"cdx-vuln-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="cyclonedx_import",
            mode=self.mode,
            control_results=control_results,
            decision=overall_decision,
            decision_reason=f"CycloneDX vulnerability {vuln_id} severity={severity}",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
