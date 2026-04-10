"""Dependency vulnerability scanner — wires ManifestDetector + OSVClient into EvaluationResults."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from ancilis.config import ResolvedConfig
from ancilis.deps.manifest import Dependency, ManifestDetector
from ancilis.deps.osv import OSVClient, Vuln
from ancilis.engine.result import ControlResult, EvaluationResult

_CONTROL_ID = "DE-01"
_CONTROL_NAME = "Dependency Evaluation"

# Lower index = higher severity
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def _result_for_severity(severity: str) -> str:
    """CRITICAL/HIGH -> FAIL, MEDIUM/LOW -> FLAG."""
    return "FAIL" if severity in ("CRITICAL", "HIGH") else "FLAG"


def _build_evaluation(control_results: list[ControlResult], mode: str) -> EvaluationResult:
    has_fail = any(cr.result == "FAIL" for cr in control_results)
    has_flag = any(cr.result == "FLAG" for cr in control_results)
    if has_fail:
        decision = "BLOCK"
    elif has_flag:
        decision = "FLAG"
    else:
        decision = "ALLOW"

    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        action_id=f"dep-scan-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id="cli-scan",
        source_type="dependency_scan",
        mode=mode,
        control_results=control_results,
        decision=decision,
        decision_reason="Dependency vulnerability scan",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=0.0,
    )


class DependencyScanner:
    """Scan a project directory for dependency vulnerabilities via OSV.dev."""

    def __init__(self, config: ResolvedConfig) -> None:
        self._config = config

    def scan(self, project_dir: Path | None = None) -> list[EvaluationResult]:
        """Scan *project_dir* (defaults to cwd) for known CVEs.

        Returns a list[EvaluationResult] with source_type="dependency_scan".
        Returns an empty list if DE-01 is explicitly disabled in config.
        """
        # DE-01 gate — respect explicit disable; absent = enabled by default
        de01 = self._config.controls.get(_CONTROL_ID)
        if de01 is not None and not de01.enabled:
            return []

        target = project_dir or Path.cwd()
        manifests = ManifestDetector().detect(target)

        if not manifests:
            return [_build_evaluation(
                [ControlResult(
                    control_id=_CONTROL_ID,
                    control_name=_CONTROL_NAME,
                    result="SKIP",
                    detail="No dependency manifests found",
                )],
                self._config.mode,
            )]

        all_deps: list[Dependency] = [d for m in manifests for d in m.dependencies]

        client = OSVClient()
        vuln_map = client.query_batch(all_deps)

        if client.last_error is not None:
            return [_build_evaluation(
                [ControlResult(
                    control_id=_CONTROL_ID,
                    control_name=_CONTROL_NAME,
                    result="FLAG",
                    detail=f"OSV.dev lookup failed: {client.last_error}",
                    evidence_data={"error": client.last_error},
                )],
                self._config.mode,
            )]

        if not vuln_map:
            return [_build_evaluation(
                [ControlResult(
                    control_id=_CONTROL_ID,
                    control_name=_CONTROL_NAME,
                    result="PASS",
                    detail=f"No known vulnerabilities in {len(all_deps)} dependencies",
                    evidence_data={"dep_count": len(all_deps)},
                )],
                self._config.mode,
            )]

        # Build a lookup so we can pull version + source_file per package
        dep_lookup: dict[str, Dependency] = {d.name: d for d in all_deps}

        # Sort packages: worst severity first, then alphabetically
        sorted_packages = sorted(
            vuln_map.items(),
            key=lambda item: (
                min(_SEVERITY_ORDER.get(v.severity, 3) for v in item[1]),
                item[0].lower(),
            ),
        )

        control_results: list[ControlResult] = []
        for pkg_name, vulns in sorted_packages:
            dep = dep_lookup.get(pkg_name)
            # Sort vulns within package by severity
            for vuln in sorted(vulns, key=lambda v: _SEVERITY_ORDER.get(v.severity, 3)):
                remediation = (
                    f"Upgrade {pkg_name} to >={vuln.fixed_version}"
                    if vuln.fixed_version
                    else ""
                )
                control_results.append(
                    ControlResult(
                        control_id=_CONTROL_ID,
                        control_name=_CONTROL_NAME,
                        result=_result_for_severity(vuln.severity),
                        detail=(
                            f"{pkg_name}=={dep.version if dep else '?'}: "
                            f"{vuln.id} ({vuln.severity}) — {vuln.summary}"
                        ),
                        evidence_data={
                            "package": pkg_name,
                            "version": dep.version if dep else None,
                            "vuln_id": vuln.id,
                            "severity": vuln.severity,
                            "fixed_version": vuln.fixed_version,
                            "source_file": dep.source_file if dep else None,
                            "aliases": vuln.aliases,
                            "affected_versions": vuln.affected_versions,
                        },
                        remediation_hint=remediation,
                    )
                )

        return [_build_evaluation(control_results, self._config.mode)]
