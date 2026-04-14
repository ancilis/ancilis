"""Dependency vulnerability scanning — manifest detection, SBOM generation, OSV lookup.

Public API:

    from ancilis.dependencies import scan_dependencies, DependencyScanResult

    result = scan_dependencies(Path("/path/to/project"))
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ancilis.dependencies.detector import Dependency, DetectionResult, detect_dependencies
from ancilis.dependencies.osv import VulnerabilityFinding, query_osv_batch
from ancilis.dependencies.sbom import CycloneDxBom, build_sbom

__all__ = [
    "scan_dependencies",
    "DependencyScanResult",
    "Dependency",
    "DetectionResult",
    "VulnerabilityFinding",
    "CycloneDxBom",
    "detect_dependencies",
    "build_sbom",
    "query_osv_batch",
]


@dataclass
class DependencyScanResult:
    manifest_path: str | None
    dependencies: list[Dependency]
    sbom: CycloneDxBom | None
    vulnerabilities: list[VulnerabilityFinding]
    osv_error: str | None
    metadata: dict[str, object] = field(default_factory=dict)


def scan_dependencies(project_dir: Path | None = None) -> DependencyScanResult:
    """Scan *project_dir* for Python dependency vulnerabilities.

    Steps:
    1. Detect the highest-priority manifest (poetry.lock > Pipfile.lock >
       requirements.txt > pyproject.toml).
    2. Generate a CycloneDX 1.5 SBOM in-memory from detected dependencies.
    3. Query OSV.dev for known CVEs.

    Returns a :class:`DependencyScanResult` with findings and SBOM.
    Returns empty results with ``osv_error=None`` if no manifest is found.
    On OSV.dev network failure, returns any found dependencies + SBOM but
    sets ``osv_error`` to the error message (non-blocking).
    """
    target = project_dir or Path.cwd()

    detection = detect_dependencies(target)
    if detection is None:
        return DependencyScanResult(
            manifest_path=None,
            dependencies=[],
            sbom=None,
            vulnerabilities=[],
            osv_error=None,
            metadata={"dep_count": 0},
        )

    sbom = build_sbom(detection.dependencies)
    findings, osv_err = query_osv_batch(detection.dependencies)

    return DependencyScanResult(
        manifest_path=detection.manifest_path,
        dependencies=detection.dependencies,
        sbom=sbom,
        vulnerabilities=findings,
        osv_error=osv_err,
        metadata={
            "manifest_format": detection.manifest_format,
            "dep_count": len(detection.dependencies),
        },
    )
