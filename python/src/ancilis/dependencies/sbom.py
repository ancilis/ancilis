"""CycloneDX SBOM generation from detected Python dependencies.

Generates an in-memory CycloneDX 1.5 BOM — no disk writes.
The SBOM is an intermediate format; the primary output of the scan pipeline
is the vulnerability list from OSV.dev.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ancilis.dependencies.detector import Dependency

_ANCILIS_VERSION = "0.1.0"


@dataclass
class CycloneDxComponent:
    type: str  # "library"
    name: str
    version: str
    purl: str


@dataclass
class CycloneDxTool:
    vendor: str
    name: str
    version: str


@dataclass
class CycloneDxMetadata:
    timestamp: str
    tools: list[CycloneDxTool] = field(default_factory=list)


@dataclass
class CycloneDxBom:
    bom_format: str  # "CycloneDX"
    spec_version: str  # "1.5"
    serial_number: str
    version: int  # 1
    metadata: CycloneDxMetadata
    components: list[CycloneDxComponent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "serialNumber": self.serial_number,
            "version": self.version,
            "metadata": {
                "timestamp": self.metadata.timestamp,
                "tools": [
                    {"vendor": t.vendor, "name": t.name, "version": t.version}
                    for t in self.metadata.tools
                ],
            },
            "components": [
                {"type": c.type, "name": c.name, "version": c.version, "purl": c.purl}
                for c in self.components
            ],
        }


def _to_purl(dep: Dependency) -> str:
    """Build a Package URL (purl) for a PyPI package."""
    # purl spec: pkg:pypi/{name}@{version}
    # Normalize name per PEP 503 (lowercase, hyphens)
    normalized = dep.name.lower().replace("_", "-").replace(".", "-")
    return f"pkg:pypi/{normalized}@{dep.version}"


def build_sbom(dependencies: list[Dependency]) -> CycloneDxBom:
    """Build a CycloneDX 1.5 BOM from a list of dependencies (in-memory only)."""
    components = [
        CycloneDxComponent(
            type="library",
            name=dep.name,
            version=dep.version,
            purl=_to_purl(dep),
        )
        for dep in dependencies
    ]
    metadata = CycloneDxMetadata(
        timestamp=datetime.now(timezone.utc).isoformat(),
        tools=[CycloneDxTool(vendor="Ancilis", name="ancilis", version=_ANCILIS_VERSION)],
    )
    return CycloneDxBom(
        bom_format="CycloneDX",
        spec_version="1.5",
        serial_number=f"urn:uuid:{uuid.uuid4()}",
        version=1,
        metadata=metadata,
        components=components,
    )
