/** CycloneDX SBOM generation from detected npm dependencies (in-memory, no disk writes). */

import { randomUUID } from "node:crypto";
import type { CycloneDxBom, CycloneDxComponent, Dependency } from "./types.js";

const ANCILIS_VERSION = "0.1.0-preview.1";

function toPurl(dep: Dependency): string {
  return `pkg:npm/${encodeURIComponent(dep.name)}@${encodeURIComponent(dep.version)}`;
}

export function buildSbom(dependencies: Dependency[]): CycloneDxBom {
  const components: CycloneDxComponent[] = dependencies.map((dep) => ({
    type: "library",
    name: dep.name,
    version: dep.version,
    purl: toPurl(dep),
  }));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "Ancilis",
          name: "ancilis",
          version: ANCILIS_VERSION,
        },
      ],
    },
    components,
  };
}
