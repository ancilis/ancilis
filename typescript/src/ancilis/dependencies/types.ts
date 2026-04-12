/** Dependency vulnerability scanning — shared type definitions. */

export interface Dependency {
  name: string;
  version: string;
  ecosystem: "npm";
}

export interface VulnerabilityFinding {
  cveId: string;
  packageName: string;
  installedVersion: string;
  severity: "critical" | "high" | "medium" | "low";
  cvssScore: number | null;
  fixedVersion: string | null;
  summary: string;
}

export interface CycloneDxComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
}

export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
  };
  components: CycloneDxComponent[];
}

export interface DetectionResult {
  manifestPath: string;
  manifestFormat: "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml";
  dependencies: Dependency[];
}

export interface DependencyScanResult {
  manifestPath: string | null;
  dependencies: Dependency[];
  sbom: CycloneDxBom | null;
  vulnerabilities: VulnerabilityFinding[];
  osvError: string | null;
}
