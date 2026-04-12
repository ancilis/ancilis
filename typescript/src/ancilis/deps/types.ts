/** Shared types for dependency vulnerability scanning. */

export interface Dependency {
  name: string;
  version: string | null;
  sourceFile: string;
}

export interface Manifest {
  path: string;
  format: string;
  dependencies: Dependency[];
}

export interface Vuln {
  id: string;
  summary: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  aliases: string[];
  affectedVersions: string;
  fixedVersion: string | null;
}
