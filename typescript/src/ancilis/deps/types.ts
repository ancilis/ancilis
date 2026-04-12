/** Dependency vulnerability scanner — shared types. */

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
  severity: string;
  aliases: string[];
  affectedVersions: string;
  fixedVersion: string | null;
}
