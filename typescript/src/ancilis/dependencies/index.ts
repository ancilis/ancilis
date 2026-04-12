/**
 * Dependency vulnerability scanning — public API.
 *
 * @example
 * ```typescript
 * import { scanDependencies } from 'ancilis/dependencies';
 *
 * const result = await scanDependencies(process.cwd());
 * console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
 * ```
 */

import { detectDependencies } from "./detector.js";
import { buildSbom } from "./sbom.js";
import { queryOsvBatch } from "./osv.js";
import type { DependencyScanResult } from "./types.js";

export type {
  Dependency,
  VulnerabilityFinding,
  CycloneDxBom,
  CycloneDxComponent,
  DetectionResult,
  DependencyScanResult,
} from "./types.js";

export { detectDependencies } from "./detector.js";
export { buildSbom } from "./sbom.js";
export { queryOsvBatch } from "./osv.js";

/**
 * Scan a project directory for npm dependency vulnerabilities.
 *
 * Detects the first lockfile found (pnpm > yarn > npm), generates a
 * CycloneDX SBOM in-memory, and queries OSV.dev for known CVEs.
 *
 * @param projectDir - Absolute path to the project root. Defaults to `process.cwd()`.
 * @returns A `DependencyScanResult` with findings and SBOM.
 */
export async function scanDependencies(
  projectDir: string = process.cwd()
): Promise<DependencyScanResult> {
  const detection = detectDependencies(projectDir);

  if (!detection) {
    return {
      manifestPath: null,
      dependencies: [],
      sbom: null,
      vulnerabilities: [],
      osvError: null,
    };
  }

  const sbom = buildSbom(detection.dependencies);
  const { findings, error } = await queryOsvBatch(detection.dependencies);

  return {
    manifestPath: detection.manifestPath,
    dependencies: detection.dependencies,
    sbom,
    vulnerabilities: findings,
    osvError: error,
  };
}
