/** Dependency vulnerability scanner — wires ManifestDetector + OSVClient into EvaluationResults. */

import { randomUUID } from "node:crypto";
import type { ResolvedConfig } from "../config/index.js";
import type { ControlResult, EvaluationResult } from "../engine/result.js";
import type { Dependency } from "./types.js";
import { ManifestDetector } from "./manifest.js";
import { OSVClient } from "./osv.js";
import type { Vuln } from "./types.js";

const CONTROL_ID = "DE-01";
const CONTROL_NAME = "Dependency Evaluation";

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

function resultForSeverity(severity: string): "FAIL" | "FLAG" {
  return severity === "CRITICAL" || severity === "HIGH" ? "FAIL" : "FLAG";
}

function buildEvaluation(
  controlResults: ControlResult[],
  mode: "audit" | "enforce",
): EvaluationResult {
  const hasFail = controlResults.some(cr => cr.result === "FAIL");
  const hasFlag = controlResults.some(cr => cr.result === "FLAG");
  const decision: "BLOCK" | "FLAG" | "ALLOW" = hasFail ? "BLOCK" : hasFlag ? "FLAG" : "ALLOW";

  return {
    evaluationId: randomUUID(),
    actionId: `dep-scan-${randomUUID().replace(/-/g, "").slice(0, 8)}`,
    timestamp: new Date().toISOString(),
    agentId: "cli-scan",
    sourceType: "dependency_scan",
    mode,
    controlResults,
    decision,
    decisionReason: "Dependency vulnerability scan",
    activeOverlays: [],
    dataClassifications: [],
    totalDurationMs: 0,
  };
}

export class DependencyScanner {
  private readonly _config: ResolvedConfig;

  constructor(config: ResolvedConfig) {
    this._config = config;
  }

  async scan(projectDir?: string): Promise<EvaluationResult[]> {
    // DE-01 gate — respect explicit disable; absent = enabled by default
    const de01 = this._config.controls.get(CONTROL_ID);
    if (de01 !== undefined && !de01.enabled) return [];

    const target = projectDir ?? process.cwd();
    const manifests = new ManifestDetector().detect(target);

    if (manifests.length === 0) {
      return [buildEvaluation(
        [{
          controlId: CONTROL_ID,
          controlName: CONTROL_NAME,
          result: "SKIP",
          detail: "No dependency manifests found",
          evidenceData: {},
          durationMs: 0,
        }],
        this._config.mode as "audit" | "enforce",
      )];
    }

    const allDeps: Dependency[] = manifests.flatMap(m => m.dependencies);

    const client = new OSVClient();
    const vulnMap = await client.queryBatch(allDeps);

    if (client.lastError !== null) {
      return [buildEvaluation(
        [{
          controlId: CONTROL_ID,
          controlName: CONTROL_NAME,
          result: "FLAG",
          detail: `OSV.dev lookup failed: ${client.lastError}`,
          evidenceData: { error: client.lastError },
          durationMs: 0,
        }],
        this._config.mode as "audit" | "enforce",
      )];
    }

    if (Object.keys(vulnMap).length === 0) {
      return [buildEvaluation(
        [{
          controlId: CONTROL_ID,
          controlName: CONTROL_NAME,
          result: "PASS",
          detail: `No known vulnerabilities in ${allDeps.length} dependencies`,
          evidenceData: { dep_count: allDeps.length },
          durationMs: 0,
        }],
        this._config.mode as "audit" | "enforce",
      )];
    }

    const depLookup = new Map<string, Dependency>(allDeps.map(d => [d.name, d]));

    // Sort packages: worst severity first, then alphabetically
    const sortedPackages = Object.entries(vulnMap).sort(([nameA, vulnsA], [nameB, vulnsB]) => {
      const minA = Math.min(...vulnsA.map((v: Vuln) => SEVERITY_ORDER[v.severity] ?? 3));
      const minB = Math.min(...vulnsB.map((v: Vuln) => SEVERITY_ORDER[v.severity] ?? 3));
      if (minA !== minB) return minA - minB;
      return nameA.toLowerCase().localeCompare(nameB.toLowerCase());
    });

    const controlResults: ControlResult[] = [];
    for (const [pkgName, vulns] of sortedPackages) {
      const dep = depLookup.get(pkgName);
      const sortedVulns = [...vulns].sort(
        (a: Vuln, b: Vuln) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3),
      );
      for (const vuln of sortedVulns) {
        const remediation = vuln.fixedVersion
          ? `Upgrade ${pkgName} to >=${vuln.fixedVersion}`
          : "";
        controlResults.push({
          controlId: CONTROL_ID,
          controlName: CONTROL_NAME,
          result: resultForSeverity(vuln.severity),
          detail: `${pkgName}==${dep?.version ?? "?"}: ${vuln.id} (${vuln.severity}) — ${vuln.summary}`,
          evidenceData: {
            package: pkgName,
            version: dep?.version ?? null,
            vuln_id: vuln.id,
            severity: vuln.severity,
            fixed_version: vuln.fixedVersion,
            source_file: dep?.sourceFile ?? null,
            aliases: vuln.aliases,
            affected_versions: vuln.affectedVersions,
          },
          durationMs: 0,
          remediationHint: remediation || undefined,
        });
      }
    }

    return [buildEvaluation(
      controlResults,
      this._config.mode as "audit" | "enforce",
    )];
  }
}
