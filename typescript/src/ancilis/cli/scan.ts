/** ancilis scan — CI/CD posture check with exit codes and JSON output. */

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { __version__ } from "../index.js";
import { join } from "node:path";
import { homedir } from "node:os";
import { basename } from "node:path";
import { randomUUID } from "node:crypto";
import { loadConfig } from "../config/index.js";
import type { ResolvedConfig } from "../config/index.js";
import { EvidenceStore } from "../evidence/store.js";
import { parsePeriod } from "../report/generator.js";
import { sharedPathFrom } from "../shared-path.js";
import { scanDependencies } from "../dependencies/index.js";
import type { VulnerabilityFinding } from "../dependencies/index.js";
import type { EvaluationResult, ControlResult } from "../engine/result.js";
import {
  bucketCount,
  bucketDuration,
  countProjectFiles,
  recordTelemetryEvent,
} from "../telemetry/index.js";

const CONTROLS_DIR = sharedPathFrom(import.meta.url, "controls");

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export interface ScanOptions {
  ci?: boolean;
  config?: string;
  db?: string;
  session?: string;
  latest?: boolean;
  /** Show all sessions — overrides latest-session default */
  all?: boolean;
  period?: string;
  /** Override project directory for dependency scanning (default: process.cwd()) */
  projectDir?: string;
}

function loadControlDefs(): Map<string, Record<string, unknown>> {
  const defs = new Map<string, Record<string, unknown>>();
  try {
    const files = readdirSync(CONTROLS_DIR).filter(f => f.endsWith(".json")).sort();
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CONTROLS_DIR, file), "utf-8")) as Record<string, unknown>;
      defs.set(data.id as string, data);
    }
  } catch { /* ok */ }
  return defs;
}

function periodToSince(period: string): string {
  const ms = parsePeriod(period);
  return new Date(Date.now() - ms).toISOString();
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function dependencyEvidencePersistenceWarning(error: unknown): string {
  return `Warning: dependency-scan evidence was not persisted: ${errorMessage(error)}`;
}

function loadConfigSafe(configPath: string | undefined): ResolvedConfig | null {
  try {
    if (configPath !== undefined) {
      // If the specified path doesn't exist, fall back to zero-config default instead of failing
      if (!existsSync(configPath)) {
        return loadConfig({
          raw: {
            agent: { name: basename(process.cwd()) },
            security: { mode: "audit" },
          },
        });
      }
      return loadConfig({ path: configPath });
    }
    // Zero-config fallback: try ancilis.yaml in cwd, else create minimal in-memory config
    const defaultPath = join(process.cwd(), "ancilis.yaml");
    if (existsSync(defaultPath)) {
      return loadConfig({ path: defaultPath });
    }
    return loadConfig({
      raw: {
        agent: { name: basename(process.cwd()) },
        security: { mode: "audit" },
      },
    });
  } catch (error: unknown) {
    process.stderr.write(`Error loading config: ${(error as Error).message ?? String(error)}\nSuggested fix: Create ancilis.yaml or run 'npx ancilis doctor' for setup help\n`);
    return null;
  }
}

function writeFirstRunSentinel(): void {
  const dir = join(homedir(), ".ancilis");
  const sentinel = join(dir, ".first-run-complete");
  if (!existsSync(sentinel)) {
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(sentinel, "");
    } catch { /* ok */ }
  }
}

function firstRunSentinelExists(): boolean {
  return existsSync(join(homedir(), ".ancilis", ".first-run-complete"));
}

function printFirstRunGuidance(out: (m: string) => void): void {
  out("Ancilis — first run");
  out("");
  out("No tool-call evidence found yet. Ancilis records evidence");
  out("when your AI agent runs with the middleware active.");
  out("");
  out("Quick start:");
  out("  1. Add middleware to your agent");
  out("  2. Run your agent (tool calls get recorded)");
  out("  3. Run `npx ancilis scan` again");
  out("");
  out("Try the demo:");
  out("  cd examples/demo && npx ancilis scan");
  out("");
  out("Docs: https://docs.ancilis.ai/quickstart");
}

function printNextSteps(out: (m: string) => void): void {
  out("");
  out("Next steps:");
  out("  npx ancilis report              — generate a compliance report");
  out("  npx ancilis status --verbose    — control-by-control breakdown");
  out("  npx ancilis scan --ci           — JSON output for CI/CD pipelines");
}

export interface ControlResult2 {
  id: string;
  name: string;
  status: "pass" | "fail" | "skip" | "pending";
  evaluations: number;
  failures: number;
  flags: number;
  skips: number;
  /** Results excluding SKIP — the denominator for pass_rate. */
  evaluated: number;
  /** PASS share of evaluated (non-SKIP) results, percent to one decimal. */
  pass_rate: number;
}

// ---------------------------------------------------------------------------
// Shared evaluation pass (used by handleScan and WatchRunner)
// ---------------------------------------------------------------------------

export interface EvaluationSummary {
  controlResults: ControlResult2[];
  posture: "compliant" | "non_compliant";
  totalEvals: number;
}

/** Run one posture pass; opens+closes its own EvidenceStore. */
export async function runEvaluation(
  config: ResolvedConfig,
  opts: { since: string; db?: string; runDepScan?: boolean },
): Promise<EvaluationSummary> {
  const store = new EvidenceStore(config, opts.db !== undefined ? { dbPath: opts.db } : undefined);
  try {
    const rawSummary = await store.getSummary({ since: opts.since });
    const summary = rawSummary as Record<string, unknown>;

    const totalEvaluations = (summary.totalEvaluations as number | undefined) ?? 0;
    const controlStats = (summary.controlPassRates as Record<string, Record<string, number>> | undefined) ?? {};
    const decisions = (summary.decisions as Record<string, number> | undefined) ?? {};

    const controlDefs = loadControlDefs();
    const enabled = [...config.controls.values()].filter(c => c.enabled).sort((a, b) => a.controlId.localeCompare(b.controlId));

    const controlResults: ControlResult2[] = [];
    let anyFailing = false;

    for (const cs of enabled) {
      const cdef = controlDefs.get(cs.controlId) ?? {};
      const displayName = (cdef.display_name as string | undefined) ?? cs.name;
      const stats = controlStats[cs.controlId] ?? {};
      const failures = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
      const flags = stats.FLAG ?? 0;
      const totalEvals = Object.values(stats).reduce((acc, v) => acc + v, 0);

      const skips = stats.SKIP ?? 0;
      const passes = stats.PASS ?? 0;
      // SKIP means "no evaluator ran", not "passed" — rate only what was evaluated.
      const evaluated = totalEvals - skips;
      const passRate = evaluated > 0 ? Math.round(passes / evaluated * 1000) / 10 : 0;

      let ctrlStatus: "pass" | "fail" | "skip" | "pending";
      if (totalEvals === 0) {
        ctrlStatus = "skip";
      } else if (failures > 0) {
        ctrlStatus = "fail";
        anyFailing = true;
      } else if (evaluated === 0) {
        // Only SKIP results — pending, not passing.
        ctrlStatus = "pending";
      } else {
        ctrlStatus = "pass";
      }
      controlResults.push({ id: cs.controlId, name: displayName, status: ctrlStatus, evaluations: totalEvals, failures, flags, skips, evaluated, pass_rate: passRate });
    }

    const normalizedDecisions: Record<string, number> = {};
    for (const [k, v] of Object.entries(decisions)) {
      normalizedDecisions[k.trim().toUpperCase()] = v;
    }
    if ((normalizedDecisions.BLOCK ?? 0) > 0) {
      anyFailing = true;
    }

    if (opts.runDepScan && config.scanDependenciesEnabled) {
      const projectDir = process.cwd();
      const depResult = await scanDependencies(projectDir);
      const threshold = config.scanDependenciesSeverityThreshold;
      const ignoreSet = new Set(config.scanDependenciesIgnore);

      if (depResult.manifestPath !== null && depResult.osvError === null) {
        const activeFindings = depResult.vulnerabilities.filter(f => !ignoreSet.has(f.cveId));
        const violating = activeFindings.filter(f => atOrAboveThreshold(f.severity, threshold));
        const depEval = buildDepEvaluationResult(config, activeFindings, depResult.dependencies.length, null, violating);
        try {
          await store.store(depEval, "dependency-scanner");
        } catch (error: unknown) {
          process.stderr.write(`${dependencyEvidencePersistenceWarning(error)}\n`);
        }
        if (violating.length > 0) anyFailing = true;
      }
    }

    return {
      controlResults,
      posture: anyFailing ? "non_compliant" : "compliant",
      totalEvals: totalEvaluations,
    };
  } finally {
    await store.close();
  }
}

// ---------------------------------------------------------------------------
// Severity threshold helpers
// ---------------------------------------------------------------------------

type SeverityLevel = "critical" | "high" | "medium" | "low";

/** Returns true if `severity` is at or above `threshold` (more severe). */
function atOrAboveThreshold(severity: SeverityLevel, threshold: SeverityLevel): boolean {
  return (SEVERITY_ORDER[severity] ?? 3) <= (SEVERITY_ORDER[threshold] ?? 3);
}

// ---------------------------------------------------------------------------
// Evidence generation for dependency scan
// ---------------------------------------------------------------------------

function buildDepEvaluationResult(
  config: ResolvedConfig,
  findings: VulnerabilityFinding[],
  depCount: number,
  osvError: string | null,
  violatingFindings: VulnerabilityFinding[],
): EvaluationResult {
  const hasFail = violatingFindings.length > 0;

  const controlResult: ControlResult = {
    controlId: "PR-03",
    controlName: "Provenance",
    result: hasFail ? "FAIL" : "PASS",
    detail: osvError
      ? `Dependency scan: OSV.dev lookup unavailable — ${osvError}`
      : hasFail
        ? `Dependency scan: ${violatingFindings.length} violation(s) at/above threshold`
        : `Dependency scan: no violations in ${depCount} dependencies`,
    evidenceData: {
      component_count: depCount,
      vulnerability_count: findings.length,
      severity_threshold: config.scanDependenciesSeverityThreshold,
      ignore_list: config.scanDependenciesIgnore,
      findings: findings.slice(0, 100).map(f => ({
        cve_id: f.cveId,
        package: f.packageName,
        version: f.installedVersion,
        severity: f.severity,
        cvss_score: f.cvssScore,
        fixed_version: f.fixedVersion,
        summary: f.summary,
      })),
      osv_error: osvError,
    },
    durationMs: 0,
  };

  return {
    evaluationId: randomUUID(),
    actionId: `dep-scan-${randomUUID().replace(/-/g, "").slice(0, 8)}`,
    timestamp: new Date().toISOString(),
    agentId: config.agentName,
    sourceType: "dependency_scan",
    mode: config.mode as "audit" | "enforce",
    controlResults: [controlResult],
    decision: hasFail ? "BLOCK" : "ALLOW",
    decisionReason: "Dependency vulnerability scan",
    activeOverlays: [...config.activeOverlays.keys()],
    dataClassifications: [],
    totalDurationMs: 0,
  };
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

export async function handleScan(options: ScanOptions, io?: { stdout(m: string): void; stderr(m: string): void }): Promise<number> {
  const startedAt = Date.now();
  const out = (msg: string): void => {
    if (io) {
      io.stdout(msg.endsWith("\n") ? msg : `${msg}\n`);
    } else {
      console.log(msg);
    }
  };
  const err = (msg: string): void => {
    const line = msg.endsWith("\n") ? msg : `${msg}\n`;
    if (io) {
      io.stderr(line);
    } else {
      process.stderr.write(line);
    }
  };

  const config = loadConfigSafe(options.config);
  if (config === null) {
    return 2;
  }

  const period = options.period ?? "24h";
  const since = periodToSince(period);

  const store = new EvidenceStore(config, options.db !== undefined ? { dbPath: options.db } : undefined);
  try {
    // Determine session scope: explicit --session > --all (no filter) > default (latest session)
    let sessionId: string | undefined;
    if (options.session !== undefined) {
      sessionId = options.session;
    } else if (!options.all) {
      const latestId = await store.latestSessionId();
      if (latestId !== null) {
        sessionId = latestId;
      }
    }

    const rawSummary = await store.getSummary({ since, sessionId });
    const summary = rawSummary as Record<string, unknown>;

    const totalEvaluations = (summary.totalEvaluations as number | undefined) ?? 0;
    const controlStats = (summary.controlPassRates as Record<string, Record<string, number>> | undefined) ?? {};
    const decisions = (summary.decisions as Record<string, number> | undefined) ?? {};

    // First-run guidance when no evidence exists (human mode only)
    if (totalEvaluations === 0 && !options.ci && !firstRunSentinelExists()) {
      printFirstRunGuidance(out);
      return 0;
    }

    const controlDefs = loadControlDefs();
    const enabled = [...config.controls.values()].filter(c => c.enabled).sort((a, b) => a.controlId.localeCompare(b.controlId));

    const controlResults: ControlResult2[] = [];
    let passingCount = 0;
    let failingCount = 0;
    let skippedCount = 0;
    let pendingCount = 0;
    let anyFailing = false;

    for (const cs of enabled) {
      const cdef = controlDefs.get(cs.controlId) ?? {};
      const displayName = (cdef.display_name as string | undefined) ?? cs.name;
      const stats = controlStats[cs.controlId] ?? {};
      const failures = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
      const flags = stats.FLAG ?? 0;
      const totalEvals = Object.values(stats).reduce((acc, v) => acc + v, 0);

      const skips = stats.SKIP ?? 0;
      const passes = stats.PASS ?? 0;
      // SKIP means "no evaluator ran", not "passed" — rate only what was evaluated.
      const evaluated = totalEvals - skips;
      const passRate = evaluated > 0 ? Math.round(passes / evaluated * 1000) / 10 : 0;

      let ctrlStatus: "pass" | "fail" | "skip" | "pending";
      if (totalEvals === 0) {
        ctrlStatus = "skip";
        skippedCount += 1;
      } else if (failures > 0) {
        ctrlStatus = "fail";
        anyFailing = true;
        failingCount += 1;
      } else if (evaluated === 0) {
        // Only SKIP results — pending, not passing.
        ctrlStatus = "pending";
        pendingCount += 1;
      } else {
        ctrlStatus = "pass";
        passingCount += 1;
      }

      controlResults.push({ id: cs.controlId, name: displayName, status: ctrlStatus, evaluations: totalEvals, failures, flags, skips, evaluated, pass_rate: passRate });
    }

    // Blocked tool calls also make posture non-compliant
    const normalizedDecisions: Record<string, number> = {};
    for (const [k, v] of Object.entries(decisions)) {
      normalizedDecisions[k.trim().toUpperCase()] = v;
    }
    if ((normalizedDecisions.BLOCK ?? 0) > 0) {
      anyFailing = true;
    }

    // -----------------------------------------------------------------------
    // Dependency scan
    // -----------------------------------------------------------------------
    interface DepScanSummary {
      status: "ok" | "violations" | "no_manifests" | "osv_error" | "disabled";
      findings: VulnerabilityFinding[];
      violatingFindings: VulnerabilityFinding[];
      componentCount: number;
      osvError: string | null;
    }

    let depSummary: DepScanSummary = {
      status: "no_manifests",
      findings: [],
      violatingFindings: [],
      componentCount: 0,
      osvError: null,
    };

    if (config.scanDependenciesEnabled) {
      const projectDir = options.projectDir ?? process.cwd();
      const depResult = await scanDependencies(projectDir);
      const threshold = config.scanDependenciesSeverityThreshold;
      const ignoreSet = new Set(config.scanDependenciesIgnore);

      if (depResult.manifestPath === null) {
        depSummary = { status: "no_manifests", findings: [], violatingFindings: [], componentCount: 0, osvError: null };
      } else if (depResult.osvError !== null) {
        depSummary = {
          status: "osv_error",
          findings: [],
          violatingFindings: [],
          componentCount: depResult.dependencies.length,
          osvError: depResult.osvError,
        };
      } else {
        const activeFindings = depResult.vulnerabilities.filter(f => !ignoreSet.has(f.cveId));
        const violating = activeFindings.filter(f => atOrAboveThreshold(f.severity, threshold));

        if (violating.length > 0) {
          anyFailing = true;
        }

        depSummary = {
          status: violating.length > 0 ? "violations" : "ok",
          findings: activeFindings,
          violatingFindings: violating,
          componentCount: depResult.dependencies.length,
          osvError: null,
        };
      }

      // Generate and store evidence record (PR-03)
      const depEval = buildDepEvaluationResult(
        config,
        depSummary.findings,
        depSummary.componentCount,
        depSummary.osvError,
        depSummary.violatingFindings,
      );
      try {
        await store.store(depEval, "dependency-scanner");
      } catch (error: unknown) {
        err(dependencyEvidencePersistenceWarning(error));
      }
    } else {
      depSummary = { status: "disabled", findings: [], violatingFindings: [], componentCount: 0, osvError: null };
    }

    const posture = anyFailing ? "non_compliant" : "compliant";
    const exitCode = anyFailing ? 1 : 0;
    const overlayIds = [...config.activeOverlays.keys()].sort();

    await recordTelemetryEvent("scan_executed", {
      language: "typescript",
      file_count_bucket: bucketCount(countProjectFiles(options.projectDir ?? process.cwd())),
      overlay_ids: overlayIds,
      duration_bucket: bucketDuration(Date.now() - startedAt),
      ci: Boolean(options.ci),
      exit_code: exitCode,
      posture,
    }).catch(() => {});

    for (const overlayId of overlayIds) {
      await recordTelemetryEvent("overlay_activated", {
        overlay_id: overlayId,
        control_count: enabled.length,
      }).catch(() => {});
    }

    if (options.ci) {
      // Sort findings by severity for CI output
      const sortedFindings = [...depSummary.findings].sort(
        (a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3),
      );

      const depCiSection = config.scanDependenciesEnabled
        ? {
            status: depSummary.status,
            component_count: depSummary.componentCount,
            severity_threshold: config.scanDependenciesSeverityThreshold,
            violation_count: depSummary.violatingFindings.length,
            total_findings: depSummary.findings.length,
            findings: sortedFindings.map(f => ({
              cve_id: f.cveId,
              package: f.packageName,
              installed_version: f.installedVersion,
              severity: f.severity,
              cvss_score: f.cvssScore,
              fixed_version: f.fixedVersion,
              summary: f.summary,
            })),
          }
        : { status: "disabled" };

      const output = {
        version: __version__,
        agent: config.agentName,
        mode: config.mode,
        timestamp: new Date().toISOString(),
        controls: controlResults,
        dependencies: depCiSection,
        summary: {
          total_controls: enabled.length,
          passing: passingCount,
          failing: failingCount,
          skipped: skippedCount,
          pending: pendingCount,
          total_evaluations: totalEvaluations,
        },
        posture,
        exit_code: exitCode,
      };
      out(JSON.stringify(output, null, 2));
    } else {
      // Human output
      const lines: string[] = [
        `Ancilis scan — ${config.agentName}`,
        `  Mode:    ${config.mode}`,
        `  Posture: ${posture}`,
        "",
      ];

      if (totalEvaluations === 0) {
        lines.push("  No evaluations recorded in period. Posture: compliant (nothing to check).");
      } else {
        for (const ctrl of controlResults) {
          const mark = ctrl.status === "pass" ? "\u2713" : ctrl.status === "fail" ? "\u2717" : ctrl.status === "pending" ? "\u25cb" : "\u2013";
          let detail = `${ctrl.evaluations} evals`;
          if (ctrl.failures > 0) detail += `, ${ctrl.failures} failures`;
          if (ctrl.flags > 0) detail += `, ${ctrl.flags} flags`;
          lines.push(`  ${mark} ${ctrl.name} \u2014 ${ctrl.status} (${detail})`);
        }
      }

      // DEPENDENCIES section
      if (config.scanDependenciesEnabled) {
        lines.push("");
        if (depSummary.status === "no_manifests") {
          lines.push("DEPENDENCIES  No dependency manifests detected (skipped)");
        } else if (depSummary.status === "osv_error") {
          lines.push("DEPENDENCIES  Vulnerability lookup unavailable (OSV.dev timeout)");
        } else if (depSummary.status === "ok") {
          lines.push(`DEPENDENCIES  No vulnerabilities found (${depSummary.componentCount} packages scanned)`);
        } else if (depSummary.status === "violations") {
          const violationCount = depSummary.violatingFindings.length;
          lines.push(`DEPENDENCIES (${violationCount} issue${violationCount === 1 ? "" : "s"} found)`);

          // Sort findings: violations first (by severity), then remainder
          const sorted = [...depSummary.violatingFindings].sort(
            (a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3),
          );
          for (const f of sorted) {
            const sev = f.severity.toUpperCase().padEnd(8);
            const fix = f.fixedVersion ? ` (upgrade to \u2265${f.fixedVersion})` : "";
            lines.push(`  ${sev} ${f.packageName} ${f.installedVersion} \u2014 ${f.cveId}${fix}`);
          }
        }
      }

      out(lines.join("\n"));
      printNextSteps(out);

      // Write sentinel after first successful scan with results
      if (totalEvaluations > 0) {
        writeFirstRunSentinel();
      }
    }

    return exitCode;
  } catch (error: unknown) {
    const errMsg = `Error during scan: ${(error as Error).message ?? String(error)}\nSuggested fix: Run your agent with Ancilis middleware to collect evidence\n`;
    if (io) { io.stderr(errMsg); } else { process.stderr.write(errMsg); }
    return 2;
  } finally {
    await store.close();
  }
}
