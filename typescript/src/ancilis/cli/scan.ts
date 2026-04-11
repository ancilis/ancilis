/** ancilis scan — CI/CD posture check with exit codes and JSON output. */

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { basename } from "node:path";
import { loadConfig } from "../config/index.js";
import type { ResolvedConfig } from "../config/index.js";
import { EvidenceStore } from "../evidence/store.js";
import { parsePeriod } from "../report/generator.js";
import { sharedPathFrom } from "../shared-path.js";

const CONTROLS_DIR = sharedPathFrom(import.meta.url, "controls");

export interface ScanOptions {
  ci?: boolean;
  config?: string;
  db?: string;
  session?: string;
  latest?: boolean;
  period?: string;
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

function loadConfigSafe(configPath: string | undefined): ResolvedConfig | null {
  try {
    if (configPath !== undefined) {
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
  out("Docs: https://ancilis.dev/quickstart");
}

function printNextSteps(out: (m: string) => void): void {
  out("");
  out("Next steps:");
  out("  npx ancilis report              — generate a compliance report");
  out("  npx ancilis status --verbose    — control-by-control breakdown");
  out("  npx ancilis scan --ci           — JSON output for CI/CD pipelines");
}

interface ControlResult {
  id: string;
  name: string;
  status: "pass" | "fail" | "skip";
  evaluations: number;
  failures: number;
  flags: number;
}

export async function handleScan(options: ScanOptions, io?: { stdout(m: string): void; stderr(m: string): void }): Promise<number> {
  const out = (msg: string): void => {
    if (io) {
      io.stdout(msg.endsWith("\n") ? msg : `${msg}\n`);
    } else {
      console.log(msg);
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
    const rawSummary = await store.getSummary({ since });
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

    const controlResults: ControlResult[] = [];
    let passingCount = 0;
    let failingCount = 0;
    let skippedCount = 0;
    let anyFailing = false;

    for (const cs of enabled) {
      const cdef = controlDefs.get(cs.controlId) ?? {};
      const displayName = (cdef.display_name as string | undefined) ?? cs.name;
      const stats = controlStats[cs.controlId] ?? {};
      const failures = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
      const flags = stats.FLAG ?? 0;
      const totalEvals = Object.values(stats).reduce((acc, v) => acc + v, 0);

      let ctrlStatus: "pass" | "fail" | "skip";
      if (totalEvals === 0) {
        ctrlStatus = "skip";
        skippedCount += 1;
      } else if (failures > 0) {
        ctrlStatus = "fail";
        anyFailing = true;
        failingCount += 1;
      } else {
        ctrlStatus = "pass";
        passingCount += 1;
      }

      controlResults.push({ id: cs.controlId, name: displayName, status: ctrlStatus, evaluations: totalEvals, failures, flags });
    }

    // Blocked tool calls also make posture non-compliant
    const normalizedDecisions: Record<string, number> = {};
    for (const [k, v] of Object.entries(decisions)) {
      normalizedDecisions[k.trim().toUpperCase()] = v;
    }
    if ((normalizedDecisions.BLOCK ?? 0) > 0) {
      anyFailing = true;
    }

    const posture = anyFailing ? "non_compliant" : "compliant";
    const exitCode = anyFailing ? 1 : 0;

    if (options.ci) {
      const output = {
        version: "0.1.0",
        agent: config.agentName,
        mode: config.mode,
        timestamp: new Date().toISOString(),
        controls: controlResults,
        summary: {
          total_controls: enabled.length,
          passing: passingCount,
          failing: failingCount,
          skipped: skippedCount,
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
          const mark = ctrl.status === "pass" ? "\u2713" : ctrl.status === "fail" ? "\u2717" : "\u2013";
          let detail = `${ctrl.evaluations} evals`;
          if (ctrl.failures > 0) detail += `, ${ctrl.failures} failures`;
          if (ctrl.flags > 0) detail += `, ${ctrl.flags} flags`;
          lines.push(`  ${mark} ${ctrl.name} \u2014 ${ctrl.status} (${detail})`);
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
