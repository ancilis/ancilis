import * as exec from "@actions/exec";
import * as core from "@actions/core";
import { writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

export interface ControlResult {
  id: string;
  name: string;
  status: "pass" | "fail" | "skip";
  evaluations: number;
  failures: number;
  flags: number;
}

export interface ScanSummary {
  total_controls: number;
  passing: number;
  failing: number;
  skipped: number;
  total_evaluations: number;
}

export interface ScanResult {
  version: string;
  agent: string;
  mode: string;
  timestamp: string;
  controls: ControlResult[];
  summary: ScanSummary;
  posture: "compliant" | "non_compliant";
  exit_code: number;
}

export interface ScannerOptions {
  overlays: string[];
  ancilisVersion: string;
  period?: string;
}

function buildConfig(overlays: string[]): string {
  return [
    "agent:",
    "  name: github-action-scan",
    "security:",
    "  mode: audit",
    `  overlays: [${overlays.map((o) => `"${o}"`).join(", ")}]`,
  ].join("\n");
}

export async function installAncilis(ancilisVersion: string): Promise<void> {
  core.info(`Installing ${ancilisVersion}...`);
  await exec.exec("pip", ["install", "--quiet", ancilisVersion]);
}

export async function runScan(options: ScannerOptions): Promise<ScanResult> {
  const { overlays, period = "24h" } = options;

  const args = ["scan", "--ci", "--period", period];
  let configPath: string | undefined;

  if (overlays.length > 0) {
    configPath = join(tmpdir(), `ancilis-action-${Date.now()}.yaml`);
    writeFileSync(configPath, buildConfig(overlays), "utf-8");
    args.push("--config", configPath);
  }

  let stdout = "";
  let stderr = "";

  try {
    const result = await exec.getExecOutput("ancilis", args, {
      silent: true,
      ignoreReturnCode: true,
    });
    stdout = result.stdout;
    stderr = result.stderr;

    if (stderr) {
      core.debug(`ancilis stderr: ${stderr}`);
    }
  } finally {
    if (configPath) {
      try {
        unlinkSync(configPath);
      } catch {
        // ignore cleanup errors
      }
    }
  }

  if (!stdout.trim()) {
    throw new Error("ancilis scan produced no output. Is ancilis installed and configured?");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout) as unknown;
  } catch {
    throw new Error(`Failed to parse ancilis scan JSON output: ${stdout.slice(0, 200)}`);
  }

  return validateScanResult(parsed);
}

export function validateScanResult(raw: unknown): ScanResult {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Scan output is not a JSON object");
  }
  const obj = raw as Record<string, unknown>;

  if (typeof obj.posture !== "string" || !["compliant", "non_compliant"].includes(obj.posture)) {
    throw new Error(`Invalid posture value: ${String(obj.posture)}`);
  }
  if (!Array.isArray(obj.controls)) {
    throw new Error("Missing or invalid controls array in scan output");
  }

  return obj as unknown as ScanResult;
}
