/** ancilis scan — dependency vulnerability scan for the current project. */

import { loadConfig } from "../config/index.js";
import { DependencyScanner } from "../deps/index.js";
import type { ControlResult, EvaluationResult } from "../engine/result.js";

export interface ScanOptions {
  ci?: boolean;
  config?: string;
  db?: string;
  period?: string;
}

interface ScanIo {
  stdout(message: string): void;
  stderr(message: string): void;
}

function print(writer: (message: string) => void, message: string): void {
  writer(message.endsWith("\n") ? message : `${message}\n`);
}

function formatResult(result: EvaluationResult): string {
  const lines: string[] = [];
  const icon = result.decision === "BLOCK" ? "✗" : result.decision === "FLAG" ? "⚠" : "✓";
  lines.push(`${icon} Dependency scan — ${result.decision}`);

  for (const cr of result.controlResults) {
    const prefix = cr.result === "FAIL" ? "  [FAIL]" : cr.result === "FLAG" ? "  [WARN]" : cr.result === "PASS" ? "  [PASS]" : `  [${cr.result}]`;
    lines.push(`${prefix} ${cr.detail}`);
    if (cr.remediationHint) {
      lines.push(`         → ${cr.remediationHint}`);
    }
  }

  return lines.join("\n");
}

function hasFailures(results: EvaluationResult[]): boolean {
  return results.some((r) =>
    r.controlResults.some((cr: ControlResult) => cr.result === "FAIL"),
  );
}

export async function handleScan(
  options: ScanOptions = {},
  io: ScanIo = { stdout: (m) => process.stdout.write(m), stderr: (m) => process.stderr.write(m) },
): Promise<number> {
  try {
    const config = loadConfig(options.config ? { path: options.config } : {});
    const scanner = new DependencyScanner(config);
    const results = await scanner.scan();

    if (results.length === 0) {
      print(io.stdout, "Dependency scan: DE-01 disabled, skipped.");
      return 0;
    }

    for (const result of results) {
      print(io.stdout, formatResult(result));
    }

    if (options.ci && hasFailures(results)) {
      print(io.stderr, "Scan failed: CRITICAL or HIGH vulnerabilities found.");
      return 1;
    }

    return 0;
  } catch (err: unknown) {
    print(io.stderr, `Scan error: ${(err as Error).message ?? String(err)}`);
    return 1;
  }
}
