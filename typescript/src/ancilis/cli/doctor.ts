/** ancilis doctor — lightweight local installation/runtime checks. */

import { mkdirSync, writeFileSync, unlinkSync, readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { loadConfig } from "../config/index.js";
import type { ResolvedConfig } from "../config/index.js";
import { EvidenceStore } from "../evidence/store.js";
import { sharedPathFrom } from "../shared-path.js";

function checkConfig(configPath?: string): { ok: boolean; detail: string; config: ResolvedConfig | null } {
  try {
    const config = loadConfig(configPath ? { path: configPath } : {});
    return { ok: true, detail: `loaded for agent '${config.agentName}' in ${config.mode} mode`, config };
  } catch (err: unknown) {
    return { ok: false, detail: (err as Error).message ?? String(err), config: null };
  }
}

function readJsonFile(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    return null;
  }
}

function listJsonFiles(dir: string): string[] {
  try {
    return readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
}

function hasOptionalMcpExtra(requireFn: NodeRequire): boolean {
  try {
    // Some SDK releases expose a broken root require target, so detect installation
    // via the exported package metadata instead of the package main entry.
    requireFn.resolve("@modelcontextprotocol/sdk/package.json");
    return true;
  } catch {
    return false;
  }
}

export interface DoctorResult {
  ok: boolean;
  output: string;
}

export async function runDoctor(configPath?: string, dbPath?: string): Promise<DoctorResult> {
  const lines: string[] = [];
  let failures = 0;
  const require = createRequire(import.meta.url);

  // Version
  let pkgVersion = "0.1.0";
  try {
    const pkgPath = new URL("../../../package.json", import.meta.url).pathname;
    const pkg = readJsonFile(pkgPath);
    if (pkg?.["version"]) pkgVersion = pkg["version"] as string;
  } catch { /* ok */ }
  lines.push(`Ancilis doctor — version ${pkgVersion}`);

  // Config check
  const { ok: configOk, detail: configDetail, config } = checkConfig(configPath);
  lines.push(`[${configOk ? "OK" : "FAIL"}] config: ${configDetail}`);
  if (!configOk) failures++;

  // Assets check
  try {
    const sharedDir = sharedPathFrom(import.meta.url);
    const controlsDir = join(sharedDir, "controls");
    const taxonomyPath = join(sharedDir, "classifications", "taxonomy.json");

    const tax = readJsonFile(taxonomyPath);
    const taxonomyVersion = (tax as { version?: string } | null)?.version ?? "unknown";
    const controlCount = listJsonFiles(controlsDir).length;
    lines.push(`[OK] assets: taxonomy ${taxonomyVersion}, ${controlCount} controls available`);
  } catch (err: unknown) {
    failures++;
    lines.push(`[FAIL] assets: ${(err as Error).message ?? String(err)}`);
  }

  // Evidence store check
  if (config !== null) {
    const store = new EvidenceStore(config, dbPath ? { dbPath } : undefined);
    try {
      const dbTarget = store.dbPath;
      if (dbTarget !== ":memory:") {
        const dbDir = dirname(dbTarget);
        mkdirSync(dbDir, { recursive: true });
        const probe = join(dbDir, ".ancilis-write-test");
        writeFileSync(probe, "ok");
        unlinkSync(probe);
      }
      const summary = await store.getSummary();
      lines.push(`[OK] evidence: path ${store.dbPath} usable, ${(summary.totalEvaluations as number) ?? 0} records present`);
    } catch (err: unknown) {
      failures++;
      lines.push(`[FAIL] evidence: ${(err as Error).message ?? String(err)}`);
    } finally {
      await store.close();
    }
  }

  if (hasOptionalMcpExtra(require)) {
    lines.push("[OK] optional mcp extra: installed");
  } else {
    lines.push("[WARN] optional mcp extra: not installed (install @modelcontextprotocol/sdk for MCP middleware)");
  }

  // Check if pandoc is available (for PDF export)
  try {
    execFileSync("pandoc", ["--version"], { timeout: 3000, stdio: "pipe" });
    lines.push("[OK] pdf reporting dependency: pandoc executable detected");
  } catch {
    lines.push("[WARN] pdf reporting dependency: PDF export falls back to markdown when pandoc/xelatex are unavailable");
  }

  // Next steps
  if (configOk && config !== null) {
    lines.push("");
    lines.push("Ready. Next steps:");
    lines.push("  ancilis status                  — view current security posture");
    lines.push("  ancilis config validate         — inspect resolved config details");
  } else if (!configOk) {
    lines.push("");
    lines.push("To get started, create ancilis.yaml in your project root:");
    lines.push("  agent:");
    lines.push("    name: my-agent");
    lines.push("");
    lines.push("Then run: ancilis doctor");
  }

  return { ok: failures === 0, output: lines.join("\n") };
}
