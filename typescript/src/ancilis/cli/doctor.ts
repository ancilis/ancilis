/** ancilis doctor — lightweight local installation/runtime checks. */

import { mkdirSync, writeFileSync, unlinkSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { loadConfig } from "../config/index.js";
import type { ResolvedConfig } from "../config/index.js";
import { EvidenceStore } from "../evidence/store.js";
import { sharedPathFrom } from "../shared-path.js";
import { red, yellow, blue } from "../errors.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function useColor(): boolean {
  return process.stdout.isTTY === true && process.env["NO_COLOR"] === undefined;
}

function checkMark(ok: boolean, colorEnabled: boolean): string {
  if (!colorEnabled) return ok ? "[OK]" : "[FAIL]";
  return ok
    ? `\u001b[32m[OK]\u001b[0m`
    : `\u001b[31m[FAIL]\u001b[0m`;
}

function warnMark(colorEnabled: boolean): string {
  return colorEnabled ? `\u001b[33m[WARN]\u001b[0m` : "[WARN]";
}

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
    requireFn.resolve("@modelcontextprotocol/sdk/package.json");
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Individual doctor checks (spec-required)
// ---------------------------------------------------------------------------

/** E010 — Node.js version matches the engines field (>= 20) */
function checkNodeVersion(): { ok: boolean; detail: string } {
  const MIN_MAJOR = 20; // keep in sync with package.json engines.node
  const raw = process.versions.node;
  const major = parseInt(raw.split(".")[0] ?? "0", 10);
  if (major >= MIN_MAJOR) {
    return { ok: true, detail: `Node.js ${raw} (>= ${MIN_MAJOR} required)` };
  }
  return {
    ok: false,
    detail: `Node.js ${raw} is below minimum ${MIN_MAJOR}.x. Upgrade to continue.`,
  };
}

/** E001 — Platform connectivity (HTTP GET to platformUrl/health) */
async function checkPlatformConnectivity(config: ResolvedConfig | null): Promise<{ ok: boolean; detail: string }> {
  const platformUrl = (config as unknown as Record<string, unknown>)?.["platformUrl"] as string | undefined;
  if (!platformUrl) {
    return { ok: false, detail: "platform_url not configured in ancilis.yaml" };
  }
  try {
    const url = `${platformUrl.replace(/\/$/, "")}/health`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      return { ok: true, detail: `${platformUrl} reachable (HTTP ${res.status})` };
    }
    return { ok: false, detail: `${platformUrl} returned HTTP ${res.status}` };
  } catch (err: unknown) {
    return {
      ok: false,
      detail: `Cannot connect to ${platformUrl}: ${(err as Error).message ?? String(err)}`,
    };
  }
}

/** E004 — DuckDB write permissions at evidence store path */
async function checkDuckDbPermissions(
  config: ResolvedConfig | null,
  dbPath?: string,
): Promise<{ ok: boolean; detail: string }> {
  if (config === null) {
    return { ok: false, detail: "skipped (config not loaded)" };
  }
  const store = new EvidenceStore(config, dbPath ? { dbPath } : undefined);
  try {
    const dbTarget = store.dbPath;
    if (dbTarget === ":memory:") {
      return { ok: true, detail: "in-memory store (no disk permissions needed)" };
    }
    const dbDir = dirname(dbTarget);
    mkdirSync(dbDir, { recursive: true });
    const probe = join(dbDir, ".ancilis-write-test");
    writeFileSync(probe, "ok");
    unlinkSync(probe);
    const summary = await store.getSummary();
    return {
      ok: true,
      detail: `path ${store.dbPath} writable, ${(summary.totalEvaluations as number) ?? 0} records present`,
    };
  } catch (err: unknown) {
    return { ok: false, detail: (err as Error).message ?? String(err) };
  } finally {
    await store.close();
  }
}

/** E003 — Overlay files configured in config actually exist on disk */
function checkOverlayExistence(config: ResolvedConfig | null): { ok: boolean; detail: string } {
  if (config === null) {
    return { ok: false, detail: "skipped (config not loaded)" };
  }

  // overlayPaths is a non-standard field that may be populated by future config
  // extensions. For now check for any string[] field indicating custom file paths.
  const overlayPaths = (
    (config as unknown as Record<string, unknown>)?.["overlayPaths"] as string[] | undefined
  ) ?? [];

  if (overlayPaths.length === 0) {
    return { ok: true, detail: "no custom overlay file paths configured" };
  }

  const missing = overlayPaths.filter((p) => !existsSync(p));
  if (missing.length === 0) {
    return { ok: true, detail: `all ${overlayPaths.length} overlay file(s) found` };
  }
  return {
    ok: false,
    detail: `overlay file(s) not found: ${missing.join(", ")}`,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface DoctorResult {
  ok: boolean;
  output: string;
}

export async function runDoctor(configPath?: string, dbPath?: string): Promise<DoctorResult> {
  const color = useColor();
  const lines: string[] = [];
  let failures = 0;
  const require = createRequire(import.meta.url);

  // Version header
  let pkgVersion = "0.1.0";
  try {
    const pkgPath = new URL("../../../package.json", import.meta.url).pathname;
    const pkg = readJsonFile(pkgPath);
    if (pkg?.["version"]) pkgVersion = pkg["version"] as string;
  } catch { /* ok */ }
  lines.push(
    color
      ? `\u001b[1mAncilis doctor\u001b[0m — version ${pkgVersion}`
      : `Ancilis doctor — version ${pkgVersion}`,
  );
  lines.push("");

  // ── Spec check 1: Node.js version (E010) ──────────────────────────────────
  const nodeCheck = checkNodeVersion();
  lines.push(`${checkMark(nodeCheck.ok, color)} node version: ${nodeCheck.detail}`);
  if (!nodeCheck.ok) {
    lines.push("  " + (color ? yellow("→ Upgrade Node.js to v18 or later") : "→ Upgrade Node.js to v18 or later"));
    failures++;
  }

  // ── Spec check 2: Config validity (E002) ──────────────────────────────────
  const { ok: configOk, detail: configDetail, config } = checkConfig(configPath);
  lines.push(`${checkMark(configOk, color)} config: ${configDetail}`);
  if (!configOk) {
    lines.push("  " + (color ? yellow("→ Run `ancilis init` to regenerate config or fix ancilis.yaml manually") : "→ Run `ancilis init` to regenerate config or fix ancilis.yaml manually"));
    lines.push("  " + (color ? blue("https://docs.ancilis.ai/errors/e002") : "https://docs.ancilis.ai/errors/e002"));
    failures++;
  }

  // ── Spec check 3: Overlay existence (E003) ────────────────────────────────
  const overlayCheck = checkOverlayExistence(config);
  lines.push(`${checkMark(overlayCheck.ok, color)} overlays: ${overlayCheck.detail}`);
  if (!overlayCheck.ok) {
    lines.push("  " + (color ? yellow("→ Check spelling or run `ancilis config validate`") : "→ Check spelling or run `ancilis config validate`"));
    lines.push("  " + (color ? blue("https://docs.ancilis.ai/errors/e003") : "https://docs.ancilis.ai/errors/e003"));
    failures++;
  }

  // ── Spec check 4: DuckDB permissions (E004) ───────────────────────────────
  const dbCheck = await checkDuckDbPermissions(config, dbPath);
  lines.push(`${checkMark(dbCheck.ok, color)} evidence store: ${dbCheck.detail}`);
  if (!dbCheck.ok) {
    lines.push("  " + (color ? yellow("→ Ensure no other process holds the DuckDB lock") : "→ Ensure no other process holds the DuckDB lock"));
    lines.push("  " + (color ? blue("https://docs.ancilis.ai/errors/e004") : "https://docs.ancilis.ai/errors/e004"));
    failures++;
  }

  // ── Spec check 5: Platform connectivity (E001) ────────────────────────────
  const platformConfigured = config !== null &&
    Boolean((config as unknown as Record<string, unknown>)?.["platformUrl"]);
  if (platformConfigured) {
    const platformCheck = await checkPlatformConnectivity(config);
    lines.push(`${checkMark(platformCheck.ok, color)} platform connectivity: ${platformCheck.detail}`);
    if (!platformCheck.ok) {
      lines.push("  " + (color ? yellow("→ Check platform_url in ancilis.yaml") : "→ Check platform_url in ancilis.yaml"));
      lines.push("  " + (color ? blue("https://docs.ancilis.ai/errors/e001") : "https://docs.ancilis.ai/errors/e001"));
      failures++;
    }
  } else {
    lines.push(`${warnMark(color)} platform connectivity: platform_url not set (offline / local-only mode)`);
  }

  // ── Additional checks ─────────────────────────────────────────────────────

  // Shared assets
  try {
    const sharedDir = sharedPathFrom(import.meta.url);
    const controlsDir = join(sharedDir, "controls");
    const taxonomyPath = join(sharedDir, "classifications", "taxonomy.json");
    const tax = readJsonFile(taxonomyPath);
    const taxonomyVersion = (tax as { version?: string } | null)?.version ?? "unknown";
    const controlCount = listJsonFiles(controlsDir).length;
    lines.push(`${checkMark(true, color)} assets: taxonomy ${taxonomyVersion}, ${controlCount} controls available`);
  } catch (err: unknown) {
    failures++;
    lines.push(`${checkMark(false, color)} assets: ${(err as Error).message ?? String(err)}`);
  }

  // Optional MCP extra
  if (hasOptionalMcpExtra(require)) {
    lines.push(`${checkMark(true, color)} optional mcp extra: installed`);
  } else {
    lines.push(`${warnMark(color)} optional mcp extra: not installed (install @modelcontextprotocol/sdk for MCP middleware)`);
  }

  // PDF export dependency
  try {
    execFileSync("pandoc", ["--version"], { timeout: 3000, stdio: "pipe" });
    lines.push(`${checkMark(true, color)} pdf reporting dependency: pandoc executable detected`);
  } catch {
    lines.push(`${warnMark(color)} pdf reporting dependency: PDF export falls back to markdown when pandoc/xelatex are unavailable`);
  }

  // Summary
  lines.push("");
  if (failures === 0) {
    lines.push(color ? `\u001b[32mAll checks passed.\u001b[0m` : "All checks passed.");
    if (configOk && config !== null) {
      lines.push("");
      lines.push("Ready. Next steps:");
      lines.push("  ancilis status                  — view current security posture");
      lines.push("  ancilis config validate         — inspect resolved config details");
    }
  } else {
    lines.push(
      color
        ? `${red(`${failures} check(s) failed.`)} Fix the issues above and re-run ${blue("ancilis doctor")}.`
        : `${failures} check(s) failed. Fix the issues above and re-run \`ancilis doctor\`.`,
    );
    if (!configOk) {
      lines.push("");
      lines.push("To get started, create ancilis.yaml in your project root:");
      lines.push("  agent:");
      lines.push("    name: my-agent");
      lines.push("");
      lines.push("Then run: ancilis doctor");
    }
  }

  return { ok: failures === 0, output: lines.join("\n") };
}
