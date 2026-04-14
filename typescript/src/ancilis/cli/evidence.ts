/** ancilis evidence — evidence store management commands. */

import { createInterface } from "node:readline";
import { readFileSync, existsSync } from "node:fs";
import { loadConfig } from "../config/index.js";
import { EvidenceStore } from "../evidence/store.js";
import { SarifImporter } from "../importers/sarif.js";
import { CycloneDxImporter } from "../importers/cyclonedx.js";

interface EvidenceIo {
  stdout(message: string): void;
  stderr(message: string): void;
  prompt?(question: string): Promise<string>;
}

function print(writer: (message: string) => void, message: string): void {
  writer(message.endsWith("\n") ? message : `${message}\n`);
}

function defaultPrompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function loadConfigSafe(configPath?: string): ReturnType<typeof loadConfig> | null {
  try {
    return loadConfig(configPath ? { path: configPath } : {});
  } catch (err: unknown) {
    return null;
  }
}

/** ancilis evidence sessions */
export async function runEvidenceSessions(options: {
  configPath?: string;
  dbPath?: string;
}, _io?: EvidenceIo): Promise<{ ok: boolean; output: string }> {
  const lines: string[] = [];

  const config = loadConfigSafe(options.configPath);
  if (config === null) {
    return { ok: false, output: "Error: Could not load config. Run `ancilis init` or pass --config." };
  }

  const store = new EvidenceStore(config, options.dbPath ? { dbPath: options.dbPath } : undefined);
  try {
    const sessions = await store.listSessions();
    if (sessions.length === 0) {
      lines.push("No sessions recorded yet.");
    } else {
      lines.push(`${"SESSION ID".padEnd(40)}  ${"RECORDS".padStart(7)}  ${"FIRST SEEN".padEnd(24)}  ${"LAST SEEN".padEnd(24)}`);
      lines.push("-".repeat(100));
      for (const s of sessions) {
        lines.push(
          `${s.session_id.padEnd(40)}  ${String(s.count).padStart(7)}  ${s.first_seen.padEnd(24)}  ${s.last_seen.padEnd(24)}`,
        );
      }
    }
    return { ok: true, output: lines.join("\n") };
  } finally {
    await store.close();
  }
}

/** ancilis evidence reset */
export async function runEvidenceReset(options: {
  configPath?: string;
  dbPath?: string;
  yes?: boolean;
}, io: EvidenceIo): Promise<{ ok: boolean; output: string }> {
  const config = loadConfigSafe(options.configPath);
  if (config === null) {
    return { ok: false, output: "Error: Could not load config. Run `ancilis init` or pass --config." };
  }

  if (!options.yes) {
    const ask = io.prompt ?? defaultPrompt;
    const answer = await ask(
      "This will permanently delete ALL evidence records and restart the hash chain. Continue? [y/N] ",
    );
    if (answer.trim().toLowerCase() !== "y" && answer.trim().toLowerCase() !== "yes") {
      return { ok: false, output: "Aborted." };
    }
  }

  const store = new EvidenceStore(config, options.dbPath ? { dbPath: options.dbPath } : undefined);
  try {
    const n = await store.reset();
    return { ok: true, output: `Evidence store reset: ${n} record(s) deleted. Hash chain restarted from genesis.` };
  } finally {
    await store.close();
  }
}

function detectFormat(file: string): "sarif" | "cyclonedx" | null {
  const lower = file.toLowerCase();
  if (lower.endsWith(".sarif") || lower.endsWith(".sarif.json")) return "sarif";
  if (lower.endsWith(".cdx.json") || lower.endsWith(".bom.json") || lower.includes("cyclonedx") || lower.includes("sbom")) {
    return "cyclonedx";
  }
  // Sniff file content
  try {
    const sniff = JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>;
    if ("runs" in sniff) return "sarif";
    if ("bomFormat" in sniff || "components" in sniff) return "cyclonedx";
  } catch {
    // fall through
  }
  return null;
}

/** ancilis evidence import */
export async function runEvidenceImport(options: {
  file: string;
  format?: "sarif" | "cyclonedx" | "auto";
  configPath?: string;
  dbPath?: string;
  agentId?: string;
}, _io?: EvidenceIo): Promise<{ ok: boolean; output: string }> {
  if (!existsSync(options.file)) {
    return { ok: false, output: `Error: File not found: ${options.file}` };
  }

  const fmt = options.format === "auto" || !options.format ? null : options.format;
  const detectedFmt = fmt ?? detectFormat(options.file);
  if (detectedFmt === null) {
    return { ok: false, output: "Error: Cannot detect format. Use --format sarif|cyclonedx." };
  }

  const agentId = options.agentId ?? "import";
  let evaluations: ReturnType<SarifImporter["parse"]>;
  try {
    if (detectedFmt === "sarif") {
      evaluations = new SarifImporter(agentId).parse(options.file);
    } else {
      evaluations = new CycloneDxImporter(agentId).parse(options.file);
    }
  } catch (err: unknown) {
    return { ok: false, output: `Error parsing ${detectedFmt} file: ${(err as Error).message ?? String(err)}` };
  }

  const config = loadConfigSafe(options.configPath);
  if (config === null) {
    return { ok: false, output: "Error: Could not load config. Pass --config path/to/ancilis.yaml or run from a directory with ancilis.yaml." };
  }

  const store = new EvidenceStore(config, options.dbPath ? { dbPath: options.dbPath } : undefined);
  try {
    let stored = 0;
    for (const evaluation of evaluations) {
      await store.store(evaluation, options.file);
      stored++;
    }
    return { ok: true, output: `Imported ${stored} evidence record(s) from ${detectedFmt.toUpperCase()} file: ${options.file}` };
  } finally {
    await store.close();
  }
}

/** Top-level evidence subcommand dispatcher — returns exit code. */
export async function handleEvidence(
  args: string[],
  io: EvidenceIo,
): Promise<number> {
  const subcommand = args[0];

  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    print(io.stdout, [
      "Usage:",
      "  ancilis evidence sessions [--config <path>] [--db <path>]",
      "  ancilis evidence reset [--config <path>] [--db <path>] [--yes|-y]",
      "  ancilis evidence import <file> [--format sarif|cyclonedx|auto] [--config <path>] [--db <path>] [--agent-id <id>]",
    ].join("\n"));
    return 0;
  }

  const rest = args.slice(1);

  if (subcommand === "sessions") {
    let configPath: string | undefined;
    let dbPath: string | undefined;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === "--config") { configPath = rest[++i]; }
      else if (rest[i] === "--db") { dbPath = rest[++i]; }
      else { throw new Error(`Unknown option for evidence sessions: ${rest[i]}`); }
    }
    const result = await runEvidenceSessions({ configPath, dbPath }, io);
    print(result.ok ? io.stdout : io.stderr, result.output);
    return result.ok ? 0 : 1;
  }

  if (subcommand === "reset") {
    let configPath: string | undefined;
    let dbPath: string | undefined;
    let yes = false;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === "--config") { configPath = rest[++i]; }
      else if (rest[i] === "--db") { dbPath = rest[++i]; }
      else if (rest[i] === "--yes" || rest[i] === "-y") { yes = true; }
      else { throw new Error(`Unknown option for evidence reset: ${rest[i]}`); }
    }
    const result = await runEvidenceReset({ configPath, dbPath, yes }, io);
    print(result.ok ? io.stdout : io.stderr, result.output);
    return result.ok ? 0 : 1;
  }

  if (subcommand === "import") {
    if (rest.length === 0 || rest[0]?.startsWith("-")) {
      throw new Error("evidence import requires a FILE argument");
    }
    const file = rest[0]!;
    let format: "sarif" | "cyclonedx" | "auto" | undefined;
    let configPath: string | undefined;
    let dbPath: string | undefined;
    let agentId: string | undefined;
    for (let i = 1; i < rest.length; i++) {
      if (rest[i] === "--format") {
        const v = rest[++i];
        if (v !== "sarif" && v !== "cyclonedx" && v !== "auto") {
          throw new Error(`Unknown format: ${v}. Use sarif, cyclonedx, or auto.`);
        }
        format = v;
      } else if (rest[i] === "--config") { configPath = rest[++i]; }
      else if (rest[i] === "--db") { dbPath = rest[++i]; }
      else if (rest[i] === "--agent-id") { agentId = rest[++i]; }
      else { throw new Error(`Unknown option for evidence import: ${rest[i]}`); }
    }
    const result = await runEvidenceImport({ file, format, configPath, dbPath, agentId }, io);
    print(result.ok ? io.stdout : io.stderr, result.output);
    return result.ok ? 0 : 1;
  }

  throw new Error(`Unknown evidence subcommand: ${subcommand}`);
}
