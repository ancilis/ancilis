#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { approveTool, formatStatus, handlePlugins, handleScan, runDoctor, runReport, validateAndFormat } from "./ancilis/cli/index.js";
import { loadConfig } from "./ancilis/config/index.js";
import { EvidenceStore } from "./ancilis/evidence/store.js";
import { BaselineManager } from "./ancilis/baselines/index.js";
import type { EvidenceSummary } from "./ancilis/report/index.js";
import { packageRootFrom } from "./ancilis/shared-path.js";

interface CliIo {
  stdout(message: string): void;
  stderr(message: string): void;
}

const defaultIo: CliIo = {
  stdout: (message) => process.stdout.write(message),
  stderr: (message) => process.stderr.write(message),
};

function print(writer: (message: string) => void, message: string): void {
  writer(message.endsWith("\n") ? message : `${message}\n`);
}

function usage(): string {
  return [
    "Usage:",
    "  ancilis doctor [--config <path>] [--db <path>]",
    "  ancilis report [--period <window>] [--format <terminal|markdown|ndjson|csv|oscal-json|pdf|aiuc1-readiness>] [--config <path>] [--db <path>] [--output <path>]",
    "  ancilis report generate [--period <window>] [--format <terminal|markdown|ndjson|csv|oscal-json|pdf|aiuc1-readiness>] [--config <path>] [--db <path>] [--output <path>]",
    "  ancilis status [--verbose] [--config <path>] [--db <path>]",
    "  ancilis config validate [--config <path>]",
    "  ancilis approve-tool <tool-name> [--config <path>]",
    "  ancilis scan [--period <window>] [--ci] [--config <path>] [--db <path>]",
    "  ancilis baseline create --label <label> [--overlay <id>] [--window <hours>] [--config <path>] [--db <path>]",
    "  ancilis baseline list [--overlay <id>] [--config <path>] [--db <path>]",
    "  ancilis baseline drift [--id <baseline-id>] [--overlay <id>] [--format terminal|json] [--config <path>] [--db <path>]",
    "  ancilis evidence verify [--config <path>] [--db <path>] [--session-id <id>] [--json]",
    "  ancilis evidence sessions [--config <path>] [--db <path>]",
    "  ancilis evidence reset [--yes] [--config <path>] [--db <path>]",
    "  ancilis evidence import <file> [--format sarif|cyclonedx|auto] [--agent-id <id>] [--config <path>] [--db <path>]",
    "  ancilis plugins list [--type producer|overlay|adapter] [--root <path>]",
    "  ancilis plugins validate <package-or-path> [--root <path>]",
    "  ancilis init [--framework <name>] [--overlay <id>] [--agent-name <name>] [--dir <path>] [--detect] [--no-sample]",
    "  ancilis --version",
  ].join("\n");
}

function loadVersion(): string {
  try {
    const packageJson = JSON.parse(
      readFileSync(join(packageRootFrom(import.meta.url), "package.json"), "utf-8"),
    ) as { version?: string };
    return packageJson.version ?? "0.1.0";
  } catch {
    return "0.1.0";
  }
}

function readOption(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new Error(`Missing value for ${flag}`);
  }
  return value;
}

function mapSummary(summary: Record<string, unknown>): EvidenceSummary {
  return {
    total_evaluations: (summary.totalEvaluations as number | undefined) ?? 0,
    decisions: (summary.decisions as Record<string, number> | undefined) ?? {},
    tools_evaluated: (summary.toolsEvaluated as string[] | undefined) ?? [],
    control_pass_rates: (summary.controlPassRates as Record<string, Record<string, number>> | undefined) ?? {},
    chain_valid: (summary.chainValid as boolean | undefined) ?? true,
    chain_errors: (summary.chainErrors as string[] | undefined) ?? [],
  };
}

async function handleDoctor(args: string[], io: CliIo): Promise<number> {
  let configPath: string | undefined;
  let dbPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--config") {
      configPath = readOption(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--db") {
      dbPath = readOption(args, index, arg);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option for doctor: ${arg}`);
  }

  const result = await runDoctor(configPath, dbPath);
  print(result.ok ? io.stdout : io.stderr, result.output);
  return result.ok ? 0 : 1;
}

async function handleReport(args: string[], io: CliIo): Promise<number> {
  const normalizedArgs = args[0] === "generate" ? args.slice(1) : args;
  let period: string | undefined;
  let format: "terminal" | "markdown" | "ndjson" | "csv" | "oscal-json" | "pdf" | "aiuc1-readiness" | undefined;
  let configPath: string | undefined;
  let dbPath: string | undefined;
  let outputPath: string | undefined;

  for (let index = 0; index < normalizedArgs.length; index += 1) {
    const arg = normalizedArgs[index];
    if (arg === "--period") {
      period = readOption(normalizedArgs, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--format") {
      const value = readOption(normalizedArgs, index, arg);
      if (!["terminal", "markdown", "ndjson", "csv", "oscal-json", "pdf", "aiuc1-readiness"].includes(value)) {
        throw new Error(`Unsupported report format: ${value}`);
      }
      format = value as "terminal" | "markdown" | "ndjson" | "csv" | "oscal-json" | "pdf" | "aiuc1-readiness";
      index += 1;
      continue;
    }
    if (arg === "--config") {
      configPath = readOption(normalizedArgs, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--db") {
      dbPath = readOption(normalizedArgs, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--output" || arg === "-o") {
      outputPath = readOption(normalizedArgs, index, arg);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option for report: ${arg}`);
  }

  const result = await runReport({ period, format, configPath, dbPath, outputPath });
  print(result.ok ? io.stdout : io.stderr, result.output);
  return result.ok ? 0 : 1;
}

async function handleStatus(args: string[], io: CliIo): Promise<number> {
  let verbose = false;
  let configPath: string | undefined;
  let dbPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--verbose" || arg === "-v") {
      verbose = true;
      continue;
    }
    if (arg === "--config") {
      configPath = readOption(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--db") {
      dbPath = readOption(args, index, arg);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option for status: ${arg}`);
  }

  try {
    const config = loadConfig(configPath ? { path: configPath } : {});
    const store = new EvidenceStore(config, dbPath ? { dbPath } : undefined);
    try {
      const summary = await store.getSummary();
      print(io.stdout, formatStatus(config, mapSummary(summary), verbose));
      return 0;
    } finally {
      await store.close();
    }
  } catch (error: unknown) {
    print(io.stderr, `Error loading config: ${(error as Error).message ?? String(error)}`);
    return 1;
  }
}

function handleConfigValidate(args: string[], io: CliIo): number {
  let configPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--config") {
      configPath = readOption(args, index, arg);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option for config validate: ${arg}`);
  }

  const result = validateAndFormat(configPath);
  print(result.valid ? io.stdout : io.stderr, result.message);
  return result.valid ? 0 : 1;
}

function handleApproveTool(args: string[], io: CliIo): number {
  if (args.length === 0 || args[0] === "--config") {
    throw new Error("approve-tool requires a tool name");
  }

  const toolName = args[0]!;
  let configPath: string | undefined;

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--config") {
      configPath = readOption(args, index, arg);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option for approve-tool: ${arg}`);
  }

  const result = approveTool(toolName, configPath ?? "ancilis.yaml");
  print(result.success ? io.stdout : io.stderr, result.message);
  return result.success ? 0 : 1;
}

async function handleBaseline(args: string[], io: CliIo): Promise<number> {
  const subcommand = args[0];
  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    print(io.stdout, [
      "Usage:",
      "  ancilis baseline create --label <label> [--overlay <id>] [--window <hours>] [--config <path>] [--db <path>]",
      "  ancilis baseline list [--overlay <id>] [--config <path>] [--db <path>]",
      "  ancilis baseline drift [--id <baseline-id>] [--overlay <id>] [--format terminal|json] [--config <path>] [--db <path>]",
    ].join("\n"));
    return 0;
  }

  const rest = args.slice(1);
  let configPath: string | undefined;
  let dbPath: string | undefined;
  let overlayId: string | undefined;
  let label: string | undefined;
  let windowHours: number | undefined;
  let baselineId: string | undefined;
  let format: "terminal" | "json" = "terminal";

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === "--config") { configPath = readOption(rest, i, arg); i++; }
    else if (arg === "--db") { dbPath = readOption(rest, i, arg); i++; }
    else if (arg === "--overlay") { overlayId = readOption(rest, i, arg); i++; }
    else if (arg === "--label") { label = readOption(rest, i, arg); i++; }
    else if (arg === "--window") { windowHours = parseInt(readOption(rest, i, arg), 10); i++; }
    else if (arg === "--id") { baselineId = readOption(rest, i, arg); i++; }
    else if (arg === "--format") {
      const v = readOption(rest, i, arg);
      if (v !== "terminal" && v !== "json") throw new Error(`Unknown format: ${v}`);
      format = v;
      i++;
    } else {
      throw new Error(`Unknown option for baseline ${subcommand}: ${arg}`);
    }
  }

  const config = loadConfig(configPath ? { path: configPath } : {});
  const store = new EvidenceStore(config, dbPath ? { dbPath } : undefined);
  const manager = new BaselineManager(store, config);

  try {
    switch (subcommand) {
      case "create": {
        if (!label) throw new Error("--label is required for baseline create");
        const baseline = await manager.create({
          label,
          overlayId,
          evidenceWindowHours: windowHours,
        });
        print(io.stdout, `Baseline created: ${baseline.baselineId} (${baseline.label})\n  Controls captured: ${baseline.controlSnapshots.length}\n  Created: ${baseline.createdAt}`);
        return 0;
      }
      case "list": {
        const baselines = await manager.listBaselines(overlayId);
        if (baselines.length === 0) {
          print(io.stdout, "No baselines found.");
        } else {
          for (const b of baselines) {
            const status = b.isActive ? "active" : "inactive";
            print(io.stdout, `  ${b.baselineId}  ${b.label}  [${status}]  ${b.createdAt}`);
          }
        }
        return 0;
      }
      case "drift": {
        const report = await manager.checkDrift({ baselineId, overlayId });
        if (format === "json") {
          print(io.stdout, JSON.stringify(report, null, 2));
        } else {
          const lines = [
            `Drift Report — ${report.overallStatus}`,
            `  Baseline: ${report.baselineLabel} (${report.baselineId})`,
            `  Checked: ${report.checkedAt}`,
            `  Controls: ${report.summary.totalControls} total, ${report.summary.regressed} regressed, ${report.summary.degraded} degraded, ${report.summary.stable} stable`,
          ];
          for (const d of report.controlDrifts) {
            lines.push(`  [${d.severity}] ${d.controlId}: ${d.baselineResult} → ${d.currentResult} (pass rate ${(d.baselinePassRate * 100).toFixed(0)}% → ${(d.currentPassRate * 100).toFixed(0)}%)`);
          }
          print(io.stdout, lines.join("\n"));
        }
        return 0;
      }
      default:
        throw new Error(`Unknown baseline subcommand: ${subcommand}`);
    }
  } finally {
    await store.close();
  }
}

async function handleEvidence(args: string[], io: CliIo): Promise<number> {
  const subcommand = args[0];
  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    print(io.stdout, [
      "Usage:",
      "  ancilis evidence verify [--config <path>] [--db <path>] [--session-id <id>] [--json]",
      "  ancilis evidence sessions [--config <path>] [--db <path>]",
      "  ancilis evidence reset [--yes] [--config <path>] [--db <path>]",
      "  ancilis evidence import <file> [--format sarif|cyclonedx|auto] [--agent-id <id>] [--config <path>] [--db <path>]",
    ].join("\n"));
    return 0;
  }

  const rest = args.slice(1);
  let configPath: string | undefined;
  let dbPath: string | undefined;
  let yes = false;
  let fmt = "auto";
  let agentId = "import";
  let sessionId: string | undefined;
  let jsonOutput = false;
  let positional: string | undefined;

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (arg === "--config") { configPath = readOption(rest, i, arg); i++; }
    else if (arg === "--db") { dbPath = readOption(rest, i, arg); i++; }
    else if (arg === "--yes" || arg === "-y") { yes = true; }
    else if (arg === "--format") { fmt = readOption(rest, i, arg); i++; }
    else if (arg === "--agent-id") { agentId = readOption(rest, i, arg); i++; }
    else if (arg === "--session-id") { sessionId = readOption(rest, i, arg); i++; }
    else if (arg === "--json") { jsonOutput = true; }
    else if (!arg.startsWith("--")) { positional = arg; }
    else { throw new Error(`Unknown option for evidence ${subcommand}: ${arg}`); }
  }

  let config;
  try {
    config = loadConfig(configPath ? { path: configPath } : {});
  } catch (err: unknown) {
    print(io.stderr, `Error loading config: ${(err as Error).message ?? String(err)}\nTip: run from a directory with ancilis.yaml or pass --config`);
    return 1;
  }

  const store = new EvidenceStore(config, dbPath ? { dbPath } : undefined);
  try {
    switch (subcommand) {
      case "verify": {
        const scope = sessionId ? { sessionId } : undefined;
        const { valid, errors } = await store.verifyChain(scope);
        const recordCount = await store.count(scope);
        if (jsonOutput) {
          print(io.stdout, JSON.stringify({
            errors,
            record_count: recordCount,
            session_id: sessionId ?? null,
            valid,
          }));
        } else if (valid) {
          const scopeText = sessionId ? ` for session ${sessionId}` : "";
          print(io.stdout, `Evidence chain valid${scopeText}: ${recordCount} record(s) verified.`);
        } else {
          const scopeText = sessionId ? ` for session ${sessionId}` : "";
          print(io.stderr, [
            `Evidence chain broken${scopeText}: ${recordCount} record(s) checked.`,
            ...errors.map(error => `- ${error}`),
          ].join("\n"));
        }
        return valid ? 0 : 1;
      }
      case "sessions": {
        const sessions = await store.listSessions();
        if (sessions.length === 0) {
          print(io.stdout, "No sessions recorded yet.");
        } else {
          print(io.stdout, `${"SESSION ID".padEnd(40)}  ${"RECORDS".padStart(7)}  ${"FIRST SEEN".padEnd(24)}  LAST SEEN`);
          print(io.stdout, "-".repeat(100));
          for (const s of sessions) {
            print(io.stdout, `${s.session_id.padEnd(40)}  ${String(s.count).padStart(7)}  ${s.first_seen.padEnd(24)}  ${s.last_seen}`);
          }
        }
        return 0;
      }
      case "reset": {
        if (!yes) {
          print(io.stderr, "This will permanently delete ALL evidence records. Pass --yes to confirm.");
          return 1;
        }
        const n = await store.reset();
        print(io.stdout, `Evidence store reset: ${n} record(s) deleted. Hash chain restarted from genesis.`);
        return 0;
      }
      case "import": {
        if (!positional) {
          throw new Error("evidence import requires a file path argument");
        }
        const { SarifImporter } = await import("./ancilis/importers/sarif.js");
        const { CycloneDxImporter } = await import("./ancilis/importers/cyclonedx.js");
        const { readFileSync } = await import("node:fs");

        // Auto-detect format
        let resolvedFmt = fmt;
        if (resolvedFmt === "auto") {
          const lower = positional.toLowerCase();
          if (lower.endsWith(".sarif") || lower.endsWith(".sarif.json")) {
            resolvedFmt = "sarif";
          } else if (lower.endsWith(".cdx.json") || lower.endsWith(".bom.json") || lower.includes("cyclonedx") || lower.includes("sbom")) {
            resolvedFmt = "cyclonedx";
          } else {
            try {
              const sniff = JSON.parse(readFileSync(positional, "utf-8")) as Record<string, unknown>;
              if ("runs" in sniff) resolvedFmt = "sarif";
              else if ("bomFormat" in sniff || "components" in sniff) resolvedFmt = "cyclonedx";
              else { print(io.stderr, "Cannot detect format. Use --format sarif|cyclonedx."); return 1; }
            } catch (e: unknown) {
              print(io.stderr, `Error reading file: ${(e as Error).message ?? String(e)}`);
              return 1;
            }
          }
        }

        const importer = resolvedFmt === "sarif"
          ? new SarifImporter(agentId)
          : new CycloneDxImporter(agentId);
        const evaluations = importer.parse(positional);
        let stored = 0;
        for (const evaluation of evaluations) {
          await store.store(evaluation, positional);
          stored++;
        }
        print(io.stdout, `Imported ${stored} evidence record(s) from ${resolvedFmt.toUpperCase()} file: ${positional}`);
        return 0;
      }
      default:
        throw new Error(`Unknown evidence subcommand: ${subcommand}`);
    }
  } finally {
    await store.close();
  }
}

async function handleInit(args: string[], io: CliIo): Promise<number> {
  let framework: string | undefined;
  let overlay: string | undefined;
  let agentName: string | undefined;
  let targetDir = ".";
  let detect = false;
  let noSample = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--framework" || arg === "-f") { framework = readOption(args, i, arg); i++; }
    else if (arg === "--overlay" || arg === "-o") { overlay = readOption(args, i, arg); i++; }
    else if (arg === "--agent-name") { agentName = readOption(args, i, arg); i++; }
    else if (arg === "--dir") { targetDir = readOption(args, i, arg); i++; }
    else if (arg === "--detect") { detect = true; }
    else if (arg === "--no-sample") { noSample = true; }
    else if (arg === "--yes" || arg === "-y") { /* accept silently for non-interactive use */ }
    else { throw new Error(`Unknown option for init: ${arg}`); }
  }

  const { existsSync, writeFileSync, readFileSync } = await import("node:fs");
  const { join: pathJoin, resolve: pathResolve, basename: pathBasename } = await import("node:path");
  const target = pathResolve(targetDir);
  const configFile = pathJoin(target, "ancilis.yaml");

  if (existsSync(configFile)) {
    print(io.stderr, `ancilis.yaml already exists at ${configFile}. Remove it first or use --dir to target a different directory.`);
    return 1;
  }

  // Framework detection from dependency files
  if (!framework) {
    const frameworkPatterns: Record<string, RegExp> = {
      langchain: /langchain(?:-core|-community|-openai|-anthropic)?/i,
      crewai: /crewai/i,
      autogen: /(?:pyautogen|autogen)/i,
      openai: /openai/i,
    };
    const detectionOrder = ["langchain", "crewai", "autogen", "openai"];

    const filesToCheck = ["requirements.txt", "pyproject.toml", "package.json"];
    for (const file of filesToCheck) {
      const filePath = pathJoin(target, file);
      if (existsSync(filePath)) {
        const content = readFileSync(filePath, "utf-8");
        for (const fw of detectionOrder) {
          if (frameworkPatterns[fw]!.test(content)) {
            if (detect) {
              framework = fw;
            } else {
              print(io.stdout, `Detected framework: ${fw} (from ${file})`);
              framework = fw;
            }
            break;
          }
        }
        if (framework) break;
      }
    }
    if (!framework) {
      if (detect) {
        framework = "generic";
        print(io.stdout, "No framework detected — using generic.");
      } else {
        framework = "generic";
      }
    }
  }

  // Default overlay
  if (!overlay) overlay = "soc2";

  // Default agent name from directory name
  if (!agentName) {
    const rawName = pathBasename(target);
    agentName = rawName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "my-agent";
  }

  // Generate ancilis.yaml
  const lines: string[] = [
    "agent:",
    `  name: ${agentName}`,
    "",
    "security:",
    "  mode: audit",
    "",
    "compliance:",
    `  overlays: [${overlay}]`,
    "  evidence:",
    "    retention_days: 365",
  ];
  writeFileSync(configFile, lines.join("\n") + "\n", "utf-8");

  const created: string[] = ["ancilis.yaml"];

  // Generate sample script
  if (!noSample) {
    const sampleLines = [
      "# Ancilis sample — generated by ancilis init",
      "# Run this to see evidence generation in action.",
      "from ancilis.middleware import AncilisMiddleware",
      "from ancilis.config import load_config",
      "",
      `# Adjust path if ancilis.yaml is not in the current directory`,
      "config = load_config()",
      "# Wrap your MCP client with Ancilis middleware:",
      "# middleware = AncilisMiddleware(config)",
    ];
    writeFileSync(pathJoin(target, "ancilis_sample.py"), sampleLines.join("\n") + "\n", "utf-8");
    created.push("ancilis_sample.py");
  }

  // Update .gitignore
  const gitignorePath = pathJoin(target, ".gitignore");
  if (existsSync(gitignorePath)) {
    const content = readFileSync(gitignorePath, "utf-8");
    if (!content.includes(".ancilis/")) {
      const sep = content.endsWith("\n") ? "" : "\n";
      writeFileSync(gitignorePath, content + sep + ".ancilis/\n", "utf-8");
      created.push("updated .gitignore");
    }
  }

  // Generate .env.example
  const envExample = pathJoin(target, ".env.example");
  if (!existsSync(envExample)) {
    writeFileSync(
      envExample,
      "# Ancilis platform API key (optional for local-only scanning)\n# ANCILIS_API_KEY=your-api-key-here\n",
      "utf-8",
    );
    created.push(".env.example");
  }

  for (const f of created) {
    print(io.stdout, `✓ ${f}`);
  }
  print(io.stdout, [
    "",
    "Next steps:",
    "  1. Review ancilis.yaml and adjust settings",
    "  2. Run: ancilis doctor       — verify your setup",
    "  3. Run: ancilis scan          — run your first compliance scan",
  ].join("\n"));
  return 0;
}

export async function runCli(args: string[], io: CliIo = defaultIo): Promise<number> {
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    print(io.stdout, usage());
    return 0;
  }

  if (args.length === 1 && args[0] === "--version") {
    print(io.stdout, loadVersion());
    return 0;
  }

  const [command, ...rest] = args;

  try {
    switch (command) {
      case "doctor":
        return await handleDoctor(rest, io);
      case "report":
        return await handleReport(rest, io);
      case "status":
        return await handleStatus(rest, io);
      case "approve-tool":
        return handleApproveTool(rest, io);
      case "config":
        if (rest[0] !== "validate") {
          throw new Error(`Unknown config subcommand: ${rest[0] ?? "<missing>"}`);
        }
        return handleConfigValidate(rest.slice(1), io);
      case "baseline":
        return await handleBaseline(rest, io);
      case "evidence":
        return await handleEvidence(rest, io);
      case "plugins":
        return await handlePlugins(rest, io);
      case "init":
        return await handleInit(rest, io);
      case "scan": {
        const knownFlags = ["--ci", "--config", "--db", "--period", "--session", "--latest", "--all"];
        const unknown = rest.filter(a => a.startsWith("--") && !knownFlags.includes(a));
        if (unknown.length > 0) throw new Error(`Unknown scan flag: ${unknown[0]}`);
        const ci = rest.includes("--ci");
        const all = rest.includes("--all");
        const configIdx = rest.indexOf("--config");
        const dbIdx = rest.indexOf("--db");
        const periodIdx = rest.indexOf("--period");
        const sessionIdx = rest.indexOf("--session");
        return await handleScan({
          ci,
          all,
          config: configIdx !== -1 ? rest[configIdx + 1] : undefined,
          db: dbIdx !== -1 ? rest[dbIdx + 1] : undefined,
          period: periodIdx !== -1 ? rest[periodIdx + 1] : undefined,
          session: sessionIdx !== -1 ? rest[sessionIdx + 1] : undefined,
        }, io);
      }
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  } catch (error: unknown) {
    print(io.stderr, `${(error as Error).message ?? String(error)}\n\n${usage()}`);
    return 1;
  }
}

function isDirectCliExecution(): boolean {
  const invokedPath = process.argv[1];
  if (!invokedPath) {
    return false;
  }

  const entrypointPath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(invokedPath) === entrypointPath;
  } catch {
    return invokedPath === entrypointPath;
  }
}

if (isDirectCliExecution()) {
  const exitCode = await runCli(process.argv.slice(2));
  process.exitCode = exitCode;
}
