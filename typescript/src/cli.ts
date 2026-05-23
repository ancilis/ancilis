#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { approveTool, formatStatus, handleScan, runDoctor, runInit, runRemediate, runReport, validateAndFormat } from "./ancilis/cli/index.js";
import { loadConfig } from "./ancilis/config/index.js";
import { EvidenceStore } from "./ancilis/evidence/store.js";
import { BaselineManager } from "./ancilis/baselines/index.js";
import type { EvidenceSummary } from "./ancilis/report/index.js";
import { packageRootFrom } from "./ancilis/shared-path.js";
import {
  bucketDuration,
  flushTelemetryEvents,
  formatTelemetryStatus,
  maybePromptForTelemetryConsent,
  readTelemetryStatus,
  recordTelemetryEvent,
  setTelemetryEnabled,
} from "./ancilis/telemetry/index.js";

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
    "  ancilis remediate [--period <window>] [--control <id>] [--config <path>] [--db <path>]",
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
    "  ancilis telemetry status",
    "  ancilis telemetry on|off|flush",
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

async function handleRemediate(args: string[], io: CliIo): Promise<number> {
  let period: string | undefined;
  let configPath: string | undefined;
  let dbPath: string | undefined;
  let sessionId: string | undefined;
  let latest = true;
  let controlId: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--period") {
      period = readOption(args, index, arg);
      index += 1;
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
    if (arg === "--session") {
      sessionId = readOption(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--latest") {
      latest = true;
      continue;
    }
    if (arg === "--all") {
      latest = false;
      continue;
    }
    if (arg === "--control") {
      controlId = readOption(args, index, arg);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option for remediate: ${arg}`);
  }

  const result = await runRemediate({ period, configPath, dbPath, sessionId, latest, controlId });
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

async function handleTelemetry(args: string[], io: CliIo): Promise<number> {
  const subcommand = args[0] ?? "status";
  if (args.length > 1) {
    throw new Error(`Unknown option for telemetry ${subcommand}: ${args[1]}`);
  }

  if (subcommand === "status") {
    print(io.stdout, formatTelemetryStatus(readTelemetryStatus()));
    return 0;
  }
  if (subcommand === "on") {
    setTelemetryEnabled(true);
    print(io.stdout, "Telemetry enabled. Anonymous usage events may be queued and sent at most once per hour.");
    return 0;
  }
  if (subcommand === "off") {
    setTelemetryEnabled(false);
    print(io.stdout, "Telemetry disabled. No new telemetry events will be queued or sent.");
    return 0;
  }
  if (subcommand === "flush") {
    const result = await flushTelemetryEvents({ force: true });
    print(io.stdout, result.sent ? `Flushed ${result.count} telemetry event(s).` : "No telemetry events flushed.");
    return 0;
  }
  throw new Error(`Unknown telemetry subcommand: ${subcommand}`);
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

  const result = await runInit(
    { framework, overlay, agentName, detect, noSample, dir: targetDir },
    io,
  );
  if (!result.ok && result.output) {
    print(io.stderr, result.output);
  }
  return result.ok ? 0 : 1;
}

async function dispatchCliCommand(command: string | undefined, rest: string[], io: CliIo): Promise<number> {
  switch (command) {
    case "doctor":
      return await handleDoctor(rest, io);
    case "report":
      return await handleReport(rest, io);
    case "remediate":
      return await handleRemediate(rest, io);
    case "status":
      return await handleStatus(rest, io);
    case "approve-tool":
      return handleApproveTool(rest, io);
    case "config":
      if (rest[0] !== "validate") {
        throw new Error(`Unknown config subcommand: ${rest[0] ?? "<missing>"}`);
      }
      return handleConfigValidate(rest.slice(1), io);
    case "telemetry":
      return await handleTelemetry(rest, io);
    case "baseline":
      return await handleBaseline(rest, io);
    case "evidence":
      return await handleEvidence(rest, io);
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
  const startedAt = Date.now();
  let exitCode = 0;

  if (command !== "telemetry") {
    await maybePromptForTelemetryConsent().catch(() => {});
  }

  try {
    exitCode = await dispatchCliCommand(command, rest, io);
    return exitCode;
  } catch (error: unknown) {
    print(io.stderr, `${(error as Error).message ?? String(error)}\n\n${usage()}`);
    exitCode = 1;
    return 1;
  } finally {
    if (command !== "telemetry") {
      await recordTelemetryEvent("cli_command", {
        command: command ?? "unknown",
        exit_code: exitCode,
        duration_bucket: bucketDuration(Date.now() - startedAt),
        ci: Boolean(process.env.CI),
      }).catch(() => {});
    }
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
