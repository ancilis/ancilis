#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { approveTool, formatStatus, handleEvidence, handleScan, runDoctor, runReport, validateAndFormat, WatchRunner, runConnect } from "./ancilis/cli/index.js";
import { loadConfig } from "./ancilis/config/index.js";
import { EvidenceStore } from "./ancilis/evidence/store.js";
import { BaselineManager } from "./ancilis/baselines/index.js";
import type { EvidenceSummary } from "./ancilis/report/index.js";
import { parsePeriod as parsePeriodMs } from "./ancilis/report/generator.js";
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
    "  ancilis scan [--period <window>] [--ci] [--config <path>] [--db <path>] [--watch] [--debounce <seconds>] [--clear] [--producers <list>]",
    "  ancilis baseline create --label <label> [--overlay <id>] [--window <hours>] [--config <path>] [--db <path>]",
    "  ancilis baseline list [--overlay <id>] [--config <path>] [--db <path>]",
    "  ancilis baseline drift [--id <baseline-id>] [--overlay <id>] [--format terminal|json] [--config <path>] [--db <path>]",
    "  ancilis evidence sessions [--config <path>] [--db <path>]",
    "  ancilis evidence reset [--config <path>] [--db <path>] [--yes]",
    "  ancilis evidence import <file> [--format sarif|cyclonedx|auto] [--config <path>] [--db <path>] [--agent-id <id>]",
    "  ancilis connect",
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
      case "connect": {
        const result = await runConnect(rest, io);
        return result.ok ? 0 : 1;
      }
      case "scan": {
        const knownFlags = ["--ci", "--config", "--db", "--period", "--session", "--latest", "--all", "--watch", "--debounce", "--clear", "--producers"];
        const unknown = rest.filter(a => a.startsWith("--") && !knownFlags.includes(a));
        if (unknown.length > 0) throw new Error(`Unknown scan flag: ${unknown[0]}`);
        const ci = rest.includes("--ci");
        const watch = rest.includes("--watch");
        const clear = rest.includes("--clear");
        const configIdx = rest.indexOf("--config");
        const dbIdx = rest.indexOf("--db");
        const periodIdx = rest.indexOf("--period");
        const debounceIdx = rest.indexOf("--debounce");
        const producersIdx = rest.indexOf("--producers");

        if (watch) {
          const configPath = configIdx !== -1 ? rest[configIdx + 1] : undefined;
          const config = loadConfig(configPath !== undefined ? { path: configPath } : {});
          const debounce = debounceIdx !== -1 ? parseFloat(rest[debounceIdx + 1] ?? "2") : 2;
          const producers = producersIdx !== -1 ? (rest[producersIdx + 1] ?? "").split(",").filter(Boolean) : undefined;
          const period = periodIdx !== -1 ? (rest[periodIdx + 1] ?? "24h") : "24h";
          const since = new Date(Date.now() - parsePeriodMs(period)).toISOString();
          const runner = new WatchRunner({
            config,
            dbPath: dbIdx !== -1 ? rest[dbIdx + 1] : undefined,
            debounce,
            clear,
            watchDir: process.cwd(),
            producers,
            since,
          });
          await runner.run();
          return 0;
        }

        return await handleScan({
          ci,
          config: configIdx !== -1 ? rest[configIdx + 1] : undefined,
          db: dbIdx !== -1 ? rest[dbIdx + 1] : undefined,
          period: periodIdx !== -1 ? rest[periodIdx + 1] : undefined,
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
