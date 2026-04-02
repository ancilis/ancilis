#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { approveTool, formatStatus, runDoctor, runReport, validateAndFormat } from "./ancilis/cli/index.js";
import { loadConfig } from "./ancilis/config/index.js";
import { EvidenceStore } from "./ancilis/evidence/store.js";
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
    "  ancilis report [--period <window>] [--format <terminal|markdown|pdf|aiuc1-readiness>] [--config <path>] [--db <path>] [--output <path>]",
    "  ancilis status [--verbose] [--config <path>] [--db <path>]",
    "  ancilis config validate [--config <path>]",
    "  ancilis approve-tool <tool-name> [--config <path>]",
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
  let period: string | undefined;
  let format: "terminal" | "markdown" | "pdf" | "aiuc1-readiness" | undefined;
  let configPath: string | undefined;
  let dbPath: string | undefined;
  let outputPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--period") {
      period = readOption(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--format") {
      const value = readOption(args, index, arg);
      if (!["terminal", "markdown", "pdf", "aiuc1-readiness"].includes(value)) {
        throw new Error(`Unsupported report format: ${value}`);
      }
      format = value as "terminal" | "markdown" | "pdf" | "aiuc1-readiness";
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
    if (arg === "--output" || arg === "-o") {
      outputPath = readOption(args, index, arg);
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
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  } catch (error: unknown) {
    print(io.stderr, `${(error as Error).message ?? String(error)}\n\n${usage()}`);
    return 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const exitCode = await runCli(process.argv.slice(2));
  process.exitCode = exitCode;
}
