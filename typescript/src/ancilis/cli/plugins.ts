/** `ancilis plugins` CLI commands. */

import { PluginRegistry } from "../plugins/index.js";
import type { PluginRecord, PluginType } from "../plugins/index.js";

interface CliIo {
  stdout(message: string): void;
  stderr(message: string): void;
}

export interface PluginsListOptions {
  readonly rootDir?: string;
  readonly pluginType?: PluginType;
}

export interface PluginsValidateOptions {
  readonly rootDir?: string;
  readonly packageOrPath: string;
}

export interface PluginsCommandResult {
  readonly ok: boolean;
  readonly output: string;
}

const PLUGIN_TYPES = new Set<PluginType>(["producer", "overlay", "adapter"]);

function readOption(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new Error(`Missing value for ${flag}`);
  }
  return value;
}

function pluginsUsage(): string {
  return [
    "Usage:",
    "  ancilis plugins list [--type producer|overlay|adapter] [--root <path>]",
    "  ancilis plugins validate <package-or-path> [--root <path>]",
  ].join("\n");
}

function recordStatus(record: PluginRecord): string {
  return record.compatible ? "compatible" : `skipped: ${record.skipReason ?? "skipped"}`;
}

function renderRecords(records: PluginRecord[]): string {
  if (records.length === 0) {
    return "No Ancilis plugins discovered.";
  }

  const lines = [
    `${"TYPE".padEnd(9)} ${"NAME".padEnd(25)} ${"PACKAGE".padEnd(25)} ${"VERSION".padEnd(10)} STATUS`,
    "-".repeat(90),
  ];
  for (const record of records) {
    lines.push([
      record.pluginType.padEnd(9),
      record.name.padEnd(25),
      record.packageName.padEnd(25),
      record.packageVersion.padEnd(10),
      recordStatus(record),
    ].join(" "));
  }
  return lines.join("\n");
}

export async function runPluginsList(options: PluginsListOptions = {}): Promise<PluginsCommandResult> {
  const registry = await PluginRegistry.discover({ rootDir: options.rootDir });
  const records = options.pluginType
    ? registry.records.filter((record) => record.pluginType === options.pluginType)
    : registry.records;
  return { ok: true, output: renderRecords(records) };
}

export async function runPluginsValidate(options: PluginsValidateOptions): Promise<PluginsCommandResult> {
  const registry = await PluginRegistry.discover({
    rootDir: options.rootDir,
    packageOrPath: options.packageOrPath,
    validateExports: true,
  });

  if (registry.records.length === 0) {
    return {
      ok: false,
      output: `No Ancilis plugin entry points found for ${options.packageOrPath}.`,
    };
  }

  const skipped = registry.skipped();
  if (skipped.length > 0) {
    return { ok: false, output: renderRecords(registry.records) };
  }

  return {
    ok: true,
    output: `Validated ${registry.records.length} Ancilis plugin entry point(s).`,
  };
}

export async function handlePlugins(args: string[], io: CliIo): Promise<number> {
  const subcommand = args[0];
  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    io.stdout(`${pluginsUsage()}\n`);
    return 0;
  }

  const rest = args.slice(1);
  let rootDir: string | undefined;

  if (subcommand === "list") {
    let pluginType: PluginType | undefined;
    for (let index = 0; index < rest.length; index += 1) {
      const arg = rest[index]!;
      if (arg === "--root") {
        rootDir = readOption(rest, index, arg);
        index += 1;
        continue;
      }
      if (arg === "--type") {
        const value = readOption(rest, index, arg);
        if (!PLUGIN_TYPES.has(value as PluginType)) {
          throw new Error(`Unsupported plugin type: ${value}`);
        }
        pluginType = value as PluginType;
        index += 1;
        continue;
      }
      throw new Error(`Unknown option for plugins list: ${arg}`);
    }

    const result = await runPluginsList({ rootDir, pluginType });
    io.stdout(`${result.output}\n`);
    return 0;
  }

  if (subcommand === "validate") {
    let packageOrPath: string | undefined;
    for (let index = 0; index < rest.length; index += 1) {
      const arg = rest[index]!;
      if (arg === "--root") {
        rootDir = readOption(rest, index, arg);
        index += 1;
        continue;
      }
      if (arg.startsWith("-")) {
        throw new Error(`Unknown option for plugins validate: ${arg}`);
      }
      if (packageOrPath !== undefined) {
        throw new Error(`Unexpected argument for plugins validate: ${arg}`);
      }
      packageOrPath = arg;
    }

    if (!packageOrPath) {
      throw new Error("plugins validate requires a package name or path");
    }

    const result = await runPluginsValidate({ rootDir, packageOrPath });
    if (result.ok) {
      io.stdout(`${result.output}\n`);
      return 0;
    }
    io.stderr(`${result.output}\n`);
    return 1;
  }

  throw new Error(`Unknown plugins subcommand: ${subcommand}`);
}
