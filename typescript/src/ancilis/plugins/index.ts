/** Plugin contracts and metadata-first discovery for TypeScript SDK extensions. */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { ActionProducer } from "../producers/protocol.js";
import { packageRootFrom } from "../shared-path.js";

export type PluginType = "producer" | "overlay" | "adapter";

export interface PluginMetadata {
  readonly name: string;
  readonly pluginType: PluginType;
  readonly version: string;
  readonly packageName: string;
  readonly packageVersion: string;
  readonly minSdkVersion: string;
  readonly maxSdkVersion?: string | null;
  readonly module: string;
  readonly exportName: string;
}

export interface PluginContext {
  readonly sdkVersion: string;
  readonly config: Readonly<Record<string, unknown>>;
}

export interface ProducerPlugin {
  readonly metadata: PluginMetadata;
  createProducer(context: PluginContext): ActionProducer;
}

export interface OverlayPlugin {
  readonly metadata: PluginMetadata;
  loadOverlayProfile(context: PluginContext): unknown;
}

export interface AdapterPlugin {
  readonly metadata: PluginMetadata;
  createAdapter(context: PluginContext): unknown;
}

export interface PluginRecord {
  readonly name: string;
  readonly pluginType: PluginType | "unknown";
  readonly packageName: string;
  readonly packageVersion: string;
  readonly packageDir: string;
  readonly metadata: PluginMetadata | null;
  readonly compatible: boolean;
  readonly plugin?: unknown;
  readonly skipReason?: string;
}

export interface PluginDiscoveryOptions {
  readonly rootDir?: string;
  readonly sdkVersion?: string;
  readonly packageOrPath?: string;
  readonly validateExports?: boolean;
}

interface PackageJson {
  readonly name?: unknown;
  readonly version?: unknown;
  readonly ancilis?: unknown;
}

interface RawPluginMetadata {
  readonly name?: unknown;
  readonly type?: unknown;
  readonly pluginType?: unknown;
  readonly version?: unknown;
  readonly minSdkVersion?: unknown;
  readonly maxSdkVersion?: unknown;
  readonly module?: unknown;
  readonly export?: unknown;
  readonly exportName?: unknown;
}

interface PackageCandidate {
  readonly packageJsonPath: string;
  readonly packageDir: string;
}

const PLUGIN_TYPES = new Set<PluginType>(["producer", "overlay", "adapter"]);

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf-8"));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function packageNameOf(pkg: PackageJson, fallback: string): string {
  return typeof pkg.name === "string" && pkg.name.length > 0 ? pkg.name : fallback;
}

function packageVersionOf(pkg: PackageJson): string {
  return typeof pkg.version === "string" && pkg.version.length > 0 ? pkg.version : "0.0.0";
}

function rawPluginsFrom(pkg: PackageJson): unknown[] {
  if (!isRecord(pkg.ancilis)) return [];
  const plugins = pkg.ancilis.plugins;
  if (Array.isArray(plugins)) {
    return plugins;
  }
  if (Object.hasOwn(pkg.ancilis, "plugin")) {
    return [pkg.ancilis.plugin];
  }
  return [];
}

function parseVersion(value: string): [number, number, number] | null {
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$/.exec(value);
  if (!match) return null;
  return [
    Number.parseInt(match[1]!, 10),
    Number.parseInt(match[2] ?? "0", 10),
    Number.parseInt(match[3] ?? "0", 10),
  ];
}

function compareVersions(left: string, right: string): number | null {
  const parsedLeft = parseVersion(left);
  const parsedRight = parseVersion(right);
  if (!parsedLeft || !parsedRight) return null;
  for (let index = 0; index < 3; index += 1) {
    const delta = parsedLeft[index]! - parsedRight[index]!;
    if (delta !== 0) return delta < 0 ? -1 : 1;
  }
  return 0;
}

function sdkVersionFromPackage(): string {
  try {
    const root = packageRootFrom(import.meta.url);
    const pkg = readJson(join(root, "package.json")) as PackageJson;
    return packageVersionOf(pkg);
  } catch {
    return "0.1.0";
  }
}

function normalizePluginMetadata(
  raw: RawPluginMetadata,
  packageName: string,
  packageVersion: string,
): PluginMetadata | null {
  const pluginType = raw.pluginType ?? raw.type;
  const exportName = raw.exportName ?? raw.export;
  if (
    typeof raw.name !== "string" ||
    raw.name.length === 0 ||
    typeof pluginType !== "string" ||
    !PLUGIN_TYPES.has(pluginType as PluginType) ||
    typeof raw.minSdkVersion !== "string" ||
    raw.minSdkVersion.length === 0 ||
    typeof raw.module !== "string" ||
    raw.module.length === 0 ||
    typeof exportName !== "string" ||
    exportName.length === 0
  ) {
    return null;
  }

  return {
    name: raw.name,
    pluginType: pluginType as PluginType,
    version: typeof raw.version === "string" && raw.version.length > 0 ? raw.version : packageVersion,
    packageName,
    packageVersion,
    minSdkVersion: raw.minSdkVersion,
    maxSdkVersion: typeof raw.maxSdkVersion === "string" && raw.maxSdkVersion.length > 0 ? raw.maxSdkVersion : null,
    module: raw.module,
    exportName,
  };
}

function compatibilitySkipReason(metadata: PluginMetadata, sdkVersion: string): string | undefined {
  const minCompare = compareVersions(sdkVersion, metadata.minSdkVersion);
  if (minCompare === null) {
    return `invalid SDK compatibility version: ${metadata.minSdkVersion}`;
  }
  if (minCompare < 0) {
    return `requires Ancilis SDK >=${metadata.minSdkVersion}`;
  }
  if (metadata.maxSdkVersion) {
    const maxCompare = compareVersions(sdkVersion, metadata.maxSdkVersion);
    if (maxCompare === null) {
      return `invalid SDK compatibility version: ${metadata.maxSdkVersion}`;
    }
    if (maxCompare > 0) {
      return `requires Ancilis SDK <=${metadata.maxSdkVersion}`;
    }
  }
  return undefined;
}

function resolvePackagePath(rootDir: string, packageOrPath: string): PackageCandidate | null {
  const explicitPath = isAbsolute(packageOrPath) ? packageOrPath : resolve(rootDir, packageOrPath);
  if (existsSync(explicitPath)) {
    const stats = statSync(explicitPath);
    const packageJsonPath = stats.isDirectory() ? join(explicitPath, "package.json") : explicitPath;
    if (existsSync(packageJsonPath)) {
      return { packageJsonPath, packageDir: dirname(packageJsonPath) };
    }
  }

  const packageJsonPath = join(rootDir, "node_modules", packageOrPath, "package.json");
  if (existsSync(packageJsonPath)) {
    return { packageJsonPath, packageDir: dirname(packageJsonPath) };
  }

  return null;
}

function discoverPackageCandidates(rootDir: string, packageOrPath?: string): PackageCandidate[] {
  if (packageOrPath) {
    const candidate = resolvePackagePath(rootDir, packageOrPath);
    return candidate ? [candidate] : [];
  }

  const candidates: PackageCandidate[] = [];
  const rootPackageJson = join(rootDir, "package.json");
  if (existsSync(rootPackageJson)) {
    candidates.push({ packageJsonPath: rootPackageJson, packageDir: rootDir });
  }

  const nodeModules = join(rootDir, "node_modules");
  if (!existsSync(nodeModules)) return candidates;

  for (const entry of readdirSync(nodeModules).sort()) {
    const entryPath = join(nodeModules, entry);
    if (entry.startsWith("ancilis-")) {
      const packageJsonPath = join(entryPath, "package.json");
      if (existsSync(packageJsonPath)) candidates.push({ packageJsonPath, packageDir: entryPath });
      continue;
    }

    if (entry.startsWith("@") && statSync(entryPath).isDirectory()) {
      for (const scopedEntry of readdirSync(entryPath).sort()) {
        if (!scopedEntry.startsWith("ancilis-")) continue;
        const packageDir = join(entryPath, scopedEntry);
        const packageJsonPath = join(packageDir, "package.json");
        if (existsSync(packageJsonPath)) candidates.push({ packageJsonPath, packageDir });
      }
    }
  }

  return candidates;
}

function moduleSpecifier(packageDir: string, metadata: PluginMetadata): string {
  if (metadata.module.startsWith(".") || metadata.module.startsWith("/")) {
    return pathToFileURL(resolve(packageDir, metadata.module)).href;
  }
  return metadata.module;
}

async function importPluginExport(
  packageDir: string,
  metadata: PluginMetadata,
): Promise<{ plugin?: unknown; skipReason?: string }> {
  try {
    const mod = await import(moduleSpecifier(packageDir, metadata));
    if (!(metadata.exportName in mod)) {
      return { skipReason: `missing plugin export: ${metadata.exportName}` };
    }
    return { plugin: mod[metadata.exportName] };
  } catch (error: unknown) {
    return { skipReason: `failed to load plugin module: ${(error as Error).message ?? String(error)}` };
  }
}

function fallbackPackageName(packageDir: string): string {
  return basename(packageDir) || "unknown";
}

function packageReadErrorRecord(candidate: PackageCandidate, error: unknown): PluginRecord {
  return {
    name: fallbackPackageName(candidate.packageDir),
    pluginType: "unknown",
    packageName: fallbackPackageName(candidate.packageDir),
    packageVersion: "0.0.0",
    packageDir: candidate.packageDir,
    metadata: null,
    compatible: false,
    skipReason: `failed to read package metadata: ${(error as Error).message ?? String(error)}`,
  };
}

function malformedRecord(packageName: string, packageVersion: string, packageDir: string, index: number): PluginRecord {
  return {
    name: `${packageName}#${index}`,
    pluginType: "unknown",
    packageName,
    packageVersion,
    packageDir,
    metadata: null,
    compatible: false,
    skipReason: "missing PluginMetadata",
  };
}

export class PluginRegistry {
  records: PluginRecord[];
  sdkVersion: string;

  constructor(records: PluginRecord[] = [], sdkVersion: string = sdkVersionFromPackage()) {
    this.records = records;
    this.sdkVersion = sdkVersion;
  }

  static async discover(options: PluginDiscoveryOptions = {}): Promise<PluginRegistry> {
    const registry = new PluginRegistry([], options.sdkVersion ?? sdkVersionFromPackage());
    return registry.refresh(options);
  }

  async refresh(options: PluginDiscoveryOptions = {}): Promise<PluginRegistry> {
    const rootDir = resolve(options.rootDir ?? process.cwd());
    const sdkVersion = options.sdkVersion ?? this.sdkVersion;
    const records: PluginRecord[] = [];

    for (const candidate of discoverPackageCandidates(rootDir, options.packageOrPath)) {
      let parsedPackage: unknown;
      try {
        parsedPackage = readJson(candidate.packageJsonPath);
      } catch (error: unknown) {
        records.push(packageReadErrorRecord(candidate, error));
        continue;
      }

      if (!isRecord(parsedPackage)) {
        records.push(packageReadErrorRecord(candidate, new Error("package.json must be an object")));
        continue;
      }

      const pkg = parsedPackage as PackageJson;
      const packageName = packageNameOf(pkg, fallbackPackageName(candidate.packageDir));
      const packageVersion = packageVersionOf(pkg);
      const rawPlugins = rawPluginsFrom(pkg);

      rawPlugins.forEach((raw, index) => {
        const metadata = isRecord(raw)
          ? normalizePluginMetadata(raw as RawPluginMetadata, packageName, packageVersion)
          : null;
        if (!metadata) {
          records.push(malformedRecord(packageName, packageVersion, candidate.packageDir, index));
          return;
        }

        const skipReason = compatibilitySkipReason(metadata, sdkVersion);
        records.push({
          name: metadata.name,
          pluginType: metadata.pluginType,
          packageName,
          packageVersion,
          packageDir: candidate.packageDir,
          metadata,
          compatible: skipReason === undefined,
          skipReason,
        });
      });
    }

    if (options.validateExports) {
      const validatedRecords: PluginRecord[] = [];
      for (const record of records) {
        if (!record.compatible || !record.metadata) {
          validatedRecords.push(record);
          continue;
        }
        const { plugin, skipReason: exportSkipReason } = await importPluginExport(record.packageDir, record.metadata);
        validatedRecords.push({
          ...record,
          plugin,
          compatible: exportSkipReason === undefined,
          skipReason: exportSkipReason,
        });
      }
      this.records = validatedRecords;
      this.sdkVersion = sdkVersion;
      return this;
    }

    this.records = records;
    this.sdkVersion = sdkVersion;
    return this;
  }

  compatible(pluginType?: PluginType): PluginRecord[] {
    return this.records.filter((record) => (
      record.compatible && (pluginType === undefined || record.pluginType === pluginType)
    ));
  }

  skipped(): PluginRecord[] {
    return this.records.filter((record) => !record.compatible);
  }

  warnings(): string[] {
    return this.skipped().map((record) => `${record.name}: ${record.skipReason ?? "skipped"}`);
  }

  async load(record: PluginRecord): Promise<unknown> {
    if (record.plugin !== undefined) return record.plugin;
    if (!record.compatible || !record.metadata) {
      throw new Error(record.skipReason ?? `Plugin '${record.name}' is not loadable.`);
    }

    const { plugin, skipReason } = await importPluginExport(record.packageDir, record.metadata);
    if (skipReason !== undefined) {
      throw new Error(skipReason);
    }

    this.records = this.records.map((candidate) => (
      candidate === record
        ? { ...candidate, plugin }
        : candidate
    ));
    return plugin;
  }
}
