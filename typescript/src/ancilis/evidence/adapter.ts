/** Plugin evidence adapter contracts and explicit runtime selection. */

import type { ResolvedConfig } from "../config/index.js";
import type { EvidenceRecord } from "./record.js";
import { PluginRegistry, type PluginContext, type PluginRecord } from "../plugins/index.js";

export interface EvidenceAdapterPayload {
  readonly record: EvidenceRecord;
  readonly adapterMetadata: Readonly<Record<string, unknown>>;
}

export interface EvidenceAdapterQuery {
  readonly agentId?: string | null;
  readonly sessionId?: string | null;
  readonly toolName?: string | null;
  readonly decision?: string | null;
  readonly since?: string | null;
  readonly limit?: number | null;
}

export interface EvidenceAdapterExport {
  readonly format?: string;
  readonly query?: EvidenceAdapterQuery;
}

export interface EvidenceAdapter {
  store(payload: EvidenceAdapterPayload): unknown;
  query(query?: EvidenceAdapterQuery): unknown;
  export(exportRequest?: EvidenceAdapterExport): unknown;
}

export interface EvidenceAdapterSelection {
  readonly adapter: EvidenceAdapter | null;
  readonly warnings: readonly string[];
}

export interface ResolveEvidenceAdapterOptions {
  readonly pluginName?: string | null;
  readonly pluginConfigs?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly pluginRegistry?: PluginRegistry;
  readonly rootDir?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isEvidenceAdapter(value: unknown): value is EvidenceAdapter {
  return (
    isRecord(value)
    && typeof value.store === "function"
    && typeof value.query === "function"
    && typeof value.export === "function"
  );
}

function warn(warnings: string[], message: string): void {
  warnings.push(message);
}

function requestedAdapterName(pluginName: string | null | undefined, warnings: string[]): string | null {
  if (pluginName === undefined || pluginName === null) return null;
  if (!pluginName.startsWith("plugin:")) {
    warn(warnings, `Plugin evidence adapter selector '${pluginName}' is not namespaced as plugin:<name>.`);
    return null;
  }
  const name = pluginName.split(":", 2)[1]?.trim() ?? "";
  if (name.length === 0) {
    warn(warnings, "Empty plugin evidence adapter selector was skipped.");
    return null;
  }
  return name;
}

async function loadAdapterPlugin(
  registry: PluginRegistry,
  record: PluginRecord,
): Promise<unknown> {
  return record.plugin ?? registry.load(record);
}

export async function resolveEvidenceAdapter(
  config: ResolvedConfig,
  options: ResolveEvidenceAdapterOptions = {},
): Promise<EvidenceAdapterSelection> {
  void config;
  const warnings: string[] = [];
  const adapterName = requestedAdapterName(options.pluginName, warnings);
  if (adapterName === null) {
    return { adapter: null, warnings };
  }

  const pluginRegistry = options.pluginRegistry ?? await PluginRegistry.discover({ rootDir: options.rootDir });
  const record = pluginRegistry
    .compatible("adapter")
    .find((candidate) => candidate.name === adapterName && candidate.metadata !== null);
  if (!record) {
    warn(warnings, `Plugin evidence adapter '${adapterName}' was not discovered or compatible.`);
    return { adapter: null, warnings };
  }

  let loadedPlugin: unknown;
  try {
    loadedPlugin = await loadAdapterPlugin(pluginRegistry, record);
  } catch {
    warn(warnings, `Plugin evidence adapter '${adapterName}' was not discovered or compatible.`);
    return { adapter: null, warnings };
  }

  if (!isRecord(loadedPlugin) || typeof loadedPlugin.createAdapter !== "function") {
    warn(warnings, `Plugin evidence adapter '${adapterName}' did not expose store(), query(), and export().`);
    return { adapter: null, warnings };
  }

  const context: PluginContext = {
    sdkVersion: pluginRegistry.sdkVersion,
    config: options.pluginConfigs?.[adapterName] ?? {},
  };

  let adapter: unknown;
  try {
    adapter = loadedPlugin.createAdapter(context);
  } catch (error: unknown) {
    warn(warnings, `failed to create plugin evidence adapter '${adapterName}': ${(error as Error).message ?? String(error)}`);
    return { adapter: null, warnings };
  }

  if (!isEvidenceAdapter(adapter)) {
    warn(warnings, `Plugin evidence adapter '${adapterName}' did not expose store(), query(), and export().`);
    return { adapter: null, warnings };
  }

  return { adapter, warnings };
}
