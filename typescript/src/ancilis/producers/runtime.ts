/** Runtime producer selection for built-in and plugin ActionProducer sources. */

import type { ResolvedConfig } from "../config/index.js";
import { Engine } from "../engine/engine.js";
import type { Action } from "../engine/action.js";
import { ToolRegistry } from "../engine/registry.js";
import { EvidenceStore } from "../evidence/store.js";
import { PluginRegistry, type PluginContext, type PluginRecord } from "../plugins/index.js";
import { CLIActionProducer } from "./cli.js";
import { HTTPActionProducer } from "./http.js";
import { MCPActionProducer } from "./mcp.js";
import type { ActionProducer } from "./protocol.js";
import { ToolActionProducer } from "./tool.js";

export const BUILTIN_PRODUCER_NAMES = ["tool", "mcp", "cli", "http"] as const;
const BUILTIN_PRODUCER_SET = new Set<string>(BUILTIN_PRODUCER_NAMES);

export interface RuntimeProducerSelection {
  readonly producers: Readonly<Record<string, ActionProducer>>;
  readonly warnings: readonly string[];
}

export interface ResolveRuntimeProducersOptions {
  readonly builtinNames?: Iterable<string>;
  readonly pluginNames?: Iterable<string>;
  readonly pluginConfigs?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly pluginRegistry?: PluginRegistry;
  readonly engine?: Engine;
  readonly registry?: ToolRegistry;
  readonly evidenceStore?: EvidenceStore;
  readonly rootDir?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isActionProducer(value: unknown): value is ActionProducer {
  return (
    isRecord(value)
    && typeof value.producerType === "string"
    && typeof value.producerVersion === "string"
    && typeof value.translate === "function"
    && typeof value.computeToolHash === "function"
    && typeof value.registerTools === "function"
  );
}

function isAction(value: unknown): value is Action {
  return (
    isRecord(value)
    && typeof value.actionId === "string"
    && typeof value.timestamp === "string"
    && typeof value.agentId === "string"
    && typeof value.actionType === "string"
    && isRecord(value.tool)
    && typeof value.tool.name === "string"
    && isRecord(value.parameters)
    && isRecord(value.parameters.raw)
    && typeof value.parameters.parameterHash === "string"
  );
}

function warn(warnings: string[], message: string): void {
  warnings.push(message);
}

function requestedPluginNames(selectors: Iterable<string>, warnings: string[]): string[] {
  const requested: string[] = [];
  for (const selector of selectors) {
    if (!selector.startsWith("plugin:")) {
      warn(warnings, `Plugin producer selector '${selector}' is not namespaced as plugin:<name>.`);
      continue;
    }
    const name = selector.split(":", 2)[1]?.trim() ?? "";
    if (name.length === 0) {
      warn(warnings, "Empty plugin producer selector was skipped.");
      continue;
    }
    if (!requested.includes(name)) requested.push(name);
  }
  return requested;
}

function buildBuiltinProducer(
  name: string,
  config: ResolvedConfig,
  engine: Engine,
  registry: ToolRegistry,
  evidenceStore?: EvidenceStore,
): ActionProducer {
  switch (name) {
    case "tool":
      return new ToolActionProducer(config, engine, registry, evidenceStore);
    case "mcp":
      return new MCPActionProducer(config, registry);
    case "cli":
      return new CLIActionProducer(config, engine, registry, evidenceStore);
    case "http":
      return new HTTPActionProducer(config, engine, registry, evidenceStore);
    default:
      throw new Error(`Unknown built-in producer '${name}'.`);
  }
}

async function loadProducerPlugin(
  registry: PluginRegistry,
  record: PluginRecord,
): Promise<unknown> {
  return record.plugin ?? registry.load(record);
}

export async function resolveRuntimeProducers(
  config: ResolvedConfig,
  options: ResolveRuntimeProducersOptions = {},
): Promise<RuntimeProducerSelection> {
  const warnings: string[] = [];
  const runtimeRegistry = options.registry ?? options.engine?.registry ?? new ToolRegistry();
  const runtimeEngine = options.engine ?? new Engine(config, { registry: runtimeRegistry });
  const builtinNames = options.builtinNames === undefined
    ? [...BUILTIN_PRODUCER_NAMES].sort()
    : [...options.builtinNames];
  const producers: Record<string, ActionProducer> = {};

  for (const name of builtinNames) {
    if (!BUILTIN_PRODUCER_SET.has(name)) {
      warn(warnings, `Unknown built-in producer '${name}' was skipped.`);
      continue;
    }
    producers[name] = buildBuiltinProducer(name, config, runtimeEngine, runtimeRegistry, options.evidenceStore);
  }

  const requestedPlugins = requestedPluginNames(options.pluginNames ?? [], warnings);
  if (requestedPlugins.length === 0) {
    return { producers, warnings };
  }

  const pluginRegistry = options.pluginRegistry ?? await PluginRegistry.discover({ rootDir: options.rootDir });
  const recordsByName = new Map(
    pluginRegistry.compatible("producer")
      .filter((record) => record.metadata !== null)
      .map((record) => [record.name, record] as const),
  );
  const pluginConfigs = options.pluginConfigs ?? {};

  for (const pluginName of requestedPlugins) {
    if (BUILTIN_PRODUCER_SET.has(pluginName)) {
      warn(warnings, `Plugin producer '${pluginName}' collides with built-in producer '${pluginName}' and was skipped.`);
      continue;
    }

    const record = recordsByName.get(pluginName);
    if (!record) {
      warn(warnings, `Plugin producer '${pluginName}' was not discovered or compatible.`);
      continue;
    }

    let loadedPlugin: unknown;
    try {
      loadedPlugin = await loadProducerPlugin(pluginRegistry, record);
    } catch (error: unknown) {
      warn(warnings, `Plugin producer '${pluginName}' was not discovered or compatible.`);
      continue;
    }

    if (!isRecord(loadedPlugin) || typeof loadedPlugin.createProducer !== "function") {
      warn(warnings, `Plugin producer '${pluginName}' did not return an ActionProducer and was skipped.`);
      continue;
    }

    const context: PluginContext = {
      sdkVersion: pluginRegistry.sdkVersion,
      config: pluginConfigs[pluginName] ?? {},
    };

    let producer: unknown;
    try {
      producer = loadedPlugin.createProducer(context);
    } catch (error: unknown) {
      warn(warnings, `failed to create plugin producer '${pluginName}': ${(error as Error).message ?? String(error)}`);
      continue;
    }

    if (!isActionProducer(producer)) {
      warn(warnings, `Plugin producer '${pluginName}' did not return an ActionProducer and was skipped.`);
      continue;
    }

    producers[`plugin:${pluginName}`] = producer;
  }

  return { producers, warnings };
}

export function translateRuntimeAction(producer: ActionProducer, rawInvocation: unknown): Action {
  const action = producer.translate(rawInvocation);
  if (!isAction(action)) {
    throw new TypeError(
      `Runtime producer ${producer.constructor?.name ?? "anonymous"} returned a non-Action result.`,
    );
  }
  return action;
}
