/** Ergonomic SDK facade for common runtime enforcement flows. */

import { existsSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "./config/index.js";
import type { LoadConfigOptions, ResolvedConfig } from "./config/index.js";
import type { Action } from "./engine/action.js";
import { Engine } from "./engine/engine.js";
import type { ToolRegistry } from "./engine/registry.js";
import type { EvaluationResult } from "./engine/result.js";
import { EvidenceStore } from "./evidence/store.js";
import { ToolActionProducer } from "./producers/tool.js";
import type { AnyFn } from "./producers/tool.js";

export interface AncilisLoadOptions extends LoadConfigOptions {
  engine?: Engine;
  registry?: ToolRegistry;
  evidenceStore?: EvidenceStore;
  evidence?: {
    dbPath?: string;
    inMemory?: boolean;
    tenantId?: string;
  };
}

export interface AncilisToolOptions {
  agentName?: string;
  toolName?: string;
}

export interface AncilisToolRun<Args extends unknown[] = unknown[], Return = unknown> {
  readonly toolName: string | undefined;
  call(...args: Args): Promise<Awaited<Return>>;
  evaluate(...args: Args): Promise<[Action, EvaluationResult]>;
}

type FacadeToolFn<Args extends unknown[], Return> = (...args: Args) => Return | Promise<Return>;

class ToolRun<Args extends unknown[], Return> implements AncilisToolRun<Args, Return> {
  constructor(
    private readonly producer: ToolActionProducer,
    private readonly fn: FacadeToolFn<Args, Return>,
    private readonly agentName: string,
    readonly toolName: string | undefined,
  ) {}

  async call(...args: Args): Promise<Awaited<Return>> {
    const result = await this.producer.execute(
      this.fn as unknown as (...args: unknown[]) => Return | Promise<Return>,
      this.agentName,
      args,
      undefined,
      this.toolName,
    );
    return result.returnValue;
  }

  async evaluate(...args: Args): Promise<[Action, EvaluationResult]> {
    return this.producer.evaluate(
      this.fn as unknown as AnyFn,
      this.agentName,
      args,
      undefined,
      this.toolName,
    );
  }
}

function resolveFacadeConfig(options: AncilisLoadOptions): ResolvedConfig {
  if (options.raw !== undefined || options.path !== undefined) {
    return loadConfig({ raw: options.raw, path: options.path });
  }

  const defaultPath = join(process.cwd(), "ancilis.yaml");
  if (existsSync(defaultPath)) {
    return loadConfig({ path: defaultPath });
  }

  return loadConfig({ raw: { agent: { name: "ancilis-agent" } } });
}

export class Ancilis {
  readonly config: ResolvedConfig;
  readonly engine: Engine;
  readonly registry: ToolRegistry;
  readonly evidenceStore: EvidenceStore;
  readonly toolProducer: ToolActionProducer;

  private constructor(
    config: ResolvedConfig,
    engine: Engine,
    registry: ToolRegistry,
    evidenceStore: EvidenceStore,
    toolProducer: ToolActionProducer,
  ) {
    this.config = config;
    this.engine = engine;
    this.registry = registry;
    this.evidenceStore = evidenceStore;
    this.toolProducer = toolProducer;
  }

  static load(options: AncilisLoadOptions = {}): Ancilis {
    const config = resolveFacadeConfig(options);
    const engine = options.engine ?? new Engine(config, { registry: options.registry });
    const registry = options.engine ? engine.registry : (options.registry ?? engine.registry);
    const evidenceStore = options.evidenceStore ?? new EvidenceStore(config, options.evidence);
    const toolProducer = new ToolActionProducer(config, engine, registry, evidenceStore);
    return new Ancilis(config, engine, registry, evidenceStore, toolProducer);
  }

  tool<Args extends unknown[], Return>(
    fn: FacadeToolFn<Args, Return>,
    options: AncilisToolOptions = {},
  ): AncilisToolRun<Args, Return> {
    return new ToolRun(this.toolProducer, fn, options.agentName ?? this.config.agentName, options.toolName);
  }
}
