/**
 * Microsoft Semantic Kernel framework producer (TypeScript parity with
 * `ancilis.producers.semantic_kernel`).
 *
 * SK's filter pipeline takes async callables of the shape
 * `(context, next) => next(context)`. This producer supplies factories that
 * observe each invocation as it passes through the pipeline.
 *
 * Note: Semantic Kernel's primary SDKs are .NET and Python. The TypeScript
 * port (`@semantic-kernel/typescript`) is in early access; this producer
 * targets the same filter shape so it works with either the official
 * TypeScript SDK or any community implementation that uses the same
 * (context, next) contract.
 */

import { createHash, randomUUID } from "node:crypto";
import type { ResolvedConfig } from "../config/index.js";
import type { Action } from "../engine/action.js";
import { Engine } from "../engine/engine.js";
import { ToolRegistry, ToolStatus } from "../engine/registry.js";
import type { ToolEntry } from "../engine/registry.js";
import type { EvaluationResult } from "../engine/result.js";
import { matchesToolList } from "../engine/tool-matching.js";
import { EvidenceStore } from "../evidence/store.js";
import { canonicalJsonStringify } from "../evidence/chain.js";
import { recordAdapterUsed } from "../telemetry/index.js";
import { ProducerType } from "./protocol.js";

const PROVIDER = "semantic-kernel";
const PRODUCER_VERSION = "0.1.0";

export type SemanticKernelEventKind =
  | "function_invocation"
  | "prompt_rendering"
  | "auto_function_invocation";

export interface SemanticKernelEvent {
  kind: SemanticKernelEventKind;
  functionName: string;
  pluginName: string;
  agentName: string;
  arguments?: unknown;
  metadata?: Record<string, unknown>;
}

export interface SemanticKernelObservation {
  action: Action;
  evaluation: EvaluationResult;
}

export type FilterFn = (context: unknown, next: (ctx: unknown) => Promise<unknown>) => Promise<unknown>;

function stringAttr(obj: unknown, attrs: readonly string[]): string | null {
  if (obj === null || obj === undefined || typeof obj !== "object") return null;
  const o = obj as Record<string, unknown>;
  for (const attr of attrs) {
    const v = o[attr];
    if (typeof v === "string" && v) return v;
  }
  return null;
}

export function _functionMetadata(context: unknown): { functionName: string; pluginName: string } {
  const fn = context && typeof context === "object" ? (context as Record<string, unknown>)["function"] : null;
  const functionName =
    stringAttr(context, ["function_name", "functionName"]) ??
    stringAttr(fn, ["name", "function_name", "functionName"]) ??
    "unknown-function";
  const pluginName =
    stringAttr(context, ["plugin_name", "pluginName"]) ??
    stringAttr(fn, ["plugin_name", "pluginName"]) ??
    "default";
  return { functionName, pluginName };
}

export function _argumentsValue(context: unknown): unknown {
  if (context === null || context === undefined || typeof context !== "object") return null;
  const args = (context as Record<string, unknown>)["arguments"];
  if (args === null || args === undefined) return null;
  if (
    typeof args === "string" ||
    typeof args === "number" ||
    typeof args === "boolean" ||
    Array.isArray(args)
  ) {
    return args;
  }
  if (typeof args === "object") {
    const o = args as Record<string, unknown>;
    for (const method of ["modelDump", "model_dump", "dict", "toDict", "to_dict"]) {
      const fn = o[method];
      if (typeof fn === "function") {
        try {
          return (fn as () => unknown).call(args);
        } catch {
          continue;
        }
      }
    }
    return args;
  }
  return String(args);
}

export class SemanticKernelActionProducer {
  protected _config: ResolvedConfig;
  protected _engine: Engine;
  protected _registry: ToolRegistry;
  protected _evidenceStore: EvidenceStore;
  private _sessionId: string = randomUUID();

  constructor(
    config: ResolvedConfig,
    engine: Engine,
    registry?: ToolRegistry,
    evidenceStore?: EvidenceStore,
  ) {
    this._config = config;
    this._engine = engine;
    this._registry = registry ?? engine.registry;
    this._evidenceStore = evidenceStore ?? new EvidenceStore(config);
    recordAdapterUsed(PROVIDER);
  }

  get config(): ResolvedConfig { return this._config; }
  get producerType(): ProducerType { return ProducerType.FRAMEWORK; }
  get producerVersion(): string { return PRODUCER_VERSION; }
  get sessionId(): string { return this._sessionId; }

  protected _toolName(event: SemanticKernelEvent): string {
    return `${PROVIDER}:${event.kind}:${event.pluginName}.${event.functionName}`;
  }

  protected _buildDcCodes(): string[] {
    const codes: string[] = [];
    for (const dcCodes of this._config.dataClassifications.values()) {
      for (const code of dcCodes) {
        if (!codes.includes(code)) codes.push(code);
      }
    }
    return codes;
  }

  translate(event: SemanticKernelEvent): Action {
    const payload: Record<string, unknown> = {
      provider: PROVIDER,
      kind: event.kind,
      function_name: event.functionName,
      plugin_name: event.pluginName,
      arguments: event.arguments ?? null,
      metadata: event.metadata ?? {},
    };
    const paramHash = createHash("sha256")
      .update(canonicalJsonStringify(payload))
      .digest("hex");
    const toolName = this._toolName(event);
    const entry = this._registry.lookup(toolName);
    const actionType =
      event.kind === "function_invocation" || event.kind === "auto_function_invocation"
        ? "tool_call"
        : "api_request";
    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: event.agentName,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType,
      tool: {
        name: toolName,
        server: PROVIDER,
        descriptionHash: entry?.descriptionHash ?? null,
      },
      parameters: { raw: payload, parameterHash: paramHash },
      context: {
        sessionId: this._sessionId,
        dataClassifications: this._buildDcCodes(),
        activeOverlays: [...this._config.activeOverlays.keys()],
      },
    };
  }

  computeToolHash(toolIdentifier: string): string {
    return createHash("sha256").update(toolIdentifier).digest("hex");
  }

  registerTools(registry: ToolRegistry): string[] {
    return registry.getAll().map((entry) => entry.name);
  }

  protected _ensureRegistered(event: SemanticKernelEvent): string {
    const name = this._toolName(event);
    if (!this._registry.lookup(name)) {
      const status = matchesToolList(name, this._config.toolsAllowed)
        ? ToolStatus.APPROVED
        : ToolStatus.OBSERVED;
      const now = new Date().toISOString();
      this._registry.register({
        name,
        descriptionHash: this.computeToolHash(name),
        status,
        approvedBy: status === ToolStatus.APPROVED ? "config" : null,
        firstSeen: now,
        statusChanged: now,
      } satisfies ToolEntry);
    }
    return name;
  }

  async observe(event: SemanticKernelEvent): Promise<SemanticKernelObservation> {
    const toolName = this._ensureRegistered(event);
    const action = this.translate(event);
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, toolName);
    return { action, evaluation };
  }

  protected _makeFilter(kind: SemanticKernelEventKind, agentName?: string): FilterFn {
    const agent = agentName ?? this._config.agentName;
    return async (context: unknown, next: (ctx: unknown) => Promise<unknown>): Promise<unknown> => {
      const { functionName, pluginName } = _functionMetadata(context);
      await this.observe({
        kind,
        functionName,
        pluginName,
        agentName: agent,
        arguments: _argumentsValue(context),
      });
      return next(context);
    };
  }

  functionInvocationFilter(agentName?: string): FilterFn {
    return this._makeFilter("function_invocation", agentName);
  }

  promptRenderingFilter(agentName?: string): FilterFn {
    return this._makeFilter("prompt_rendering", agentName);
  }

  autoFunctionInvocationFilter(agentName?: string): FilterFn {
    return this._makeFilter("auto_function_invocation", agentName);
  }
}
