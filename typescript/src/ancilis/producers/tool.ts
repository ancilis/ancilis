/** ToolActionProducer — wraps Python functions/tools for security evaluation. */

import { createHash, randomUUID } from "node:crypto";
import type { ResolvedConfig } from "../config/index.js";
import type { Action } from "../engine/action.js";
import { Engine } from "../engine/engine.js";
import { ToolRegistry, ToolStatus } from "../engine/registry.js";
import type { ToolEntry } from "../engine/registry.js";
import type { EvaluationResult } from "../engine/result.js";
import { EvidenceStore } from "../evidence/store.js";
import { canonicalJsonStringify } from "../evidence/chain.js";
import { matchesToolList } from "../engine/tool-matching.js";
import { ProducerType } from "./protocol.js";

export type AnyFn = (...args: unknown[]) => unknown;

export interface ToolInvocation {
  fn: AnyFn;
  agentName: string;
  args?: unknown[];
  kwargs?: Record<string, unknown>;
  toolName?: string;
}

export interface ToolExecutionResult<R = unknown> {
  action: Action;
  evaluation: EvaluationResult;
  blocked: boolean;
  returnValue: R;
}

export interface ToolWrapOptions {
  producer: ToolActionProducer;
  agentName?: string;
  toolName?: string;
}

export interface EvaluateAndExecuteOptions {
  producer: ToolActionProducer;
  agentName: string;
  args?: unknown[];
  kwargs?: Record<string, unknown>;
  toolName?: string;
}

export class BlockedActionError extends Error {
  toolName: string;
  evaluation: EvaluationResult;
  displayMessage: string;

  constructor(toolName: string, evaluation: EvaluationResult) {
    const failed = evaluation.controlResults
      .filter(r => r.result === "FAIL" || r.result === "ERROR")
      .map(r => (r.displayName ?? r.controlName).toLowerCase());
    const reasonStr = failed.length > 0 ? failed.join(", ") : "policy violation";
    const msg =
      `Ancilis [blocked]: Action '${toolName}' blocked — ${reasonStr}.\n` +
      `  To approve: ancilis approve-tool ${toolName}\n` +
      `  To review: ancilis status`;
    super(msg);
    this.name = "BlockedActionError";
    this.toolName = toolName;
    this.evaluation = evaluation;
    this.displayMessage = msg;
  }
}

export class ToolActionProducer {
  private _config: ResolvedConfig;
  private _engine: Engine;
  private _registry: ToolRegistry;
  private _evidenceStore: EvidenceStore;
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
  }

  get producerType(): ProducerType { return ProducerType.FRAMEWORK; }
  get producerVersion(): string { return "0.1.0"; }
  /** Unique identifier for this producer instance (one per agent run). */
  get sessionId(): string { return this._sessionId; }

  private _qualifiedName(fn: AnyFn, toolName?: string): string {
    if (toolName) return toolName;
    const name = (fn as { name?: string }).name ?? "tool";
    return `tool:${name}`;
  }

  private _buildDcCodes(): string[] {
    const codes: string[] = [];
    for (const dcCodes of this._config.dataClassifications.values()) {
      for (const code of dcCodes) {
        if (!codes.includes(code)) codes.push(code);
      }
    }
    return codes;
  }

  translate(invocation: ToolInvocation): Action {
    const toolName = this._qualifiedName(invocation.fn, invocation.toolName);
    const payload = {
      args: invocation.args ?? [],
      kwargs: invocation.kwargs ?? {},
    };
    const paramHash = createHash("sha256")
      .update(canonicalJsonStringify(payload))
      .digest("hex");
    const entry = this._registry.lookup(toolName);

    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: invocation.agentName,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType: "tool_call",
      tool: {
        name: toolName,
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

  computeToolHash(fn: AnyFn | string): string {
    const ident =
      typeof fn === "string"
        ? fn
        : `tool:${(fn as { name?: string }).name ?? "unknown"}:${fn.toString()}`;
    return createHash("sha256").update(ident).digest("hex");
  }

  registerTools(registry: ToolRegistry): string[] {
    return registry.getAll().map((entry) => entry.name);
  }

  private _ensureRegistered(fn: AnyFn, toolName: string): void {
    if (this._registry.lookup(toolName)) return;
    const status = matchesToolList(toolName, this._config.toolsAllowed)
      ? ToolStatus.APPROVED
      : ToolStatus.OBSERVED;
    const now = new Date().toISOString();
    this._registry.register({
      name: toolName,
      descriptionHash: this.computeToolHash(fn),
      status,
      approvedBy: status === ToolStatus.APPROVED ? "config" : null,
      firstSeen: now,
      statusChanged: now,
    } satisfies ToolEntry);
  }

  async evaluate(
    fn: AnyFn,
    agentName: string,
    args?: unknown[],
    kwargs?: Record<string, unknown>,
    toolName?: string,
  ): Promise<[Action, EvaluationResult]> {
    const resolvedName = this._qualifiedName(fn, toolName);
    this._ensureRegistered(fn, resolvedName);
    const action = this.translate({ fn, agentName, args, kwargs, toolName: resolvedName });
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, resolvedName);
    return [action, evaluation];
  }

  async execute<R = unknown>(
    fn: (...args: unknown[]) => R | Promise<R>,
    agentName: string,
    args?: unknown[],
    kwargs?: Record<string, unknown>,
    toolName?: string,
  ): Promise<ToolExecutionResult<Awaited<R>>> {
    const [action, evaluation] = await this.evaluate(fn as AnyFn, agentName, args, kwargs, toolName);
    if (evaluation.decision === "BLOCK") {
      throw new BlockedActionError(action.tool.name, evaluation);
    }
    const callArgs = [...(args ?? [])];
    if (kwargs && Object.keys(kwargs).length > 0) {
      callArgs.push(kwargs);
    }
    const returnValue = await fn(...callArgs);
    return { action, evaluation, blocked: false, returnValue };
  }

  wrapTool<R>(
    fn: (...args: unknown[]) => R | Promise<R>,
    agentName?: string,
    toolName?: string,
  ): (...args: unknown[]) => Promise<Awaited<R>> {
    const self = this;
    return async (...args: unknown[]): Promise<Awaited<R>> => {
      const resolvedAgent = agentName ?? self._config.agentName;
      const result = await self.execute(fn, resolvedAgent, args, undefined, toolName);
      return result.returnValue;
    };
  }
}

export function wrapTool<R>(
  fn: (...args: unknown[]) => R | Promise<R>,
  options: ToolWrapOptions,
): (...args: unknown[]) => Promise<Awaited<R>> {
  return options.producer.wrapTool(fn, options.agentName, options.toolName);
}

export function tool<R>(
  options: ToolWrapOptions,
): (fn: (...args: unknown[]) => R | Promise<R>) => (...args: unknown[]) => Promise<Awaited<R>> {
  return (fn) => options.producer.wrapTool(fn, options.agentName, options.toolName);
}

export function evaluateAndExecute<R>(
  fn: (...args: unknown[]) => R | Promise<R>,
  options: EvaluateAndExecuteOptions,
): Promise<ToolExecutionResult<Awaited<R>>> {
  return options.producer.execute(fn, options.agentName, options.args, options.kwargs, options.toolName);
}
