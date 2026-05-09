/**
 * CrewAI framework producer (TypeScript parity with `ancilis.producers.crewai`).
 *
 * CrewAI's official surface is Python-only, but TS parity preserves the
 * ergonomics for users who run mixed-language stacks or wrap CrewAI through
 * a polyglot proxy. The producer exposes step / task / crew callback factories
 * with the same signatures the Python SDK uses.
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

const PROVIDER = "crewai";
const PRODUCER_VERSION = "0.1.0";

export type CrewAIEventKind = "step" | "task" | "crew";

export interface CrewAIEvent {
  kind: CrewAIEventKind;
  name: string;
  agentName: string;
  output?: unknown;
  metadata?: Record<string, unknown>;
}

export interface CrewAIObservation {
  action: Action;
  evaluation: EvaluationResult;
}

function firstStringAttr(obj: unknown, attrs: readonly string[]): string | null {
  if (obj === null || obj === undefined || typeof obj !== "object") return null;
  const o = obj as Record<string, unknown>;
  for (const attr of attrs) {
    const v = o[attr];
    if (typeof v === "string" && v) return v;
  }
  return null;
}

function firstStringKey(obj: unknown, keys: readonly string[]): string | null {
  if (obj === null || obj === undefined || typeof obj !== "object" || Array.isArray(obj)) {
    return null;
  }
  const o = obj as Record<string, unknown>;
  for (const k of keys) {
    const v = o[k];
    if (typeof v === "string" && v) return v;
  }
  return null;
}

const STEP_KEYS = ["tool", "tool_name", "agent_role", "agent", "name"] as const;
const TASK_KEYS = ["description", "task_id", "name", "agent_role"] as const;
const CREW_KEYS = ["name", "id", "crew_id"] as const;

export function _stepName(stepOutput: unknown, fallback: string): string {
  return (
    firstStringAttr(stepOutput, STEP_KEYS) ??
    firstStringKey(stepOutput, STEP_KEYS) ??
    fallback
  );
}

export function _taskName(taskOutput: unknown, fallback: string): string {
  return (
    firstStringAttr(taskOutput, TASK_KEYS) ??
    firstStringKey(taskOutput, TASK_KEYS) ??
    fallback
  );
}

export function _crewName(crewOutput: unknown, fallback: string): string {
  return (
    firstStringAttr(crewOutput, CREW_KEYS) ??
    firstStringKey(crewOutput, CREW_KEYS) ??
    fallback
  );
}

export function _serializable(value: unknown): unknown {
  if (
    value === null ||
    value === undefined ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    Array.isArray(value)
  ) {
    return value;
  }
  if (typeof value === "object") {
    const o = value as Record<string, unknown>;
    for (const method of ["modelDump", "model_dump", "dict", "toDict", "to_dict"]) {
      const fn = o[method];
      if (typeof fn === "function") {
        try {
          return (fn as () => unknown).call(value);
        } catch {
          continue;
        }
      }
    }
    // Plain object — return as-is for JSON serialization.
    return value;
  }
  return String(value);
}

export class CrewAIActionProducer {
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

  protected _toolName(event: CrewAIEvent): string {
    return `${PROVIDER}:${event.kind}:${event.name}`;
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

  translate(event: CrewAIEvent): Action {
    const payload: Record<string, unknown> = {
      provider: PROVIDER,
      kind: event.kind,
      name: event.name,
      output: _serializable(event.output),
      metadata: event.metadata ?? {},
    };
    const paramHash = createHash("sha256")
      .update(canonicalJsonStringify(payload))
      .digest("hex");
    const toolName = this._toolName(event);
    const entry = this._registry.lookup(toolName);
    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: event.agentName,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType: event.kind === "step" ? "tool_call" : "api_request",
      tool: {
        name: toolName,
        server: PROVIDER,
        descriptionHash: entry?.descriptionHash ?? null,
      },
      parameters: { raw: payload, parameterHash: paramHash },
      context: {
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

  protected _ensureRegistered(event: CrewAIEvent): string {
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

  async observe(event: CrewAIEvent): Promise<CrewAIObservation> {
    const toolName = this._ensureRegistered(event);
    const action = this.translate(event);
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, toolName);
    return { action, evaluation };
  }

  // --- CrewAI-shaped callback factories ---

  /** Returns a callback matching CrewAI's `step_callback` signature. */
  stepCallback(agentName?: string): (stepOutput: unknown) => Promise<void> {
    const agent = agentName ?? this._config.agentName;
    return async (stepOutput: unknown): Promise<void> => {
      await this.observe({
        kind: "step",
        name: _stepName(stepOutput, "step"),
        agentName: agent,
        output: stepOutput,
      });
    };
  }

  /** Returns a callback for the per-Task `callback=` argument. */
  taskCallback(agentName?: string): (taskOutput: unknown) => Promise<void> {
    const agent = agentName ?? this._config.agentName;
    return async (taskOutput: unknown): Promise<void> => {
      await this.observe({
        kind: "task",
        name: _taskName(taskOutput, "task"),
        agentName: agent,
        output: taskOutput,
      });
    };
  }

  /** Returns a callback suitable for crew-level step/completion callbacks. */
  crewCallback(agentName?: string): (crewOutput: unknown) => Promise<void> {
    const agent = agentName ?? this._config.agentName;
    return async (crewOutput: unknown): Promise<void> => {
      await this.observe({
        kind: "crew",
        name: _crewName(crewOutput, "crew"),
        agentName: agent,
        output: crewOutput,
      });
    };
  }
}
