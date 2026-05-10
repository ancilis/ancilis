/**
 * LangChain.js / LangGraph framework producer.
 *
 * Mirrors the Python `ancilis.producers.langchain` module. Exposes a
 * `LangChainCallbackHandler` that conforms to the LangChain.js callback
 * shape (`handleLLMStart`, `handleChatModelStart`, `handleToolStart`,
 * `handleChainStart`) by duck-typing — works with any Runnable, Chain, or
 * LLM via the `callbacks` array. Same handler covers LangGraph through the
 * shared callback bus.
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

const PROVIDER = "langchain";
const PRODUCER_VERSION = "0.1.0";

export type LangChainEventKind = "llm" | "chat_model" | "tool" | "chain";

export interface LangChainEvent {
  kind: LangChainEventKind;
  name: string;
  agentName: string;
  inputs?: unknown;
  serialized?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface LangChainObservation {
  action: Action;
  evaluation: EvaluationResult;
}

function nameFromSerialized(
  serialized: Record<string, unknown> | undefined,
  fallback: string,
): string {
  if (!serialized) return fallback;
  const name = serialized["name"];
  if (typeof name === "string" && name) return name;
  const id = serialized["id"];
  if (Array.isArray(id) && id.length > 0) return String(id[id.length - 1]);
  return fallback;
}

export class LangChainActionProducer {
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

  protected _toolName(event: LangChainEvent): string {
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

  translate(event: LangChainEvent): Action {
    const payload: Record<string, unknown> = {
      provider: PROVIDER,
      kind: event.kind,
      name: event.name,
      inputs: event.inputs ?? null,
      serialized: event.serialized ?? {},
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
      actionType: event.kind === "tool" ? "tool_call" : "api_request",
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

  protected _ensureRegistered(event: LangChainEvent): string {
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

  async observe(event: LangChainEvent): Promise<LangChainObservation> {
    const toolName = this._ensureRegistered(event);
    const action = this.translate(event);
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, toolName);
    return { action, evaluation };
  }
}

/**
 * Drop-in callback handler for any LangChain.js Runnable, Chain, or LLM.
 *
 * Conforms to the LangChain.js `BaseCallbackHandler` shape via duck-typing —
 * has the expected `handle*` async methods plus `name` for identification.
 * Pass an instance into the `callbacks=[handler]` array of any LangChain
 * construct. Same handler covers LangGraph nodes via the shared callback bus.
 */
export class LangChainCallbackHandler {
  public readonly name = "ancilis-langchain-callback-handler";
  public readonly raiseError = false;
  public readonly ignoreLLM = false;
  public readonly ignoreChain = false;
  public readonly ignoreAgent = false;
  public readonly ignoreRetriever = false;
  public readonly ignoreCustomEvent = true;

  private _producer: LangChainActionProducer;
  private _agentName?: string;

  constructor(producer: LangChainActionProducer, agentName?: string) {
    this._producer = producer;
    this._agentName = agentName;
  }

  get producer(): LangChainActionProducer { return this._producer; }

  private _agent(): string {
    return this._agentName ?? this._producer.config.agentName;
  }

  async handleLLMStart(
    serialized: Record<string, unknown>,
    prompts: string[],
    runId?: string,
    ..._rest: unknown[]
  ): Promise<void> {
    await this._producer.observe({
      kind: "llm",
      name: nameFromSerialized(serialized, "llm"),
      agentName: this._agent(),
      inputs: { prompts: prompts ?? [] },
      serialized: serialized ?? {},
      metadata: { runId: runId ?? null },
    });
  }

  async handleChatModelStart(
    serialized: Record<string, unknown>,
    messages: unknown[][],
    runId?: string,
    ..._rest: unknown[]
  ): Promise<void> {
    await this._producer.observe({
      kind: "chat_model",
      name: nameFromSerialized(serialized, "chat_model"),
      agentName: this._agent(),
      inputs: {
        messages: (messages ?? []).map((batch) => batch.map((m) => String(m))),
      },
      serialized: serialized ?? {},
      metadata: { runId: runId ?? null },
    });
  }

  async handleToolStart(
    serialized: Record<string, unknown>,
    inputStr: string,
    runId?: string,
    ..._rest: unknown[]
  ): Promise<void> {
    await this._producer.observe({
      kind: "tool",
      name: nameFromSerialized(serialized, "tool"),
      agentName: this._agent(),
      inputs: { input: inputStr },
      serialized: serialized ?? {},
      metadata: { runId: runId ?? null },
    });
  }

  async handleChainStart(
    serialized: Record<string, unknown>,
    inputs: Record<string, unknown>,
    runId?: string,
    ..._rest: unknown[]
  ): Promise<void> {
    await this._producer.observe({
      kind: "chain",
      name: nameFromSerialized(serialized, "chain"),
      agentName: this._agent(),
      inputs: inputs ?? {},
      serialized: serialized ?? {},
      metadata: { runId: runId ?? null },
    });
  }

  // --- noop handlers required for the full BaseCallbackHandler shape ---

  async handleLLMEnd(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleLLMNewToken(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleLLMError(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleChainEnd(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleChainError(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleToolEnd(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleToolError(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleText(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleAgentAction(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleAgentEnd(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleRetrieverStart(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleRetrieverEnd(..._args: unknown[]): Promise<void> { /* noop */ }
  async handleRetrieverError(..._args: unknown[]): Promise<void> { /* noop */ }
}

// Test-only export
export { nameFromSerialized as _nameFromSerialized };
