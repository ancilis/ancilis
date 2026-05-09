/**
 * LLM SDK producers for Anthropic, OpenAI, Google Gemini, Mistral, Cohere,
 * xAI, and four OpenAI-compatible inference platforms (Groq, Together,
 * Fireworks, DeepSeek).
 *
 * Mirrors the Python `ancilis.producers.llm` module. Each producer wraps the
 * SDK call surface so every model invocation becomes an evaluated, evidence-
 * recorded Action. Duck-typed against the upstream SDKs — no hard imports.
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
import { BlockedActionError } from "./tool.js";
import { ProducerType } from "./protocol.js";

const PRODUCER_VERSION = "0.1.0";

export interface LLMInvocation {
  model: string;
  agentName: string;
  messages?: unknown[];
  system?: unknown;
  tools?: unknown[];
  response?: unknown;
  metadata?: Record<string, unknown>;
}

export interface LLMObservation {
  action: Action;
  evaluation: EvaluationResult;
}

export interface LLMExecutionResult<R = unknown> {
  action: Action;
  evaluation: EvaluationResult;
  blocked: boolean;
  response?: R;
}

/**
 * Base producer for LLM SDK calls. Subclasses set `provider` and may override
 * `extractInvocation` to normalize provider-specific kwargs into LLMInvocation.
 */
export class LLMActionProducer {
  static readonly provider: string = "llm";

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
    recordAdapterUsed(this.provider);
  }

  /** Concrete provider slug for this instance — overridden via static. */
  get provider(): string {
    return (this.constructor as typeof LLMActionProducer).provider;
  }

  get producerType(): ProducerType { return ProducerType.FRAMEWORK; }
  get producerVersion(): string { return PRODUCER_VERSION; }
  get sessionId(): string { return this._sessionId; }

  protected _toolName(invocation: LLMInvocation): string {
    const model = invocation.model || "unknown-model";
    return `llm:${this.provider}:${model}`;
  }

  protected _payload(invocation: LLMInvocation): Record<string, unknown> {
    return {
      provider: this.provider,
      model: invocation.model,
      messages: invocation.messages ?? [],
      system: invocation.system ?? null,
      tools: invocation.tools ?? [],
      metadata: invocation.metadata ?? {},
    };
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

  translate(invocation: LLMInvocation): Action {
    const payload = this._payload(invocation);
    const paramHash = createHash("sha256")
      .update(canonicalJsonStringify(payload))
      .digest("hex");
    const toolName = this._toolName(invocation);
    const entry = this._registry.lookup(toolName);
    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: invocation.agentName,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType: "api_request",
      tool: {
        name: toolName,
        server: this.provider,
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

  protected _ensureRegistered(invocation: LLMInvocation): string {
    const name = this._toolName(invocation);
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

  async observe(invocation: LLMInvocation): Promise<LLMObservation> {
    const toolName = this._ensureRegistered(invocation);
    const action = this.translate(invocation);
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, toolName);
    return { action, evaluation };
  }

  async execute<R = unknown>(
    invocation: LLMInvocation,
    transport: () => R | Promise<R>,
    enforce = false,
  ): Promise<LLMExecutionResult<R>> {
    const { action, evaluation } = await this.observe(invocation);
    if (enforce && evaluation.decision === "BLOCK") {
      throw new BlockedActionError(action.tool.name, evaluation);
    }
    const response = await transport();
    return { action, evaluation, blocked: false, response };
  }

  /**
   * Normalize provider-specific kwargs into LLMInvocation. Default extractor
   * handles the common Anthropic/OpenAI shape (`model`, `messages`, `system`,
   * `tools`); subclasses override for variant shapes.
   */
  protected extractInvocation(kwargs: Record<string, unknown>, agentName: string): LLMInvocation {
    const reserved = new Set(["model", "messages", "system", "tools"]);
    const metadata: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(kwargs)) {
      if (!reserved.has(k)) metadata[k] = v;
    }
    return {
      model: String(kwargs["model"] ?? "unknown-model"),
      agentName,
      messages: Array.isArray(kwargs["messages"]) ? (kwargs["messages"] as unknown[]) : [],
      system: kwargs["system"],
      tools: Array.isArray(kwargs["tools"]) ? (kwargs["tools"] as unknown[]) : undefined,
      metadata,
    };
  }

  /**
   * Wrap an SDK `create`-style callable so each invocation is observed first.
   * Works with `client.messages.create` (Anthropic),
   * `client.chat.completions.create` and `client.responses.create` (OpenAI),
   * and `client.models.generateContent` (Gemini, when called with kwargs).
   */
  wrapCreate<R = unknown>(
    create: (kwargs: Record<string, unknown>) => R | Promise<R>,
    agentName?: string,
    enforce = false,
  ): (kwargs: Record<string, unknown>) => Promise<LLMExecutionResult<R>> {
    return async (kwargs: Record<string, unknown>): Promise<LLMExecutionResult<R>> => {
      const invocation = this.extractInvocation(
        kwargs,
        agentName ?? this._config.agentName,
      );
      return this.execute(invocation, () => create(kwargs), enforce);
    };
  }
}

export class AnthropicActionProducer extends LLMActionProducer {
  static override readonly provider: string = "anthropic";
}

export class OpenAIActionProducer extends LLMActionProducer {
  static override readonly provider: string = "openai";

  protected override extractInvocation(
    kwargs: Record<string, unknown>,
    agentName: string,
  ): LLMInvocation {
    const reserved = new Set(["model", "messages", "system", "tools", "input", "instructions"]);
    let messages: unknown[] | undefined = Array.isArray(kwargs["messages"])
      ? (kwargs["messages"] as unknown[])
      : undefined;
    if (messages === undefined && "input" in kwargs) {
      const raw = kwargs["input"];
      if (typeof raw === "string") {
        messages = [{ role: "user", content: raw }];
      } else if (Array.isArray(raw)) {
        messages = raw;
      } else if (raw !== undefined && raw !== null) {
        messages = [raw];
      }
    }
    const metadata: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(kwargs)) {
      if (!reserved.has(k)) metadata[k] = v;
    }
    return {
      model: String(kwargs["model"] ?? "unknown-model"),
      agentName,
      messages: messages ?? [],
      system: kwargs["instructions"] ?? kwargs["system"],
      tools: Array.isArray(kwargs["tools"]) ? (kwargs["tools"] as unknown[]) : undefined,
      metadata,
    };
  }
}

export class GeminiActionProducer extends LLMActionProducer {
  static override readonly provider: string = "gemini";

  protected override extractInvocation(
    kwargs: Record<string, unknown>,
    agentName: string,
  ): LLMInvocation {
    const reserved = new Set(["model", "contents", "systemInstruction", "system_instruction", "tools", "config"]);
    const contents = kwargs["contents"];
    let messages: unknown[] = [];
    if (typeof contents === "string") {
      messages = [{ role: "user", content: contents }];
    } else if (Array.isArray(contents)) {
      messages = contents;
    } else if (contents !== undefined && contents !== null) {
      messages = [contents];
    }

    let system: unknown;
    let tools: unknown[] | undefined;
    const config = kwargs["config"];
    if (config && typeof config === "object" && !Array.isArray(config)) {
      const cfg = config as Record<string, unknown>;
      system = cfg["system_instruction"] ?? cfg["systemInstruction"] ?? kwargs["system_instruction"];
      tools = Array.isArray(cfg["tools"])
        ? (cfg["tools"] as unknown[])
        : Array.isArray(kwargs["tools"])
          ? (kwargs["tools"] as unknown[])
          : undefined;
    } else {
      system = kwargs["system_instruction"] ?? kwargs["systemInstruction"];
      tools = Array.isArray(kwargs["tools"]) ? (kwargs["tools"] as unknown[]) : undefined;
    }

    const metadata: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(kwargs)) {
      if (!reserved.has(k)) metadata[k] = v;
    }
    return {
      model: String(kwargs["model"] ?? "unknown-model"),
      agentName,
      messages,
      system,
      tools,
      metadata,
    };
  }
}

export class MistralActionProducer extends LLMActionProducer {
  static override readonly provider: string = "mistral";
}

export class CohereActionProducer extends LLMActionProducer {
  static override readonly provider: string = "cohere";

  protected override extractInvocation(
    kwargs: Record<string, unknown>,
    agentName: string,
  ): LLMInvocation {
    const reserved = new Set([
      "model",
      "messages",
      "message",
      "chat_history",
      "chatHistory",
      "preamble",
      "system",
      "tools",
    ]);
    let messages: unknown[] = Array.isArray(kwargs["messages"])
      ? [...(kwargs["messages"] as unknown[])]
      : [];
    if (messages.length === 0) {
      const history = kwargs["chat_history"] ?? kwargs["chatHistory"];
      if (Array.isArray(history)) messages.push(...(history as unknown[]));
      const current = kwargs["message"];
      if (current !== undefined && current !== null) {
        messages.push({ role: "user", content: current });
      }
    }
    const metadata: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(kwargs)) {
      if (!reserved.has(k)) metadata[k] = v;
    }
    return {
      model: String(kwargs["model"] ?? "unknown-model"),
      agentName,
      messages,
      system: kwargs["preamble"] ?? kwargs["system"],
      tools: Array.isArray(kwargs["tools"]) ? (kwargs["tools"] as unknown[]) : undefined,
      metadata,
    };
  }
}

// xAI / Groq / Together / Fireworks / DeepSeek all expose OpenAI-compatible
// chat APIs. They subclass OpenAIActionProducer to inherit the input/messages
// normalization and change only the provider slug.

export class XAIActionProducer extends OpenAIActionProducer {
  static override readonly provider: string = "xai";
}

export class GroqActionProducer extends OpenAIActionProducer {
  static override readonly provider: string = "groq";
}

export class TogetherActionProducer extends OpenAIActionProducer {
  static override readonly provider: string = "together";
}

export class FireworksActionProducer extends OpenAIActionProducer {
  static override readonly provider: string = "fireworks";
}

export class DeepSeekActionProducer extends OpenAIActionProducer {
  static override readonly provider: string = "deepseek";
}
