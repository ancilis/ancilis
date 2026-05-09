/**
 * AutoGen / AG2 framework producer (TypeScript parity with
 * `ancilis.producers.autogen`).
 *
 * Wraps AutoGen's `ConversableAgent` hook lifecycle so each inter-agent
 * message and reply becomes an Action object. Duck-typed against AutoGen —
 * no hard import. Exposes `sendHook` / `receiveHook` factories matching the
 * AutoGen-documented hook signatures, plus `attach()` to auto-wire hooks
 * against any object that has either a `register_hook` method or a
 * `hook_lists` dict.
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

const PROVIDER = "autogen";
const PRODUCER_VERSION = "0.1.0";

export type AutoGenEventKind = "send" | "receive" | "reply";

export interface AutoGenEvent {
  kind: AutoGenEventKind;
  sender: string;
  recipient: string;
  message?: unknown;
  metadata?: Record<string, unknown>;
}

export interface AutoGenObservation {
  action: Action;
  evaluation: EvaluationResult;
}

export function _agentName(agent: unknown, fallback: string): string {
  if (agent === null || agent === undefined) return fallback;
  if (typeof agent === "object") {
    const name = (agent as Record<string, unknown>)["name"];
    if (typeof name === "string" && name) return name;
  }
  return String(agent);
}

export function _serializableMessage(message: unknown): unknown {
  if (
    message === null ||
    message === undefined ||
    typeof message === "string" ||
    typeof message === "number" ||
    typeof message === "boolean"
  ) {
    return message;
  }
  if (Array.isArray(message)) {
    return message.map((m) => _serializableMessage(m));
  }
  if (typeof message === "object") {
    const o = message as Record<string, unknown>;
    for (const method of ["modelDump", "model_dump", "dict", "toDict", "to_dict"]) {
      const fn = o[method];
      if (typeof fn === "function") {
        try {
          return (fn as () => unknown).call(message);
        } catch {
          continue;
        }
      }
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(o)) out[k] = _serializableMessage(v);
    return out;
  }
  return String(message);
}

type SendHook = (
  sender?: unknown,
  message?: unknown,
  recipient?: unknown,
  silent?: boolean,
) => Promise<unknown>;

type ReceiveHook = (messages?: unknown) => Promise<unknown>;

export class AutoGenActionProducer {
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

  protected _toolName(event: AutoGenEvent): string {
    return `${PROVIDER}:${event.kind}:${event.sender}->${event.recipient}`;
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

  translate(event: AutoGenEvent): Action {
    const payload: Record<string, unknown> = {
      provider: PROVIDER,
      kind: event.kind,
      sender: event.sender,
      recipient: event.recipient,
      message: _serializableMessage(event.message),
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
      agentId: event.sender,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType: "api_request",
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

  protected _ensureRegistered(event: AutoGenEvent): string {
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

  async observe(event: AutoGenEvent): Promise<AutoGenObservation> {
    const toolName = this._ensureRegistered(event);
    const action = this.translate(event);
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, toolName);
    return { action, evaluation };
  }

  /** Hook with AutoGen's process_message_before_send signature. Returns the message unchanged. */
  sendHook(agentName?: string): SendHook {
    const fallback = agentName ?? this._config.agentName;
    return async (sender, message, recipient, silent = false): Promise<unknown> => {
      await this.observe({
        kind: "send",
        sender: _agentName(sender, fallback),
        recipient: _agentName(recipient, "unknown"),
        message,
        metadata: { silent: Boolean(silent) },
      });
      return message;
    };
  }

  /** Hook with AutoGen's process_last_received_message signature. Returns messages unchanged. */
  receiveHook(agentName?: string): ReceiveHook {
    const fallback = agentName ?? this._config.agentName;
    return async (messages): Promise<unknown> => {
      let lastMessage: unknown = null;
      let sender = "unknown";
      if (Array.isArray(messages) && messages.length > 0) {
        lastMessage = messages[messages.length - 1];
        if (lastMessage && typeof lastMessage === "object") {
          const lm = lastMessage as Record<string, unknown>;
          const candidate = lm["name"] ?? lm["role"];
          if (candidate !== undefined) sender = String(candidate);
        }
      }
      await this.observe({
        kind: "receive",
        sender,
        recipient: fallback,
        message: lastMessage,
        metadata: {},
      });
      return messages;
    };
  }

  /**
   * Auto-wire send + receive hooks against a ConversableAgent-shaped object.
   *
   * Tries `register_hook(name, fn)` first (newer AG2), then `hook_lists` dict
   * (older autogen), then falls back to direct attribute assignment on the
   * object. Returns the dict of registered callables so callers can introspect.
   */
  attach(agent: unknown, agentName?: string): Record<string, SendHook | ReceiveHook> {
    const targetName = agentName ?? _agentName(agent, this._config.agentName);
    const send = this.sendHook(targetName);
    const receive = this.receiveHook(targetName);
    const registered: Record<string, SendHook | ReceiveHook> = {
      process_message_before_send: send,
      process_last_received_message: receive,
    };

    if (agent === null || agent === undefined || typeof agent !== "object") {
      return registered;
    }
    const a = agent as Record<string, unknown>;
    const registerHook = a["register_hook"];
    if (typeof registerHook === "function") {
      for (const [name, fn] of Object.entries(registered)) {
        try {
          (registerHook as (...args: unknown[]) => unknown).call(agent, name, fn);
        } catch {
          // Some implementations expect named args { hookable_method, hook }.
          (registerHook as (...args: unknown[]) => unknown).call(agent, {
            hookable_method: name,
            hook: fn,
          });
        }
      }
      return registered;
    }
    const hookLists = a["hook_lists"];
    if (hookLists && typeof hookLists === "object" && !Array.isArray(hookLists)) {
      const hl = hookLists as Record<string, unknown[]>;
      for (const [name, fn] of Object.entries(registered)) {
        if (!Array.isArray(hl[name])) hl[name] = [];
        (hl[name] as unknown[]).push(fn);
      }
      return registered;
    }
    // Fallback: bare attribute assignment.
    for (const [name, fn] of Object.entries(registered)) a[name] = fn;
    return registered;
  }
}
