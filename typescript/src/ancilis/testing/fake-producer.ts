/** FakeProducer — inject synthetic evidence without running real agent code. */

import { createHash } from "node:crypto";
import { ProducerType } from "../producers/protocol.js";
import type { ActionProducer } from "../producers/protocol.js";
import type { Action } from "../engine/action.js";
import { ToolRegistry, ToolStatus } from "../engine/registry.js";
import { makeAction } from "./helpers.js";

/**
 * Injects synthetic evidence without running real agent code.
 *
 * Implements the ActionProducer protocol. Use in tests to produce Action
 * objects with controlled data, without any real tool connectivity.
 *
 * @example
 * const producer = new FakeProducer("identity");
 * producer.emit("user.id", "alice");
 * producer.emit("session.start", { timestamp: "2026-04-11T10:00:00Z" });
 *
 * const action = producer.makeAction();
 * const result = engine.evaluate(action);
 */
export class FakeProducer implements ActionProducer {
  private readonly _producerName: string;
  private readonly _agentId: string;
  private readonly _agentOwner: string | null;
  private _emitted: Record<string, unknown> = {};

  constructor(
    producerName: string = "fake",
    agentId: string = "test-agent",
    agentOwner: string | null = null,
  ) {
    this._producerName = producerName;
    this._agentId = agentId;
    this._agentOwner = agentOwner;
  }

  get producerType(): ProducerType {
    return ProducerType.MANUAL;
  }

  get producerVersion(): string {
    return "0.1.0-test";
  }

  /** Record a synthetic evidence item. */
  emit(key: string, value: unknown): void {
    this._emitted[key] = value;
  }

  /** All emitted evidence items (read-only copy). */
  get emittedData(): Record<string, unknown> {
    return { ...this._emitted };
  }

  /** Reset all emitted items. */
  clear(): void {
    this._emitted = {};
  }

  /** Create an Action for engine evaluation. */
  makeAction(options: {
    toolName?: string;
    parameters?: Record<string, unknown>;
    sessionId?: string | null;
    dataClassifications?: string[];
    sourceType?: string;
  } = {}): Action {
    const merged = { ...this._emitted, ...(options.parameters ?? {}) };
    return makeAction({
      toolName: options.toolName ?? this._producerName,
      agentId: this._agentId,
      agentOwner: this._agentOwner,
      parameters: merged,
      sessionId: options.sessionId,
      dataClassifications: options.dataClassifications,
      sourceType: options.sourceType,
    });
  }

  // --- ActionProducer protocol ---

  translate(rawInvocation: unknown): Action {
    if (rawInvocation !== null && typeof rawInvocation === "object") {
      const inv = rawInvocation as Record<string, unknown>;
      return this.makeAction({
        toolName: (inv["tool"] as string | undefined) ?? this._producerName,
        parameters: (inv["parameters"] as Record<string, unknown> | undefined) ?? {},
      });
    }
    return this.makeAction();
  }

  computeToolHash(toolIdentifier: unknown): string {
    return createHash("sha256").update(String(toolIdentifier)).digest("hex");
  }

  registerTools(registry: ToolRegistry): string[] {
    const toolName = this._producerName;
    const now = new Date().toISOString();
    registry.register({
      name: toolName,
      status: ToolStatus.OBSERVED,
      firstSeen: now,
      statusChanged: now,
    });
    return [toolName];
  }
}
