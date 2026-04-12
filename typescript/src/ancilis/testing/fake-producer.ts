/** FakeProducer — inject synthetic evidence for testing without running real agent code. */

import { randomUUID } from "node:crypto";
import { loadConfig } from "../config/index.js";
import type { ResolvedConfig } from "../config/index.js";
import { Engine } from "../engine/engine.js";
import type { Action } from "../engine/action.js";
import type { EvaluationResult } from "../engine/result.js";
import { MockEvidenceStore } from "./mock-evidence-store.js";

export interface FakeEvaluationResult {
  action: Action;
  evaluation: EvaluationResult;
  record: Awaited<ReturnType<MockEvidenceStore["store"]>>;
}

/**
 * FakeProducer runs engine evaluations against a `MockEvidenceStore`,
 * letting tests verify control behavior without real agent code or
 * platform connectivity.
 *
 * @example
 * ```ts
 * const producer = new FakeProducer();
 * const { evaluation } = await producer.evaluate("read_file", { path: "/etc/passwd" });
 * expectControlToPass(evaluation, "PR-01");
 * ```
 *
 * Supply a custom `ResolvedConfig` to test overlay/control combinations:
 * ```ts
 * const producer = new FakeProducer({ config: ComplianceScenarios.missingIdentity() });
 * const { evaluation } = await producer.evaluate("send_email");
 * expectControlToFail(evaluation, "PR-01");
 * ```
 */
export class FakeProducer {
  readonly store: MockEvidenceStore;
  readonly config: ResolvedConfig;
  private _engine: Engine;
  private _defaultAgentId: string | null;

  constructor(options?: {
    config?: ResolvedConfig;
    certifications?: string[];
    /** Force a specific agentId on every evaluate() call (useful for failure scenarios). */
    defaultAgentId?: string | null;
  }) {
    this.config =
      options?.config ??
      loadConfig({ raw: { agent: { name: "test-agent" } } });
    this.store = new MockEvidenceStore({
      certifications: options?.certifications ?? this.config.activeCertifications,
    });
    this._engine = new Engine(this.config);
    this._defaultAgentId = options?.defaultAgentId ?? null;
  }

  /**
   * Evaluate a named tool call and store evidence.
   *
   * @param toolName  Tool / action name (e.g. `"read_file"`, `"send_email"`).
   * @param params    Optional raw parameters for the action.
   * @param agentId   Override the agent identity for this call.
   */
  async evaluate(
    toolName: string,
    params: Record<string, unknown> = {},
    agentId?: string,
  ): Promise<FakeEvaluationResult> {
    const action: Action = {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: agentId ?? this._defaultAgentId ?? this.config.agentId ?? this.config.agentName,
      sourceType: "fake",
      producerType: "fake",
      producerVersion: "0.0.0",
      agentOwner: this.config.agentOwner ?? null,
      actionType: "tool_call",
      tool: { name: toolName, descriptionHash: null },
      parameters: { raw: params, parameterHash: "fake" },
      context: {
        dataClassifications: [...this.config.dataClassifications.values()].flat(),
        activeOverlays: [...this.config.activeOverlays.keys()],
      },
    };

    const evaluation = this._engine.evaluate(action);
    const record = await this.store.store(evaluation, toolName);
    return { action, evaluation, record };
  }

  /**
   * Run multiple tool calls in sequence and return all results.
   */
  async evaluateAll(
    calls: Array<{ toolName: string; params?: Record<string, unknown>; agentId?: string }>,
  ): Promise<FakeEvaluationResult[]> {
    const results: FakeEvaluationResult[] = [];
    for (const call of calls) {
      results.push(await this.evaluate(call.toolName, call.params, call.agentId));
    }
    return results;
  }

  /** Reset the in-memory store between test cases. */
  reset(): void {
    this.store.clear();
  }
}
