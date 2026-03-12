/** MCP middleware — intercepts tool calls, evaluates via engine, enforces decisions. */

import type { ResolvedConfig } from "../config/index.js";
import { loadConfig } from "../config/index.js";
import { Engine } from "../engine/engine.js";
import { ToolRegistry } from "../engine/registry.js";
import type { EvaluationResult } from "../engine/result.js";
import { buildAction } from "./action-builder.js";
import { registerToolsFromList } from "./discovery.js";
import type { DriftEvent } from "./discovery.js";
import { EvidenceStore } from "../evidence/store.js";
import { scanResponse } from "./response-scanner.js";
import type { ScanResult } from "./response-scanner.js";

/** Minimal interface for an MCP client — avoids tight coupling to SDK version. */
export interface McpClientLike {
  callTool(params: { name: string; arguments?: Record<string, unknown> }, ...rest: unknown[]): Promise<{ content: Array<{ type: string; text?: string; [key: string]: unknown }>; [key: string]: unknown }>;
  listTools(...args: unknown[]): Promise<{ tools: Array<{ name: string; description?: string; [key: string]: unknown }>; [key: string]: unknown }>;
}

export class BlockedToolCallError extends Error {
  tool_name: string;
  evaluation: EvaluationResult;
  displayMessage: string;

  constructor(toolName: string, evaluation: EvaluationResult) {
    const failed = evaluation.controlResults
      .filter(r => r.result === "FAIL" || r.result === "ERROR")
      .map(r => r.controlId);
    super(`Tool call '${toolName}' blocked by policy. Failed controls: ${failed.join(", ")}`);
    this.name = "BlockedToolCallError";
    this.tool_name = toolName;
    this.evaluation = evaluation;
    // Developer-facing message using display names
    const reasons = evaluation.controlResults
      .filter(r => r.result === "FAIL" || r.result === "ERROR")
      .map(r => (r.displayName ?? r.controlName).toLowerCase());
    const reasonStr = reasons.length > 0 ? reasons.join(", ") : "policy violation";
    this.displayMessage =
      `Ancilis [blocked]: Tool '${toolName}' blocked — ${reasonStr}.\n` +
      `  To approve: ancilis approve-tool ${toolName}\n` +
      `  To review: ancilis status`;
  }
}

export interface AncilisMiddlewareOptions {
  configPath?: string;
  config?: ResolvedConfig;
}

export class AncilisMiddleware {
  private _config: ResolvedConfig;
  private _client: McpClientLike;
  private _registry: ToolRegistry;
  private _engine: Engine;
  private _evaluationLog: EvaluationResult[] = [];
  private _scanResults: ScanResult[] = [];
  private _driftEvents: DriftEvent[] = [];
  private _evidenceStore: EvidenceStore;
  private _issueCount = 0;

  constructor(client: McpClientLike, options: AncilisMiddlewareOptions = {}) {
    if (options.config) {
      this._config = options.config;
    } else if (options.configPath) {
      this._config = loadConfig({ path: options.configPath });
    } else {
      this._config = loadConfig({ raw: { agent: { name: "ancilis-agent" } } });
    }

    this._client = client;
    this._registry = new ToolRegistry();
    this._engine = new Engine(this._config, { registry: this._registry });
    this._evidenceStore = new EvidenceStore(this._config);
  }

  get config(): ResolvedConfig { return this._config; }
  get registry(): ToolRegistry { return this._registry; }
  get evidenceStore(): EvidenceStore { return this._evidenceStore; }
  get evaluationLog(): EvaluationResult[] { return [...this._evaluationLog]; }
  get scanResults(): ScanResult[] { return [...this._scanResults]; }
  get driftEvents(): DriftEvent[] { return [...this._driftEvents]; }

  async callTool(name: string, args?: Record<string, unknown>): Promise<{ content: Array<{ type: string; text?: string; [key: string]: unknown }>; [key: string]: unknown }> {
    // 1. Build Action
    const action = buildAction(name, args, this._config, this._registry);

    // 2. Evaluate
    const evaluation = this._engine.evaluate(action);
    this._evaluationLog.push(evaluation);

    // 3. Store evidence
    await this._evidenceStore.store(evaluation, name);

    // Track issues for summary line
    if (evaluation.controlResults.some(r => r.result === "FAIL" || r.result === "ERROR")) {
      this._issueCount++;
    }

    // 4. Enforce
    if (evaluation.decision === "BLOCK") {
      throw new BlockedToolCallError(name, evaluation);
    }

    // 5. Forward to MCP server
    const result = await this._client.callTool({ name, arguments: args });

    // 6. Scan response
    const responseText = this.extractResponseText(result);
    if (responseText) {
      const scan = scanResponse(name, responseText);
      if (scan.patterns.length > 0 || scan.encryptionFindings.length > 0) {
        this._scanResults.push(scan);
      }
    }

    // 7. Return
    return result;
  }

  async listTools(): Promise<{ tools: Array<{ name: string; description?: string; [key: string]: unknown }>; [key: string]: unknown }> {
    const result = await this._client.listTools();
    const tools = result.tools ?? [];

    const drift = registerToolsFromList(
      tools.map(t => ({ name: t.name, description: t.description })),
      this._registry,
    );
    this._driftEvents.push(...drift);

    return result;
  }

  getRecommendations(): string[] {
    const recs: string[] = [];
    for (const scan of this._scanResults) {
      recs.push(...scan.recommendations);
    }
    return recs;
  }

  getSummaryLine(): string {
    const total = this._evaluationLog.length;
    const issues = this._issueCount;
    return `Ancilis: ${total} tool calls evaluated. ${issues} issues. Run \`ancilis status\` for details.`;
  }

  getLastEvaluation(): EvaluationResult | undefined {
    return this._evaluationLog[this._evaluationLog.length - 1];
  }

  private extractResponseText(result: { content: Array<{ type: string; text?: string; [key: string]: unknown }>; [key: string]: unknown }): string {
    const parts: string[] = [];
    if (Array.isArray(result.content)) {
      for (const item of result.content) {
        if (typeof item === "object" && item !== null && "text" in item && typeof item.text === "string") {
          parts.push(item.text);
        }
      }
    }
    return parts.join("\n");
  }
}
