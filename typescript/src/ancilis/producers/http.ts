/** HTTPActionProducer — observe/report mode for outbound HTTP requests. */

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
import { BlockedActionError } from "./tool.js";
import { ProducerType } from "./protocol.js";

export interface HTTPRequest {
  method: string;
  url: string;
  agentName: string;
  headers?: Record<string, string>;
  body?: unknown;
  serviceName?: string;
  metadata?: Record<string, unknown>;
}

export interface HTTPObservation {
  action: Action;
  evaluation: EvaluationResult;
}

export interface HTTPExecutionResult<R = unknown> {
  action: Action;
  evaluation: EvaluationResult;
  blocked: boolean;
  response?: R;
}

export class HTTPActionProducer {
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

  get producerType(): ProducerType { return ProducerType.HTTP; }
  get producerVersion(): string { return "0.1.0"; }
  /** Unique identifier for this producer instance (one per agent run). */
  get sessionId(): string { return this._sessionId; }

  private _toolName(request: HTTPRequest): string {
    try {
      const parsed = new URL(request.url);
      const host = parsed.host || "unknown-host";
      return `http:${request.method.toUpperCase()}:${host}`;
    } catch {
      return `http:${request.method.toUpperCase()}:unknown-host`;
    }
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

  private _getHost(url: string): string {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
  }

  translate(request: HTTPRequest): Action {
    const toolName = this._toolName(request);
    const payload: Record<string, unknown> = {
      method: request.method.toUpperCase(),
      url: request.url,
      headers: request.headers ?? {},
      body: request.body ?? null,
      metadata: request.metadata ?? {},
    };
    const paramHash = createHash("sha256")
      .update(canonicalJsonStringify(payload))
      .digest("hex");
    const entry = this._registry.lookup(toolName);

    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: request.agentName,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType: "api_request",
      tool: {
        name: toolName,
        server: request.serviceName ?? this._getHost(request.url),
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

  private _ensureRegistered(request: HTTPRequest): string {
    const toolName = this._toolName(request);
    if (!this._registry.lookup(toolName)) {
      const status = matchesToolList(toolName, this._config.toolsAllowed)
        ? ToolStatus.APPROVED
        : ToolStatus.OBSERVED;
      const now = new Date().toISOString();
      this._registry.register({
        name: toolName,
        descriptionHash: this.computeToolHash(toolName),
        status,
        approvedBy: status === ToolStatus.APPROVED ? "config" : null,
        firstSeen: now,
        statusChanged: now,
      } satisfies ToolEntry);
    }
    return toolName;
  }

  async observe(request: HTTPRequest): Promise<HTTPObservation> {
    const toolName = this._ensureRegistered(request);
    const action = this.translate(request);
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, toolName);
    return { action, evaluation };
  }

  async execute<R = unknown>(
    request: HTTPRequest,
    transport: () => R | Promise<R>,
    enforce = false,
  ): Promise<HTTPExecutionResult<R>> {
    const { action, evaluation } = await this.observe(request);
    if (enforce && evaluation.decision === "BLOCK") {
      throw new BlockedActionError(action.tool.name, evaluation);
    }
    const response = await transport();
    return { action, evaluation, blocked: false, response };
  }

  wrapTransport<R>(
    transport: (method: string, url: string, ...args: unknown[]) => R | Promise<R>,
    agentName?: string,
    serviceName?: string,
    enforce = false,
  ): (method: string, url: string, ...args: unknown[]) => Promise<HTTPExecutionResult<R>> {
    const self = this;
    return async (method: string, url: string, ...args: unknown[]): Promise<HTTPExecutionResult<R>> => {
      const kwargs = args.find(a => typeof a === "object" && a !== null) as Record<string, unknown> | undefined;
      const request: HTTPRequest = {
        method,
        url,
        agentName: agentName ?? self._config.agentName,
        headers: kwargs?.["headers"] as Record<string, string> | undefined,
        body: kwargs?.["data"] ?? kwargs?.["json"],
        serviceName,
      };
      return self.execute(
        request,
        () => transport(method, url, ...args),
        enforce,
      );
    };
  }
}
