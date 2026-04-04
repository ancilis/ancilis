/** MCPActionProducer — wraps existing MCP action building and discovery logic. */

import { createHash } from "node:crypto";
import type { ResolvedConfig } from "../config/index.js";
import type { Action } from "../engine/action.js";
import type { ToolRegistry } from "../engine/registry.js";
import { buildAction } from "../middleware/action-builder.js";
import {
  registerToolsFromList,
  type DiscoverableTool,
  type DriftEvent,
} from "../middleware/discovery.js";
import { ProducerType } from "./protocol.js";

export interface MCPInvocation {
  name: string;
  arguments?: Record<string, unknown>;
}

export class MCPActionProducer {
  private _config: ResolvedConfig;
  private _registry: ToolRegistry;

  constructor(config: ResolvedConfig, registry: ToolRegistry) {
    this._config = config;
    this._registry = registry;
  }

  get producerType(): ProducerType { return ProducerType.MCP; }
  get producerVersion(): string { return "0.1.0"; }

  translate(rawInvocation: MCPInvocation): Action {
    const action = buildAction(
      rawInvocation.name,
      rawInvocation.arguments,
      this._config,
      this._registry,
    );
    action.sourceType = this.producerType;
    action.producerType = this.producerType;
    action.producerVersion = this.producerVersion;
    return action;
  }

  computeToolHash(toolIdentifier: unknown): string {
    const description = String(toolIdentifier ?? "");
    return createHash("sha256").update(description).digest("hex");
  }

  registerTools(registry: ToolRegistry): string[] {
    return registry.getAll().map((entry) => entry.name);
  }

  registerToolsFromResponse(
    tools: DiscoverableTool[],
    registry: ToolRegistry,
    preApproved?: string[],
  ): DriftEvent[] {
    return registerToolsFromList(tools, registry, preApproved);
  }
}
