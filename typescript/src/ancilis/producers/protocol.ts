/** Shared producer protocol surface for Python parity. */

import type { Action } from "../engine/action.js";
import type { ToolRegistry } from "../engine/registry.js";

export enum ProducerType {
  MCP = "mcp",
  CLI = "cli",
  HTTP = "http",
  A2A = "a2a",
  FRAMEWORK = "framework",
  MANUAL = "manual",
}

export interface ActionProducer {
  readonly producerType: ProducerType;
  readonly producerVersion: string;
  translate(rawInvocation: unknown): Action;
  computeToolHash(toolIdentifier: unknown): string;
  registerTools(registry: ToolRegistry): string[];
}
