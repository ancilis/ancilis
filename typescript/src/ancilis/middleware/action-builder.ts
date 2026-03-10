/** Translates MCP tool calls into framework-agnostic Action objects. */

import { createHash, randomUUID } from "node:crypto";
import type { ResolvedConfig } from "../config/index.js";
import type { Action } from "../engine/action.js";
import type { ToolRegistry } from "../engine/registry.js";

export function buildAction(
  toolName: string,
  args: Record<string, unknown> | undefined,
  config: ResolvedConfig,
  registry: ToolRegistry,
): Action {
  const rawArgs = args ?? {};
  const paramHash = createHash("sha256")
    .update(JSON.stringify(rawArgs, Object.keys(rawArgs).sort()))
    .digest("hex");

  const entry = registry.lookup(toolName);
  const toolVersion = entry?.version ?? null;
  const descriptionHash = entry?.descriptionHash ?? null;

  const dcCodes: string[] = [];
  for (const codes of config.dataClassifications.values()) {
    for (const code of codes) {
      if (!dcCodes.includes(code)) dcCodes.push(code);
    }
  }

  return {
    actionId: randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: config.agentName,
    agentOwner: config.agentOwner || null,
    actionType: "tool_call",
    tool: {
      name: toolName,
      version: toolVersion,
      descriptionHash,
    },
    parameters: { raw: rawArgs, parameterHash: paramHash },
    context: {
      dataClassifications: dcCodes,
      activeOverlays: [...config.activeOverlays.keys()],
    },
  };
}
