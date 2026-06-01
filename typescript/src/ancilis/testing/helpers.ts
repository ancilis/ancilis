/** Internal helpers shared across the ancilis/testing module. */

import { createHash, randomUUID } from "node:crypto";
import { AKSI_FRAMEWORK_VERSION } from "../aksi/version.js";
import { loadConfig } from "../config/index.js";
import type { ResolvedConfig } from "../config/index.js";
import type { Action, ActionContext, ActionParameters, ToolInfo } from "../engine/action.js";

export interface MakeTestConfigOptions {
  agentName?: string;
  mode?: "audit" | "enforce";
  overlay?: string;
  raw?: Record<string, unknown>;
}

/** Create a minimal ResolvedConfig for testing without a YAML file. */
export function makeTestConfig(options: MakeTestConfigOptions = {}): ResolvedConfig {
  const { agentName = "test-agent", mode = "audit", overlay, raw = {} } = options;
  const base: Record<string, unknown> = {
    agent: { name: agentName },
    security: { mode },
    ...raw,
  };
  if (overlay) {
    base.compliance = { overlays: [overlay] };
  }
  return loadConfig({ raw: base });
}

export interface MakeActionOptions {
  toolName?: string;
  agentId?: string;
  agentOwner?: string | null;
  frameworkVersion?: string;
  parameters?: Record<string, unknown>;
  sessionId?: string | null;
  dataClassifications?: string[];
  sourceType?: string;
}

/** Create a test Action with sensible defaults. */
export function makeAction(options: MakeActionOptions = {}): Action {
  const {
    toolName = "test_tool",
    agentId = "test-agent",
    agentOwner = null,
    frameworkVersion = AKSI_FRAMEWORK_VERSION,
    parameters = {},
    sessionId = null,
    dataClassifications = [],
    sourceType = "agent",
  } = options;

  const parameterHash = createHash("sha256")
    .update(JSON.stringify(parameters))
    .digest("hex");

  const tool: ToolInfo = { name: toolName };
  const actionParameters: ActionParameters = { raw: parameters, parameterHash };
  const context: ActionContext = {
    sessionId,
    dataClassifications,
  };

  return {
    actionId: randomUUID(),
    timestamp: new Date().toISOString(),
    agentId,
    agentOwner,
    actionType: "tool_call",
    sourceType,
    frameworkVersion,
    tool,
    parameters: actionParameters,
    context,
  };
}
