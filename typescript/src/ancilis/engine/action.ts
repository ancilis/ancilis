/** Action object — standardized representation of an agent action for evaluation. */

export interface ToolInfo {
  name: string;
  version?: string | null;
  server?: string | null;
  descriptionHash?: string | null;
}

export interface ActionParameters {
  raw: Record<string, unknown>;
  parameterHash: string;
}

export interface ActionContext {
  sessionId?: string | null;
  parentActionId?: string | null;
  dataClassifications?: string[];
  activeOverlays?: string[];
}

export interface Action {
  actionId: string;
  timestamp: string;
  agentId: string;
  agentOwner?: string | null;
  actionType: "tool_call" | "api_request" | "data_access";
  tool: ToolInfo;
  parameters: ActionParameters;
  context?: ActionContext;
}
