import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  checkPostureInputSchema,
  checkPostureOutputSchema,
  evaluateActionInputSchema,
  evaluateActionOutputSchema,
  getEvidenceInputSchema,
  getEvidenceOutputSchema,
  type CheckPostureInput,
  type CheckPostureOutput,
  type EvaluateActionInput,
  type EvaluateActionOutput,
  type GetEvidenceInput,
  type GetEvidenceOutput,
} from "./contracts.js";

export interface AncilisMcpServerOptions {
  configPath?: string;
  dbPath?: string;
  name?: string;
  version?: string;
}

function textResult<T extends Record<string, unknown>>(structuredContent: T): CallToolResult {
  return {
    content: [{
      type: "text",
      text: JSON.stringify(structuredContent, null, 2),
    }],
    structuredContent,
  };
}

function placeholderPosture(input: CheckPostureInput, options: AncilisMcpServerOptions): CheckPostureOutput {
  return {
    agent: { name: input.agent_id ?? "ancilis-agent", id: input.agent_id ?? null, owner: null },
    mode: "audit",
    posture: "not_evaluated",
    summary: {
      total_evaluations: 0,
      decisions: {},
      tools_evaluated: [],
      control_pass_rates: {},
    },
    controls: [],
    evidence: {
      db_path: input.db_path ?? options.dbPath ?? ":memory:",
      chain_valid: true,
      chain_errors: [],
    },
    warnings: [],
  };
}

function placeholderEvaluation(input: EvaluateActionInput): EvaluateActionOutput {
  const toolName = input.tool_name.replace(/[^a-zA-Z0-9_-]/g, "-");

  return {
    action_id: `mcp-${toolName}`,
    evaluation_id: `mcp-${toolName}-evaluation`,
    timestamp: new Date(0).toISOString(),
    decision: "ALLOW",
    decision_reason: "Evaluation is not implemented in this MCP server slice.",
    mode: "audit",
    control_results: [],
    active_overlays: [],
    data_classifications: [],
    detected_data_types: [],
    would_store_evidence: false,
  };
}

function placeholderEvidence(_input: GetEvidenceInput): GetEvidenceOutput {
  return {
    records: [],
    chain_valid: true,
    chain_errors: [],
  };
}

export function createAncilisMcpServer(options: AncilisMcpServerOptions = {}): McpServer {
  const server = new McpServer({
    name: options.name ?? "ancilis",
    version: options.version ?? "0.1.0",
  });

  server.registerTool(
    "ancilis_check_posture",
    {
      title: "Check Ancilis posture",
      description: "Summarize Ancilis runtime posture for the configured evidence store.",
      inputSchema: checkPostureInputSchema,
      outputSchema: checkPostureOutputSchema,
      annotations: { readOnlyHint: true },
    },
    (input) => textResult(placeholderPosture(input, options)),
  );

  server.registerTool(
    "ancilis_evaluate_action",
    {
      title: "Evaluate proposed action",
      description: "Evaluate a proposed tool action against Ancilis controls without executing it.",
      inputSchema: evaluateActionInputSchema,
      outputSchema: evaluateActionOutputSchema,
      annotations: { readOnlyHint: true },
    },
    (input) => textResult(placeholderEvaluation(input)),
  );

  server.registerTool(
    "ancilis_get_evidence",
    {
      title: "Get Ancilis evidence",
      description: "Read recent Ancilis evidence records and hash-chain status.",
      inputSchema: getEvidenceInputSchema,
      outputSchema: getEvidenceOutputSchema,
      annotations: { readOnlyHint: true },
    },
    (input) => textResult(placeholderEvidence(input)),
  );

  return server;
}

export async function runAncilisMcpServer(options: AncilisMcpServerOptions = {}): Promise<McpServer> {
  const server = createAncilisMcpServer(options);
  await server.connect(new StdioServerTransport());
  return server;
}
