import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { loadConfig, type ResolvedConfig } from "../config/index.js";
import type { Action } from "../engine/action.js";
import { Engine } from "../engine/engine.js";
import type { ControlResult } from "../engine/result.js";
import { ToolRegistry, ToolStatus } from "../engine/registry.js";
import { EvidenceStore } from "../evidence/store.js";
import type { EvidenceRecord } from "../evidence/record.js";
import { MCPActionProducer } from "../producers/mcp.js";
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

type SummaryShape = {
  total_evaluations: number;
  decisions: Record<string, number>;
  tools_evaluated: string[];
  control_pass_rates: Record<string, Record<string, number>>;
  chain_valid: boolean;
  chain_errors: string[];
};

const DETERMINISTIC_TIMESTAMP_BASE_MS = Date.UTC(2026, 0, 1);
const DETERMINISTIC_TIMESTAMP_WINDOW_MS = 366 * 24 * 60 * 60 * 1000;

function textResult<T extends Record<string, unknown>>(structuredContent: T): CallToolResult {
  return {
    content: [{
      type: "text",
      text: JSON.stringify(structuredContent, null, 2),
    }],
    structuredContent,
  };
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value).sort(([a], [b]) => a.localeCompare(b))) {
      if (item !== undefined) out[key] = canonicalize(item);
    }
    return out;
  }
  if (typeof value === "bigint") return value.toString();
  return value;
}

function deterministicHash(namespace: string, payload: unknown): string {
  return createHash("sha256")
    .update(namespace)
    .update("\0")
    .update(JSON.stringify(canonicalize(payload)))
    .digest("hex");
}

function deterministicId(prefix: string, hash: string): string {
  return `${prefix}-${hash.slice(0, 32)}`;
}

function deterministicTimestamp(hash: string): string {
  const offset = Number(BigInt(`0x${hash.slice(0, 12)}`) % BigInt(DETERMINISTIC_TIMESTAMP_WINDOW_MS));
  return new Date(DETERMINISTIC_TIMESTAMP_BASE_MS + offset).toISOString();
}

function loadMcpConfig(input: Pick<CheckPostureInput, "config_path" | "agent_id">, options: AncilisMcpServerOptions): ResolvedConfig {
  const configPath = input.config_path ?? options.configPath;
  if (configPath) return loadConfig({ path: configPath });

  return loadConfig({
    raw: {
      agent: {
        name: options.name ?? input.agent_id ?? "ancilis-agent",
      },
    },
  });
}

function createEvidenceStore(
  config: ResolvedConfig,
  input: Pick<CheckPostureInput, "config_path" | "db_path">,
  options: AncilisMcpServerOptions,
): EvidenceStore {
  const dbPath = input.db_path ?? options.dbPath;
  if (!dbPath && !(input.config_path ?? options.configPath)) {
    return new EvidenceStore(config, { inMemory: true });
  }
  return new EvidenceStore(config, dbPath ? { dbPath } : undefined);
}

function isMissingPersistentStore(store: EvidenceStore): boolean {
  return store.dbPath !== ":memory:" && !existsSync(store.dbPath);
}

function numberRecord(value: unknown): Record<string, number> {
  if (!value || typeof value !== "object") return {};
  const out: Record<string, number> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === "number") out[key] = raw;
  }
  return out;
}

function controlStatsRecord(value: unknown): Record<string, Record<string, number>> {
  if (!value || typeof value !== "object") return {};
  const out: Record<string, Record<string, number>> = {};
  for (const [controlId, rawStats] of Object.entries(value)) {
    out[controlId] = numberRecord(rawStats);
  }
  return out;
}

function normalizeSummary(raw: Record<string, unknown>): SummaryShape {
  return {
    total_evaluations: (raw.total_evaluations as number | undefined) ?? (raw.totalEvaluations as number | undefined) ?? 0,
    decisions: numberRecord(raw.decisions),
    tools_evaluated: ((raw.tools_evaluated as string[] | undefined) ?? (raw.toolsEvaluated as string[] | undefined) ?? []),
    control_pass_rates: controlStatsRecord(raw.control_pass_rates ?? raw.controlPassRates),
    chain_valid: (raw.chain_valid as boolean | undefined) ?? (raw.chainValid as boolean | undefined) ?? true,
    chain_errors: (raw.chain_errors as string[] | undefined) ?? (raw.chainErrors as string[] | undefined) ?? [],
  };
}

function controlStatus(
  stats: Record<string, number>,
  totalEvaluations: number,
): "not_evaluated" | "pass" | "fail" | "flag" | "skip" {
  const pass = stats.PASS ?? 0;
  const fail = stats.FAIL ?? 0;
  const flag = stats.FLAG ?? 0;
  const skip = stats.SKIP ?? 0;
  const error = stats.ERROR ?? 0;
  const total = pass + fail + flag + skip + error;
  if (totalEvaluations === 0 || total === 0) return "not_evaluated";
  if (fail > 0 || error > 0) return "fail";
  if (flag > 0) return "flag";
  if (pass > 0) return "pass";
  return "skip";
}

function buildControls(config: ResolvedConfig, summary: SummaryShape): CheckPostureOutput["controls"] {
  return [...config.controls.values()]
    .sort((a, b) => a.controlId.localeCompare(b.controlId))
    .map((control) => {
      const stats = summary.control_pass_rates[control.controlId] ?? {};
      return {
        control_id: control.controlId,
        name: control.name,
        enabled: control.enabled,
        status: controlStatus(stats, summary.total_evaluations),
        pass: stats.PASS ?? 0,
        fail: stats.FAIL ?? 0,
        flag: stats.FLAG ?? 0,
        skip: stats.SKIP ?? 0,
        error: stats.ERROR ?? 0,
      };
    });
}

function postureFrom(summary: SummaryShape, controls: CheckPostureOutput["controls"]): CheckPostureOutput["posture"] {
  if (summary.total_evaluations === 0) return "not_evaluated";
  if (!summary.chain_valid) return "non_compliant";
  if (controls.some(control => control.enabled && (control.fail > 0 || control.error > 0))) {
    return "non_compliant";
  }
  return "compliant";
}

async function checkPosture(input: CheckPostureInput, options: AncilisMcpServerOptions): Promise<CheckPostureOutput> {
  const config = loadMcpConfig(input, options);
  const store = createEvidenceStore(config, input, options);

  try {
    const rawSummary = await store.getSummary({ sessionId: input.session_id });
    const summary = normalizeSummary(rawSummary);
    const controls = buildControls(config, summary);

    return {
      agent: {
        name: config.agentName,
        id: input.agent_id ?? config.agentId,
        owner: config.agentOwner || null,
      },
      mode: config.mode as "audit" | "enforce",
      posture: postureFrom(summary, controls),
      summary: {
        total_evaluations: summary.total_evaluations,
        decisions: summary.decisions,
        tools_evaluated: summary.tools_evaluated,
        control_pass_rates: summary.control_pass_rates,
      },
      controls,
      evidence: {
        db_path: store.dbPath,
        chain_valid: summary.chain_valid,
        chain_errors: summary.chain_errors,
      },
      warnings: [...config.warnings],
    };
  } finally {
    await store.close();
  }
}

function preseedApprovedTools(config: ResolvedConfig, registry: ToolRegistry): void {
  const now = new Date().toISOString();
  for (const toolName of config.toolsAllowed) {
    registry.register({
      name: toolName,
      status: ToolStatus.APPROVED,
      approvedBy: "config",
      firstSeen: now,
      statusChanged: now,
    });
  }
}

function controlResultOutput(result: ControlResult, stableDuration = false): EvaluateActionOutput["control_results"][number] {
  const output: EvaluateActionOutput["control_results"][number] = {
    control_id: result.controlId,
    control_name: result.controlName,
    result: result.result,
    detail: result.detail,
    evidence_data: result.evidenceData,
    duration_ms: stableDuration ? 0 : result.durationMs,
  };
  if (result.displayName !== undefined) output.display_name = result.displayName;
  if (result.displayDetail !== undefined) output.display_detail = result.displayDetail;
  if (result.remediationHint !== undefined) output.remediation_hint = result.remediationHint;
  return output;
}

function deterministicActionHash(config: ResolvedConfig, input: EvaluateActionInput, action: Action): string {
  return deterministicHash("ancilis-mcp-proposed-action-v1", {
    agent: {
      name: config.agentName,
      id: config.agentId,
      owner: config.agentOwner || null,
    },
    mode: config.mode,
    input: {
      tool_name: input.tool_name,
      arguments: input.arguments ?? {},
      agent_id: input.agent_id ?? null,
      session_id: input.session_id ?? null,
      source_type: input.source_type ?? null,
    },
    action: {
      agent_id: action.agentId,
      source_type: action.sourceType ?? null,
      producer_type: action.producerType ?? null,
      producer_version: action.producerVersion ?? null,
      action_type: action.actionType,
      tool: action.tool,
      parameters: action.parameters,
      context: action.context ?? {},
    },
  });
}

function evaluateProposedAction(input: EvaluateActionInput, options: AncilisMcpServerOptions): EvaluateActionOutput {
  const config = loadMcpConfig(input, options);
  const registry = new ToolRegistry();
  preseedApprovedTools(config, registry);

  const producer = new MCPActionProducer(config, registry);
  const action = producer.translate({
    name: input.tool_name,
    arguments: input.arguments,
  });
  if (input.session_id !== undefined || input.source_type !== undefined) {
    action.context = {
      ...action.context,
      sessionId: input.session_id ?? action.context?.sessionId,
    };
    action.sourceType = input.source_type ?? action.sourceType;
  }

  const engine = new Engine(config, { registry });
  const evaluation = engine.evaluate(action);
  const stableControlResults = evaluation.controlResults.map(result => controlResultOutput(result, true));
  const actionHash = deterministicActionHash(config, input, action);
  const evaluationHash = deterministicHash("ancilis-mcp-evaluation-v1", {
    action_id: deterministicId("mcp-action", actionHash),
    decision: evaluation.decision,
    decision_reason: evaluation.decisionReason,
    mode: evaluation.mode,
    control_results: stableControlResults,
    active_overlays: evaluation.activeOverlays,
    data_classifications: evaluation.dataClassifications,
    detected_data_types: evaluation.detectedDataTypes ?? [],
  });

  return {
    action_id: deterministicId("mcp-action", actionHash),
    evaluation_id: deterministicId("mcp-evaluation", evaluationHash),
    timestamp: deterministicTimestamp(evaluationHash),
    decision: evaluation.decision,
    decision_reason: evaluation.decisionReason,
    mode: evaluation.mode,
    control_results: stableControlResults,
    active_overlays: [...evaluation.activeOverlays],
    data_classifications: [...evaluation.dataClassifications],
    detected_data_types: [...(evaluation.detectedDataTypes ?? [])],
    would_store_evidence: false,
  };
}

function parseJson<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return JSON.parse(value) as T;
  return value as T;
}

function evidenceRecordOutput(record: EvidenceRecord): GetEvidenceOutput["records"][number] {
  return {
    record_id: record.recordId,
    timestamp: record.timestamp,
    agent_id: record.agentId,
    session_id: record.sessionId ?? null,
    source_type: record.sourceType,
    tool_name: record.toolName,
    decision: record.decision as "ALLOW" | "BLOCK" | "FLAG",
    mode: record.mode as "audit" | "enforce",
    control_results: record.controlResults,
    active_overlays: record.activeOverlays,
    data_classifications: record.dataClassifications,
    active_certifications: record.activeCertifications,
    record_hash: record.recordHash,
    previous_hash: record.previousHash,
    output_summary: record.outputSummary ?? null,
    total_duration_ms: record.totalDurationMs,
  };
}

function rowToEvidenceRecord(row: Record<string, unknown>): EvidenceRecord {
  return {
    recordId: row.record_id as string,
    evaluationId: row.evaluation_id as string,
    timestamp: row.timestamp as string,
    agentId: row.agent_id as string,
    sessionId: (row.session_id as string | null | undefined) ?? null,
    sourceType: (row.source_type as string | undefined) ?? "agent",
    toolName: row.tool_name as string,
    decision: row.decision as string,
    mode: row.mode as string,
    controlResults: parseJson<Array<Record<string, unknown>>>(row.control_results, []),
    activeOverlays: parseJson<string[]>(row.active_overlays, []),
    dataClassifications: parseJson<string[]>(row.data_classifications, []),
    activeCertifications: parseJson<string[]>(row.active_certifications, []),
    recordHash: row.record_hash as string,
    previousHash: row.previous_hash as string,
    totalDurationMs: row.total_duration_ms as number,
    outputSummary: (row.output_summary as string | null | undefined) ?? null,
  };
}

async function getEvidence(input: GetEvidenceInput, options: AncilisMcpServerOptions): Promise<GetEvidenceOutput> {
  const config = loadMcpConfig(input, options);
  const store = createEvidenceStore(config, input, options);

  try {
    if (isMissingPersistentStore(store)) {
      return { records: [], chain_valid: true, chain_errors: [] };
    }

    const conditions: string[] = [];
    const params: unknown[] = [];
    if (input.session_id !== undefined) {
      conditions.push("session_id = ?");
      params.push(input.session_id);
    }
    if (input.tool_name !== undefined) {
      conditions.push("tool_name = ?");
      params.push(input.tool_name);
    }
    const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";
    params.push(input.limit ?? 20);

    const rows = await store.query(
      `SELECT
        seq_id, record_id, evaluation_id, timestamp, agent_id, session_id, source_type, tool_name,
        decision, mode, control_results, active_overlays, data_classifications,
        active_certifications, record_hash, previous_hash, total_duration_ms, output_summary
       FROM evidence_records${whereClause}
       ORDER BY timestamp DESC, seq_id DESC
       LIMIT ?`,
      params,
    );
    const chain = await store.verifyChain();

    return {
      records: (rows as Array<Record<string, unknown>>).map(row => evidenceRecordOutput(rowToEvidenceRecord(row))),
      chain_valid: chain.valid,
      chain_errors: chain.errors,
    };
  } finally {
    await store.close();
  }
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
    async (input) => textResult(await checkPosture(input, options)),
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
    (input) => textResult(evaluateProposedAction(input, options)),
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
    async (input) => textResult(await getEvidence(input, options)),
  );

  return server;
}

export async function runAncilisMcpServer(options: AncilisMcpServerOptions = {}): Promise<McpServer> {
  const server = createAncilisMcpServer(options);
  await server.connect(new StdioServerTransport());
  return server;
}
