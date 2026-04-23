import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import * as ancilis from "../src/ancilis/index.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { EvaluationResult } from "../src/ancilis/engine/result.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import {
  checkPostureOutputSchema,
  createAncilisMcpServer,
  evaluateActionOutputSchema,
  getEvidenceOutputSchema,
  runAncilisMcpServer,
} from "../src/ancilis/mcp/index.js";

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "ancilis-mcp-"));
}

function writeConfig(dir: string): string {
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, [
    "agent:",
    "  name: mcp-agent",
    "  owner: security",
    "  agent_id: 11111111-1111-4111-8111-111111111111",
    "security:",
    "  mode: audit",
    "  tools:",
    "    allowed:",
    "      - demo.tool",
    "      - mcp:allowed.tool",
    "      - mcp:blocked.tool",
    "my_agent_handles:",
    "  - credit_cards",
    "",
  ].join("\n"));
  return path;
}

function evaluation(overrides: Partial<EvaluationResult> = {}): EvaluationResult {
  return {
    evaluationId: "eval-1",
    actionId: "action-1",
    timestamp: "2026-04-20T00:00:00.000Z",
    agentId: "mcp-agent",
    sourceType: "mcp",
    mode: "audit",
    decision: "ALLOW",
    decisionReason: "All controls passed.",
    controlResults: [{
      controlId: "PR-01",
      controlName: "Identity",
      result: "PASS",
      detail: "ok",
      evidenceData: {},
      durationMs: 1,
    }],
    activeOverlays: [],
    dataClassifications: [],
    totalDurationMs: 1,
    context: { sessionId: "session-a" },
    ...overrides,
  };
}

async function seedEvidence(configPath: string, dbPath: string): Promise<void> {
  const config = loadConfig({ path: configPath });
  const store = new EvidenceStore(config, { dbPath });
  await store.store(evaluation({
    evaluationId: "eval-older",
    actionId: "action-older",
    timestamp: "2026-04-20T00:00:00.000Z",
    context: { sessionId: "session-a" },
  }), "mcp:allowed.tool", "older");
  await store.store(evaluation({
    evaluationId: "eval-newer",
    actionId: "action-newer",
    timestamp: "2026-04-20T00:01:00.000Z",
    decision: "BLOCK",
    decisionReason: "A control failed.",
    controlResults: [{
      controlId: "PR-01",
      controlName: "Identity",
      result: "FAIL",
      detail: "not approved",
      evidenceData: {},
      durationMs: 2,
    }],
    totalDurationMs: 2,
    context: { sessionId: "session-b" },
  }), "mcp:blocked.tool", "newer");
  await store.close();
}

async function evidenceCount(configPath: string, dbPath: string): Promise<number> {
  const config = loadConfig({ path: configPath });
  const store = new EvidenceStore(config, { dbPath });
  try {
    return await store.count();
  } finally {
    await store.close();
  }
}

async function connectTestClient(options: Parameters<typeof createAncilisMcpServer>[0] = {}) {
  const server = createAncilisMcpServer(options);
  const client = new Client({ name: "ancilis-test-client", version: "0.1.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return { client, server };
}

describe("Ancilis MCP server", () => {
  it("exports MCP server helpers from the package root", () => {
    expect(ancilis.createAncilisMcpServer).toBe(createAncilisMcpServer);
    expect(ancilis.runAncilisMcpServer).toBeDefined();
  });

  it("keeps the stdio server alive until stdin closes", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    let settled = false;

    const serverPromise = runAncilisMcpServer({ stdin, stdout }).then(() => {
      settled = true;
    });

    await delay(25);
    expect(settled).toBe(false);

    stdin.end();
    await serverPromise;
    expect(settled).toBe(true);
  });

  it("lists exactly the Ancilis assessment tools with explicit schemas", async () => {
    const { client, server } = await connectTestClient();

    try {
      const result = await client.listTools();
      const tools = result.tools.map(tool => tool.name);

      expect(tools).toEqual([
        "ancilis_check_posture",
        "ancilis_evaluate_action",
        "ancilis_get_evidence",
      ]);
      for (const tool of result.tools) {
        expect(tool.inputSchema).toMatchObject({ type: "object" });
        expect(tool.outputSchema).toMatchObject({ type: "object" });
      }
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("returns schema-valid placeholder structured output for each tool", async () => {
    const { client, server } = await connectTestClient();

    try {
      const posture = await client.callTool({ name: "ancilis_check_posture", arguments: {} });
      const evaluation = await client.callTool({
        name: "ancilis_evaluate_action",
        arguments: { tool_name: "demo.tool", arguments: { value: 1 } },
      });
      const evidence = await client.callTool({ name: "ancilis_get_evidence", arguments: {} });

      expect(checkPostureOutputSchema.parse(posture.structuredContent)).toMatchObject({
        posture: "not_evaluated",
      });
      expect(evaluateActionOutputSchema.parse(evaluation.structuredContent)).toMatchObject({
        would_store_evidence: false,
      });
      expect(getEvidenceOutputSchema.parse(evidence.structuredContent)).toMatchObject({
        records: [],
        chain_valid: true,
      });
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("evaluates proposed actions through the engine without writing evidence", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "evidence.duckdb");
    await seedEvidence(configPath, dbPath);
    const before = await evidenceCount(configPath, dbPath);
    const { client, server } = await connectTestClient({ configPath, dbPath });

    try {
      const evaluation = await client.callTool({
        name: "ancilis_evaluate_action",
        arguments: {
          tool_name: "demo.tool",
          arguments: { path: "/tmp/card.txt", contents: "4111 1111 1111 1111" },
          session_id: "proposed-session",
        },
      });
      const parsed = evaluateActionOutputSchema.parse(evaluation.structuredContent);

      expect(parsed.would_store_evidence).toBe(false);
      expect(parsed.timestamp).not.toBe(new Date(0).toISOString());
      expect(parsed.decision_reason).not.toMatch(/not implemented/i);
      expect(parsed.mode).toBe("audit");
      expect(parsed.control_results.length).toBeGreaterThan(0);
      expect(parsed.active_overlays).toContain("pci-dss-v4");
      expect(parsed.data_classifications).toContain("DC-CHD");
      expect(parsed.detected_data_types).toEqual(["DC-CHD"]);

      const provenance = parsed.control_results.find(result => result.control_id === "PR-03");
      expect(provenance).toMatchObject({
        result: "FLAG",
        evidence_data: {
          tool_name: "demo.tool",
          registered: true,
          approved: true,
          tool_status: "approved",
        },
      });

      await client.callTool({ name: "ancilis_get_evidence", arguments: { limit: 100 } });
      expect(await evidenceCount(configPath, dbPath)).toBe(before);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("returns deterministic structured output for identical proposed actions", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir);
    const { client, server } = await connectTestClient({ configPath });
    const call = {
      name: "ancilis_evaluate_action",
      arguments: {
        tool_name: "demo.tool",
        arguments: { contents: "4111 1111 1111 1111", path: "/tmp/card.txt" },
        session_id: "proposed-session",
      },
    };

    try {
      const first = await client.callTool(call);
      const second = await client.callTool(call);
      const firstParsed = evaluateActionOutputSchema.parse(first.structuredContent);
      const secondParsed = evaluateActionOutputSchema.parse(second.structuredContent);

      expect(secondParsed).toEqual(firstParsed);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("summarizes seeded evidence into compliant and non-compliant posture states", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "evidence.duckdb");
    await seedEvidence(configPath, dbPath);
    const { client, server } = await connectTestClient({ configPath, dbPath });

    try {
      const allPosture = await client.callTool({ name: "ancilis_check_posture", arguments: {} });
      const parsedAll = checkPostureOutputSchema.parse(allPosture.structuredContent);

      expect(parsedAll.agent).toEqual({
        name: "mcp-agent",
        id: "11111111-1111-4111-8111-111111111111",
        owner: "security",
      });
      expect(parsedAll.posture).toBe("non_compliant");
      expect(parsedAll.summary.total_evaluations).toBe(2);
      expect(parsedAll.summary.decisions).toMatchObject({ ALLOW: 1, BLOCK: 1 });
      expect(parsedAll.evidence.chain_valid).toBe(true);
      expect(parsedAll.controls.find(control => control.control_id === "PR-01")).toMatchObject({
        status: "fail",
        pass: 1,
        fail: 1,
      });

      const sessionPosture = await client.callTool({
        name: "ancilis_check_posture",
        arguments: { session_id: "session-a" },
      });
      expect(checkPostureOutputSchema.parse(sessionPosture.structuredContent).posture).toBe("compliant");
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("returns recent evidence newest-first and honors limit, session, and tool filters", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "evidence.duckdb");
    await seedEvidence(configPath, dbPath);
    const { client, server } = await connectTestClient({ configPath, dbPath });

    try {
      const latest = await client.callTool({
        name: "ancilis_get_evidence",
        arguments: { limit: 1 },
      });
      const parsedLatest = getEvidenceOutputSchema.parse(latest.structuredContent);
      expect(parsedLatest.chain_valid).toBe(true);
      expect(parsedLatest.records.map(record => record.tool_name)).toEqual(["mcp:blocked.tool"]);
      expect(parsedLatest.records[0]).toMatchObject({
        session_id: "session-b",
        output_summary: "newer",
      });

      const filtered = await client.callTool({
        name: "ancilis_get_evidence",
        arguments: { session_id: "session-a", tool_name: "mcp:allowed.tool" },
      });
      const parsedFiltered = getEvidenceOutputSchema.parse(filtered.structuredContent);
      expect(parsedFiltered.records.map(record => record.tool_name)).toEqual(["mcp:allowed.tool"]);
      expect(parsedFiltered.records[0]?.session_id).toBe("session-a");
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("does not create a persistent DuckDB file when read-only evidence path is missing", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "missing.duckdb");
    const { client, server } = await connectTestClient({ configPath, dbPath });

    try {
      const posture = await client.callTool({ name: "ancilis_check_posture", arguments: {} });
      const evidence = await client.callTool({ name: "ancilis_get_evidence", arguments: {} });

      expect(checkPostureOutputSchema.parse(posture.structuredContent)).toMatchObject({
        posture: "not_evaluated",
        evidence: { db_path: dbPath, chain_valid: true, chain_errors: [] },
      });
      expect(getEvidenceOutputSchema.parse(evidence.structuredContent)).toEqual({
        records: [],
        chain_valid: true,
        chain_errors: [],
      });
      expect(existsSync(dbPath)).toBe(false);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("exports output contracts that validate representative stable payloads", () => {
    expect(checkPostureOutputSchema.parse({
      agent: { name: "agent", id: null, owner: null },
      mode: "audit",
      posture: "not_evaluated",
      summary: {
        total_evaluations: 0,
        decisions: {},
        tools_evaluated: [],
        control_pass_rates: {},
      },
      controls: [{
        control_id: "PR-01",
        name: "Identity",
        enabled: true,
        status: "not_evaluated",
        pass: 0,
        fail: 0,
        flag: 0,
        skip: 0,
        error: 0,
      }],
      evidence: { db_path: ":memory:", chain_valid: true, chain_errors: [] },
      warnings: [],
    }).posture).toBe("not_evaluated");

    const parsedEvaluation = evaluateActionOutputSchema.parse({
      action_id: "action-1",
      evaluation_id: "evaluation-1",
      timestamp: "2026-04-20T00:00:00.000Z",
      decision: "ALLOW",
      decision_reason: "All controls passed.",
      mode: "audit",
      control_results: [{
        control_id: "PR-01",
        control_name: "Identity",
        result: "PASS",
        detail: "ok",
        evidence_data: {},
        duration_ms: 0,
        display_name: "Agent Identity",
        display_detail: "Identity must match config",
        remediation_hint: "Set agent.name correctly",
      }],
      active_overlays: [],
      data_classifications: [],
      detected_data_types: [],
      would_store_evidence: false,
    });
    expect(parsedEvaluation.control_results[0]?.display_name).toBe("Agent Identity");
    expect(parsedEvaluation.would_store_evidence).toBe(false);

    expect(getEvidenceOutputSchema.parse({
      records: [{
        record_id: "record-1",
        timestamp: "2026-04-20T00:00:00.000Z",
        agent_id: "agent",
        session_id: null,
        source_type: "mcp",
        tool_name: "demo.tool",
        decision: "ALLOW",
        mode: "audit",
        control_results: [],
        active_overlays: [],
        data_classifications: [],
        active_certifications: [],
        record_hash: "abc",
        previous_hash: "def",
        output_summary: null,
        total_duration_ms: 1,
      }],
      chain_valid: true,
      chain_errors: [],
    }).records).toHaveLength(1);
  });
});
