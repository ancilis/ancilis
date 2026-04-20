import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import {
  checkPostureOutputSchema,
  createAncilisMcpServer,
  evaluateActionOutputSchema,
  getEvidenceOutputSchema,
} from "../src/ancilis/mcp/index.js";

async function connectTestClient() {
  const server = createAncilisMcpServer();
  const client = new Client({ name: "ancilis-test-client", version: "0.1.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return { client, server };
}

describe("Ancilis MCP server", () => {
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

    expect(evaluateActionOutputSchema.parse({
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
      }],
      active_overlays: [],
      data_classifications: [],
      detected_data_types: [],
      would_store_evidence: false,
    }).would_store_evidence).toBe(false);

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
