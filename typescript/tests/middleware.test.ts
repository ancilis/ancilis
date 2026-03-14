/**
 * Tests for ancilis middleware — Unit 3: MCP Middleware & Pattern Detection.
 */

import { describe, it, expect, vi } from "vitest";
import { loadConfig } from "../src/ancilis/config/index.js";
import { AncilisMiddleware, BlockedToolCallError } from "../src/ancilis/middleware/middleware.js";
import type { McpClientLike } from "../src/ancilis/middleware/middleware.js";
import { scanResponse } from "../src/ancilis/middleware/response-scanner.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { ToolStatus } from "../src/ancilis/engine/index.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";

function makeConfig(overrides: Record<string, unknown> = {}): ResolvedConfig {
  return loadConfig({ raw: { agent: { name: "test-agent" }, ...overrides } });
}

function makeMw(client: McpClientLike, opts: { config?: ResolvedConfig } = {}): AncilisMiddleware {
  const config = opts.config ?? makeConfig();
  return new AncilisMiddleware(client, { config, evidenceStore: new EvidenceStore(config, { inMemory: true }) });
}

function mockClient(options: {
  callToolReturn?: { content: Array<{ type: string; text?: string }> };
  tools?: Array<{ name: string; description?: string }>;
} = {}): McpClientLike {
  const callToolReturn = options.callToolReturn ?? { content: [{ type: "text", text: "OK" }] };
  return {
    callTool: vi.fn().mockResolvedValue(callToolReturn),
    listTools: vi.fn().mockResolvedValue({ tools: options.tools ?? [] }),
  };
}

// --- Middleware Initialization ---

describe("Middleware Init", () => {
  it("initializes with config object", () => {
    const config = makeConfig();
    const client = mockClient();
    const mw = makeMw(client, { config });
    expect(mw.config.agentName).toBe("test-agent");
  });

  it("initializes with minimal config", () => {
    const config = makeConfig();
    const mw = makeMw(mockClient(), { config });
    expect(mw.config.mode).toBe("audit");
  });
});

// --- Tool Call Interception ---

describe("Tool Call Interception", () => {
  it("audit mode allows and forwards", async () => {
    const config = makeConfig();
    const client = mockClient();
    const mw = makeMw(client, { config });
    mw.registry.register({ name: "my-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    const result = await mw.callTool("my-tool", { key: "value" });
    expect(client.callTool).toHaveBeenCalledWith({ name: "my-tool", arguments: { key: "value" } });
    expect(result.content[0]!.text).toBe("OK");
  });

  it("enforce mode all pass forwards", async () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const client = mockClient();
    const mw = makeMw(client, { config });
    mw.registry.register({ name: "my-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("my-tool", { key: "value" });
    expect(client.callTool).toHaveBeenCalled();
  });

  it("enforce mode control fails blocks", async () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const client = mockClient();
    const mw = makeMw(client, { config });

    await expect(mw.callTool("unknown-tool", {})).rejects.toThrow(BlockedToolCallError);
    expect(client.callTool).not.toHaveBeenCalled();
  });

  it("blocked call has evaluation", async () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const client = mockClient();
    const mw = makeMw(client, { config });

    try {
      await mw.callTool("unknown-tool", {});
    } catch (e) {
      expect(e).toBeInstanceOf(BlockedToolCallError);
      expect((e as BlockedToolCallError).evaluation.decision).toBe("BLOCK");
    }
  });

  it("action built correctly", async () => {
    const config = makeConfig();
    const client = mockClient();
    const mw = makeMw(client, { config });
    mw.registry.register({ name: "my-tool", version: "1.0", descriptionHash: "abc", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("my-tool", { param: "val" });
    const ev = mw.getLastEvaluation();
    expect(ev).toBeDefined();
    expect(ev!.agentId).toBe("test-agent");
    expect(ev!.mode).toBe("audit");
  });
});

// --- Auto-Discovery ---

describe("Auto-Discovery", () => {
  it("list_tools registers tools", async () => {
    const tools = [
      { name: "tool-a", description: "Description A" },
      { name: "tool-b", description: "Description B" },
    ];
    const client = mockClient({ tools });
    const mw = makeMw(client);

    await mw.listTools();
    expect(mw.registry.isRegistered("tool-a")).toBe(true);
    expect(mw.registry.isRegistered("tool-b")).toBe(true);
  });

  it("discovered tool passes provenance", async () => {
    const tools = [{ name: "tool-a", description: "Desc A" }];
    const client = mockClient({ tools });
    const config = makeConfig({ security: { mode: "enforce", tools: { allowed: ["tool-a"] } } });
    const mw = makeMw(client, { config });

    await mw.listTools();
    await mw.callTool("tool-a", {});
    expect(client.callTool).toHaveBeenCalled();
  });

  it("description drift detected", async () => {
    const client: McpClientLike = {
      callTool: vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] }),
      listTools: vi.fn()
        .mockResolvedValueOnce({ tools: [{ name: "tool-a", description: "Version 1" }] })
        .mockResolvedValueOnce({ tools: [{ name: "tool-a", description: "Version 2 changed" }] }),
    };
    const mw = makeMw(client);

    await mw.listTools();
    await mw.listTools();

    expect(mw.driftEvents.length).toBe(1);
    expect(mw.driftEvents[0]!.toolName).toBe("tool-a");
  });
});

// --- Pattern Detection on Responses ---

describe("Response Scanning", () => {
  it("SSN in response generates recommendation", async () => {
    const client = mockClient({ callToolReturn: { content: [{ type: "text", text: "Patient SSN: 123-45-6789" }] } });
    const mw = makeMw(client);
    mw.registry.register({ name: "patient-lookup", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("patient-lookup", {});
    const recs = mw.getRecommendations();
    expect(recs.some(r => r.includes("personal_info"))).toBe(true);
  });

  it("credit card in response detected", async () => {
    const client = mockClient({ callToolReturn: { content: [{ type: "text", text: "Card: 4111 1111 1111 1111" }] } });
    const mw = makeMw(client);
    mw.registry.register({ name: "payment-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("payment-tool", {});
    expect(mw.getRecommendations().some(r => r.includes("credit_cards"))).toBe(true);
  });

  it("high entropy flagged as encrypted", async () => {
    const encrypted = "aK7xP9mQ2rT5wB8nY1cD4fG6hJ0kL3vE".repeat(2);
    const client = mockClient({ callToolReturn: { content: [{ type: "text", text: `Data: ${encrypted}` }] } });
    const mw = makeMw(client);
    mw.registry.register({ name: "secure-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("secure-tool", {});
    expect(mw.scanResults.length).toBeGreaterThan(0);
    expect(mw.scanResults[0]!.encryptionFindings.some(f => f.findingType === "high_entropy")).toBe(true);
  });

  it("clean response no recommendations", async () => {
    const client = mockClient({ callToolReturn: { content: [{ type: "text", text: "Everything is fine. Status: OK" }] } });
    const mw = makeMw(client);
    mw.registry.register({ name: "status-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("status-tool", {});
    expect(mw.getRecommendations().length).toBe(0);
  });

  it("recommendations accumulate", async () => {
    const client: McpClientLike = {
      callTool: vi.fn()
        .mockResolvedValueOnce({ content: [{ type: "text", text: "SSN: 123-45-6789" }] })
        .mockResolvedValueOnce({ content: [{ type: "text", text: "Card: 4111 1111 1111 1111" }] }),
      listTools: vi.fn().mockResolvedValue({ tools: [] }),
    };
    const mw = makeMw(client);
    mw.registry.register({ name: "tool-a", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });
    mw.registry.register({ name: "tool-b", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("tool-a", {});
    await mw.callTool("tool-b", {});
    expect(mw.getRecommendations().length).toBeGreaterThanOrEqual(2);
  });
});

// --- Enforcement ---

describe("Enforcement", () => {
  it("audit failure allows through", async () => {
    const client = mockClient();
    const mw = makeMw(client);

    const result = await mw.callTool("unregistered-tool", {});
    expect(client.callTool).toHaveBeenCalled();
    expect(mw.getLastEvaluation()!.decision).toBe("ALLOW");
  });

  it("enforce failure blocks", async () => {
    const client = mockClient();
    const mw = makeMw(client, { config: makeConfig({ security: { mode: "enforce" } }) });

    await expect(mw.callTool("unregistered-tool", {})).rejects.toThrow(BlockedToolCallError);
    expect(client.callTool).not.toHaveBeenCalled();
  });
});

// --- Engine Integration ---

describe("Engine Integration", () => {
  it("evaluation result accessible", async () => {
    const client = mockClient();
    const mw = makeMw(client);
    mw.registry.register({ name: "my-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("my-tool", { x: 1 });
    const ev = mw.getLastEvaluation();
    expect(ev).toBeDefined();
    expect(ev!.controlResults.length).toBeGreaterThan(0);
  });

  it("evaluation log grows", async () => {
    const client = mockClient();
    const mw = makeMw(client);
    mw.registry.register({ name: "tool-a", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("tool-a", {});
    await mw.callTool("tool-a", {});
    expect(mw.evaluationLog.length).toBe(2);
  });
});

// --- Edge Cases ---

describe("Edge Cases", () => {
  it("empty parameters", async () => {
    const client = mockClient();
    const mw = makeMw(client);
    mw.registry.register({ name: "my-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await mw.callTool("my-tool");
    expect(client.callTool).toHaveBeenCalledWith({ name: "my-tool", arguments: undefined });
  });

  it("MCP server error handled", async () => {
    const client: McpClientLike = {
      callTool: vi.fn().mockRejectedValue(new Error("MCP server down")),
      listTools: vi.fn().mockResolvedValue({ tools: [] }),
    };
    const mw = makeMw(client);
    mw.registry.register({ name: "my-tool", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });

    await expect(mw.callTool("my-tool", {})).rejects.toThrow("MCP server down");
    expect(mw.evaluationLog.length).toBe(1);
  });
});

// --- Response Scanner Unit Tests ---

describe("Response Scanner", () => {
  it("scan response SSN", () => {
    const result = scanResponse("test-tool", "SSN: 000-00-0000");
    expect(result.patterns.some(p => p.patternType === "ssn")).toBe(true);
    expect(result.recommendations.some(r => r.includes("personal_info"))).toBe(true);
  });

  it("scan response clean", () => {
    const result = scanResponse("test-tool", "Everything is normal.");
    expect(result.patterns.length).toBe(0);
    expect(result.recommendations.length).toBe(0);
  });

  it("scan response JWT", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz";
    const result = scanResponse("test-tool", `Token: ${jwt}`);
    expect(result.encryptionFindings.some(f => f.findingType === "jwt_token")).toBe(true);
  });
});
