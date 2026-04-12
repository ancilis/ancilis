/**
 * Parity tests for PR-06, PR-07, PR-08 evaluators (TypeScript ↔ Python).
 */

import { randomUUID } from "node:crypto";
import { describe, expect, it, beforeEach } from "vitest";
import { PR06ConfigBaselineEvaluator } from "../src/ancilis/controls/pr06ConfigBaseline.js";
import { PR07TransportEvaluator } from "../src/ancilis/controls/pr07Transport.js";
import { PR08InputEvaluator } from "../src/ancilis/controls/pr08Input.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { Action } from "../src/ancilis/engine/action.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";

function makeConfig(): ResolvedConfig {
  return loadConfig({ raw: { agent: { name: "test-agent" } } });
}

function makeAction(overrides: {
  toolName?: string;
  descriptionHash?: string | null;
  params?: Record<string, unknown>;
  context?: Record<string, unknown>;
} = {}): Action {
  return {
    actionId: randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "test-agent",
    agentOwner: null,
    actionType: "tool_call",
    sourceType: "framework",
    producerType: "framework",
    producerVersion: "0.1.0",
    tool: {
      name: overrides.toolName ?? "test-tool",
      descriptionHash: "descriptionHash" in overrides ? overrides.descriptionHash : "abc123hash",
    },
    parameters: {
      raw: overrides.params ?? {},
      parameterHash: "param-hash",
    },
    context: overrides.context ?? {},
  };
}

// ─── PR-06 ─────────────────────────────────────────────────────────────────

describe("PR06ConfigBaselineEvaluator", () => {
  let evaluator: PR06ConfigBaselineEvaluator;
  const config = makeConfig();

  beforeEach(() => {
    evaluator = new PR06ConfigBaselineEvaluator();
  });

  it("establishes baseline on first call and returns PASS", () => {
    const result = evaluator.evaluate(makeAction({ descriptionHash: "hash-v1" }), config);
    expect(result.result).toBe("PASS");
    expect(result.detail).toContain("baseline established");
    expect(result.evidenceData).toMatchObject({ baseline_established: true, hash_match: true });
  });

  it("returns PASS when hash matches baseline on second call", () => {
    const action = makeAction({ descriptionHash: "hash-v1" });
    evaluator.evaluate(action, config);
    const second = evaluator.evaluate(makeAction({ descriptionHash: "hash-v1" }), config);
    expect(second.result).toBe("PASS");
    expect(second.detail).toContain("matches baseline");
  });

  it("returns FAIL when description hash changes (drift detected)", () => {
    evaluator.evaluate(makeAction({ descriptionHash: "hash-v1" }), config);
    const result = evaluator.evaluate(makeAction({ descriptionHash: "hash-v2" }), config);
    expect(result.result).toBe("FAIL");
    expect(result.detail).toContain("drift detected");
    expect(result.evidenceData).toMatchObject({ hash_match: false });
  });

  it("returns SKIP when tool has no descriptionHash", () => {
    const result = evaluator.evaluate(makeAction({ descriptionHash: null }), config);
    expect(result.result).toBe("SKIP");
  });

  it("returns SKIP when action has no tool name", () => {
    const action = makeAction({ toolName: "" });
    (action.tool as { name: string }).name = "";
    const result = evaluator.evaluate(action, config);
    expect(result.result).toBe("SKIP");
  });

  it("tracks baselines per tool independently", () => {
    evaluator.evaluate(makeAction({ toolName: "tool-a", descriptionHash: "hash-a1" }), config);
    evaluator.evaluate(makeAction({ toolName: "tool-b", descriptionHash: "hash-b1" }), config);

    // tool-a drifts, tool-b stays same
    const driftA = evaluator.evaluate(makeAction({ toolName: "tool-a", descriptionHash: "hash-a2" }), config);
    const stableB = evaluator.evaluate(makeAction({ toolName: "tool-b", descriptionHash: "hash-b1" }), config);

    expect(driftA.result).toBe("FAIL");
    expect(stableB.result).toBe("PASS");
  });
});

// ─── PR-07 ─────────────────────────────────────────────────────────────────

describe("PR07TransportEvaluator", () => {
  const evaluator = new PR07TransportEvaluator();
  const config = makeConfig();

  it("returns PASS when no URLs present", () => {
    const result = evaluator.evaluate(makeAction({ params: { query: "hello" } }), config);
    expect(result.result).toBe("PASS");
    expect(result.detail).toContain("No URLs found");
  });

  it("returns PASS for https:// URLs", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { url: "https://api.example.com/data" } }),
      config,
    );
    expect(result.result).toBe("PASS");
    expect(result.detail).toContain("secure transport");
  });

  it("returns PASS for wss:// URLs", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { ws_url: "wss://stream.example.com" } }),
      config,
    );
    expect(result.result).toBe("PASS");
  });

  it("returns FAIL for http:// URL pointing to external host", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { url: "http://api.example.com/data" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
    expect(result.detail).toContain("Insecure transport");
    expect(result.evidenceData).toMatchObject({ insecure_urls: ["http://api.example.com/data"] });
  });

  it("returns FAIL for ws:// URL pointing to external host", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { ws: "ws://stream.example.com" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
  });

  it("exempts localhost http:// from FAIL", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { url: "http://localhost:3000/health" } }),
      config,
    );
    expect(result.result).toBe("PASS");
    expect((result.evidenceData as { localhost_exempt: string[] }).localhost_exempt).toHaveLength(1);
  });

  it("exempts 127.0.0.1 http:// from FAIL", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { url: "http://127.0.0.1:8080/" } }),
      config,
    );
    expect(result.result).toBe("PASS");
  });

  it("also checks context server_url", () => {
    const result = evaluator.evaluate(
      makeAction({ context: { server_url: "http://external.example.com" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
  });

  it("checks nested URL keys one level deep", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { connection: { url: "http://insecure.example.com" } } }),
      config,
    );
    expect(result.result).toBe("FAIL");
  });

  it("checks all known URL keys — baseUrl, endpoint, api_url, etc.", () => {
    for (const key of ["endpoint", "baseUrl", "base_url", "api_url"]) {
      const r = evaluator.evaluate(
        makeAction({ params: { [key]: "http://bad.example.com" } }),
        config,
      );
      expect(r.result, `expected FAIL for key '${key}'`).toBe("FAIL");
    }
  });
});

// ─── PR-08 ─────────────────────────────────────────────────────────────────

describe("PR08InputEvaluator", () => {
  const evaluator = new PR08InputEvaluator();
  const config = makeConfig();

  it("returns PASS for clean input", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { query: "show me the status" } }),
      config,
    );
    expect(result.result).toBe("PASS");
    expect(result.evidenceData).toMatchObject({ scan_result: "clean", patterns_found: [] });
  });

  it("returns FAIL for SQL DROP TABLE injection", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { input: "; DROP TABLE users" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
    expect((result.evidenceData as { patterns_found: string[] }).patterns_found).toContain("sql_drop_table");
  });

  it("returns FAIL for UNION SELECT injection", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { query: "x UNION SELECT * FROM secrets" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
    expect((result.evidenceData as { patterns_found: string[] }).patterns_found).toContain("sql_union_select");
  });

  it("returns FAIL for OR 1=1 injection", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { user: "admin' OR 1=1" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
    expect((result.evidenceData as { patterns_found: string[] }).patterns_found).toContain("sql_or_injection");
  });

  it("returns FAIL for command injection with subshell", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { cmd: "echo $(cat /etc/shadow)" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
    expect((result.evidenceData as { patterns_found: string[] }).patterns_found).toContain("cmd_subshell");
  });

  it("returns FAIL for path traversal", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { path: "../../etc/passwd" } }),
      config,
    );
    expect(result.result).toBe("FAIL");
    const patterns = (result.evidenceData as { patterns_found: string[] }).patterns_found;
    expect(patterns.some(p => p.startsWith("path_"))).toBe(true);
  });

  it("returns FLAG for suspicious-only sql_comment_injection", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { query: "SELECT * FROM users WHERE name='admin'--" } }),
      config,
    );
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData).toMatchObject({ scan_result: "suspicious" });
  });

  it("returns PASS for empty params", () => {
    const result = evaluator.evaluate(makeAction({ params: {} }), config);
    expect(result.result).toBe("PASS");
  });

  it("scans nested objects up to depth 3 for Python parity", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { outer: { inner: "; DROP TABLE accounts" } } }),
      config,
    );
    expect(result.result).toBe("FAIL");
  });

  it("scans array string values for Python parity", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { items: ["safe", "; DROP TABLE orders"] } }),
      config,
    );
    expect(result.result).toBe("FAIL");
  });

  it("reports parameter_keys in evidence", () => {
    const result = evaluator.evaluate(
      makeAction({ params: { foo: "clean", bar: "also clean" } }),
      config,
    );
    expect((result.evidenceData as { parameter_keys: string[] }).parameter_keys).toEqual(["foo", "bar"]);
  });
});
