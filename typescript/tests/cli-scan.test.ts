/**
 * Integration tests for `ancilis scan` CLI command.
 * Parity with python/tests/test_cli_scan.py (11 test cases).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { stringify as stringifyYaml } from "yaml";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine, ToolRegistry, ToolStatus } from "../src/ancilis/engine/index.js";
import type { Action, EvaluationResult } from "../src/ancilis/engine/index.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import { handleScan } from "../src/ancilis/cli/scan.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-scan-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(dir: string, data: Record<string, unknown>): string {
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, stringifyYaml(data));
  return path;
}

function minimalConfig(): Record<string, unknown> {
  return { agent: { name: "test-agent" } };
}

function captureIo(): {
  io: { stdout(message: string): void; stderr(message: string): void };
  stdout(): string;
  stderr(): string;
} {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout(msg) { out.push(msg); },
      stderr(msg) { err.push(msg); },
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

/** Minimal EvaluationResult with a PR-02 FAIL and BLOCK decision; no session context. */
function makeFailEvaluation(decision: "BLOCK" | "FLAG" = "BLOCK"): EvaluationResult {
  return {
    evaluationId: `fail-eval-${randomUUID()}`,
    actionId: `fail-action-${randomUUID()}`,
    timestamp: new Date().toISOString(),
    agentId: "test-agent",
    sourceType: "agent",
    mode: "enforce",
    controlResults: [
      {
        controlId: "PR-02",
        controlName: "Scope",
        result: "FAIL",
        detail: "Tool is not in the allowlist.",
        evidenceData: {},
        durationMs: 1.0,
      },
    ],
    decision,
    decisionReason: "Blocked by scope",
    activeOverlays: [],
    dataClassifications: [],
    totalDurationMs: 1.0,
    // No context → session_id stored as NULL
  };
}

/** Store n clean passing evaluations; each tagged with sessionId "sess-1". */
async function populateCleanEvidence(config: ResolvedConfig, store: EvidenceStore, n = 3): Promise<void> {
  const registry = new ToolRegistry();
  registry.register({
    name: "read_file",
    status: ToolStatus.APPROVED,
    approvedBy: "config",
    firstSeen: new Date().toISOString(),
    statusChanged: new Date().toISOString(),
  });
  const engine = new Engine(config, { registry });
  for (let i = 0; i < n; i++) {
    const action: Action = {
      actionId: `action-${randomUUID()}`,
      timestamp: new Date().toISOString(),
      agentId: config.agentName,
      agentOwner: "test-owner",
      actionType: "tool_call",
      tool: { name: "read_file" },
      parameters: { raw: {} } as any,
      context: { sessionId: "sess-1" } as any,
    };
    const evaluation = engine.evaluate(action);
    // Propagate session id into result so store records session_id = "sess-1"
    evaluation.context = { sessionId: "sess-1" };
    await store.store(evaluation, "read_file");
  }
}

// ---------------------------------------------------------------------------
// Scan behaviour tests
// ---------------------------------------------------------------------------

describe("TestScanCommand", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("clean evidence → exit 0", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateCleanEvidence(config, store);
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(0);
    expect(capture.stdout().toLowerCase()).toContain("compliant");
  });

  it("--ci with clean evidence → valid JSON, exit 0", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateCleanEvidence(config, store);
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { ci: true, config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(0);
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    expect(data["version"]).toBe("0.1.0");
    expect(data["agent"]).toBe("test-agent");
    expect(data["posture"]).toBe("compliant");
    expect(data["exit_code"]).toBe(0);
    expect(Array.isArray(data["controls"])).toBe(true);
    const summary = data["summary"] as Record<string, unknown>;
    expect(typeof summary["passing"]).toBe("number");
    expect(typeof summary["total_controls"]).toBe("number");
    expect(typeof data["timestamp"]).toBe("string");
  });

  it("violations → exit 1", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    await store.store(makeFailEvaluation("BLOCK"), "blocked-tool");
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { config: cfgPath, db: dbPath, period: "1y", all: true },
      capture.io,
    );

    expect(exitCode).toBe(1);
    expect(capture.stdout().toLowerCase()).toContain("non_compliant");
  });

  it("--ci with violations → JSON shows failing controls, exit 1", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    await store.store(makeFailEvaluation("BLOCK"), "blocked-tool");
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { ci: true, config: cfgPath, db: dbPath, period: "1y", all: true },
      capture.io,
    );

    expect(exitCode).toBe(1);
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    expect(data["posture"]).toBe("non_compliant");
    expect(data["exit_code"]).toBe(1);
    const controls = data["controls"] as Array<Record<string, unknown>>;
    const failing = controls.filter(c => c["status"] === "fail");
    expect(failing.length).toBeGreaterThan(0);
  });

  it("missing config → falls back to zero-config default, exit 0", async () => {
    const capture = captureIo();
    const exitCode = await handleScan(
      { config: join(dir, "missing.yaml"), db: join(dir, "evidence.duckdb") },
      capture.io,
    );

    expect(exitCode).toBe(0);
    expect(capture.stdout()).toContain("Ancilis scan");
  });

  it("no --ci flag → human-readable output (not JSON)", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateCleanEvidence(config, store);
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(0);
    // Human output has "Ancilis scan" header
    expect(capture.stdout()).toContain("Ancilis scan");
    // Should not be valid JSON
    expect(() => JSON.parse(capture.stdout())).toThrow();
  });

  it("--session scopes to named session — different session sees no evaluations", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    // Store a violation with no session (NULL)
    await store.store(makeFailEvaluation("BLOCK"), "blocked-tool");
    await store.close();

    const capture = captureIo();
    // Scan a different session — no records with session_id="sess-clean"
    const exitCode = await handleScan(
      { ci: true, config: cfgPath, db: dbPath, period: "1y", session: "sess-clean" },
      capture.io,
    );

    expect(exitCode).toBe(0);
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    expect(data["posture"]).toBe("compliant");
    const summary = data["summary"] as Record<string, unknown>;
    expect(summary["total_evaluations"]).toBe(0);
  });

  it("no evaluations in store → exit 0, no-evidence guidance or no-evaluations message", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");

    const capture = captureIo();
    const exitCode = await handleScan(
      { config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(0);
    // Either first-run guidance ("No tool-call evidence") or regular human output ("No evaluations recorded")
    expect(capture.stdout()).toMatch(/[Nn]o.*(tool-call evidence|evaluations)/);
  });

  it("--ci schema fields all present with empty store", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");

    const capture = captureIo();
    const exitCode = await handleScan(
      { ci: true, config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(0);
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    const requiredTop = ["version", "agent", "mode", "timestamp", "controls", "summary", "posture", "exit_code"];
    for (const field of requiredTop) {
      expect(data, `missing top-level field: ${field}`).toHaveProperty(field);
    }
    const summary = data["summary"] as Record<string, unknown>;
    const requiredSummary = ["total_controls", "passing", "failing", "skipped", "total_evaluations"];
    for (const field of requiredSummary) {
      expect(summary, `missing summary field: ${field}`).toHaveProperty(field);
    }
  });
});

// ---------------------------------------------------------------------------
// Latest-session default tests
// ---------------------------------------------------------------------------

describe("TestScanLatestSessionDefault", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("default scan shows only latest session — prior violations in NULL session don't bleed in", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });

    // Old session: BLOCK violation stored with NULL session_id
    await store.store(makeFailEvaluation("BLOCK"), "bad-tool");

    // Latest session: clean passes with session_id="sess-1"
    await populateCleanEvidence(config, store, 3);
    await store.close();

    const capture = captureIo();
    // Default scan (no --all, no --session) → should pick up latest session "sess-1" only
    const exitCode = await handleScan(
      { ci: true, config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(0, capture.stdout());
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    expect(data["posture"]).toBe("compliant");
  });

  it("--all shows all sessions including prior violations", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });

    // Old failure: NULL session_id
    await store.store(makeFailEvaluation("BLOCK"), "bad-tool");
    // Latest session: clean
    await populateCleanEvidence(config, store, 3);
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { ci: true, all: true, config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(1);
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    expect(data["posture"]).toBe("non_compliant");
  });

  it("--session <id> scopes to that session regardless of latest-session default", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });

    // Store 2 clean evals with session_id="sess-1"
    await populateCleanEvidence(config, store, 2);
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { ci: true, session: "sess-1", config: cfgPath, db: dbPath, period: "1y" },
      capture.io,
    );

    expect(exitCode).toBe(0);
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    expect(data["posture"]).toBe("compliant");
    const summary = data["summary"] as Record<string, unknown>;
    expect(summary["total_evaluations"]).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// SKIP-only controls are pending, not passing (0.2.0)
// ---------------------------------------------------------------------------

describe("TestScanSkipIsPending", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /** EvaluationResult where PR-01 only ever SKIPs. */
  function makeSkipEvaluation(): EvaluationResult {
    return {
      evaluationId: `skip-eval-${randomUUID()}`,
      actionId: `skip-action-${randomUUID()}`,
      timestamp: new Date().toISOString(),
      agentId: "test-agent",
      sourceType: "agent",
      mode: "audit",
      controlResults: [
        {
          controlId: "PR-01",
          controlName: "Identity",
          result: "SKIP",
          detail: "No evaluator ran.",
          evidenceData: {},
          durationMs: 1.0,
        },
      ],
      decision: "ALLOW",
      decisionReason: "audit",
      activeOverlays: [],
      dataClassifications: [],
      totalDurationMs: 1.0,
    };
  }

  it("--ci reports a SKIP-only control as pending with a zero pass rate", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    await store.store(makeSkipEvaluation(), "read_file");
    await store.close();

    const capture = captureIo();
    const exitCode = await handleScan(
      { ci: true, config: cfgPath, db: dbPath, period: "1y", all: true },
      capture.io,
    );

    expect(exitCode).toBe(0);
    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    const controls = data["controls"] as Array<Record<string, unknown>>;
    const pr01 = controls.find((c) => c["id"] === "PR-01")!;

    expect(pr01["status"]).toBe("pending");
    expect(pr01["skips"]).toBe(1);
    expect(pr01["evaluated"]).toBe(0);
    expect(pr01["pass_rate"]).toBe(0);

    const summary = data["summary"] as Record<string, unknown>;
    expect(summary["pending"]).toBe(1);
    expect(summary["passing"]).toBe(0);
    // Pending is not a violation — posture stays compliant with exit 0.
    expect(data["posture"]).toBe("compliant");
  });

  it("--ci pass_rate is computed over evaluated (non-SKIP) results", async () => {
    const cfgPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: cfgPath });
    const store = new EvidenceStore(config, { dbPath });
    const mixed = makeSkipEvaluation();
    mixed.controlResults = [
      { controlId: "PR-01", controlName: "Identity", result: "PASS", detail: "ok", evidenceData: {}, durationMs: 1.0 },
      { controlId: "PR-01", controlName: "Identity", result: "SKIP", detail: "skipped", evidenceData: {}, durationMs: 1.0 },
    ];
    await store.store(mixed, "read_file");
    await store.close();

    const capture = captureIo();
    await handleScan({ ci: true, config: cfgPath, db: dbPath, period: "1y", all: true }, capture.io);

    const data = JSON.parse(capture.stdout()) as Record<string, unknown>;
    const controls = data["controls"] as Array<Record<string, unknown>>;
    const pr01 = controls.find((c) => c["id"] === "PR-01")!;

    expect(pr01["status"]).toBe("pass");
    expect(pr01["evaluations"]).toBe(2);
    expect(pr01["evaluated"]).toBe(1);
    expect(pr01["pass_rate"]).toBe(100);
  });
});
