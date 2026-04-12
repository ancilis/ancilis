/**
 * Tests for ancilis evidence — Unit 4: Evidence Generation & Storage.
 */

import { describe, it, expect, afterEach } from "vitest";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import duckdb from "duckdb";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import type { EvaluationResult } from "../src/ancilis/engine/result.js";
import { GENESIS_SEED, canonicalPayload, computeHash } from "../src/ancilis/evidence/chain.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";

function makeConfig(overrides: Record<string, unknown> = {}): ResolvedConfig {
  return loadConfig({ raw: { agent: { name: "test-agent" }, ...overrides } });
}

function makeEvaluation(overrides: Partial<EvaluationResult> = {}): EvaluationResult {
  return {
    evaluationId: "eval-001",
    actionId: "action-001",
    timestamp: "2025-01-15T10:30:00Z",
    agentId: "test-agent",
    sourceType: "mcp",
    mode: "audit",
    controlResults: [
      {
        controlId: "PR-01",
        controlName: "Agent Identity",
        result: "PASS",
        detail: "Agent identity verified",
        evidenceData: { agent_id: "test-agent" },
        durationMs: 1.5,
      },
    ],
    decision: "ALLOW",
    decisionReason: "All controls passed",
    activeOverlays: [],
    dataClassifications: [],
    totalDurationMs: 5.0,
    ...overrides,
  };
}

function queryOneString(dbPath: string, sql: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const db = new duckdb.Database(dbPath);
    const conn = db.connect();
    conn.all(sql, (err: duckdb.DuckDbError | null, rows: duckdb.TableData) => {
      if (err) {
        conn.close(() => db.close(() => reject(err)));
        return;
      }
      const value = ((rows[0] as Record<string, unknown> | undefined)?.control_results ?? "") as string;
      conn.close(() => db.close(() => resolve(value)));
    });
  });
}

// --- Hash Chain ---

describe("Hash Chain", () => {
  it("genesis seed is deterministic", () => {
    expect(GENESIS_SEED).toBe(GENESIS_SEED);
    expect(GENESIS_SEED.length).toBe(64);
  });

  it("canonical payload is deterministic", () => {
    const args = {
      evaluationId: "e1",
      timestamp: "2025-01-01T00:00:00Z",
      agentId: "agent",
      sourceType: "agent",
      toolName: "tool",
      decision: "ALLOW",
      mode: "audit",
      controlResults: [] as Array<Record<string, unknown>>,
      activeOverlays: [] as string[],
      dataClassifications: [] as string[],
      activeCertifications: [] as string[],
      totalDurationMs: 1.0,
      previousHash: GENESIS_SEED,
    };
    expect(canonicalPayload(args)).toBe(canonicalPayload(args));
  });

  it("canonical payload has sorted keys", () => {
    const payload = canonicalPayload({
      evaluationId: "e1",
      timestamp: "t1",
      agentId: "a1",
      sourceType: "agent",
      toolName: "tool",
      decision: "ALLOW",
      mode: "audit",
      controlResults: [],
      activeOverlays: [],
      dataClassifications: [],
      activeCertifications: [],
      totalDurationMs: 0.0,
      previousHash: "prev",
    });
    const parsed = JSON.parse(payload);
    const keys = Object.keys(parsed);
    expect(keys).toEqual([...keys].sort());
  });

  it("canonical payload matches Python-style recursive JSON canonicalization", () => {
    const payload = canonicalPayload({
      evaluationId: "e1",
      timestamp: "2025-01-01T00:00:00Z",
      agentId: "agent",
      sourceType: "agent",
      toolName: "tool",
      decision: "ALLOW",
      mode: "audit",
      controlResults: [
        {
          result: "PASS",
          detail: "Agent identity verified",
          control_name: "Agent Identity",
          control_id: "PR-01",
          evidence_data: {
            z_last: "z",
            a_first: "a",
          },
          duration_ms: 1,
        },
      ],
      activeOverlays: [],
      dataClassifications: [],
      activeCertifications: [],
      totalDurationMs: 5,
      previousHash: GENESIS_SEED,
    });

    expect(payload).toBe(
      `{"active_certifications":[],"active_overlays":[],"agent_id":"agent","control_results":[{"control_id":"PR-01","control_name":"Agent Identity","detail":"Agent identity verified","duration_ms":1.0,"evidence_data":{"a_first":"a","z_last":"z"},"result":"PASS"}],"data_classifications":[],"decision":"ALLOW","evaluation_id":"e1","mode":"audit","previous_hash":"${GENESIS_SEED}","source_type":"agent","timestamp":"2025-01-01T00:00:00Z","tool_name":"tool","total_duration_ms":5.0}`,
    );
  });

  it("canonical payload escapes unicode strings and preserves nested float literals like Python json.dumps", () => {
    const payload = canonicalPayload({
      evaluationId: "e1",
      timestamp: "2025-01-01T00:00:00Z",
      agentId: "agent",
      sourceType: "agent",
      toolName: "tool",
      decision: "ALLOW",
      mode: "audit",
      controlResults: [
        {
          control_id: "DE-01",
          control_name: "Behavioral Anomaly Detection",
          detail: "Baseline not yet established — monitoring started.",
          duration_ms: 1.0,
          evidence_data: {
            current_rate_vs_baseline: 0.0,
            display_message: "Tool call frequency is 1.0x above baseline average — normal",
          },
          result: "PASS",
        },
      ],
      activeOverlays: [],
      dataClassifications: [],
      activeCertifications: [],
      totalDurationMs: 5.0,
      previousHash: GENESIS_SEED,
    });

    expect(payload).toBe(
      `{"active_certifications":[],"active_overlays":[],"agent_id":"agent","control_results":[{"control_id":"DE-01","control_name":"Behavioral Anomaly Detection","detail":"Baseline not yet established \\u2014 monitoring started.","duration_ms":1.0,"evidence_data":{"current_rate_vs_baseline":0.0,"display_message":"Tool call frequency is 1.0x above baseline average \\u2014 normal"},"result":"PASS"}],"data_classifications":[],"decision":"ALLOW","evaluation_id":"e1","mode":"audit","previous_hash":"${GENESIS_SEED}","source_type":"agent","timestamp":"2025-01-01T00:00:00Z","tool_name":"tool","total_duration_ms":5.0}`,
    );
  });

  it("compute hash produces SHA-256", () => {
    const h = computeHash("test data");
    expect(h.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(h)).toBe(true);
  });

  it("different input different hash", () => {
    expect(computeHash("input1")).not.toBe(computeHash("input2"));
  });
});

// --- Evidence Store ---

describe("Evidence Store", () => {
  let store: EvidenceStore;

  afterEach(async () => {
    if (store) await store.close();
  });

  it("store creates record", async () => {
    const config = makeConfig();
    store = new EvidenceStore(config, { inMemory: true });
    const ev = makeEvaluation();

    const record = await store.store(ev, "my-tool");
    expect(record.evaluationId).toBe("eval-001");
    expect(record.sourceType).toBe("mcp");
    expect(record.toolName).toBe("my-tool");
    expect(record.decision).toBe("ALLOW");
    expect(record.recordHash.length).toBe(64);
  });

  it("first record uses genesis seed", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });
    const record = await store.store(makeEvaluation(), "tool-a");
    expect(record.previousHash).toBe(GENESIS_SEED);
  });

  it("hash chain links", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    const r1 = await store.store(makeEvaluation({ evaluationId: "e1" }), "tool-a");
    const r2 = await store.store(makeEvaluation({ evaluationId: "e2" }), "tool-b");

    expect(r1.previousHash).toBe(GENESIS_SEED);
    expect(r2.previousHash).toBe(r1.recordHash);
    expect(r2.recordHash).not.toBe(r1.recordHash);
  });

  it("count", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    expect(await store.count()).toBe(0);
    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    expect(await store.count()).toBe(1);
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    expect(await store.count()).toBe(2);
  });

  it("get records all", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");

    const records = await store.getRecords();
    expect(records.length).toBe(2);
  });

  it("get records filter tool", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1" }), "tool-a");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "tool-b");

    const records = await store.getRecords({ toolName: "tool-a" });
    expect(records.length).toBe(1);
    expect(records[0]!.toolName).toBe("tool-a");
  });

  it("get records filter decision", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1", decision: "ALLOW" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2", decision: "BLOCK" }), "t2");

    const records = await store.getRecords({ decision: "BLOCK" });
    expect(records.length).toBe(1);
    expect(records[0]!.decision).toBe("BLOCK");
  });

  it("verify chain valid", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    await store.store(makeEvaluation({ evaluationId: "e3" }), "t3");

    const { valid, errors } = await store.verifyChain();
    expect(valid).toBe(true);
    expect(errors).toEqual([]);
  });

  it("verify chain detects output summary tampering", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    const record = await store.store(makeEvaluation({ evaluationId: "e1" }), "t1", "safe summary");
    await new Promise<void>((resolve, reject) => {
      (store as unknown as { _conn: duckdb.Connection })._conn.run(
        "UPDATE evidence_records SET output_summary = ? WHERE record_id = ?",
        "tampered summary",
        record.recordId,
        (err: duckdb.DuckDbError | null) => (err ? reject(err) : resolve()),
      );
    });

    const { valid, errors } = await store.verifyChain();
    expect(valid).toBe(false);
    expect(errors.some(error => error.includes("hash mismatch"))).toBe(true);
  });

  it("verify chain accepts Python-style unicode escapes and nested float literals from the shared store", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });
    await store.count();

    const recordId = randomUUID();
    const controlResultsJson =
      "[{\"control_id\":\"DE-01\",\"control_name\":\"Behavioral Anomaly Detection\",\"detail\":\"Baseline not yet established \\u2014 monitoring started.\",\"duration_ms\":1.0,\"evidence_data\":{\"current_rate_vs_baseline\":0.0,\"display_message\":\"Tool call frequency is 1.0x above baseline average \\u2014 normal\"},\"result\":\"PASS\"}]";
    const canonical =
      `{"active_certifications":[],"active_overlays":[],"agent_id":"agent","control_results":${controlResultsJson},"data_classifications":[],"decision":"ALLOW","evaluation_id":"e1","mode":"audit","previous_hash":"${GENESIS_SEED}","source_type":"agent","timestamp":"2025-01-01T00:00:00Z","tool_name":"tool","total_duration_ms":5.0}`;

    await new Promise<void>((resolve, reject) => {
      (store as unknown as { _conn: duckdb.Connection })._conn.run(
        `INSERT INTO evidence_records (
          record_id, evaluation_id, timestamp, agent_id, source_type, tool_name,
          decision, mode, control_results, active_overlays,
          data_classifications, active_certifications,
          record_hash, previous_hash, total_duration_ms, output_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        recordId,
        "e1",
        "2025-01-01T00:00:00Z",
        "agent",
        "agent",
        "tool",
        "ALLOW",
        "audit",
        controlResultsJson,
        "[]",
        "[]",
        "[]",
        computeHash(canonical),
        GENESIS_SEED,
        5.0,
        null,
        (err: duckdb.DuckDbError | null) => (err ? reject(err) : resolve()),
      );
    });

    const { valid, errors } = await store.verifyChain();
    expect(valid).toBe(true);
    expect(errors).toEqual([]);
  });

  it("verify chain empty", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });
    const { valid, errors } = await store.verifyChain();
    expect(valid).toBe(true);
    expect(errors).toEqual([]);
  });

  it("active certifications stored", async () => {
    const config = makeConfig();
    config.activeCertifications = ["SOC2", "HIPAA"];
    store = new EvidenceStore(config, { inMemory: true });

    const record = await store.store(makeEvaluation(), "t1");
    expect(record.activeCertifications).toEqual(["SOC2", "HIPAA"]);
  });

  it("active certifications default empty", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });
    const record = await store.store(makeEvaluation(), "t1");
    expect(record.activeCertifications).toEqual([]);
  });

  it("blocked evaluation stored", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });
    const record = await store.store(makeEvaluation({ decision: "BLOCK" }), "blocked-tool");
    expect(record.decision).toBe("BLOCK");
    expect(await store.count()).toBe(1);
  });

  it("persists control result durations as float literals for Python-compatible verification", async () => {
    const dbPath = join(tmpdir(), `ancilis-evidence-${randomUUID()}.duckdb`);
    store = new EvidenceStore(makeConfig(), { dbPath });

    await store.store(makeEvaluation({
      totalDurationMs: 5.0,
      controlResults: [
        {
          controlId: "PR-01",
          controlName: "Agent Identity",
          result: "PASS",
          detail: "Agent identity verified",
          evidenceData: { agent_id: "test-agent" },
          durationMs: 1.0,
        },
      ],
    }), "tool-a");

    const controlResultsJson = await queryOneString(
      dbPath,
      "SELECT control_results::VARCHAR as control_results FROM evidence_records LIMIT 1",
    );

    expect(controlResultsJson).toContain("\"duration_ms\":1.0");
  });
});

// --- Summary ---

describe("Summary", () => {
  let store: EvidenceStore;

  afterEach(async () => {
    if (store) await store.close();
  });

  it("get summary empty", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });
    const summary = await store.getSummary();
    expect(summary.totalEvaluations).toBe(0);
    expect(summary.chainValid).toBe(true);
  });

  it("get summary with records", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1", decision: "ALLOW" }), "tool-a");
    await store.store(makeEvaluation({ evaluationId: "e2", decision: "ALLOW" }), "tool-b");
    await store.store(makeEvaluation({ evaluationId: "e3", decision: "BLOCK" }), "tool-a");

    const summary = await store.getSummary();
    expect(summary.totalEvaluations).toBe(3);
    expect((summary.decisions as Record<string, number>).ALLOW).toBe(2);
    expect((summary.decisions as Record<string, number>).BLOCK).toBe(1);
    expect(new Set(summary.toolsEvaluated as string[])).toEqual(new Set(["tool-a", "tool-b"]));
    expect(summary.chainValid).toBe(true);
  });

  it("get summary control pass rates", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(
      makeEvaluation({
        evaluationId: "e2",
        controlResults: [
          { controlId: "PR-01", controlName: "Agent Identity", result: "FAIL", detail: "Failed", evidenceData: {}, durationMs: 1.0 },
        ],
      }),
      "t2",
    );

    const summary = await store.getSummary();
    const rates = summary.controlPassRates as Record<string, Record<string, number>>;
    expect(rates["PR-01"]!.PASS).toBe(1);
    expect(rates["PR-01"]!.FAIL).toBe(1);
  });

  it("get summary aggregates pattern detections", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(
      makeEvaluation({
        evaluationId: "e1",
        controlResults: [
          {
            controlId: "PR-04",
            controlName: "Data Exposure Prevention",
            result: "PASS",
            detail: "Patterns detected",
            evidenceData: {
              scan_result: "patterns_found",
              patterns_detected: [
                { type: "credit_card", count: 2, redacted_sample: "****1111" },
                { type: "ssn", count: 1, redacted_sample: "***-**-6789" },
              ],
            },
            durationMs: 1.0,
          },
        ],
      }),
      "t1",
    );

    const summary = await store.getSummary();
    expect(summary.patternDetections).toEqual({ credit_card: 2, ssn: 1 });
  });

  it("get summary supports since filtering", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "old", timestamp: "2024-01-01T00:00:00Z" }), "tool-a");
    await store.store(makeEvaluation({ evaluationId: "new", timestamp: "2025-06-01T00:00:00Z" }), "tool-b");

    const summary = await store.getSummary({ since: "2025-01-01T00:00:00Z" });
    expect(summary.totalEvaluations).toBe(1);
    expect(summary.toolsEvaluated).toEqual(["tool-b"]);
  });

  it("get summary stays read-only when the persistent store does not exist yet", async () => {
    const dbPath = join(tmpdir(), `ancilis-empty-summary-${randomUUID()}.duckdb`);
    store = new EvidenceStore(makeConfig(), { dbPath });

    const summary = await store.getSummary();

    expect(summary.totalEvaluations).toBe(0);
    expect(existsSync(dbPath)).toBe(false);
  });
});

// --- Purge ---

describe("Purge", () => {
  let store: EvidenceStore;

  afterEach(async () => {
    if (store) await store.close();
  });

  it("purge before", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1", timestamp: "2024-01-01T00:00:00Z" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2", timestamp: "2025-06-01T00:00:00Z" }), "t2");
    expect(await store.count()).toBe(2);

    const removed = await store.purgeBefore("2025-01-01T00:00:00Z");
    expect(removed).toBe(1);
    expect(await store.count()).toBe(1);
  });

  it("purge none removed", async () => {
    store = new EvidenceStore(makeConfig(), { inMemory: true });

    await store.store(makeEvaluation({ evaluationId: "e1", timestamp: "2025-06-01T00:00:00Z" }), "t1");

    const removed = await store.purgeBefore("2024-01-01T00:00:00Z");
    expect(removed).toBe(0);
    expect(await store.count()).toBe(1);
  });
});

// ===== listSessions / latestSessionId / reset =====

describe("EvidenceStore.listSessions", () => {
  it("returns empty array when no sessions recorded", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const sessions = await store.listSessions();
    expect(sessions).toEqual([]);
    await store.close();
  });

  it("groups records by session_id", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const e1 = makeEvaluation({ evaluationId: "e1" });
    e1.context = { sessionId: "sess-A" } as typeof e1.context;
    await store.store(e1, "tool1");
    const e2 = makeEvaluation({ evaluationId: "e2" });
    e2.context = { sessionId: "sess-A" } as typeof e2.context;
    await store.store(e2, "tool2");
    const e3 = makeEvaluation({ evaluationId: "e3" });
    e3.context = { sessionId: "sess-B" } as typeof e3.context;
    await store.store(e3, "tool3");

    const sessions = await store.listSessions();
    const ids = sessions.map((s) => s.session_id);
    expect(ids).toContain("sess-A");
    expect(ids).toContain("sess-B");
    const sessA = sessions.find((s) => s.session_id === "sess-A");
    expect(sessA?.count).toBe(2);
    await store.close();
  });
});

describe("EvidenceStore.reset", () => {
  it("returns 0 when store is empty", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const n = await store.reset();
    expect(n).toBe(0);
    await store.close();
  });

  it("deletes all records and returns count", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    expect(await store.count()).toBe(2);

    const n = await store.reset();
    expect(n).toBe(2);
    expect(await store.count()).toBe(0);
    await store.close();
  });
});

describe("EvidenceStore.latestSessionId", () => {
  it("returns null when store is empty", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const id = await store.latestSessionId();
    expect(id).toBeNull();
    await store.close();
  });

  it("returns session_id of most recent record", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const e1 = makeEvaluation({ evaluationId: "e1" });
    e1.context = { sessionId: "sess-A" } as typeof e1.context;
    await store.store(e1, "tool1");
    const e2 = makeEvaluation({ evaluationId: "e2" });
    e2.context = { sessionId: "sess-B" } as typeof e2.context;
    await store.store(e2, "tool2");
    const id = await store.latestSessionId();
    expect(id).toBe("sess-B"); // most recent
    await store.close();
  });

  it("returns null when latest record has no session_id", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const e1 = makeEvaluation({ evaluationId: "e1" });
    e1.context = { sessionId: "sess-A" } as typeof e1.context;
    await store.store(e1, "tool1");
    // Store a second record with no session_id (context undefined)
    const e2 = makeEvaluation({ evaluationId: "e2" });
    e2.context = undefined as typeof e2.context;
    await store.store(e2, "tool2");
    const id = await store.latestSessionId();
    expect(id).toBeNull();
    await store.close();
  });
});

// --- detectedDataTypes + sdkVersion store round-trip (ANC-736) ---

describe("EvidenceStore detectedDataTypes field", () => {
  it("stores and retrieves empty detectedDataTypes", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const ev = makeEvaluation({ detectedDataTypes: [] });
    await store.store(ev, "scan-tool");
    const records = await store.getRecords();
    expect(records[0].detectedDataTypes).toEqual([]);
    await store.close();
  });

  it("stores and retrieves DC code array", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const ev = makeEvaluation({ detectedDataTypes: ["DC-PII", "DC-CHD"] });
    await store.store(ev, "scan-tool");
    const records = await store.getRecords();
    expect(records[0].detectedDataTypes).toEqual(["DC-PII", "DC-CHD"]);
    await store.close();
  });

  it("multiple records keep independent detectedDataTypes", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    await store.store(makeEvaluation({ evaluationId: "e1", detectedDataTypes: ["DC-PII"] }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2", detectedDataTypes: ["DC-IP"] }), "t2");
    const records = await store.getRecords();
    expect(records[0].detectedDataTypes).toEqual(["DC-PII"]);
    expect(records[1].detectedDataTypes).toEqual(["DC-IP"]);
    await store.close();
  });

  it("defaults to empty array when field is absent", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    const ev = makeEvaluation();
    // detectedDataTypes not set — should default to []
    await store.store(ev, "scan-tool");
    const records = await store.getRecords();
    expect(records[0].detectedDataTypes).toEqual([]);
    await store.close();
  });
});

describe("EvidenceStore sdkVersion field", () => {
  it("sdkVersion is a string or null (never undefined)", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    await store.store(makeEvaluation(), "t1");
    const records = await store.getRecords();
    // sdkVersion may be null if package.json is not resolvable in the test env,
    // but it must not be undefined — the field should always be present.
    expect(records[0].sdkVersion === null || typeof records[0].sdkVersion === "string").toBe(true);
    await store.close();
  });

  it("sdkVersion is consistent across multiple records", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    const records = await store.getRecords();
    expect(records[0].sdkVersion).toBe(records[1].sdkVersion);
    await store.close();
  });

  it("sdkVersion round-trips through store correctly", async () => {
    // Directly inject a known version value to test the round-trip path
    // bypassing module-level version resolution.
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    await store.store(makeEvaluation(), "t1");
    // Directly update the record in DuckDB to set a known sdk_version
    const conn = (store as unknown as Record<string, unknown>)._conn as import("duckdb").Connection;
    await new Promise<void>((resolve, reject) => {
      conn.run("UPDATE evidence_records SET sdk_version = '1.2.3'", (err) => err ? reject(err) : resolve());
    });
    const records = await store.getRecords();
    expect(records[0].sdkVersion).toBe("1.2.3");
    await store.close();
  });
});

// --- classificationContext + llmProvider store round-trip (ANC-782) ---

describe("EvidenceStore classificationContext field", () => {
  it("defaults to empty object when llm_provider is not set", async () => {
    const store = new EvidenceStore(makeConfig(), { inMemory: true });
    await store.store(makeEvaluation(), "tool");
    const records = await store.getRecords();
    expect(records[0].classificationContext).toEqual({});
    await store.close();
  });

  it("includes llm_provider when set in config", async () => {
    const store = new EvidenceStore(
      makeConfig({ agent: { name: "test-agent", llm_provider: "openai" } }),
      { inMemory: true },
    );
    await store.store(makeEvaluation(), "tool");
    const records = await store.getRecords();
    expect(records[0].classificationContext).toEqual({ llm_provider: "openai" });
    await store.close();
  });

  it("classificationContext is independent per record", async () => {
    const store = new EvidenceStore(
      makeConfig({ agent: { name: "test-agent", llm_provider: "anthropic" } }),
      { inMemory: true },
    );
    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    const records = await store.getRecords();
    expect(records[0].classificationContext).toEqual({ llm_provider: "anthropic" });
    expect(records[1].classificationContext).toEqual({ llm_provider: "anthropic" });
    await store.close();
  });

  it("round-trips non-empty classificationContext correctly", async () => {
    // Verify that a populated classificationContext survives write-then-read.
    // (Empty-object case is covered by the first test above.)
    const store = new EvidenceStore(
      makeConfig({ agent: { name: "test-agent", llm_provider: "bedrock" } }),
      { inMemory: true },
    );
    await store.store(makeEvaluation({ evaluationId: "e1" }), "tool");
    const records = await store.getRecords();
    expect(records[0].classificationContext).toEqual({ llm_provider: "bedrock" });
    await store.close();
  });
});

describe("ResolvedConfig llmProvider field", () => {
  it("defaults to null when llm_provider is not specified", () => {
    const config = makeConfig();
    expect(config.llmProvider).toBeNull();
  });

  it("resolves llm_provider string from config", () => {
    const config = makeConfig({ agent: { name: "test-agent", llm_provider: "bedrock" } });
    expect(config.llmProvider).toBe("bedrock");
  });
});
