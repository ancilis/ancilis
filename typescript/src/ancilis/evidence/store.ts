/** DuckDB-backed evidence store with hash chain integrity. */

import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import duckdb from "duckdb";
import type { EvaluationResult } from "../engine/result.js";
import type { ResolvedConfig } from "../config/index.js";
import { GENESIS_SEED, canonicalPayload, computeHash } from "./chain.js";
import type { EvidenceRecord } from "./record.js";

const CREATE_TABLE_SQL = `
CREATE SEQUENCE IF NOT EXISTS evidence_seq START 1;
CREATE TABLE IF NOT EXISTS evidence_records (
    seq_id BIGINT DEFAULT nextval('evidence_seq'),
    record_id VARCHAR PRIMARY KEY,
    evaluation_id VARCHAR NOT NULL,
    timestamp VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    tool_name VARCHAR NOT NULL,
    decision VARCHAR NOT NULL,
    mode VARCHAR NOT NULL,
    control_results JSON NOT NULL,
    active_overlays JSON NOT NULL,
    data_classifications JSON NOT NULL,
    active_certifications JSON NOT NULL,
    record_hash VARCHAR NOT NULL,
    previous_hash VARCHAR NOT NULL,
    total_duration_ms DOUBLE NOT NULL
);
`;

const INSERT_SQL = `
INSERT INTO evidence_records (
    record_id, evaluation_id, timestamp, agent_id, tool_name,
    decision, mode, control_results, active_overlays,
    data_classifications, active_certifications,
    record_hash, previous_hash, total_duration_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`;

function execAsync(conn: duckdb.Connection, sql: string): Promise<void> {
  return new Promise((resolve, reject) => {
    conn.exec(sql, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function allAsync(conn: duckdb.Connection, sql: string, params: unknown[] = []): Promise<duckdb.TableData> {
  return new Promise((resolve, reject) => {
    conn.all(sql, ...params, (err: duckdb.DuckDbError | null, rows: duckdb.TableData) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function runAsync(conn: duckdb.Connection, sql: string, params: unknown[] = []): Promise<void> {
  return new Promise((resolve, reject) => {
    conn.run(sql, ...params, (err: duckdb.DuckDbError | null) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function agentDbPath(agentName: string): string {
  const safeName = agentName.replace(/[^a-zA-Z0-9_-]/g, "_");
  const cwdHash = createHash("sha256").update(process.cwd()).digest("hex").slice(0, 8);
  return join(homedir(), ".ancilis", `${safeName}-${cwdHash}`, "evidence.duckdb");
}

function normalizeDecisionKey(decision: string): string {
  return decision.trim().toUpperCase();
}

export class EvidenceStore {
  private _db: duckdb.Database | null = null;
  private _conn: duckdb.Connection | null = null;
  private _certifications: string[];
  private _initialized: Promise<void> | null = null;
  private _dbPath: string;
  private _inMemory: boolean;

  constructor(config: ResolvedConfig, options?: { dbPath?: string; inMemory?: boolean }) {
    this._certifications = [...(config.activeCertifications ?? [])];
    this._inMemory = options?.inMemory ?? false;

    if (this._inMemory) {
      this._dbPath = ":memory:";
    } else if (options?.dbPath) {
      this._dbPath = options.dbPath;
    } else {
      const agentName = config.agentName || "default";
      this._dbPath = agentDbPath(agentName);
    }
    // No filesystem access here — lazy init on first use
  }

  private async ensureInitialized(): Promise<void> {
    if (this._initialized) return this._initialized;

    this._initialized = (async () => {
      if (this._inMemory) {
        this._db = new duckdb.Database(":memory:");
      } else {
        mkdirSync(dirname(this._dbPath), { recursive: true });
        this._db = new duckdb.Database(this._dbPath);
      }
      this._conn = this._db.connect();
      await execAsync(this._conn, CREATE_TABLE_SQL);
    })();

    return this._initialized;
  }

  async close(): Promise<void> {
    if (!this._initialized) return;
    await this._initialized;
    return new Promise((resolve) => {
      if (this._conn && this._db) {
        this._conn.close(() => {
          this._db!.close(() => resolve());
        });
      } else {
        resolve();
      }
    });
  }

  private async getLastHash(): Promise<string> {
    await this.ensureInitialized();
    const rows = await allAsync(
      this._conn!,
      "SELECT record_hash FROM evidence_records ORDER BY seq_id DESC LIMIT 1",
    );
    return rows.length > 0 ? (rows[0] as Record<string, unknown>).record_hash as string : GENESIS_SEED;
  }

  async store(evaluation: EvaluationResult, toolName: string): Promise<EvidenceRecord> {
    await this.ensureInitialized();
    const recordId = randomUUID();
    const previousHash = await this.getLastHash();

    const controlResultsData = evaluation.controlResults.map(cr => ({
      control_id: cr.controlId,
      control_name: cr.controlName,
      result: cr.result,
      detail: cr.detail,
      evidence_data: cr.evidenceData,
      duration_ms: cr.durationMs,
    }));

    const canon = canonicalPayload({
      evaluationId: evaluation.evaluationId,
      timestamp: evaluation.timestamp,
      agentId: evaluation.agentId,
      toolName,
      decision: evaluation.decision,
      mode: evaluation.mode,
      controlResults: controlResultsData,
      activeOverlays: evaluation.activeOverlays,
      dataClassifications: evaluation.dataClassifications,
      activeCertifications: this._certifications,
      totalDurationMs: evaluation.totalDurationMs,
      previousHash,
    });
    const recordHash = computeHash(canon);

    const record: EvidenceRecord = {
      recordId,
      evaluationId: evaluation.evaluationId,
      timestamp: evaluation.timestamp,
      agentId: evaluation.agentId,
      toolName,
      decision: evaluation.decision,
      mode: evaluation.mode,
      controlResults: controlResultsData,
      activeOverlays: evaluation.activeOverlays,
      dataClassifications: evaluation.dataClassifications,
      activeCertifications: this._certifications,
      recordHash,
      previousHash,
      totalDurationMs: evaluation.totalDurationMs,
    };

    await runAsync(this._conn!, INSERT_SQL, [
      record.recordId,
      record.evaluationId,
      record.timestamp,
      record.agentId,
      record.toolName,
      record.decision,
      record.mode,
      JSON.stringify(record.controlResults),
      JSON.stringify(record.activeOverlays),
      JSON.stringify(record.dataClassifications),
      JSON.stringify(record.activeCertifications),
      record.recordHash,
      record.previousHash,
      record.totalDurationMs,
    ]);

    return record;
  }

  async getRecords(filters?: {
    agentId?: string;
    toolName?: string;
    decision?: string;
    limit?: number;
  }): Promise<EvidenceRecord[]> {
    await this.ensureInitialized();
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filters?.agentId) {
      conditions.push("agent_id = ?");
      params.push(filters.agentId);
    }
    if (filters?.toolName) {
      conditions.push("tool_name = ?");
      params.push(filters.toolName);
    }
    if (filters?.decision) {
      conditions.push("decision = ?");
      params.push(filters.decision);
    }

    const where = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";
    const limit = filters?.limit ?? 100;
    params.push(limit);

    const rows = await allAsync(
      this._conn!,
      `SELECT * FROM evidence_records${where} ORDER BY seq_id ASC LIMIT ?`,
      params,
    );

    return rows.map(row => this.rowToRecord(row as Record<string, unknown>));
  }

  async count(): Promise<number> {
    await this.ensureInitialized();
    const rows = await allAsync(this._conn!, "SELECT COUNT(*)::INTEGER as cnt FROM evidence_records");
    return (rows[0] as Record<string, unknown>).cnt as number;
  }

  async verifyChain(): Promise<{ valid: boolean; errors: string[] }> {
    await this.ensureInitialized();
    const rows = await allAsync(
      this._conn!,
      "SELECT * FROM evidence_records ORDER BY seq_id ASC",
    );

    if (rows.length === 0) {
      return { valid: true, errors: [] };
    }

    const errors: string[] = [];
    let expectedPrevious = GENESIS_SEED;

    for (const row of rows) {
      const record = this.rowToRecord(row as Record<string, unknown>);

      if (record.previousHash !== expectedPrevious) {
        errors.push(
          `Record ${record.recordId}: previous_hash mismatch. ` +
          `Expected ${expectedPrevious.slice(0, 16)}..., got ${record.previousHash.slice(0, 16)}...`
        );
      }

      const canon = canonicalPayload({
        evaluationId: record.evaluationId,
        timestamp: record.timestamp,
        agentId: record.agentId,
        toolName: record.toolName,
        decision: record.decision,
        mode: record.mode,
        controlResults: record.controlResults,
        activeOverlays: record.activeOverlays,
        dataClassifications: record.dataClassifications,
        activeCertifications: record.activeCertifications,
        totalDurationMs: record.totalDurationMs,
        previousHash: record.previousHash,
      });
      const expectedHash = computeHash(canon);

      if (record.recordHash !== expectedHash) {
        errors.push(
          `Record ${record.recordId}: hash mismatch. ` +
          `Expected ${expectedHash.slice(0, 16)}..., got ${record.recordHash.slice(0, 16)}...`
        );
      }

      expectedPrevious = record.recordHash;
    }

    return { valid: errors.length === 0, errors };
  }

  async getSummary(): Promise<Record<string, unknown>> {
    await this.ensureInitialized();
    const total = await this.count();

    if (total === 0) {
      return {
        totalEvaluations: 0,
        decisions: {},
        toolsEvaluated: [],
        chainValid: true,
        chainErrors: [],
      };
    }

    const decisionRows = await allAsync(
      this._conn!,
      "SELECT decision, COUNT(*)::INTEGER as cnt FROM evidence_records GROUP BY decision",
    );
    const decisions: Record<string, number> = {};
    for (const row of decisionRows) {
      const r = row as Record<string, unknown>;
      const decision = normalizeDecisionKey(r.decision as string);
      decisions[decision] = (decisions[decision] ?? 0) + (r.cnt as number);
    }

    const toolRows = await allAsync(
      this._conn!,
      "SELECT DISTINCT tool_name FROM evidence_records ORDER BY tool_name",
    );
    const tools = toolRows.map(r => (r as Record<string, unknown>).tool_name as string);

    const { valid: chainValid, errors: chainErrors } = await this.verifyChain();

    const crRows = await allAsync(
      this._conn!,
      "SELECT control_results FROM evidence_records",
    );
    const controlStats: Record<string, Record<string, number>> = {};
    for (const row of crRows) {
      const crJson = (row as Record<string, unknown>).control_results;
      const results = typeof crJson === "string" ? JSON.parse(crJson) : crJson;
      for (const cr of results as Array<Record<string, unknown>>) {
        const cid = cr.control_id as string;
        if (!controlStats[cid]) {
          controlStats[cid] = { PASS: 0, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 };
        }
        const result = (cr.result as string) ?? "SKIP";
        if (result in controlStats[cid]!) {
          controlStats[cid]![result]!++;
        }
      }
    }

    return {
      totalEvaluations: total,
      decisions,
      toolsEvaluated: tools,
      controlPassRates: controlStats,
      chainValid,
      chainErrors,
    };
  }

  async purgeBefore(beforeTimestamp: string): Promise<number> {
    await this.ensureInitialized();
    const countRows = await allAsync(
      this._conn!,
      "SELECT COUNT(*)::INTEGER as cnt FROM evidence_records WHERE timestamp < ?",
      [beforeTimestamp],
    );
    const count = (countRows[0] as Record<string, unknown>).cnt as number;

    if (count > 0) {
      await runAsync(
        this._conn!,
        "DELETE FROM evidence_records WHERE timestamp < ?",
        [beforeTimestamp],
      );
    }

    return count;
  }

  private rowToRecord(row: Record<string, unknown>): EvidenceRecord {
    const parseJson = (val: unknown): unknown =>
      typeof val === "string" ? JSON.parse(val) : val;

    return {
      recordId: row.record_id as string,
      evaluationId: row.evaluation_id as string,
      timestamp: row.timestamp as string,
      agentId: row.agent_id as string,
      toolName: row.tool_name as string,
      decision: row.decision as string,
      mode: row.mode as string,
      controlResults: parseJson(row.control_results) as Array<Record<string, unknown>>,
      activeOverlays: parseJson(row.active_overlays) as string[],
      dataClassifications: parseJson(row.data_classifications) as string[],
      activeCertifications: parseJson(row.active_certifications) as string[],
      recordHash: row.record_hash as string,
      previousHash: row.previous_hash as string,
      totalDurationMs: row.total_duration_ms as number,
    };
  }
}
