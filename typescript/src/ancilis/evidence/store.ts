/** DuckDB-backed evidence store with hash chain integrity. */

import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { packageRootFrom } from "../shared-path.js";
import duckdb from "duckdb";
import type { EvaluationResult } from "../engine/result.js";
import type { ResolvedConfig } from "../config/index.js";
import { GENESIS_SEED, canonicalJsonStringify, canonicalPayload, computeHash } from "./chain.js";
import type { EvidenceRecord } from "./record.js";

let _sdkVersion: string | undefined;
try {
  _sdkVersion = (JSON.parse(
    readFileSync(join(packageRootFrom(import.meta.url), "package.json"), "utf-8"),
  ) as { version: string }).version;
} catch {
  _sdkVersion = undefined;
}

const CREATE_TABLE_SQL = `
CREATE SEQUENCE IF NOT EXISTS evidence_seq START 1;
CREATE TABLE IF NOT EXISTS evidence_records (
    seq_id BIGINT DEFAULT nextval('evidence_seq'),
    record_id VARCHAR PRIMARY KEY,
    evaluation_id VARCHAR NOT NULL,
    timestamp VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    session_id VARCHAR,
    source_type VARCHAR NOT NULL DEFAULT 'agent',
    tool_name VARCHAR NOT NULL,
    decision VARCHAR NOT NULL,
    mode VARCHAR NOT NULL,
    control_results JSON NOT NULL,
    active_overlays JSON NOT NULL,
    data_classifications JSON NOT NULL,
    active_certifications JSON NOT NULL,
    record_hash VARCHAR NOT NULL,
    previous_hash VARCHAR NOT NULL,
    total_duration_ms DOUBLE NOT NULL,
    output_summary VARCHAR,
    tenant_id VARCHAR,
    detected_data_types JSON NOT NULL DEFAULT '[]',
    sdk_version VARCHAR,
    classification_context JSON NOT NULL DEFAULT '{}'
);
`;

const INSERT_SQL = `
INSERT INTO evidence_records (
    record_id, evaluation_id, timestamp, agent_id, session_id, source_type, tool_name,
    decision, mode, control_results, active_overlays,
    data_classifications, active_certifications,
    record_hash, previous_hash, total_duration_ms, output_summary, tenant_id,
    detected_data_types, sdk_version, classification_context
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`;

const SELECT_COLUMNS = `
seq_id, record_id, evaluation_id, timestamp, agent_id, session_id, source_type, tool_name,
decision, mode, control_results, active_overlays, data_classifications,
active_certifications, record_hash, previous_hash, total_duration_ms, output_summary, tenant_id,
detected_data_types, sdk_version, classification_context
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

type SessionScope = { sessionId?: string | null } | string | undefined;

function sessionIdFrom(scope: SessionScope): string | null | undefined {
  if (typeof scope === "string") return scope;
  return scope?.sessionId;
}

export class EvidenceStore {
  private _db: duckdb.Database | null = null;
  private _conn: duckdb.Connection | null = null;
  private _certifications: string[];
  private _llmProvider: string | null;
  private _initialized: Promise<void> | null = null;
  private _dbPath: string;
  private _inMemory: boolean;
  private _tenantId: string | undefined;

  constructor(config: ResolvedConfig, options?: { dbPath?: string; inMemory?: boolean; tenantId?: string }) {
    this._certifications = [...(config.activeCertifications ?? [])];
    this._llmProvider = config.llmProvider ?? null;
    this._inMemory = options?.inMemory ?? false;
    this._tenantId = options?.tenantId;

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

  get dbPath(): string {
    return this._dbPath;
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
      const columns = await allAsync(this._conn, "PRAGMA table_info('evidence_records')");
      const names = new Set(columns.map((row) => (row as Record<string, unknown>).name as string));
      if (!names.has("session_id")) {
        await execAsync(this._conn, "ALTER TABLE evidence_records ADD COLUMN session_id VARCHAR");
      }
      if (!names.has("source_type")) {
        await execAsync(this._conn, "ALTER TABLE evidence_records ADD COLUMN source_type VARCHAR NOT NULL DEFAULT 'agent'");
      }
      if (!names.has("output_summary")) {
        await execAsync(this._conn, "ALTER TABLE evidence_records ADD COLUMN output_summary VARCHAR");
      }
      if (!names.has("tenant_id")) {
        await execAsync(this._conn, "ALTER TABLE evidence_records ADD COLUMN tenant_id VARCHAR");
      }
      if (!names.has("detected_data_types")) {
        await execAsync(this._conn, "ALTER TABLE evidence_records ADD COLUMN detected_data_types JSON DEFAULT '[]'");
      }
      if (!names.has("sdk_version")) {
        await execAsync(this._conn, "ALTER TABLE evidence_records ADD COLUMN sdk_version VARCHAR");
      }
      if (!names.has("classification_context")) {
        await execAsync(this._conn, "ALTER TABLE evidence_records ADD COLUMN classification_context JSON DEFAULT '{}'");
      }
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
    const whereClause = this._tenantId ? " WHERE tenant_id = ?" : "";
    const params = this._tenantId ? [this._tenantId] : [];
    const rows = await allAsync(
      this._conn!,
      `SELECT record_hash FROM evidence_records${whereClause} ORDER BY seq_id DESC LIMIT 1`,
      params,
    );
    return rows.length > 0 ? (rows[0] as Record<string, unknown>).record_hash as string : GENESIS_SEED;
  }

  async store(
    evaluation: EvaluationResult,
    toolName: string,
    outputSummary?: string | null,
  ): Promise<EvidenceRecord> {
    await this.ensureInitialized();
    const recordId = randomUUID();
    const previousHash = await this.getLastHash();
    const sessionId = evaluation.context?.sessionId ?? null;
    const detectedDataTypes = [...(evaluation.detectedDataTypes ?? [])];
    const sdkVersion = _sdkVersion ?? null;
    const classificationContext: Record<string, unknown> = {};
    if (this._llmProvider) {
      classificationContext.llm_provider = this._llmProvider;
    }

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
      sourceType: evaluation.sourceType ?? "agent",
      toolName,
      decision: evaluation.decision,
      mode: evaluation.mode,
      controlResults: controlResultsData,
      activeOverlays: evaluation.activeOverlays,
      dataClassifications: evaluation.dataClassifications,
      activeCertifications: this._certifications,
      totalDurationMs: evaluation.totalDurationMs,
      previousHash,
      outputSummary,
      sessionId,
      tenantId: this._tenantId,
      detectedDataTypes,
      sdkVersion,
      classificationContext,
    });
    const recordHash = computeHash(canon);

    const record: EvidenceRecord = {
      recordId,
      evaluationId: evaluation.evaluationId,
      timestamp: evaluation.timestamp,
      agentId: evaluation.agentId,
      sourceType: evaluation.sourceType ?? "agent",
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
      outputSummary: outputSummary ?? null,
      sessionId,
      tenantId: this._tenantId ?? null,
      detectedDataTypes,
      sdkVersion,
      classificationContext,
    };

    await runAsync(this._conn!, INSERT_SQL, [
      record.recordId,
      record.evaluationId,
      record.timestamp,
      record.agentId,
      record.sessionId ?? null,
      record.sourceType ?? "agent",
      record.toolName,
      record.decision,
      record.mode,
      canonicalJsonStringify(record.controlResults),
      JSON.stringify(record.activeOverlays),
      JSON.stringify(record.dataClassifications),
      JSON.stringify(record.activeCertifications),
      record.recordHash,
      record.previousHash,
      record.totalDurationMs,
      record.outputSummary,
      record.tenantId ?? null,
      JSON.stringify(record.detectedDataTypes ?? []),
      record.sdkVersion ?? null,
      JSON.stringify(record.classificationContext ?? {}),
    ]);

    return record;
  }

  async getRecords(filters?: {
    agentId?: string;
    toolName?: string;
    decision?: string;
    since?: string;
    sessionId?: string;
    limit?: number | null;
  }): Promise<EvidenceRecord[]> {
    await this.ensureInitialized();
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (this._tenantId) {
      conditions.push("tenant_id = ?");
      params.push(this._tenantId);
    }
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
    if (filters?.sessionId) {
      conditions.push("session_id = ?");
      params.push(filters.sessionId);
    }
    if (filters?.since) {
      conditions.push("timestamp >= ?");
      params.push(filters.since);
    }

    const where = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";
    const limit = filters?.limit ?? 100;
    const limitClause = limit === null ? "" : " LIMIT ?";
    if (limit !== null) {
      params.push(limit);
    }

    const rows = await allAsync(
      this._conn!,
      `SELECT ${SELECT_COLUMNS} FROM evidence_records${where} ORDER BY seq_id ASC${limitClause}`,
      params,
    );

    return rows.map(row => this.rowToRecord(row as Record<string, unknown>));
  }

  async count(scope?: SessionScope): Promise<number> {
    await this.ensureInitialized();
    const conditions: string[] = [];
    const params: unknown[] = [];
    const sessionId = sessionIdFrom(scope);
    if (this._tenantId) {
      conditions.push("tenant_id = ?");
      params.push(this._tenantId);
    }
    if (sessionId !== undefined && sessionId !== null) {
      conditions.push("session_id = ?");
      params.push(sessionId);
    }
    const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";
    const rows = await allAsync(this._conn!, `SELECT COUNT(*)::INTEGER as cnt FROM evidence_records${whereClause}`, params);
    return (rows[0] as Record<string, unknown>).cnt as number;
  }

  async verifyChain(scope?: SessionScope): Promise<{ valid: boolean; errors: string[] }> {
    await this.ensureInitialized();
    const whereClause = this._tenantId ? " WHERE tenant_id = ?" : "";
    const params = this._tenantId ? [this._tenantId] : [];
    const sessionId = sessionIdFrom(scope);
    const rows = await allAsync(
      this._conn!,
      `SELECT ${SELECT_COLUMNS} FROM evidence_records${whereClause} ORDER BY seq_id ASC`,
      params,
    );

    if (rows.length === 0) {
      return { valid: true, errors: [] };
    }

    const errors: string[] = [];
    let expectedPrevious = GENESIS_SEED;

    for (const row of rows) {
      const record = this.rowToRecord(row as Record<string, unknown>);
      const inScope = sessionId === undefined || sessionId === null || record.sessionId === sessionId;

      if (inScope && record.previousHash !== expectedPrevious) {
        errors.push(
          `Record ${record.recordId}: previous_hash mismatch. ` +
          `Expected ${expectedPrevious.slice(0, 16)}..., got ${record.previousHash.slice(0, 16)}...`
        );
      }

      const canon = canonicalPayload({
        evaluationId: record.evaluationId,
        timestamp: record.timestamp,
        agentId: record.agentId,
        sourceType: record.sourceType ?? "agent",
        toolName: record.toolName,
        decision: record.decision,
        mode: record.mode,
        controlResults: record.controlResults,
        activeOverlays: record.activeOverlays,
        dataClassifications: record.dataClassifications,
        activeCertifications: record.activeCertifications,
        totalDurationMs: record.totalDurationMs,
        previousHash: record.previousHash,
        outputSummary: record.outputSummary,
        sessionId: record.sessionId,
        tenantId: record.tenantId,
        detectedDataTypes: record.detectedDataTypes,
        sdkVersion: record.sdkVersion,
        classificationContext: record.classificationContext,
      });
      const expectedHash = computeHash(canon);

      if (inScope && record.recordHash !== expectedHash) {
        const legacyCanon = canonicalPayload({
          evaluationId: record.evaluationId,
          timestamp: record.timestamp,
          agentId: record.agentId,
          sourceType: record.sourceType ?? "agent",
          toolName: record.toolName,
          decision: record.decision,
          mode: record.mode,
          controlResults: record.controlResults,
          activeOverlays: record.activeOverlays,
          dataClassifications: record.dataClassifications,
          activeCertifications: record.activeCertifications,
          totalDurationMs: record.totalDurationMs,
          previousHash: record.previousHash,
          outputSummary: record.outputSummary,
          sessionId: record.sessionId,
          tenantId: record.tenantId,
        });
        const legacyHash = computeHash(legacyCanon);
        if (record.recordHash !== legacyHash) {
          errors.push(
            `Record ${record.recordId}: hash mismatch. ` +
            `Expected ${expectedHash.slice(0, 16)}..., got ${record.recordHash.slice(0, 16)}...`
          );
        }
      }

      expectedPrevious = record.recordHash;
    }

    return { valid: errors.length === 0, errors };
  }

  async getSummary(options?: { since?: string; sessionId?: string }): Promise<Record<string, unknown>> {
    if (!this._initialized && !this._inMemory && !existsSync(this._dbPath)) {
      return {
        totalEvaluations: 0,
        decisions: {},
        toolsEvaluated: [],
        chainValid: true,
        chainErrors: [],
        controlPassRates: {},
        patternDetections: {},
      };
    }

    await this.ensureInitialized();
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (options?.since) {
      conditions.push("timestamp >= ?");
      params.push(options.since);
    }
    if (options?.sessionId !== undefined) {
      conditions.push("session_id = ?");
      params.push(options.sessionId);
    }
    const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";

    const totalRows = await allAsync(
      this._conn!,
      `SELECT COUNT(*)::INTEGER as cnt FROM evidence_records${whereClause}`,
      params,
    );
    const total = ((totalRows[0] as Record<string, unknown> | undefined)?.cnt as number | undefined) ?? 0;

    if (total === 0 && !options?.since) {
      return {
        totalEvaluations: 0,
        decisions: {},
        toolsEvaluated: [],
        chainValid: true,
        chainErrors: [],
        controlPassRates: {},
        patternDetections: {},
      };
    }

    const decisionRows = await allAsync(
      this._conn!,
      `SELECT decision, COUNT(*)::INTEGER as cnt FROM evidence_records${whereClause} GROUP BY decision`,
      params,
    );
    const decisions: Record<string, number> = {};
    for (const row of decisionRows) {
      const r = row as Record<string, unknown>;
      const decision = normalizeDecisionKey(r.decision as string);
      decisions[decision] = (decisions[decision] ?? 0) + (r.cnt as number);
    }

    const toolRows = await allAsync(
      this._conn!,
      `SELECT DISTINCT tool_name FROM evidence_records${whereClause} ORDER BY tool_name`,
      params,
    );
    const tools = toolRows.map(r => (r as Record<string, unknown>).tool_name as string);

    const { valid: chainValid, errors: chainErrors } = await this.verifyChain();

    const crRows = await allAsync(
      this._conn!,
      `SELECT control_results FROM evidence_records${whereClause}`,
      params,
    );
    const controlStats: Record<string, Record<string, number>> = {};
    const patternDetections: Record<string, number> = {};
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
        const evidenceData = (cr.evidence_data as Record<string, unknown> | undefined) ?? {};
        const patterns = (evidenceData.patterns_detected as Array<Record<string, unknown>> | undefined) ?? [];
        for (const pattern of patterns) {
          const patternType = pattern.type;
          const count = pattern.count;
          if (typeof patternType === "string" && typeof count === "number") {
            patternDetections[patternType] = (patternDetections[patternType] ?? 0) + count;
          }
        }
      }
    }

    return {
      totalEvaluations: total,
      decisions,
      toolsEvaluated: tools,
      controlPassRates: controlStats,
      patternDetections,
      chainValid,
      chainErrors,
    };
  }

  /** Execute a DDL or DML statement with no result. */
  async exec(sql: string): Promise<void> {
    await this.ensureInitialized();
    return execAsync(this._conn!, sql);
  }

  /** Run a parameterised query and return all rows. */
  async query(sql: string, params: unknown[] = []): Promise<duckdb.TableData> {
    await this.ensureInitialized();
    return allAsync(this._conn!, sql, params);
  }

  /** Run a parameterised DML statement (INSERT / UPDATE / DELETE). */
  async run(sql: string, params: unknown[] = []): Promise<void> {
    await this.ensureInitialized();
    return runAsync(this._conn!, sql, params);
  }

  async listSessions(): Promise<Array<{ session_id: string; count: number; first_seen: string; last_seen: string }>> {
    await this.ensureInitialized();
    const tenantFilter = this._tenantId ? "AND tenant_id = ?" : "";
    const params = this._tenantId ? [this._tenantId] : [];
    const rows = await allAsync(
      this._conn!,
      `SELECT session_id, COUNT(*)::INTEGER as cnt,
       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
       FROM evidence_records
       WHERE session_id IS NOT NULL ${tenantFilter}
       GROUP BY session_id ORDER BY last_seen DESC`,
      params,
    );
    return (rows as Array<Record<string, unknown>>).map((r) => ({
      session_id: r.session_id as string,
      count: r.cnt as number,
      first_seen: r.first_seen as string,
      last_seen: r.last_seen as string,
    }));
  }

  async latestSessionId(): Promise<string | null> {
    await this.ensureInitialized();
    const conditions = ["session_id IS NOT NULL"];
    const params: unknown[] = [];
    if (this._tenantId) {
      conditions.push("tenant_id = ?");
      params.push(this._tenantId);
    }
    const rows = await allAsync(
      this._conn!,
      `SELECT session_id FROM evidence_records WHERE ${conditions.join(" AND ")} ORDER BY timestamp DESC, seq_id DESC LIMIT 1`,
      params,
    );
    const row = (rows as Array<Record<string, unknown>>)[0];
    return row ? (row.session_id as string) : null;
  }

  async reset(): Promise<number> {
    await this.ensureInitialized();
    const countRows = await allAsync(this._conn!, "SELECT COUNT(*)::INTEGER as cnt FROM evidence_records", []);
    const n = ((countRows[0] as Record<string, unknown>).cnt as number) ?? 0;
    if (n > 0) {
      await runAsync(this._conn!, "DELETE FROM evidence_records", []);
    }
    return n;
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
      sourceType: (row.source_type as string | undefined) ?? "agent",
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
      outputSummary: (row.output_summary as string | null | undefined) ?? null,
      sessionId: (row.session_id as string | null | undefined) ?? null,
      tenantId: (row.tenant_id as string | null | undefined) ?? null,
      detectedDataTypes: (parseJson(row.detected_data_types) ?? []) as string[],
      sdkVersion: (row.sdk_version as string | null | undefined) ?? null,
      classificationContext: (parseJson(row.classification_context) ?? {}) as Record<string, unknown>,
    };
  }
}
