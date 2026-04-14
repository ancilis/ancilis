/** MockEvidenceStore — in-memory evidence store for testing (no DuckDB). */

import { randomUUID } from "node:crypto";
import { GENESIS_SEED, canonicalPayload, computeHash } from "../evidence/chain.js";
import type { EvidenceRecord } from "../evidence/record.js";
import type { EvaluationResult } from "../engine/result.js";

/**
 * In-memory evidence store for use in tests. Provides the same
 * store/query interface as `EvidenceStore` but requires no filesystem
 * or DuckDB dependency — everything lives in process memory.
 *
 * Extra test helpers:
 *   - `clear()` — wipe all records between tests
 *   - `getAll()` — retrieve every stored record
 *   - `getRecordsForTool(name)` — filter by tool name
 *   - `getRecordsForDecision(decision)` — filter by decision
 *   - `getLastRecord()` — most recently stored record
 *   - `addFakeRecord(partial)` — inject a record without going through evaluation
 */
export class MockEvidenceStore {
  private _records: EvidenceRecord[] = [];
  private _certifications: string[];
  private _tenantId: string | undefined;

  /** Path sentinel — keeps the same property name as the real store. */
  readonly dbPath = ":memory:";

  constructor(options?: { certifications?: string[]; tenantId?: string }) {
    this._certifications = options?.certifications ?? [];
    this._tenantId = options?.tenantId;
  }

  // ---------------------------------------------------------------------------
  // Core store interface (mirrors EvidenceStore)
  // ---------------------------------------------------------------------------

  async store(
    evaluation: EvaluationResult,
    toolName: string,
    outputSummary?: string | null,
  ): Promise<EvidenceRecord> {
    const recordId = randomUUID();
    const previousHash =
      this._records.length > 0
        ? this._records[this._records.length - 1]!.recordHash
        : GENESIS_SEED;
    const sessionId = evaluation.context?.sessionId ?? null;
    const detectedDataTypes = [...(evaluation.detectedDataTypes ?? [])];
    const sdkVersion = null;
    const classificationContext: Record<string, unknown> = {};

    const controlResultsData = evaluation.controlResults.map((cr) => ({
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

    this._records.push(record);
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
    let records = [...this._records];

    if (this._tenantId) {
      records = records.filter((r) => r.tenantId === this._tenantId);
    }
    if (filters?.agentId) {
      records = records.filter((r) => r.agentId === filters.agentId);
    }
    if (filters?.toolName) {
      records = records.filter((r) => r.toolName === filters.toolName);
    }
    if (filters?.decision) {
      records = records.filter((r) => r.decision === filters.decision);
    }
    if (filters?.sessionId) {
      records = records.filter((r) => r.sessionId === filters.sessionId);
    }
    if (filters?.since) {
      records = records.filter((r) => r.timestamp >= filters.since!);
    }

    const limit = filters?.limit ?? 100;
    if (limit !== null) {
      records = records.slice(0, limit);
    }

    return records;
  }

  async count(scope?: { sessionId?: string | null } | string): Promise<number> {
    const sessionId = typeof scope === "string" ? scope : scope?.sessionId;
    let records = this._records;
    if (this._tenantId) {
      records = records.filter((r) => r.tenantId === this._tenantId);
    }
    if (sessionId !== undefined && sessionId !== null) {
      records = records.filter((r) => r.sessionId === sessionId);
    }
    return records.length;
  }

  async verifyChain(scope?: { sessionId?: string | null } | string): Promise<{ valid: boolean; errors: string[] }> {
    const records = this._tenantId
      ? this._records.filter((r) => r.tenantId === this._tenantId)
      : this._records;
    const sessionId = typeof scope === "string" ? scope : scope?.sessionId;

    if (records.length === 0) return { valid: true, errors: [] };

    const errors: string[] = [];
    let expectedPrevious = GENESIS_SEED;

    for (const record of records) {
      const inScope = sessionId === undefined || sessionId === null || record.sessionId === sessionId;

      if (inScope && record.previousHash !== expectedPrevious) {
        errors.push(
          `Record ${record.recordId}: previous_hash mismatch. ` +
            `Expected ${expectedPrevious.slice(0, 16)}..., got ${record.previousHash.slice(0, 16)}...`,
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
              `Expected ${expectedHash.slice(0, 16)}..., got ${record.recordHash.slice(0, 16)}...`,
          );
        }
      }

      expectedPrevious = record.recordHash;
    }

    return { valid: errors.length === 0, errors };
  }

  async getSummary(): Promise<Record<string, unknown>> {
    const records = this._tenantId
      ? this._records.filter((r) => r.tenantId === this._tenantId)
      : this._records;

    const decisions: Record<string, number> = {};
    const toolsSet = new Set<string>();
    const controlStats: Record<string, Record<string, number>> = {};

    for (const record of records) {
      const d = record.decision.trim().toUpperCase();
      decisions[d] = (decisions[d] ?? 0) + 1;
      toolsSet.add(record.toolName);

      for (const cr of record.controlResults as Array<Record<string, unknown>>) {
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

    const { valid: chainValid, errors: chainErrors } = await this.verifyChain();

    return {
      totalEvaluations: records.length,
      decisions,
      toolsEvaluated: [...toolsSet].sort(),
      controlPassRates: controlStats,
      patternDetections: {},
      chainValid,
      chainErrors,
    };
  }

  // ---------------------------------------------------------------------------
  // Test helpers (not present on real EvidenceStore)
  // ---------------------------------------------------------------------------

  /** Remove all stored records. Call this in `beforeEach` to isolate tests. */
  clear(): void {
    this._records = [];
  }

  /** Return all stored records in insertion order. */
  getAll(): EvidenceRecord[] {
    return [...this._records];
  }

  /** Return the most recently stored record, or `undefined` if empty. */
  getLastRecord(): EvidenceRecord | undefined {
    return this._records[this._records.length - 1];
  }

  /** Return all records for a given tool name. */
  getRecordsForTool(toolName: string): EvidenceRecord[] {
    return this._records.filter((r) => r.toolName === toolName);
  }

  /** Return all records matching a decision (`ALLOW`, `BLOCK`, `FLAG`). */
  getRecordsForDecision(decision: string): EvidenceRecord[] {
    return this._records.filter(
      (r) => r.decision.trim().toUpperCase() === decision.trim().toUpperCase(),
    );
  }

  /**
   * Inject a fake record directly — useful for seeding store state without
   * running an Engine evaluation.
   */
  addFakeRecord(partial: Partial<EvidenceRecord> & { toolName: string }): EvidenceRecord {
    const previousHash =
      this._records.length > 0
        ? this._records[this._records.length - 1]!.recordHash
        : GENESIS_SEED;

    const record: EvidenceRecord = {
      recordId: partial.recordId ?? randomUUID(),
      evaluationId: partial.evaluationId ?? randomUUID(),
      timestamp: partial.timestamp ?? new Date().toISOString(),
      agentId: partial.agentId ?? "test-agent",
      sourceType: partial.sourceType ?? "agent",
      toolName: partial.toolName,
      decision: partial.decision ?? "ALLOW",
      mode: partial.mode ?? "audit",
      controlResults: partial.controlResults ?? [],
      activeOverlays: partial.activeOverlays ?? [],
      dataClassifications: partial.dataClassifications ?? [],
      activeCertifications: partial.activeCertifications ?? this._certifications,
      recordHash: "",
      previousHash,
      totalDurationMs: partial.totalDurationMs ?? 0,
      outputSummary: partial.outputSummary ?? null,
      sessionId: partial.sessionId ?? null,
      tenantId: partial.tenantId ?? this._tenantId ?? null,
      detectedDataTypes: partial.detectedDataTypes ?? [],
      sdkVersion: partial.sdkVersion ?? null,
      classificationContext: partial.classificationContext ?? {},
    };

    const canon = canonicalPayload({
      evaluationId: record.evaluationId,
      timestamp: record.timestamp,
      agentId: record.agentId,
      sourceType: record.sourceType,
      toolName: record.toolName,
      decision: record.decision,
      mode: record.mode,
      controlResults: record.controlResults,
      activeOverlays: record.activeOverlays,
      dataClassifications: record.dataClassifications,
      activeCertifications: record.activeCertifications,
      totalDurationMs: record.totalDurationMs,
      previousHash,
      outputSummary: record.outputSummary,
      sessionId: record.sessionId,
      tenantId: record.tenantId,
      detectedDataTypes: record.detectedDataTypes,
      sdkVersion: record.sdkVersion,
      classificationContext: record.classificationContext,
    });
    record.recordHash = computeHash(canon);

    this._records.push(record);
    return record;
  }

  /** No-op — present so code that calls `.close()` on the real store still works. */
  async close(): Promise<void> {
    // no-op
  }
}
