/**
 * BaselineManager — snapshot and drift detection for evidence baselines.
 *
 * Trust model: baselines are operator assertions (policy intent), not a link in
 * the evidence hash chain. They are stored in the same DuckDB database as
 * evidence_records for convenience, but they carry no cryptographic guarantee.
 * Treat them as configuration, not as audit proof.
 */

import { randomUUID } from "node:crypto";
import type { EvidenceStore } from "../evidence/store.js";
import type { ResolvedConfig } from "../config/index.js";
import { computeControlStats, DriftDetector, dominantResult, passRate } from "./drift.js";
import type { Baseline, ControlSnapshot, DriftReport } from "./models.js";

const CREATE_BASELINES_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS baselines (
    baseline_id VARCHAR PRIMARY KEY,
    created_at VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    overlay_id VARCHAR,
    label VARCHAR NOT NULL,
    control_snapshots JSON NOT NULL,
    metadata JSON,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    tenant_id VARCHAR
);`;

function rowToBaseline(row: Record<string, unknown>): Baseline {
  const snapshotsRaw = typeof row.control_snapshots === "string"
    ? JSON.parse(row.control_snapshots)
    : row.control_snapshots;
  const snapshots: ControlSnapshot[] = (snapshotsRaw as Array<Record<string, unknown>>).map(s => ({
    controlId: (s.control_id ?? s.controlId) as string,
    result: s.result as string,
    passRate: (s.pass_rate ?? s.passRate) as number,
    totalEvaluations: (s.total_evaluations ?? s.totalEvaluations) as number,
    evidenceWindowStart: (s.evidence_window_start ?? s.evidenceWindowStart) as string,
    evidenceWindowEnd: (s.evidence_window_end ?? s.evidenceWindowEnd) as string,
  }));
  const metaRaw = row.metadata;
  const metadata = metaRaw
    ? (typeof metaRaw === "string" ? JSON.parse(metaRaw) as Record<string, unknown> : metaRaw as Record<string, unknown>)
    : null;
  return {
    baselineId: row.baseline_id as string,
    createdAt: row.created_at as string,
    agentId: row.agent_id as string,
    overlayId: (row.overlay_id as string | null | undefined) ?? null,
    label: row.label as string,
    controlSnapshots: snapshots,
    metadata,
    isActive: Boolean(row.is_active),
  };
}

function snapshotsToJson(snapshots: ControlSnapshot[]): string {
  return JSON.stringify(snapshots.map(s => ({
    control_id: s.controlId,
    result: s.result,
    pass_rate: s.passRate,
    total_evaluations: s.totalEvaluations,
    evidence_window_start: s.evidenceWindowStart,
    evidence_window_end: s.evidenceWindowEnd,
  })));
}

export class BaselineManager {
  private _store: EvidenceStore;
  private _config: ResolvedConfig;
  private _detector: DriftDetector;
  private _tenantId: string | undefined;
  private _initialized: Promise<void> | null = null;

  constructor(store: EvidenceStore, config: ResolvedConfig, options?: { tenantId?: string }) {
    this._store = store;
    this._config = config;
    this._detector = new DriftDetector();
    this._tenantId = options?.tenantId;
  }

  private get agentId(): string {
    return (this._config.agentName as string | undefined) || "default";
  }

  private ensureTable(): Promise<void> {
    if (this._initialized) return this._initialized;
    this._initialized = (async () => {
      await this._store.exec(CREATE_BASELINES_TABLE_SQL);
      // Migrate: add tenant_id column if absent
      const cols = await this._store.query("PRAGMA table_info('baselines')");
      const hasCol = (cols as Array<Record<string, unknown>>).some(c => c.name === "tenant_id");
      if (!hasCol) {
        await this._store.exec("ALTER TABLE baselines ADD COLUMN tenant_id VARCHAR");
      }
      await this._store.exec("CREATE INDEX IF NOT EXISTS idx_baselines_agent_active ON baselines(agent_id, is_active)");
      await this._store.exec("CREATE INDEX IF NOT EXISTS idx_baselines_agent_overlay ON baselines(agent_id, overlay_id)");
    })();
    return this._initialized;
  }

  async create(options: {
    label: string;
    overlayId?: string;
    evidenceWindowHours?: number;
    metadata?: Record<string, unknown>;
  }): Promise<Baseline> {
    await this.ensureTable();
    const { label, overlayId, evidenceWindowHours = 168, metadata } = options;
    const agentId = this.agentId;
    const now = new Date();
    const windowStart = new Date(now.getTime() - evidenceWindowHours * 3600 * 1000).toISOString();
    const windowEnd = now.toISOString();

    const conditions: string[] = ["agent_id = ?", "timestamp >= ?"];
    const params: unknown[] = [agentId, windowStart];
    if (this._tenantId) {
      conditions.push("tenant_id = ?");
      params.push(this._tenantId);
    }
    if (overlayId !== undefined) {
      conditions.push("list_contains(CAST(active_overlays AS VARCHAR[]), ?)");
      params.push(overlayId);
    }

    const where = ` WHERE ${conditions.join(" AND ")}`;
    const rows = await this._store.query(
      `SELECT control_results FROM evidence_records${where}`,
      params,
    );

    const stats = computeControlStats(rows as Array<{ control_results: unknown }>);

    const snapshots: ControlSnapshot[] = Object.entries(stats).map(([cid, s]) => ({
      controlId: cid,
      result: dominantResult(s),
      passRate: passRate(s),
      totalEvaluations: s.total,
      evidenceWindowStart: windowStart,
      evidenceWindowEnd: windowEnd,
    }));

    // Deactivate existing active baseline for same agent+overlay
    if (overlayId !== undefined) {
      await this._store.run(
        "UPDATE baselines SET is_active = FALSE WHERE agent_id = ? AND overlay_id = ? AND is_active = TRUE",
        [agentId, overlayId],
      );
    } else {
      await this._store.run(
        "UPDATE baselines SET is_active = FALSE WHERE agent_id = ? AND overlay_id IS NULL AND is_active = TRUE",
        [agentId],
      );
    }

    const baselineId = randomUUID();
    const createdAt = now.toISOString();
    const baseline: Baseline = {
      baselineId,
      createdAt,
      agentId,
      overlayId: overlayId ?? null,
      label,
      controlSnapshots: snapshots,
      metadata: metadata ?? null,
      isActive: true,
    };

    await this._store.run(
      "INSERT INTO baselines (baseline_id, created_at, agent_id, overlay_id, label, control_snapshots, metadata, is_active, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        baseline.baselineId,
        baseline.createdAt,
        baseline.agentId,
        baseline.overlayId,
        baseline.label,
        snapshotsToJson(baseline.controlSnapshots),
        baseline.metadata !== null ? JSON.stringify(baseline.metadata) : null,
        baseline.isActive,
        this._tenantId ?? null,
      ],
    );

    return baseline;
  }

  async listBaselines(overlayId?: string): Promise<Baseline[]> {
    await this.ensureTable();
    const agentId = this.agentId;
    const conditions: string[] = ["agent_id = ?"];
    const params: unknown[] = [agentId];

    if (this._tenantId) {
      conditions.push("tenant_id = ?");
      params.push(this._tenantId);
    }
    if (overlayId !== undefined) {
      conditions.push("overlay_id = ?");
      params.push(overlayId);
    }

    const where = ` WHERE ${conditions.join(" AND ")}`;
    const rows = await this._store.query(
      `SELECT baseline_id, created_at, agent_id, overlay_id, label, control_snapshots, metadata, is_active FROM baselines${where} ORDER BY created_at DESC`,
      params,
    );
    return (rows as Array<Record<string, unknown>>).map(rowToBaseline);
  }

  async getBaseline(baselineId: string): Promise<Baseline> {
    await this.ensureTable();
    const rows = await this._store.query(
      "SELECT baseline_id, created_at, agent_id, overlay_id, label, control_snapshots, metadata, is_active FROM baselines WHERE baseline_id = ?",
      [baselineId],
    );
    const row = (rows as Array<Record<string, unknown>>)[0];
    if (!row) throw new Error(`Baseline not found: ${baselineId}`);
    return rowToBaseline(row);
  }

  async checkDrift(options?: { baselineId?: string; overlayId?: string }): Promise<DriftReport> {
    await this.ensureTable();
    const agentId = this.agentId;
    let baseline: Baseline;

    if (options?.baselineId) {
      baseline = await this.getBaseline(options.baselineId);
    } else {
      const conditions: string[] = ["agent_id = ?", "is_active = TRUE"];
      const params: unknown[] = [agentId];
      if (this._tenantId) {
        conditions.push("tenant_id = ?");
        params.push(this._tenantId);
      }
      if (options?.overlayId !== undefined) {
        conditions.push("overlay_id = ?");
        params.push(options.overlayId);
      }
      const where = ` WHERE ${conditions.join(" AND ")}`;
      const rows = await this._store.query(
        `SELECT baseline_id, created_at, agent_id, overlay_id, label, control_snapshots, metadata, is_active FROM baselines${where} ORDER BY created_at DESC LIMIT 1`,
        params,
      );
      const row = (rows as Array<Record<string, unknown>>)[0];
      if (!row) throw new Error("No active baseline found. Run 'ancilis baseline create' first.");
      baseline = rowToBaseline(row);
    }

    const since = baseline.createdAt;
    const conditions: string[] = ["agent_id = ?", "timestamp >= ?"];
    const params: unknown[] = [agentId, since];
    if (this._tenantId) {
      conditions.push("tenant_id = ?");
      params.push(this._tenantId);
    }
    if (baseline.overlayId !== null) {
      conditions.push("list_contains(CAST(active_overlays AS VARCHAR[]), ?)");
      params.push(baseline.overlayId);
    }
    const where = ` WHERE ${conditions.join(" AND ")}`;

    const evidenceRows = await this._store.query(
      `SELECT control_results, evaluation_id, tool_name, timestamp FROM evidence_records${where}`,
      params,
    );

    // No evaluations since baseline → posture unchanged, report STABLE immediately.
    const typedEvidenceRows = evidenceRows as Array<Record<string, unknown>>;
    if (typedEvidenceRows.length === 0) {
      const { randomUUID } = await import("node:crypto");
      return {
        driftReportId: randomUUID(),
        baselineId: baseline.baselineId,
        baselineLabel: baseline.label,
        checkedAt: new Date().toISOString(),
        agentId: baseline.agentId,
        overlayId: baseline.overlayId,
        overallStatus: "STABLE",
        summary: {
          totalControls: baseline.controlSnapshots.length,
          regressed: 0,
          degraded: 0,
          stable: baseline.controlSnapshots.length,
        },
        controlDrifts: [],
      };
    }

    const currentStats = computeControlStats(
      typedEvidenceRows.map(r => ({ control_results: r.control_results })),
    );

    // First failure timestamps per control — single-pass over already-fetched rows, no N+1
    const firstFailures: Record<string, string | null> = {};
    for (const cid of Object.keys(currentStats)) {
      firstFailures[cid] = null;
    }
    for (const row of typedEvidenceRows) {
      const crRaw = row.control_results;
      const crs = typeof crRaw === "string"
        ? JSON.parse(crRaw) as Array<Record<string, unknown>>
        : crRaw as Array<Record<string, unknown>>;
      for (const cr of crs) {
        const cid = cr.control_id as string;
        const result = ((cr.result as string | undefined) ?? "SKIP").toUpperCase();
        if (result === "FAIL" || result === "ERROR") {
          const ts = row.timestamp as string;
          if (firstFailures[cid] === null || ts < firstFailures[cid]!) {
            firstFailures[cid] = ts;
          }
        }
      }
    }

    // New failure evaluation IDs and tools per control
    const newFailureIds: Record<string, string[]> = {};
    const failureTools: Record<string, string[]> = {};
    for (const row of typedEvidenceRows) {
      const crRaw = row.control_results;
      const crs = typeof crRaw === "string"
        ? JSON.parse(crRaw) as Array<Record<string, unknown>>
        : crRaw as Array<Record<string, unknown>>;
      for (const cr of crs) {
        const cid = cr.control_id as string;
        const result = ((cr.result as string | undefined) ?? "SKIP").toUpperCase();
        if (result === "FAIL" || result === "ERROR") {
          if (!newFailureIds[cid]) newFailureIds[cid] = [];
          if (!failureTools[cid]) failureTools[cid] = [];
          newFailureIds[cid]!.push(row.evaluation_id as string);
          const toolName = row.tool_name as string;
          if (!failureTools[cid]!.includes(toolName)) {
            failureTools[cid]!.push(toolName);
          }
        }
      }
    }

    return this._detector.detect(baseline, currentStats, firstFailures, newFailureIds, failureTools);
  }

  async deactivate(baselineId: string): Promise<void> {
    await this.ensureTable();
    await this._store.run(
      "UPDATE baselines SET is_active = FALSE WHERE baseline_id = ?",
      [baselineId],
    );
  }
}
