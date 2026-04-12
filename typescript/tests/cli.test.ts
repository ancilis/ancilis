/** Tests for CLI commands and report generation. */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { stringify as stringifyYaml, parse as parseYaml } from "yaml";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine, ToolRegistry, ToolStatus } from "../src/ancilis/engine/index.js";
import type { ToolEntry, Action, EvaluationResult } from "../src/ancilis/engine/index.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import type { EvidenceRecord } from "../src/ancilis/evidence/index.js";
import { formatStatus } from "../src/ancilis/cli/status.js";
import { validateAndFormat } from "../src/ancilis/cli/validate.js";
import { approveTool } from "../src/ancilis/cli/approve.js";
import { runDoctor, runReport } from "../src/ancilis/cli/index.js";
import { runCli } from "../src/cli.js";
import * as ancilis from "../src/ancilis/index.js";
import { ReportGenerator, renderTerminal, renderMarkdown, renderPdf, renderNdjson, renderCsv, renderOscalJson } from "../src/ancilis/report/index.js";
import type { EvidenceSummary, ReportData } from "../src/ancilis/report/index.js";
import type { RenderPdfResult } from "../src/ancilis/index.js";

// --- Helpers ---

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(dir: string, data: Record<string, unknown>): string {
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, stringifyYaml(data));
  return path;
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
      stdout(message: string) {
        out.push(message);
      },
      stderr(message: string) {
        err.push(message);
      },
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

function minimalConfig(): Record<string, unknown> {
  return { agent: { name: "test-agent" } };
}

function fullConfig(): Record<string, unknown> {
  return {
    agent: { name: "test-agent" },
    security: { mode: "audit" },
    my_agent_handles: ["credit_cards", "personal_info"],
    compliance: { evidence: { retention_days: 365 } },
  };
}

function makeAction(toolName = "read_file", agentId = "test-agent"): Action {
  return {
    actionId: `action-${randomUUID()}`,
    timestamp: new Date().toISOString(),
    agentId,
    agentOwner: "test-owner",
    actionType: "tool_call",
    tool: { name: toolName },
    parameters: { raw: {} } as any,
    context: { sessionId: "sess-1" } as any,
  };
}

function emptySummary(): EvidenceSummary {
  return {
    total_evaluations: 0,
    decisions: {},
    tools_evaluated: [],
    chain_valid: true,
    chain_errors: [],
  };
}

function populatedSummary(n = 5): EvidenceSummary {
  return {
    total_evaluations: n,
    decisions: { ALLOW: n },
    tools_evaluated: ["read_file"],
    control_pass_rates: {
      "PR-01": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-02": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-03": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-04": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-05": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "DE-01": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
    },
    chain_valid: true,
    chain_errors: [],
  };
}

function rendererReport(failingControls = 1): ReportData {
  const passingControl = (controlId: string, displayName: string): Record<string, unknown> => ({
    controlId,
    displayName,
    threshold: "95",
    total: 10,
    passed: 10,
    failed: 0,
    flagged: 0,
    passRate: 100,
  });

  const failingControl: Record<string, unknown> = {
    controlId: "PR-03",
    displayName: "Data Exposure Prevention",
    threshold: "95",
    total: 10,
    passed: 8,
    failed: 2,
    flagged: 0,
    passRate: 80,
  };

  const baselineControls = [
    passingControl("PR-01", "Identity Verification"),
    passingControl("PR-02", "Access Governance"),
    failingControls > 0 ? failingControl : passingControl("PR-03", "Data Exposure Prevention"),
    passingControl("PR-04", "Output Validation"),
    passingControl("PR-05", "Runtime Logging"),
    passingControl("DE-01", "Baseline Monitoring"),
  ];

  const makeSection = (overlayName: string): Record<string, unknown> => ({
    overlayName,
    triggeredBy: overlayName === "SOC 2" ? "credit_cards" : "",
    strictControls: overlayName === "PCI-DSS v4.0" ? ["PR-03"] : [],
    controls: [
      {
        controlId: "PR-03",
        citations: ["Art. 5(1)(f)", "Art. 32"],
        total: 10,
        passRate: failingControls > 0 ? 80 : 100,
        failed: failingControls > 0 ? 2 : 0,
      },
      {
        controlId: "PR-01",
        citations: ["CC6.1"],
        total: 10,
        passRate: 100,
        failed: 0,
      },
    ],
    gaps: failingControls > 0 ? [{ displayName: "Data Exposure Prevention", failed: 2 }] : [],
    evidenceRetentionDays: 365,
    retentionMet: true,
  });

  return {
    agentName: "test-agent",
    mode: "audit",
    periodStart: "2026-01-01T00:00:00.000Z",
    periodEnd: "2026-01-31T00:00:00.000Z",
    generatedAt: "2026-01-31T00:00:00.000Z",
    reportFormat: "markdown",
    baseline: {
      controls: baselineControls,
      toolsEvaluated: ["read_file"],
      totalEvaluations: 1234,
      decisions: { allow: 1222, block: 12, flag: 0 },
      evidenceRetentionDays: 365,
    },
    complianceSections: [
      makeSection("SOC 2"),
      makeSection("PCI-DSS v4.0"),
      makeSection("GLBA"),
      makeSection("GDPR"),
    ],
    certification: {
      certificationName: "AIUC-1",
      readinessPercentage: 87,
      readyCount: 15,
      totalRequirements: 18,
      coveragePercentage: 83,
      automatedCount: 10,
      operatorCount: 2,
      evidenceCount: 1234,
      chainValid: true,
    },
    advisory: null,
    totalEvaluations: 1234,
    chainValid: true,
    chainErrors: [],
  };
}

async function populateEvidence(
  config: ResolvedConfig,
  store: EvidenceStore,
  entries: Array<{ timestamp?: string; toolName?: string; outputSummary?: string }> = [{}],
): Promise<void> {
  const registry = new ToolRegistry();
  registry.register({
    name: "read_file",
    status: ToolStatus.APPROVED,
    approvedBy: "config",
    firstSeen: new Date().toISOString(),
    statusChanged: new Date().toISOString(),
  });

  const engine = new Engine(config, { registry });
  for (const entry of entries) {
    const toolName = entry.toolName ?? "read_file";
    const action: Action = {
      ...makeAction(toolName, config.agentName),
      timestamp: entry.timestamp ?? new Date().toISOString(),
    };
    const evaluation = engine.evaluate(action);
    evaluation.timestamp = entry.timestamp ?? evaluation.timestamp;
    await store.store(evaluation, toolName, entry.outputSummary);
  }
}

function sampleEvidenceRecord(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    recordId: "record-1",
    evaluationId: "evaluation-1",
    timestamp: "2026-04-04T00:00:00Z",
    agentId: "test-agent",
    sourceType: "agent",
    toolName: "read_file",
    decision: "ALLOW",
    mode: "audit",
    controlResults: [{ control_id: "PR-01", result: "PASS" }],
    activeOverlays: [],
    dataClassifications: [],
    activeCertifications: [],
    recordHash: "hash-1",
    previousHash: "prev-1",
    totalDurationMs: 5,
    outputSummary: "sample-output",
    ...overrides,
  };
}

// ===== Status Tests =====

describe("formatStatus", () => {
  it("shows agent name and mode", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, emptySummary());
    expect(output).toContain("test-agent");
    expect(output).toContain("Mode: audit");
  });

  it("shows control count", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, emptySummary());
    expect(output).toContain("Controls:");
    expect(output).toContain("active");
  });

  it("shows empty evidence message", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, emptySummary());
    expect(output).toContain("No evaluations recorded");
  });

  it("counts blocked decisions case-insensitively", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, {
      ...emptySummary(),
      total_evaluations: 2,
      decisions: { block: 2 },
    });
    expect(output).toContain("2 blocked");
  });

  it("shows overlay info when active", () => {
    const config = loadConfig({ raw: fullConfig() });
    const output = formatStatus(config, emptySummary());
    expect(output.toLowerCase()).toMatch(/soc 2|gdpr/);
  });

  it("verbose adds per-control detail", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, populatedSummary(), true);
    expect(output).toContain("Controls:");
    // Should have checkmarks for passing controls
    expect(output).toContain("\u2713");
  });

  it("verbose shows activation details", () => {
    const config = loadConfig({ raw: fullConfig() });
    const output = formatStatus(config, populatedSummary(), true);
    expect(output).toContain("Activation:");
  });

  it("no control IDs in default output", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, populatedSummary());
    // PR-01: and DE-01: should not appear as labels
    for (const line of output.split("\n")) {
      if (line.includes("certification_targets")) continue;
      expect(line).not.toContain("PR-01:");
      expect(line).not.toContain("DE-01:");
    }
  });

  it("no control IDs in verbose output", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, populatedSummary(), true);
    for (const line of output.split("\n")) {
      if (line.includes("certification_targets") || line.includes("Controls:")) continue;
      expect(line).not.toContain("PR-01:");
      expect(line).not.toContain("DE-01:");
    }
  });

  it("zero-config has no framework references", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, emptySummary()).toLowerCase();
    expect(output).not.toContain("hipaa");
    expect(output).not.toContain("gdpr");
    expect(output).not.toContain("aiuc");
  });
});

// ===== Validate Tests =====

describe("validateAndFormat", () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("valid config shows check mark", () => {
    const path = writeConfig(dir, minimalConfig());
    const { valid, message } = validateAndFormat(path);
    expect(valid).toBe(true);
    expect(message).toContain("\u2713");
    expect(message).toContain("test-agent");
  });

  it("invalid data type shows error", () => {
    const data = { ...minimalConfig(), my_agent_handles: ["fake_data"] };
    const path = writeConfig(dir, data);
    const { valid, message } = validateAndFormat(path);
    expect(valid).toBe(false);
    expect(message).toContain("Unknown data type");
  });

  it("missing config shows error", () => {
    const { valid, message } = validateAndFormat("/nonexistent/ancilis.yaml");
    expect(valid).toBe(false);
  });

  it("both paths show activation summary", () => {
    const path = writeConfig(dir, fullConfig());
    const { valid, message } = validateAndFormat(path);
    expect(valid).toBe(true);
    expect(message).toContain("test-agent");
  });
});

// ===== Approve Tool Tests =====

describe("approveTool", () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("adds tool to config", () => {
    const path = writeConfig(dir, minimalConfig());
    const { success, message } = approveTool("send_email", path);
    expect(success).toBe(true);
    expect(message).toContain("Added 'send_email'");

    // Verify written
    const data = parseYaml(readFileSync(path, "utf-8"));
    expect(data.security.tools.allowed).toContain("send_email");
  });

  it("already approved", () => {
    const data = { ...minimalConfig(), security: { tools: { allowed: ["send_email"] } } };
    const path = writeConfig(dir, data);
    const { success, message } = approveTool("send_email", path);
    expect(success).toBe(true);
    expect(message).toContain("already");
  });

  it("config not found", () => {
    const { success } = approveTool("x", "/nonexistent/ancilis.yaml");
    expect(success).toBe(false);
  });
});

// ===== Doctor Tests =====

describe("runDoctor", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reports core checks and current evidence count", async () => {
    const configPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "evidence.duckdb");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateEvidence(config, store);
    await store.close();

    const result = await runDoctor(configPath, dbPath);

    expect(result.ok).toBe(true);
    expect(result.output).toContain("Ancilis doctor");
    expect(result.output).toContain("[OK] config:");
    expect(result.output).toContain("[OK] assets:");
    expect(result.output).toContain("[OK] evidence store:");
    expect(result.output).toContain("1 records present");
  });

  it("fails on missing config", async () => {
    const result = await runDoctor(join(dir, "missing.yaml"));

    expect(result.ok).toBe(false);
    expect(result.output).toContain("[FAIL] config:");
  });

  it("reports the packaged taxonomy version and optional mcp diagnostic", async () => {
    const configPath = writeConfig(dir, minimalConfig());
    const taxonomyPath = join(process.cwd(), "shared", "classifications", "taxonomy.json");
    const taxonomy = JSON.parse(readFileSync(taxonomyPath, "utf-8")) as { version: string };

    const result = await runDoctor(configPath, join(dir, "doctor.duckdb"));

    expect(result.output).toContain(`taxonomy ${taxonomy.version}`);
    expect(result.output).toContain("optional mcp extra:");
  });

  it("reports the optional mcp extra as installed when the package is present", async () => {
    const configPath = writeConfig(dir, minimalConfig());

    const result = await runDoctor(configPath, join(dir, "doctor.duckdb"));

    expect(result.output).toContain("[OK] optional mcp extra: installed");
  });

  it("includes node version check in output", async () => {
    const configPath = writeConfig(dir, minimalConfig());

    const result = await runDoctor(configPath, join(dir, "doctor.duckdb"));

    expect(result.output).toMatch(/\[OK\] node version: Node\.js \d+\.\d+\.\d+ \(>= 18 required\)/);
  });

  it("includes overlay existence check in output", async () => {
    const configPath = writeConfig(dir, minimalConfig());

    const result = await runDoctor(configPath, join(dir, "doctor.duckdb"));

    expect(result.output).toContain("[OK] overlays:");
  });

  it("prints 'All checks passed.' summary on success", async () => {
    const configPath = writeConfig(dir, minimalConfig());

    const result = await runDoctor(configPath, join(dir, "doctor.duckdb"));

    expect(result.ok).toBe(true);
    expect(result.output).toContain("All checks passed.");
  });

  it("prints failure count summary on any failure", async () => {
    const result = await runDoctor(join(dir, "missing.yaml"), join(dir, "no.duckdb"));

    expect(result.ok).toBe(false);
    expect(result.output).toMatch(/\d+ check\(s\) failed/);
  });

  it("skips platform connectivity check when platform_url is not set", async () => {
    const configPath = writeConfig(dir, minimalConfig());

    const result = await runDoctor(configPath, join(dir, "doctor.duckdb"));

    expect(result.output).toContain("platform connectivity: platform_url not set");
    expect(result.output).not.toContain("[FAIL] platform connectivity:");
  });
});

// ===== Report Command Tests =====

describe("runReport", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("filters evidence to the requested reporting period", async () => {
    const configPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "report.duckdb");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    const now = Date.now();

    await populateEvidence(config, store, [
      { timestamp: new Date(now - 45 * 86400000).toISOString() },
      { timestamp: new Date(now - 2 * 86400000).toISOString() },
    ]);
    await store.close();

    const result = await runReport({
      configPath,
      dbPath,
      period: "30d",
      format: "markdown",
    });

    expect(result.ok).toBe(true);
    expect(result.output).toContain("- Evaluations: 1");
    expect(result.output).not.toContain("- Evaluations: 2");
  });

  it("writes markdown output to a file", async () => {
    const configPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "report.duckdb");
    const outputPath = join(dir, "report.md");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateEvidence(config, store);
    await store.close();

    const result = await runReport({
      configPath,
      dbPath,
      period: "30d",
      format: "markdown",
      outputPath,
    });

    expect(result.ok).toBe(true);
    expect(existsSync(outputPath)).toBe(true);
    expect(readFileSync(outputPath, "utf-8")).toContain("# Ancilis Posture Report");
  });

  it("writes ndjson output to a file", async () => {
    const configPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "report.duckdb");
    const outputPath = join(dir, "report.ndjson");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    const now = Date.now();
    await populateEvidence(config, store, [
      { timestamp: new Date(now - 2 * 86400000).toISOString(), outputSummary: "recent" },
      { timestamp: new Date(now - 45 * 86400000).toISOString(), outputSummary: "older" },
    ]);
    await store.close();

    const result = await runReport({
      configPath,
      dbPath,
      period: "7d",
      format: "ndjson",
      outputPath,
    });

    expect(result.ok).toBe(true);
    expect(existsSync(outputPath)).toBe(true);
    const rows = readFileSync(outputPath, "utf-8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.tool_name).toBe("read_file");
    expect(rows[0]?.output_summary).toBe("recent");
    expect(rows[0]?.decision).toBe("ALLOW");
    expect(rows[0]?.source_type).toBe("agent");
    expect(rows[0]?.record_hash).toBeTruthy();
    expect(rows[0]?.previous_hash).toBeTruthy();
  });

  it("writes csv output to a file", async () => {
    const configPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "report.duckdb");
    const outputPath = join(dir, "report.csv");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateEvidence(config, store, [{ outputSummary: "csv-export" }]);
    await store.close();

    const result = await runReport({
      configPath,
      dbPath,
      period: "30d",
      format: "csv",
      outputPath,
    });

    expect(result.ok).toBe(true);
    expect(existsSync(outputPath)).toBe(true);
    const rows = readFileSync(outputPath, "utf-8").trim().split("\n");
    expect(rows[0]).toContain("record_id,evaluation_id,timestamp,agent_id,source_type,tool_name,decision,mode");
    expect(rows).toHaveLength(2);
    expect(rows[1]).toContain("read_file");
    expect(rows[1]).toContain("ALLOW");
    expect(rows[1]).toContain("csv-export");
    expect(rows[1]).toContain(",[],[],[],");
  });

  it("writes oscal json output to a file", async () => {
    const configPath = writeConfig(dir, fullConfig());
    const dbPath = join(dir, "report.duckdb");
    const outputPath = join(dir, "report-oscal.json");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateEvidence(config, store);
    await store.close();

    const result = await runReport({
      configPath,
      dbPath,
      period: "30d",
      format: "oscal-json",
      outputPath,
    });

    expect(result.ok).toBe(true);
    expect(existsSync(outputPath)).toBe(true);
    const document = JSON.parse(readFileSync(outputPath, "utf-8")) as {
      "assessment-results"?: {
        metadata?: { title?: string };
        results?: Array<{ findings?: Array<{ target?: { type?: string } }> }>;
      };
    };
    expect(document["assessment-results"]?.metadata?.title).toContain("test-agent");
    expect(
      document["assessment-results"]?.results?.[0]?.findings?.some(
        (finding) => finding.target?.type === "baseline_control",
      ),
    ).toBe(true);
  });

  it("reports a markdown fallback when pdf tooling is unavailable", async () => {
    const configPath = writeConfig(dir, minimalConfig());
    const dbPath = join(dir, "report.duckdb");
    const outputPath = join(dir, "report.pdf");
    const fallbackPath = join(dir, "report.md");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateEvidence(config, store);
    await store.close();

    const originalPath = process.env.PATH;
    process.env.PATH = "";

    try {
      const result = await runReport({
        configPath,
        dbPath,
        period: "30d",
        format: "pdf",
        outputPath,
      });

      expect(result.ok).toBe(true);
      expect(result.output).toBe(
        `PDF export unavailable (pandoc/xelatex unavailable); wrote Markdown fallback to ${fallbackPath}`,
      );
      expect(result.outputPath).toBe(fallbackPath);
      expect(existsSync(outputPath)).toBe(false);
      expect(readFileSync(fallbackPath, "utf-8")).toContain("# Ancilis Posture Report");
    } finally {
      process.env.PATH = originalPath;
    }
  });
});

describe("package metadata", () => {
  it("exports public runtime helpers from the package root", () => {
    const root = ancilis as Record<string, unknown>;

    expect(root.ToolStatus).toBeDefined();
    expect(root.scanResponse).toBeDefined();
    expect(root.loadCertificationProfile).toBeDefined();
    expect(root.loadCertificationProfiles).toBeDefined();
    expect(root.loadControlDefinitions).toBeDefined();
    expect(root.loadOverlayProfiles).toBeDefined();
  });

  it("exports PDF renderer result types from the package root", () => {
    const result: RenderPdfResult = {
      format: "markdown",
      outputPath: "ancilis-report.md",
    };

    expect(result.format).toBe("markdown");
    expect(result.outputPath).toBe("ancilis-report.md");
  });

  it("ships a CLI executable for npm consumers", { timeout: 30_000 }, () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf-8")) as {
      bin?: Record<string, string>;
    };

    expect(pkg.bin).toEqual({ ancilis: "./dist/cli.js" });

    const packed = JSON.parse(
      execFileSync("npm", ["pack", "--dry-run", "--json"], {
        cwd: process.cwd(),
        encoding: "utf-8",
      }),
    ) as Array<{ files: Array<{ path: string }> }>;

    expect(packed[0]?.files.some((file) => file.path === "dist/cli.js")).toBe(true);
  });

  it("does not ship Python build artifacts in the npm tarball", () => {
    const packed = JSON.parse(
      execFileSync("npm", ["pack", "--dry-run", "--json"], {
        cwd: process.cwd(),
        encoding: "utf-8",
      }),
    ) as Array<{ files: Array<{ path: string }> }>;

    const paths = packed[0]?.files.map((file) => file.path) ?? [];

    expect(paths).not.toContain("dist/ancilis-0.1.0-py3-none-any.whl");
    expect(paths).not.toContain("dist/ancilis-0.1.0.tar.gz");
  });

  it("provides an ESLint 9 config for TypeScript source", () => {
    const eslintPath = join(process.cwd(), "node_modules", ".bin", "eslint");
    expect(() =>
      execFileSync(eslintPath, ["typescript/src/cli.ts"], {
        cwd: process.cwd(),
        encoding: "utf-8",
        stdio: "pipe",
      }),
    ).not.toThrow();
  });
});

// ===== Report — Baseline Tests =====

describe("Report — Baseline", () => {
  it("baseline report with no overlays", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, populatedSummary(5));
    const report = gen.generate("30d");
    expect(report.baseline).toBeDefined();
    expect((report.baseline as any).totalEvaluations).toBe(5);
    expect(report.complianceSections.length).toBe(0);
    expect(report.certification).toBeNull();
  });

  it("terminal output", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, populatedSummary(3));
    const report = gen.generate();
    const output = renderTerminal(report);
    expect(output).toContain("test-agent");
    expect(output).toContain("Controls:");
  });

  it("terminal output includes evaluated tools", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, populatedSummary(3));
    const report = gen.generate();
    const output = renderTerminal(report);
    expect(output).toContain("Tools evaluated: read_file");
  });

  it("markdown output", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, populatedSummary(3));
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);
    expect(md).toContain("# Ancilis Posture Report");
    expect(md).toContain("Baseline Security");
    expect(md).toContain("Pass Rate");
  });

  it("renders baseline pass rates with one decimal place", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const summary: EvidenceSummary = {
      ...emptySummary(),
      total_evaluations: 1,
      control_pass_rates: {
        "PR-01": { PASS: 1, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      },
    };

    const gen = new ReportGenerator(config, summary);
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);

    expect(md).toContain("| Identity verification | 100.0% | 1 | Pass |");
  });
});

// ===== Report — Compliance Tests =====

describe("Report — Compliance", () => {
  it("overlays produce compliance sections", () => {
    const config = loadConfig({ raw: fullConfig() });
    const gen = new ReportGenerator(config, populatedSummary(3));
    const report = gen.generate();
    expect(report.complianceSections.length).toBeGreaterThan(0);
    const names = report.complianceSections.map(s => s.overlayName as string);
    // credit_cards and personal_info activate SOC 2 and GDPR
    expect(names.some(n => n.includes("SOC 2"))).toBe(true);
  });

  it("compliance sections have citations", () => {
    const config = loadConfig({ raw: fullConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate();
    // SOC 2 is activated by credit_cards and personal_info
    const soc2 = report.complianceSections.find(s => (s.overlayName as string).includes("SOC 2"));
    expect(soc2).toBeDefined();
    const controls = soc2!.controls as Record<string, unknown>[];
    expect(controls.some(c => (c.citations as string[])?.length > 0)).toBe(true);
  });

  it("multiple overlays", () => {
    const config = loadConfig({ raw: fullConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate();
    // credit_cards and personal_info trigger SOC 2 and GDPR
    expect(report.complianceSections.length).toBeGreaterThanOrEqual(2);
  });

  it("compliance markdown", () => {
    const config = loadConfig({ raw: fullConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);
    expect(md).toContain("Compliance Posture");
    expect(md).toContain("Citation");
  });

  it("renders compliance pass rates with one decimal place", () => {
    const config = loadConfig({ raw: fullConfig() });
    const summary = populatedSummary(2);
    summary.control_pass_rates = {
      ...summary.control_pass_rates,
      "PR-01": { PASS: 2, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
    };

    const gen = new ReportGenerator(config, summary);
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);

    expect(md).toContain("| Art. 5(1)(f), Art. 32 | PR-01 | 2 | 100.0% |");
  });

  it("compliance output includes evidence retention guidance", () => {
    const config = loadConfig({ raw: fullConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);
    expect(md).toContain("Evidence retention:");
  });

  it("gaps framed as improvements", () => {
    const config = loadConfig({ raw: fullConfig() });
    const summary = populatedSummary(2);
    // Add some failures
    summary.control_pass_rates!["PR-04"] = { PASS: 1, FAIL: 1, FLAG: 0, SKIP: 0, ERROR: 0 };
    const gen = new ReportGenerator(config, summary);
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);
    if (md.includes("Areas for Improvement")) {
      const afterGaps = md.split("Areas for Improvement")[1]?.split("##")[0] ?? "";
      expect(afterGaps.toLowerCase()).not.toContain("failure");
      expect(afterGaps.toLowerCase()).toContain("issues");
    }
  });
});

// ===== Report — AIUC-1 Readiness Tests =====

describe("Report — AIUC-1 Readiness", () => {
  function certConfig(): ResolvedConfig {
    const config = loadConfig({ raw: minimalConfig() });
    config.activeCertifications = ["aiuc-1"];
    return config;
  }

  it("aiuc1 readiness falls back to the standard posture report without active certifications", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, populatedSummary(5));
    const report = gen.generate("30d", "aiuc1-readiness");
    const md = renderMarkdown(report);

    expect(report.certification).toBeNull();
    expect(md).toContain("# Ancilis Posture Report");
    expect(md).not.toContain("AIUC-1 READINESS REPORT");
  });

  it("aiuc1 report generated", () => {
    const config = certConfig();
    const gen = new ReportGenerator(config, populatedSummary(5));
    const report = gen.generate("30d", "aiuc1-readiness");
    expect(report.certification).not.toBeNull();
    expect(report.certification!.certificationId).toBe("aiuc-1");
  });

  it("automated coverage has requirement mappings", () => {
    const config = certConfig();
    const gen = new ReportGenerator(config, populatedSummary(5));
    const report = gen.generate("30d", "aiuc1-readiness");
    const cert = report.certification!;
    expect((cert.automatedCount as number)).toBeGreaterThan(0);
    const automated = cert.automatedCoverage as Record<string, unknown>[];
    for (const item of automated) {
      expect(item.requirementId).toBeDefined();
      expect(item.aksiControl).toBeDefined();
    }
  });

  it("operator items match profile", () => {
    const config = certConfig();
    const gen = new ReportGenerator(config, populatedSummary(5));
    const report = gen.generate("30d", "aiuc1-readiness");
    const cert = report.certification!;
    const operator = cert.operatorActionRequired as Record<string, string>[];
    expect(operator.length).toBeGreaterThan(0);
    const reqIds = operator.map(item => item.requirementId);
    expect(reqIds).toContain("A006");
    expect(reqIds).toContain("F001");
  });

  it("operator items framed correctly", () => {
    const config = certConfig();
    const gen = new ReportGenerator(config, populatedSummary(5));
    const report = gen.generate("30d", "aiuc1-readiness");
    const md = renderMarkdown(report);
    expect(md.toLowerCase()).toContain("your team");
    expect(md.toLowerCase()).not.toContain("ancilis failed");
  });

  it("hash chain status shown", () => {
    const config = certConfig();
    const gen = new ReportGenerator(config, populatedSummary(3));
    const report = gen.generate("30d", "aiuc1-readiness");
    const md = renderMarkdown(report);
    expect(md.toLowerCase()).toContain("hash chain");
  });

  it("evidence counts from summary", () => {
    const config = certConfig();
    const gen = new ReportGenerator(config, populatedSummary(7));
    const report = gen.generate("30d", "aiuc1-readiness");
    expect(report.certification!.evidenceCount).toBe(7);
  });

  it("aiuc1 readiness markdown", () => {
    const config = certConfig();
    const gen = new ReportGenerator(config, populatedSummary(5));
    const report = gen.generate("30d", "aiuc1-readiness");
    const md = renderMarkdown(report);
    expect(md).toContain("AIUC-1 READINESS REPORT");
    expect(md).toContain("Readiness Summary");
    expect(md).toContain("Readiness:");
    expect(md).toContain("Coverage:");
    expect(md).toContain("Operator Action Required");
  });
});

// ===== Report — Combined Mode Tests =====

describe("Report — Combined Mode", () => {
  it("both paths produce all sections", () => {
    const config = loadConfig({ raw: fullConfig() });
    config.activeCertifications = ["aiuc-1"];
    const gen = new ReportGenerator(config, populatedSummary(3));
    const report = gen.generate();
    expect(report.baseline).toBeDefined();
    expect(report.complianceSections.length).toBeGreaterThan(0);
    expect(report.certification).not.toBeNull();
  });

  it("sections are additive in markdown", () => {
    const config = loadConfig({ raw: fullConfig() });
    config.activeCertifications = ["aiuc-1"];
    const gen = new ReportGenerator(config, populatedSummary(3));
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);
    expect(md).toContain("Baseline Security");
    expect(md).toContain("Compliance Posture");
    expect(md).toContain("AIUC-1");
  });
});

describe("Report — Advisory", () => {
  it("renders advisory recommendations from pattern detections", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, {
      ...populatedSummary(1),
      pattern_detections: {
        credit_card: 2,
      },
    });
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);

    expect(report.advisory).not.toBeNull();
    expect(md).toContain("Classification Advisory");
    expect(md).toContain("credit_cards");
    expect(md).toContain("my_agent_handles");
  });
});

// ===== Output Format Tests =====

describe("Output Formats", () => {
  it("terminal and markdown contain same agent name", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate();
    const terminal = renderTerminal(report);
    const md = renderMarkdown(report);
    expect(terminal).toContain("test-agent");
    expect(md).toContain("test-agent");
  });

  it("markdown has headers and tables", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate("30d", "markdown");
    const md = renderMarkdown(report);
    expect(md).toContain("# ");
    expect(md).toContain("|");
  });

  it("ndjson emits evidence records", () => {
    const rows = renderNdjson([
      sampleEvidenceRecord(),
      sampleEvidenceRecord({
        recordId: "record-2",
        evaluationId: "evaluation-2",
        outputSummary: "second-output",
      }),
    ])
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));

    expect(rows[0]?.record_id).toBe("record-1");
    expect(rows[0]?.agent_id).toBe("test-agent");
    expect(rows[0]?.tool_name).toBe("read_file");
    expect(rows[1]?.output_summary).toBe("second-output");
  });

  it("csv emits a stable evidence export schema", () => {
    const rows = renderCsv([sampleEvidenceRecord()]).trim().split("\n");

    expect(rows[0]).toContain("record_id,evaluation_id,timestamp,agent_id,source_type,tool_name,decision,mode");
    expect(rows[0]).toContain("control_results,active_overlays,data_classifications,active_certifications");
    expect(rows[0]).toContain("record_hash,previous_hash,total_duration_ms,output_summary");
    expect(rows[1]).toContain("record-1");
    expect(rows[1]).toContain("test-agent");
    expect(rows[1]).toContain("read_file");
    expect(rows[1]).toContain("sample-output");
  });

  it("oscal json emits assessment results with control findings", () => {
    const config = loadConfig({ raw: fullConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate("30d", "oscal-json");
    const document = JSON.parse(renderOscalJson(report)) as {
      "assessment-results"?: {
        metadata?: { title?: string };
        results?: Array<{ findings?: Array<{ target?: { type?: string; controlId?: string } }> }>;
      };
    };

    expect(document["assessment-results"]?.metadata?.title).toContain("test-agent");
    expect(
      document["assessment-results"]?.results?.[0]?.findings?.some(
        (finding) => finding.target?.type === "baseline_control" && finding.target?.controlId === "PR-01",
      ),
    ).toBe(true);
    expect(
      document["assessment-results"]?.results?.[0]?.findings?.some(
        (finding) => finding.target?.type === "compliance_control",
      ),
    ).toBe(true);
  });

  it("pdf renderer writes a markdown fallback next to the requested pdf when pandoc is unavailable", () => {
    const dir = tmpDir();
    const outputPath = join(dir, "report.pdf");
    const fallbackPath = join(dir, "report.md");
    const markdown = "# Example Report\n";

    const result = renderPdf(markdown, outputPath, {
      execFile: () => {
        const err = new Error("pandoc missing") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        throw err;
      },
    });

    expect(result).toEqual({
      format: "markdown",
      outputPath: fallbackPath,
      fallbackReason: "pandoc/xelatex unavailable",
    });
    expect(existsSync(outputPath)).toBe(false);
    expect(readFileSync(fallbackPath, "utf-8")).toBe(markdown);
    rmSync(fallbackPath, { force: true });
  });
});

describe("Report Renderer UX", () => {
  it("terminal adds posture summary and collapses passing controls", () => {
    const output = renderTerminal(rendererReport(1));

    expect(output).toContain("Posture: ATTENTION");
    expect(output).toContain("Evaluations: 1,234 total | 12 blocked | 1,222 allowed");
    expect(output).toContain("Active overlays: SOC 2, PCI-DSS v4.0, GLBA, GDPR");
    expect(output).toContain("Active certifications: AIUC-1 (87% ready)");
    expect(output).toContain("Evidence chain: ✓ intact (1,234 records)");
    expect(output).toContain("✗ Data Exposure Prevention — 80.0% pass rate (10 evaluations)");
    expect(output).toContain("✓ 5 controls passing");
    expect(output).not.toContain("Access Governance — 100.0% pass rate");
  });

  it("terminal replaces overlay sections with a compact matrix", () => {
    const output = renderTerminal(rendererReport(1));

    expect(output).toContain("Compliance Matrix:");
    expect(output).toContain("Control");
    expect(output).toContain("SOC 2");
    expect(output).toContain("PCI-DSS v4.0");
    expect(output).toContain("PR-03");
    expect(output).toContain("✗(2)");
    expect(output).not.toContain("SOC 2 Compliance Posture");
    expect(output).not.toContain("GDPR Compliance Posture");
    expect(output.split("\n").length).toBeLessThan(40);
  });

  it("terminal uses color when stdout is a tty", () => {
    const descriptor = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
    delete process.env.NO_COLOR;
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });

    try {
      const output = renderTerminal(rendererReport(1));
      expect(output).toContain("\u001b[1m");
      expect(output).toContain("\u001b[31m");
      expect(output).toContain("\u001b[32m");
    } finally {
      if (descriptor) {
        Object.defineProperty(process.stdout, "isTTY", descriptor);
      }
    }
  });

  it("terminal disables color when NO_COLOR is set", () => {
    const descriptor = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
    process.env.NO_COLOR = "1";
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });

    try {
      const output = renderTerminal(rendererReport(1));
      expect(output).not.toContain("\u001b[");
    } finally {
      delete process.env.NO_COLOR;
      if (descriptor) {
        Object.defineProperty(process.stdout, "isTTY", descriptor);
      }
    }
  });

  it("markdown adds an executive summary and attention section", () => {
    const md = renderMarkdown(rendererReport(1));

    expect(md).toContain("## Executive Summary");
    expect(md).toContain("**Posture: ATTENTION**");
    expect(md).toContain("5 of 6 controls passing across 4 active overlays.");
    expect(md).toContain("Active overlays: SOC 2, PCI-DSS v4.0, GLBA, GDPR");
    expect(md).toContain("Active certifications: AIUC-1 (87% ready)");
    expect(md).toContain("Evidence chain: intact (1,234 records, SHA-256 verified)");
    expect(md).toContain("### Attention Required");
    expect(md).toContain("**Data Exposure Prevention**: 2 failures in reporting period");
  });

  it("markdown omits the attention section when all controls pass", () => {
    const md = renderMarkdown(rendererReport(0));

    expect(md).toContain("## Executive Summary");
    expect(md).toContain("**Posture: HEALTHY**");
    expect(md).toContain("6 of 6 controls passing across 4 active overlays.");
    expect(md).not.toContain("### Attention Required");
  });
});

describe("runCli", () => {
  it("accepts report generate as an alias for the report command", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir, fullConfig());
    const dbPath = join(dir, "report.duckdb");
    const outputPath = join(dir, "report-generate.md");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateEvidence(config, store);
    await store.close();

    const { io, stdout, stderr } = captureIo();
    const exitCode = await runCli(
      ["report", "generate", "--config", configPath, "--db", dbPath, "--format", "markdown", "--output", outputPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(stdout()).toContain(`Report written to ${outputPath}`);
    expect(existsSync(outputPath)).toBe(true);
    expect(readFileSync(outputPath, "utf-8")).toContain("# Ancilis Posture Report");
  });

  it("accepts oscal-json as a report format", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir, fullConfig());
    const dbPath = join(dir, "report.duckdb");
    const outputPath = join(dir, "report-oscal.json");
    const config = loadConfig({ path: configPath });
    const store = new EvidenceStore(config, { dbPath });
    await populateEvidence(config, store);
    await store.close();

    const { io, stdout, stderr } = captureIo();
    const exitCode = await runCli(
      ["report", "--config", configPath, "--db", dbPath, "--format", "oscal-json", "--output", outputPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(stdout()).toContain(`Report written to ${outputPath}`);
    expect(existsSync(outputPath)).toBe(true);
  });
});

// ===== Display Fields Tests =====

describe("Display Fields", () => {
  it("engine post-processes display fields", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const registry = new ToolRegistry();
    registry.register({ name: "read_file", status: ToolStatus.APPROVED, approvedBy: "config", firstSeen: new Date().toISOString(), statusChanged: new Date().toISOString() });
    const engine = new Engine(config, { registry });
    const action = makeAction();
    const result = engine.evaluate(action);
    for (const cr of result.controlResults) {
      if (cr.result !== "SKIP") {
        expect(cr.displayName).toBeTruthy();
        expect(cr.displayDetail).toBeTruthy();
      }
    }
  });
});

// ===== Progressive Disclosure Tests =====

describe("Progressive Disclosure", () => {
  it("zero-config has no framework references", () => {
    const config = loadConfig({ raw: minimalConfig() });
    const output = formatStatus(config, emptySummary()).toLowerCase();
    expect(output).not.toContain("hipaa");
    expect(output).not.toContain("gdpr");
    expect(output).not.toContain("aiuc");
  });

  it("data handling adds overlay info", () => {
    const config = loadConfig({ raw: fullConfig() });
    const gen = new ReportGenerator(config, populatedSummary(2));
    const report = gen.generate();
    expect(report.complianceSections.length).toBeGreaterThan(0);
  });
});
