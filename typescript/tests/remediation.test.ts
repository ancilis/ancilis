import { describe, expect, it } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { stringify as stringifyYaml } from "yaml";
import { loadConfig } from "../src/ancilis/config/index.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import type { EvaluationResult } from "../src/ancilis/engine/result.js";
import {
  buildRemediationRecommendations,
  loadRemediationGuides,
  renderRemediationRecommendations,
} from "../src/ancilis/remediation/index.js";
import { runCli } from "../src/cli.js";

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-remediation-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(dir: string): string {
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, stringifyYaml({ agent: { name: "demo-agent" } }), "utf-8");
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
      stdout(message: string) { out.push(message); },
      stderr(message: string) { err.push(message); },
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

async function storeFailingPr01(configPath: string, dbPath: string): Promise<void> {
  const config = loadConfig({ path: configPath });
  const store = new EvidenceStore(config, { dbPath });
  try {
    const evaluation: EvaluationResult = {
      evaluationId: "eval-1",
      actionId: "action-1",
      timestamp: new Date().toISOString(),
      agentId: "demo-agent",
      sourceType: "agent",
      mode: "audit",
      controlResults: [
        {
          controlId: "PR-01",
          controlName: "Identity",
          result: "FAIL",
          detail: "Missing agent identity",
          evidenceData: {},
          durationMs: 1,
        },
      ],
      decision: "FLAG",
      decisionReason: "Identity gap",
      activeOverlays: [],
      dataClassifications: [],
      totalDurationMs: 1,
    };
    await store.store(evaluation, "read_file");
  } finally {
    await store.close();
  }
}

describe("remediation guidance", () => {
  it("loads shared remediation guides", () => {
    const guides = loadRemediationGuides();

    expect([...guides.keys()]).toEqual(expect.arrayContaining(["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]));
    expect(guides.get("PR-01")?.timeEstimate).toBe("5 minutes");
    expect(guides.get("PR-01")?.codeExample).toContain("agent:");
  });

  it("builds recommendations for current gaps", () => {
    const config = loadConfig({ raw: { agent: { name: "demo-agent" } } });
    const recommendations = buildRemediationRecommendations(config, {
      controlPassRates: {
        "PR-01": { PASS: 0, FAIL: 1, ERROR: 0, FLAG: 0, SKIP: 0 },
        "PR-02": { PASS: 3, FAIL: 0, ERROR: 0, FLAG: 0, SKIP: 0 },
        "PR-03": { PASS: 1, FAIL: 0, ERROR: 0, FLAG: 1, SKIP: 0 },
      },
    });
    const output = renderRemediationRecommendations(recommendations);

    expect(recommendations.map(item => item.guide.controlId)).toEqual(["PR-01", "PR-03"]);
    expect(output).toContain("PR-01 (Identity verification) — GAP");
    expect(output).toContain("demo-agent");
    expect(output).toContain("PR-03 (Data exposure prevention) — PARTIAL");
  });

  it("remediate CLI shows guidance for current gaps", async () => {
    const dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "evidence.duckdb");
    await storeFailingPr01(configPath, dbPath);

    const { io, stdout, stderr } = captureIo();
    const exitCode = await runCli(
      ["remediate", "--config", configPath, "--db", dbPath, "--all"],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(stdout()).toContain("PR-01 (Identity verification) — GAP");
    expect(stdout()).toContain("How to fix:");
    expect(stdout()).toContain("agent.name");
  });
});
