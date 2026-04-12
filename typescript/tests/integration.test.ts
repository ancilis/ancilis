/**
 * End-to-end integration tests — config bad paths, audit vs enforce, CLI errors.
 * Parity with Python test_integration.py (ANC-838).
 */

import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dump as yamlDump } from "js-yaml";
import { loadConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import { ToolActionProducer, BlockedActionError } from "../src/ancilis/producers/tool.js";
import { validateAndFormat } from "../src/ancilis/cli/validate.js";
import { runDoctor } from "../src/ancilis/cli/doctor.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function writeTempConfig(data: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "ancilis-test-"));
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, yamlDump(data));
  return path;
}

function dummyTool(x: string): string {
  return `result:${x}`;
}

// ---------------------------------------------------------------------------
// Config bad-path tests
// ---------------------------------------------------------------------------

describe("TestConfigBadPaths", () => {
  it("malformed YAML produces an error via validateAndFormat", () => {
    const dir = mkdtempSync(join(tmpdir(), "ancilis-test-"));
    const path = join(dir, "ancilis.yaml");
    writeFileSync(path, ": invalid: yaml: {{[");
    const result = validateAndFormat(path);
    expect(result.valid).toBe(false);
    expect(result.message).toBeTruthy();
  });

  it("empty agent name raises an error", () => {
    expect(() => loadConfig({ raw: { agent: { name: "" } } })).toThrow();
  });

  it("unknown data type raises ValueError", () => {
    expect(() =>
      loadConfig({ raw: { agent: { name: "test" }, my_agent_handles: ["unicorn_data"] } }),
    ).toThrow(/unknown data type/i);
  });

  it("invalid security.mode raises an error", () => {
    expect(() =>
      loadConfig({ raw: { agent: { name: "test" }, security: { mode: "yolo" } } }),
    ).toThrow();
  });

  it("unknown control ID in overrides raises an error", () => {
    expect(() =>
      loadConfig({
        raw: {
          agent: { name: "test" },
          security: { controls: { "FAKE-99": { enabled: true } } },
        },
      }),
    ).toThrow(/unknown control/i);
  });

  it("unrecognized cert target produces a warning instead of crashing", () => {
    const config = loadConfig({
      raw: {
        agent: { name: "test" },
        certification_targets: ["aiuc-99"],
      },
    });
    expect(config.warnings.some((w) => w.includes("aiuc-99"))).toBe(true);
  });

  it("validateAndFormat with nonexistent config path returns valid=false", () => {
    const result = validateAndFormat("/nonexistent/path/ancilis.yaml");
    expect(result.valid).toBe(false);
    expect(result.message.toLowerCase()).toMatch(/not found|no such file|error|invalid/);
  });

  it("validateAndFormat with unknown data type returns valid=false", () => {
    const path = writeTempConfig({
      agent: { name: "test" },
      my_agent_handles: ["unicorn_data"],
    });
    const result = validateAndFormat(path);
    expect(result.valid).toBe(false);
    expect(result.message).toMatch(/unknown data type|invalid/i);
  });
});

// ---------------------------------------------------------------------------
// Audit vs Enforce end-to-end
// ---------------------------------------------------------------------------

describe("TestAuditVsEnforce", () => {
  it("audit mode allows unapproved tool (observed but not blocked)", async () => {
    const config = loadConfig({
      raw: {
        agent: { name: "test" },
        security: { mode: "audit", tools: { allowed: ["approved_tool"] } },
      },
    });
    const engine = new Engine(config);
    const evidence = new EvidenceStore(config, { inMemory: true });
    const producer = new ToolActionProducer(config, engine, undefined, evidence);

    const result = await producer.execute(dummyTool, "test", ["hello"], undefined, "unapproved_tool");

    expect(result.blocked).toBe(false);
    expect(result.evaluation.decision).toBe("ALLOW");
    expect(result.evaluation.mode).toBe("audit");
    expect(result.returnValue).toBe("result:hello");

    const summary = await evidence.getSummary();
    expect(summary.totalEvaluations).toBe(1);
    await evidence.close();
  });

  it("enforce mode blocks unapproved tool and records BLOCK evidence", async () => {
    const config = loadConfig({
      raw: {
        agent: { name: "test" },
        security: { mode: "enforce", tools: { allowed: ["approved_tool"] } },
      },
    });
    const engine = new Engine(config);
    const evidence = new EvidenceStore(config, { inMemory: true });
    const producer = new ToolActionProducer(config, engine, undefined, evidence);

    await expect(
      producer.execute(dummyTool, "test", ["hello"], undefined, "unapproved_tool"),
    ).rejects.toThrow(BlockedActionError);

    const summary = await evidence.getSummary();
    expect(summary.totalEvaluations).toBe(1);
    const decisions = summary.decisions as Record<string, number>;
    expect(decisions["BLOCK"]).toBe(1);
    await evidence.close();
  });

  it("enforce mode allows approved tool", async () => {
    const config = loadConfig({
      raw: {
        agent: { name: "test" },
        security: { mode: "enforce", tools: { allowed: ["approved_tool"] } },
      },
    });
    const engine = new Engine(config);
    const evidence = new EvidenceStore(config, { inMemory: true });
    const producer = new ToolActionProducer(config, engine, undefined, evidence);

    const result = await producer.execute(dummyTool, "test", ["hello"], undefined, "approved_tool");

    expect(result.blocked).toBe(false);
    expect(result.evaluation.decision).toBe("ALLOW");
    expect(result.evaluation.mode).toBe("enforce");
    await evidence.close();
  });

  it("evidence records contain the correct mode field", async () => {
    for (const mode of ["audit", "enforce"] as const) {
      const config = loadConfig({
        raw: {
          agent: { name: "test" },
          security: { mode, tools: { allowed: ["test_tool"] } },
        },
      });
      const engine = new Engine(config);
      const evidence = new EvidenceStore(config, { inMemory: true });
      const producer = new ToolActionProducer(config, engine, undefined, evidence);

      await producer.execute(dummyTool, "test", ["x"], undefined, "test_tool");

      const records = await evidence.getRecords();
      expect(records).toHaveLength(1);
      expect(records[0]?.mode).toBe(mode);
      await evidence.close();
    }
  });
});

// ---------------------------------------------------------------------------
// CLI error paths
// ---------------------------------------------------------------------------

describe("TestCLIErrorPaths", () => {
  it("validateAndFormat with missing config returns valid=false with error message", () => {
    const result = validateAndFormat("/nonexistent/ancilis.yaml");
    expect(result.valid).toBe(false);
    expect(result.message).toBeTruthy();
  });

  it("runDoctor with missing config returns ok=false and FAIL in output", async () => {
    const result = await runDoctor("/nonexistent/path/ancilis.yaml");
    expect(result.ok).toBe(false);
    expect(result.output).toContain("FAIL");
    expect(result.output).toContain("ancilis.yaml");
  });

  it("runDoctor with valid config returns ok=true and OK in output", async () => {
    const path = writeTempConfig({ agent: { name: "test" } });
    const result = await runDoctor(path);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("OK");
    expect(result.output).toContain("Ready");
  });
});
