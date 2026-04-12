/**
 * Tests for `ancilis evidence` CLI commands:
 *   evidence sessions / evidence reset / evidence import
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../src/ancilis/config/index.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import { Engine, ToolRegistry, ToolStatus } from "../src/ancilis/engine/index.js";
import type { Action } from "../src/ancilis/engine/index.js";
import {
  handleEvidence,
  runEvidenceSessions,
  runEvidenceReset,
  runEvidenceImport,
} from "../src/ancilis/cli/evidence.js";
import { runCli } from "../src/cli.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "..", "shared", "fixtures");
const SARIF_FIXTURE = join(FIXTURES, "sample.sarif");
const CDX_FIXTURE = join(FIXTURES, "sample-sbom.cdx.json");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-evidence-cli-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(dir: string, extra: Record<string, unknown> = {}): string {
  const path = join(dir, "ancilis.yaml");
  const content = { agent: { name: "test-agent" }, ...extra };
  writeFileSync(path, Object.entries(content).map(([k, v]) => `${k}:\n  ${JSON.stringify(v)}`).join("\n"));
  // Simple inline yaml
  writeFileSync(path, `agent:\n  name: "test-agent"\n`);
  return path;
}

function captureIo(): {
  io: { stdout(m: string): void; stderr(m: string): void; prompt?(q: string): Promise<string> };
  stdout(): string;
  stderr(): string;
  setPromptAnswer(answer: string): void;
} {
  const out: string[] = [];
  const err: string[] = [];
  let promptAnswer = "n";
  return {
    io: {
      stdout(m) { out.push(m); },
      stderr(m) { err.push(m); },
      prompt: () => Promise.resolve(promptAnswer),
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
    setPromptAnswer(a: string) { promptAnswer = a; },
  };
}

async function populateStore(dbPath: string, configPath: string, count = 3): Promise<void> {
  const config = loadConfig({ path: configPath });
  const store = new EvidenceStore(config, { dbPath });
  const registry = new ToolRegistry();
  registry.register({
    name: "read_file",
    status: ToolStatus.APPROVED,
    approvedBy: "config",
    firstSeen: new Date().toISOString(),
    statusChanged: new Date().toISOString(),
  });
  const engine = new Engine(config, { registry });
  for (let i = 0; i < count; i++) {
    const action: Action = {
      actionId: `action-${randomUUID()}`,
      timestamp: new Date().toISOString(),
      agentId: "test-agent",
      agentOwner: "owner",
      actionType: "tool_call",
      tool: { name: "read_file", input: { path: `/file${i}.txt` } },
    };
    const evaluation = engine.evaluate(action);
    evaluation.context = { sessionId: "test-agent" };
    await store.store(evaluation, "read_file");
  }
  await store.close();
}

// ---------------------------------------------------------------------------
// runEvidenceSessions
// ---------------------------------------------------------------------------

describe("evidence sessions", () => {
  let dir: string;

  afterEach(() => {
    if (existsSync(dir)) rmSync(dir, { recursive: true });
  });

  it("reports no sessions on empty store", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");

    const result = await runEvidenceSessions({ configPath, dbPath });
    expect(result.ok).toBe(true);
    expect(result.output).toContain("No sessions recorded yet.");
  });

  it("lists sessions after evidence is stored", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    await populateStore(dbPath, configPath, 5);

    const result = await runEvidenceSessions({ configPath, dbPath });
    expect(result.ok).toBe(true);
    expect(result.output).toContain("SESSION ID");
    expect(result.output).toContain("RECORDS");
    expect(result.output).toContain("test-agent");
  });

  it("returns error when config is missing", async () => {
    dir = tmpDir();
    const result = await runEvidenceSessions({
      configPath: join(dir, "nonexistent.yaml"),
    });
    expect(result.ok).toBe(false);
    expect(result.output).toContain("Error");
  });

  it("handleEvidence routes to sessions subcommand", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io, stdout } = captureIo();

    const code = await handleEvidence(["sessions", "--config", configPath, "--db", dbPath], io);
    expect(code).toBe(0);
    expect(stdout()).toContain("No sessions recorded yet.");
  });
});

// ---------------------------------------------------------------------------
// runEvidenceReset
// ---------------------------------------------------------------------------

describe("evidence reset", () => {
  let dir: string;

  afterEach(() => {
    if (existsSync(dir)) rmSync(dir, { recursive: true });
  });

  it("clears records with --yes flag", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    await populateStore(dbPath, configPath, 4);

    const { io } = captureIo();
    const result = await runEvidenceReset({ configPath, dbPath, yes: true }, io);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("4 record(s) deleted");
    expect(result.output).toContain("genesis");
  });

  it("aborts when prompt answer is not y", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    await populateStore(dbPath, configPath, 2);

    const { io, setPromptAnswer } = captureIo();
    setPromptAnswer("n");
    const result = await runEvidenceReset({ configPath, dbPath, yes: false }, io);
    expect(result.ok).toBe(false);
    expect(result.output).toBe("Aborted.");
  });

  it("proceeds when prompt answer is y", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    await populateStore(dbPath, configPath, 3);

    const { io, setPromptAnswer } = captureIo();
    setPromptAnswer("y");
    const result = await runEvidenceReset({ configPath, dbPath, yes: false }, io);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("3 record(s) deleted");
  });

  it("reset of empty store returns 0 deleted", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");

    const { io } = captureIo();
    const result = await runEvidenceReset({ configPath, dbPath, yes: true }, io);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("0 record(s) deleted");
  });

  it("sessions shows no records after reset", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    await populateStore(dbPath, configPath, 2);

    const { io } = captureIo();
    await runEvidenceReset({ configPath, dbPath, yes: true }, io);

    const result = await runEvidenceSessions({ configPath, dbPath });
    expect(result.ok).toBe(true);
    expect(result.output).toContain("No sessions recorded yet.");
  });

  it("handleEvidence routes to reset subcommand", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    await populateStore(dbPath, configPath, 2);

    const { io, stdout } = captureIo();
    const code = await handleEvidence(["reset", "--config", configPath, "--db", dbPath, "--yes"], io);
    expect(code).toBe(0);
    expect(stdout()).toContain("deleted");
  });
});

// ---------------------------------------------------------------------------
// runEvidenceImport
// ---------------------------------------------------------------------------

describe("evidence import", () => {
  let dir: string;

  afterEach(() => {
    if (existsSync(dir)) rmSync(dir, { recursive: true });
  });

  it("imports SARIF file with auto-detection", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io } = captureIo();

    const result = await runEvidenceImport(
      { file: SARIF_FIXTURE, configPath, dbPath },
      io,
    );
    expect(result.ok).toBe(true);
    expect(result.output).toContain("SARIF");
    expect(result.output).toMatch(/Imported \d+ evidence record/);
  });

  it("imports SARIF file with explicit --format sarif", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io } = captureIo();

    const result = await runEvidenceImport(
      { file: SARIF_FIXTURE, format: "sarif", configPath, dbPath },
      io,
    );
    expect(result.ok).toBe(true);
    expect(result.output).toContain("SARIF");
  });

  it("imports CycloneDX file with auto-detection", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io } = captureIo();

    const result = await runEvidenceImport(
      { file: CDX_FIXTURE, configPath, dbPath },
      io,
    );
    expect(result.ok).toBe(true);
    expect(result.output).toContain("CYCLONEDX");
  });

  it("imports CycloneDX file with explicit --format cyclonedx", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io } = captureIo();

    const result = await runEvidenceImport(
      { file: CDX_FIXTURE, format: "cyclonedx", configPath, dbPath },
      io,
    );
    expect(result.ok).toBe(true);
    expect(result.output).toContain("CYCLONEDX");
  });

  it("auto-detects SARIF from .sarif extension", async () => {
    dir = tmpDir();
    // Create a copy with .sarif extension
    const sarif = join(dir, "findings.sarif");
    const { readFileSync } = await import("node:fs");
    writeFileSync(sarif, readFileSync(SARIF_FIXTURE));
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io } = captureIo();

    const result = await runEvidenceImport({ file: sarif, configPath, dbPath }, io);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("SARIF");
  });

  it("auto-detects CycloneDX from .cdx.json extension", async () => {
    dir = tmpDir();
    const cdx = join(dir, "sbom.cdx.json");
    const { readFileSync } = await import("node:fs");
    writeFileSync(cdx, readFileSync(CDX_FIXTURE));
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io } = captureIo();

    const result = await runEvidenceImport({ file: cdx, configPath, dbPath }, io);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("CYCLONEDX");
  });

  it("returns error for missing file", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const { io } = captureIo();

    const result = await runEvidenceImport(
      { file: join(dir, "nonexistent.sarif"), configPath },
      io,
    );
    expect(result.ok).toBe(false);
    expect(result.output).toContain("File not found");
  });

  it("returns error for undetectable format", async () => {
    dir = tmpDir();
    const ambiguous = join(dir, "data.json");
    writeFileSync(ambiguous, JSON.stringify({ unknownKey: true }));
    const configPath = writeConfig(dir);
    const { io } = captureIo();

    const result = await runEvidenceImport({ file: ambiguous, configPath }, io);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("Cannot detect format");
  });

  it("uses custom --agent-id on imported records", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io } = captureIo();

    await runEvidenceImport(
      { file: SARIF_FIXTURE, agentId: "my-scanner", configPath, dbPath },
      io,
    );

    // Sessions should show "my-scanner" as the session id
    const sessions = await runEvidenceSessions({ configPath, dbPath });
    expect(sessions.ok).toBe(true);
    expect(sessions.output).toContain("my-scanner");
  });

  it("handleEvidence routes to import subcommand", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const { io, stdout } = captureIo();

    const code = await handleEvidence(
      ["import", SARIF_FIXTURE, "--config", configPath, "--db", dbPath],
      io,
    );
    expect(code).toBe(0);
    expect(stdout()).toMatch(/Imported \d+ evidence record/);
  });
});

// ---------------------------------------------------------------------------
// handleEvidence — top-level routing
// ---------------------------------------------------------------------------

describe("handleEvidence routing", () => {
  it("shows help for missing subcommand", async () => {
    const { io, stdout } = captureIo();
    const code = await handleEvidence([], io);
    expect(code).toBe(0);
    expect(stdout()).toContain("ancilis evidence sessions");
  });

  it("shows help for --help flag", async () => {
    const { io, stdout } = captureIo();
    const code = await handleEvidence(["--help"], io);
    expect(code).toBe(0);
    expect(stdout()).toContain("ancilis evidence reset");
  });

  it("throws for unknown subcommand", async () => {
    const { io } = captureIo();
    await expect(handleEvidence(["bogus"], io)).rejects.toThrow("Unknown evidence subcommand: bogus");
  });
});

// ---------------------------------------------------------------------------
// runCli integration
// ---------------------------------------------------------------------------

describe("runCli evidence integration", () => {
  let dir: string;

  afterEach(() => {
    if (existsSync(dir)) rmSync(dir, { recursive: true });
  });

  it("evidence sessions via runCli", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    const out: string[] = [];
    const err: string[] = [];
    const io = { stdout: (m: string) => out.push(m), stderr: (m: string) => err.push(m) };

    const code = await runCli(["evidence", "sessions", "--config", configPath, "--db", dbPath], io);
    expect(code).toBe(0);
    expect(out.join("")).toContain("No sessions recorded yet.");
    expect(err.join("")).toBe("");
  });

  it("evidence reset --yes via runCli", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");
    await populateStore(dbPath, configPath, 2);

    const out: string[] = [];
    const err: string[] = [];
    const io = { stdout: (m: string) => out.push(m), stderr: (m: string) => err.push(m) };

    const code = await runCli(["evidence", "reset", "--config", configPath, "--db", dbPath, "--yes"], io);
    expect(code).toBe(0);
    expect(out.join("")).toContain("deleted");
  });

  it("evidence import via runCli", async () => {
    dir = tmpDir();
    const configPath = writeConfig(dir);
    const dbPath = join(dir, "ev.duckdb");

    const out: string[] = [];
    const err: string[] = [];
    const io = { stdout: (m: string) => out.push(m), stderr: (m: string) => err.push(m) };

    const code = await runCli(["evidence", "import", SARIF_FIXTURE, "--config", configPath, "--db", dbPath], io);
    expect(code).toBe(0);
    expect(out.join("")).toMatch(/Imported \d+ evidence record/);
  });
});
