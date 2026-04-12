/** Integration tests for `runCli baseline` subcommands. */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { stringify as stringifyYaml } from "yaml";
import { loadConfig } from "../src/ancilis/config/index.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import { BaselineManager } from "../src/ancilis/baselines/index.js";
import { runCli } from "../src/cli.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-baseline-cli-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(dir: string): string {
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, stringifyYaml({ agent: { name: "test-agent" } }));
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

/** Open a file-backed store, create a baseline, then close it. */
async function createBaselineOnDisk(
  configPath: string,
  dbPath: string,
  label: string,
): Promise<string> {
  const config = loadConfig({ path: configPath });
  const store = new EvidenceStore(config, { dbPath });
  const manager = new BaselineManager(store, config);
  const baseline = await manager.create({ label });
  await store.close();
  return baseline.baselineId;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("runCli baseline", () => {
  let dir: string;
  let configPath: string;
  let dbPath: string;

  beforeEach(() => {
    dir = tmpDir();
    configPath = writeConfig(dir);
    dbPath = join(dir, "evidence.duckdb");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // create
  // -------------------------------------------------------------------------

  it("create: exits 0 and prints baseline ID and label", async () => {
    const { io, stdout, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "create", "--label", "v1.0", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(stdout()).toContain("Baseline created:");
    expect(stdout()).toContain("v1.0");
    // Output includes "Controls captured: 0" when no evidence exists
    expect(stdout()).toContain("Controls captured:");
  });

  it("create: missing --label exits 1 and prints error", async () => {
    const { io, stdout, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "create", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(1);
    expect(stderr()).toContain("--label is required");
    // stdout should still print usage on error
    expect(stdout()).toBe("");
  });

  // -------------------------------------------------------------------------
  // list
  // -------------------------------------------------------------------------

  it("list: prints 'No baselines found.' when none exist", async () => {
    const { io, stdout, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "list", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(stdout()).toContain("No baselines found.");
  });

  it("list: shows created baseline with label and active status", async () => {
    // Pre-create a baseline on disk
    const baselineId = await createBaselineOnDisk(configPath, dbPath, "release-1");

    const { io, stdout, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "list", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(stdout()).toContain("release-1");
    expect(stdout()).toContain("[active]");
    expect(stdout()).toContain(baselineId);
  });

  it("list: shows multiple baselines with only the latest active", async () => {
    await createBaselineOnDisk(configPath, dbPath, "v1");
    await createBaselineOnDisk(configPath, dbPath, "v2");

    const { io, stdout } = captureIo();
    await runCli(
      ["baseline", "list", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(stdout()).toContain("v1");
    expect(stdout()).toContain("v2");
    // Only one should be active
    const activeCount = (stdout().match(/\[active\]/g) ?? []).length;
    const inactiveCount = (stdout().match(/\[inactive\]/g) ?? []).length;
    expect(activeCount).toBe(1);
    expect(inactiveCount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // drift
  // -------------------------------------------------------------------------

  it("drift: exits 0 and prints terminal drift report", async () => {
    await createBaselineOnDisk(configPath, dbPath, "drift-baseline");

    const { io, stdout, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "drift", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(stdout()).toContain("Drift Report");
    expect(stdout()).toContain("drift-baseline");
    expect(stdout()).toContain("Controls:");
  });

  it("drift: exits 0 and prints valid JSON with --format json", async () => {
    await createBaselineOnDisk(configPath, dbPath, "json-baseline");

    const { io, stdout, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "drift", "--format", "json", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");

    const parsed = JSON.parse(stdout()) as Record<string, unknown>;
    expect(parsed).toHaveProperty("overallStatus");
    expect(parsed).toHaveProperty("baselineId");
    expect(parsed).toHaveProperty("baselineLabel", "json-baseline");
    expect(parsed).toHaveProperty("controlDrifts");
  });

  it("drift: exits 1 when no active baseline exists", async () => {
    const { io, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "drift", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(1);
    expect(stderr()).toContain("No active baseline found");
  });

  it("drift: exits 0 and shows STABLE status for baseline with no subsequent evidence", async () => {
    await createBaselineOnDisk(configPath, dbPath, "stable-baseline");

    const { io, stdout } = captureIo();

    const exitCode = await runCli(
      ["baseline", "drift", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(0);
    expect(stdout()).toContain("STABLE");
  });

  // -------------------------------------------------------------------------
  // unknown subcommand
  // -------------------------------------------------------------------------

  it("unknown subcommand exits 1", async () => {
    const { io, stderr } = captureIo();

    const exitCode = await runCli(
      ["baseline", "frobulate", "--config", configPath, "--db", dbPath],
      io,
    );

    expect(exitCode).toBe(1);
    expect(stderr()).toContain("Unknown baseline subcommand");
  });

  // -------------------------------------------------------------------------
  // help
  // -------------------------------------------------------------------------

  it("--help exits 0 and prints usage", async () => {
    const { io, stdout } = captureIo();

    const exitCode = await runCli(["baseline", "--help"], io);

    expect(exitCode).toBe(0);
    expect(stdout()).toContain("baseline create");
    expect(stdout()).toContain("baseline list");
    expect(stdout()).toContain("baseline drift");
  });
});
