/** Tests for ancilis connect command. */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { runConnect } from "../src/ancilis/cli/connect.js";

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-connect-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function captureIo() {
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

describe("runConnect", () => {
  let homeDir: string;

  beforeEach(() => {
    homeDir = tmpDir();
  });

  afterEach(() => {
    rmSync(homeDir, { recursive: true, force: true });
  });

  it("shows not-connected status when platform.json is missing", async () => {
    const { io, stdout } = captureIo();
    const result = await runConnect([], io, { homeDir });
    expect(result.ok).toBe(true);
    expect(stdout()).toMatch(/Status: not connected/);
    expect(stdout()).toMatch(/ancilis\.ai/);
  });

  it("shows connected status when platform.json exists", async () => {
    const ancilisDir = join(homeDir, ".ancilis");
    mkdirSync(ancilisDir, { recursive: true });
    writeFileSync(
      join(ancilisDir, "platform.json"),
      JSON.stringify({ platform: "app.ancilis.ai" }),
    );

    const { io, stdout } = captureIo();
    const result = await runConnect([], io, { homeDir });
    expect(result.ok).toBe(true);
    expect(stdout()).toMatch(/Status: connected/);
    expect(stdout()).toMatch(/ancilis\.ai/);
    expect(stdout()).toMatch(/platform\.json/);
  });

  it("handles malformed platform.json gracefully", async () => {
    const ancilisDir = join(homeDir, ".ancilis");
    mkdirSync(ancilisDir, { recursive: true });
    writeFileSync(join(ancilisDir, "platform.json"), "not json{{");

    const { io, stdout } = captureIo();
    const result = await runConnect([], io, { homeDir });
    expect(result.ok).toBe(true);
    expect(stdout()).toMatch(/Status: connected/);
  });

  it("returns ok: true in both states", async () => {
    const { io } = captureIo();
    const result = await runConnect([], io, { homeDir });
    expect(result.ok).toBe(true);
  });
});
