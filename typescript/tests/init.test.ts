/** Tests for ancilis init command. */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { detectFramework, sanitizeName, runInit } from "../src/ancilis/cli/init.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-init-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function captureIo(): { io: { stdout(m: string): void; stderr(m: string): void }; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: (m: string) => out.push(m),
      stderr: (m: string) => err.push(m),
    },
    out,
    err,
  };
}

// ---------------------------------------------------------------------------
// sanitizeName
// ---------------------------------------------------------------------------

describe("sanitizeName", () => {
  it("lowercases and replaces non-alphanum with hyphens", () => {
    expect(sanitizeName("My Agent Name")).toBe("my-agent-name");
  });

  it("strips leading and trailing hyphens", () => {
    expect(sanitizeName("---agent---")).toBe("agent");
  });

  it("handles empty string", () => {
    expect(sanitizeName("")).toBe("my-agent");
  });

  it("handles special characters", () => {
    expect(sanitizeName("agent@v2.0!")).toBe("agent-v2-0");
  });

  it("preserves valid names unchanged", () => {
    expect(sanitizeName("my-agent-v1")).toBe("my-agent-v1");
  });

  it("handles numbers", () => {
    expect(sanitizeName("agent123")).toBe("agent123");
  });
});

// ---------------------------------------------------------------------------
// detectFramework
// ---------------------------------------------------------------------------

describe("detectFramework", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns null when no package.json", () => {
    expect(detectFramework(dir)).toBeNull();
  });

  it("detects langchain from package.json dependencies", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      dependencies: { "langchain": "^0.1.0" },
    }));
    const result = detectFramework(dir);
    expect(result).not.toBeNull();
    expect(result!.framework).toBe("langchain");
    expect(result!.source).toBe("package.json");
    expect(result!.confidence).toBe("high");
  });

  it("detects @langchain/* scoped packages", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      dependencies: { "@langchain/openai": "^0.1.0" },
    }));
    const result = detectFramework(dir);
    expect(result?.framework).toBe("langchain");
  });

  it("detects openai from package.json", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      dependencies: { "openai": "^4.0.0" },
    }));
    expect(detectFramework(dir)?.framework).toBe("openai");
  });

  it("detects @anthropic-ai/sdk", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      dependencies: { "@anthropic-ai/sdk": "^0.20.0" },
    }));
    expect(detectFramework(dir)?.framework).toBe("anthropic");
  });

  it("detects @modelcontextprotocol/sdk", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      devDependencies: { "@modelcontextprotocol/sdk": "^0.5.0" },
    }));
    expect(detectFramework(dir)?.framework).toBe("mcp");
  });

  it("returns null when no known framework packages", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      dependencies: { "express": "^4.0.0", "lodash": "^4.0.0" },
    }));
    expect(detectFramework(dir)).toBeNull();
  });

  it("handles invalid JSON gracefully", () => {
    writeFileSync(join(dir, "package.json"), "not valid json");
    expect(detectFramework(dir)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// runInit — non-interactive mode
// ---------------------------------------------------------------------------

describe("runInit non-interactive", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("creates ancilis.yaml with given framework, overlay, and agent name", async () => {
    const { io } = captureIo();
    const result = await runInit(
      { framework: "openai", overlay: "soc2", agentName: "my-agent", detect: true, noSample: true, dir },
      io,
    );
    expect(result.ok).toBe(true);
    expect(existsSync(join(dir, "ancilis.yaml"))).toBe(true);
    const yaml = readFileSync(join(dir, "ancilis.yaml"), "utf-8");
    expect(yaml).toMatch(/name: my-agent/);
    expect(yaml).toMatch(/- soc2/);
    expect(yaml).toMatch(/mode: audit/);
  });

  it("creates .env.example", async () => {
    const { io } = captureIo();
    await runInit({ framework: "generic", overlay: "gdpr", detect: true, noSample: true, dir }, io);
    expect(existsSync(join(dir, ".env.example"))).toBe(true);
    const content = readFileSync(join(dir, ".env.example"), "utf-8");
    expect(content).toMatch(/ANCILIS_API_KEY/);
  });

  it("creates sample scan script when noSample is false", async () => {
    const { io } = captureIo();
    await runInit({ framework: "openai", overlay: "soc2", detect: true, dir }, io);
    expect(existsSync(join(dir, "ancilis_scan.ts"))).toBe(true);
  });

  it("skips scan script when noSample is true", async () => {
    const { io } = captureIo();
    await runInit({ framework: "openai", overlay: "soc2", detect: true, noSample: true, dir }, io);
    expect(existsSync(join(dir, "ancilis_scan.ts"))).toBe(false);
  });

  it("updates .gitignore to include .ancilis/", async () => {
    writeFileSync(join(dir, ".gitignore"), "node_modules/\n");
    const { io } = captureIo();
    await runInit({ framework: "generic", overlay: "soc2", detect: true, noSample: true, dir }, io);
    const content = readFileSync(join(dir, ".gitignore"), "utf-8");
    expect(content).toMatch(/\.ancilis\//);
  });

  it("does not add .ancilis/ to .gitignore if already present", async () => {
    writeFileSync(join(dir, ".gitignore"), "node_modules/\n.ancilis/\n");
    const { io } = captureIo();
    await runInit({ framework: "generic", overlay: "soc2", detect: true, noSample: true, dir }, io);
    const content = readFileSync(join(dir, ".gitignore"), "utf-8");
    const count = (content.match(/\.ancilis\//g) ?? []).length;
    expect(count).toBe(1);
  });

  it("does not create .gitignore if it doesn't exist", async () => {
    const { io } = captureIo();
    await runInit({ framework: "generic", overlay: "soc2", detect: true, noSample: true, dir }, io);
    expect(existsSync(join(dir, ".gitignore"))).toBe(false);
  });

  it("sanitizes agent name", async () => {
    const { io } = captureIo();
    await runInit({ framework: "generic", overlay: "soc2", agentName: "My Cool Agent!", detect: true, noSample: true, dir }, io);
    const yaml = readFileSync(join(dir, "ancilis.yaml"), "utf-8");
    expect(yaml).toMatch(/name: my-cool-agent/);
  });

  it("returns ok:false if ancilis.yaml already exists in detect mode", async () => {
    writeFileSync(join(dir, "ancilis.yaml"), "# existing\n");
    const { io } = captureIo();
    const result = await runInit({ detect: true, noSample: true, dir }, io);
    expect(result.ok).toBe(false);
    // Original file should be untouched
    expect(readFileSync(join(dir, "ancilis.yaml"), "utf-8")).toBe("# existing\n");
  });

  it("idempotent: running twice does not corrupt ancilis.yaml when first run succeeds", async () => {
    const { io: io1 } = captureIo();
    const { io: io2 } = captureIo();
    await runInit({ framework: "openai", overlay: "soc2", detect: true, noSample: true, dir }, io1);
    const firstContent = readFileSync(join(dir, "ancilis.yaml"), "utf-8");
    // Second run should fail non-destructively
    const r2 = await runInit({ framework: "openai", overlay: "soc2", detect: true, noSample: true, dir }, io2);
    expect(r2.ok).toBe(false);
    expect(readFileSync(join(dir, "ancilis.yaml"), "utf-8")).toBe(firstContent);
  });

  it("auto-detects framework from package.json in detect mode", async () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      dependencies: { "@anthropic-ai/sdk": "^0.20.0" },
    }));
    const { io, out } = captureIo();
    await runInit({ detect: true, overlay: "soc2", noSample: true, dir }, io);
    expect(existsSync(join(dir, "ancilis.yaml"))).toBe(true);
    expect(out.join("")).toMatch(/Detected framework: anthropic/);
  });

  it("uses generic when detect mode finds no framework", async () => {
    const { io, out } = captureIo();
    await runInit({ detect: true, overlay: "soc2", noSample: true, dir }, io);
    expect(existsSync(join(dir, "ancilis.yaml"))).toBe(true);
    expect(out.join("")).toMatch(/No framework detected/);
  });

  it("generates valid ancilis.yaml for all supported overlays", async () => {
    const overlays = ["soc2", "gdpr", "hipaa", "cmmc-l2"];
    for (const overlay of overlays) {
      const subDir = join(dir, overlay);
      mkdirSync(subDir, { recursive: true });
      const { io } = captureIo();
      const result = await runInit({ framework: "generic", overlay, detect: true, noSample: true, dir: subDir }, io);
      expect(result.ok).toBe(true);
      const yaml = readFileSync(join(subDir, "ancilis.yaml"), "utf-8");
      expect(yaml).toMatch(new RegExp(`- ${overlay}`));
    }
  });
});
