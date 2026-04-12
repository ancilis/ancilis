/** Tests for ancilis scan --watch: WatchRunner and watch-display utilities. */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { getProducersForPaths, WatchRunner } from "../src/ancilis/cli/watch.js";
import {
  formatHeader,
  formatDelta,
  printSessionSummary,
} from "../src/ancilis/cli/watch-display.js";
import type { WatchControlResult } from "../src/ancilis/cli/watch-display.js";
import { loadConfig } from "../src/ancilis/config/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-watch-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function minConfig() {
  return loadConfig({
    raw: {
      agent: { name: "test-agent" },
      security: { mode: "audit" },
    },
  });
}

function mkResults(overrides: Partial<WatchControlResult>[] = []): WatchControlResult[] {
  const defaults: WatchControlResult[] = [
    { id: "PR-01", name: "Identity", status: "pass", evaluations: 5, failures: 0, flags: 0 },
    { id: "PR-02", name: "Scope", status: "fail", evaluations: 3, failures: 1, flags: 0 },
    { id: "DE-01", name: "Baseline Detection", status: "skip", evaluations: 0, failures: 0, flags: 0 },
  ];
  return defaults.map((d, i) => ({ ...d, ...(overrides[i] ?? {}) }));
}

// ---------------------------------------------------------------------------
// getProducersForPaths
// ---------------------------------------------------------------------------

describe("getProducersForPaths", () => {
  it("maps package.json to dependency producer", () => {
    expect(getProducersForPaths(["/project/package.json"])).toContain("dependency");
  });

  it("maps lock files to dependency producer", () => {
    expect(getProducersForPaths(["/project/package-lock.json"])).toContain("dependency");
    expect(getProducersForPaths(["/project/yarn.lock"])).toContain("dependency");
    expect(getProducersForPaths(["/project/pnpm-lock.yaml"])).toContain("dependency");
  });

  it("maps .duckdb files to evidence producer", () => {
    expect(getProducersForPaths(["/project/.ancilis/evidence.duckdb"])).toContain("evidence");
  });

  it("maps .db files to evidence producer", () => {
    expect(getProducersForPaths(["/project/custom.db"])).toContain("evidence");
  });

  it("maps arbitrary source files to all producer", () => {
    expect(getProducersForPaths(["/project/src/agent.ts"])).toContain("all");
    expect(getProducersForPaths(["/project/README.md"])).toContain("all");
  });

  it("returns [all] for empty input", () => {
    expect(getProducersForPaths([])).toEqual(["all"]);
  });

  it("deduplicates producers across multiple paths", () => {
    const result = getProducersForPaths(["/project/package.json", "/project/yarn.lock"]);
    expect(result).toEqual(["dependency"]);
  });

  it("combines multiple producer types from mixed paths", () => {
    const result = getProducersForPaths(["/project/package.json", "/project/src/main.ts"]);
    expect(result).toContain("dependency");
    expect(result).toContain("all");
  });
});

// ---------------------------------------------------------------------------
// formatHeader
// ---------------------------------------------------------------------------

describe("formatHeader", () => {
  it("includes agent name, posture, and eval count", () => {
    const header = formatHeader("my-agent", "compliant", 42);
    // Strip ANSI codes for plain comparison
    const plain = header.replace(/\x1b\[[0-9;]*m/g, "");
    expect(plain).toMatch(/compliant/);
    expect(plain).toMatch(/my-agent/);
    expect(plain).toMatch(/42 evals/);
  });

  it("includes a timestamp in HH:MM:SS format", () => {
    const header = formatHeader("agent", "non_compliant", 0);
    const plain = header.replace(/\x1b\[[0-9;]*m/g, "");
    expect(plain).toMatch(/\d{2}:\d{2}:\d{2}/);
  });
});

// ---------------------------------------------------------------------------
// formatDelta
// ---------------------------------------------------------------------------

describe("formatDelta", () => {
  it("returns empty array when prevResults is null (first scan)", () => {
    const results = mkResults();
    expect(formatDelta(null, results)).toEqual([]);
  });

  it("returns empty array when nothing changed", () => {
    const results = mkResults();
    expect(formatDelta(results, results)).toEqual([]);
  });

  it("detects a pass → fail transition", () => {
    const prev = mkResults([{ status: "pass" }]);
    const next = mkResults([{ status: "fail" }]);
    const delta = formatDelta(prev, next);
    expect(delta.length).toBe(1);
    expect(delta[0]).toMatch(/Identity/);
    expect(delta[0]).toMatch(/✓.*→.*✗/);
  });

  it("detects a fail → pass transition", () => {
    const prev = mkResults([{}, { status: "fail" }]);
    const next = mkResults([{}, { status: "pass" }]);
    const delta = formatDelta(prev, next);
    expect(delta.length).toBe(1);
    expect(delta[0]).toMatch(/Scope/);
  });

  it("detects multiple simultaneous status changes", () => {
    const prev = mkResults([{ status: "pass" }, { status: "fail" }]);
    const next = mkResults([{ status: "fail" }, { status: "pass" }]);
    const delta = formatDelta(prev, next);
    expect(delta.length).toBe(2);
  });

  it("ignores controls not in prev (new controls)", () => {
    const prev = mkResults().slice(0, 2);
    const next = mkResults();
    // DE-01 (index 2) is not in prev, so no delta for it
    const delta = formatDelta(prev, next);
    expect(delta.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// printSessionSummary — verify no crash and output format
// ---------------------------------------------------------------------------

describe("printSessionSummary", () => {
  it("writes session summary without crashing", () => {
    const written: string[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string) => { written.push(chunk); return true; }) as typeof process.stdout.write;
    try {
      const start = new Date(Date.now() - 75000); // 1m 15s ago
      printSessionSummary(start, 3, mkResults(), "compliant");
    } finally {
      process.stdout.write = origWrite;
    }
    const output = written.join("").replace(/\x1b\[[0-9;]*m/g, "");
    expect(output).toMatch(/Watch session ended/);
    expect(output).toMatch(/3 scan/);
    expect(output).toMatch(/compliant/);
  });

  it("handles null final results gracefully", () => {
    const written: string[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string) => { written.push(chunk); return true; }) as typeof process.stdout.write;
    try {
      printSessionSummary(new Date(), 0, null, null);
    } finally {
      process.stdout.write = origWrite;
    }
    const output = written.join("").replace(/\x1b\[[0-9;]*m/g, "");
    expect(output).toMatch(/Watch session ended/);
  });
});

// ---------------------------------------------------------------------------
// WatchRunner — constructor and option parsing
// ---------------------------------------------------------------------------

describe("WatchRunner constructor", () => {
  it("instantiates with minimal options", () => {
    const config = minConfig();
    const runner = new WatchRunner({
      config,
      debounce: 2,
      clear: false,
      watchDir: tmpdir(),
      since: new Date().toISOString(),
    });
    expect(runner).toBeInstanceOf(WatchRunner);
  });

  it("accepts all optional options without error", () => {
    const config = minConfig();
    const runner = new WatchRunner({
      config,
      dbPath: "/tmp/test.duckdb",
      debounce: 5,
      clear: true,
      watchDir: tmpdir(),
      producers: ["dependency"],
      since: new Date().toISOString(),
      sessionId: "sess-123",
    });
    expect(runner).toBeInstanceOf(WatchRunner);
  });
});
