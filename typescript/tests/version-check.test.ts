/** Tests for ancilis version-check module. */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

import {
  isCiEnvironment,
  isSuppressed,
  readCache,
  writeCache,
  shouldNotify,
  checkAndNotify,
  fetchLatestVersion,
} from "../src/ancilis/cli/version-check.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-vc-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function captureIo() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: (m: string) => out.push(m),
      stderr: (m: string) => err.push(m),
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

// ---------------------------------------------------------------------------
// isCiEnvironment
// ---------------------------------------------------------------------------

describe("isCiEnvironment", () => {
  const CI_VARS = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI", "TRAVIS", "TF_BUILD", "BUILDKITE"];

  beforeEach(() => {
    for (const v of CI_VARS) delete process.env[v];
  });

  afterEach(() => {
    for (const v of CI_VARS) delete process.env[v];
  });

  it("returns false when no CI vars set", () => {
    expect(isCiEnvironment()).toBe(false);
  });

  it.each(CI_VARS)("returns true when %s is set", (varName) => {
    process.env[varName] = "true";
    expect(isCiEnvironment()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isSuppressed
// ---------------------------------------------------------------------------

describe("isSuppressed", () => {
  beforeEach(() => {
    delete process.env["CI"];
    delete process.env["ANCILIS_NO_UPDATE_CHECK"];
  });

  afterEach(() => {
    delete process.env["CI"];
    delete process.env["ANCILIS_NO_UPDATE_CHECK"];
  });

  it("returns false with no flags or env vars", () => {
    expect(isSuppressed([])).toBe(false);
  });

  it("returns true when --no-update-check flag present", () => {
    expect(isSuppressed(["--no-update-check"])).toBe(true);
  });

  it("returns true when ANCILIS_NO_UPDATE_CHECK=1", () => {
    process.env["ANCILIS_NO_UPDATE_CHECK"] = "1";
    expect(isSuppressed([])).toBe(true);
  });

  it("returns true when ANCILIS_NO_UPDATE_CHECK=true", () => {
    process.env["ANCILIS_NO_UPDATE_CHECK"] = "true";
    expect(isSuppressed([])).toBe(true);
  });

  it("returns true when ANCILIS_NO_UPDATE_CHECK=yes", () => {
    process.env["ANCILIS_NO_UPDATE_CHECK"] = "yes";
    expect(isSuppressed([])).toBe(true);
  });

  it("returns true when CI env var is set", () => {
    process.env["CI"] = "true";
    expect(isSuppressed([])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// readCache / writeCache
// ---------------------------------------------------------------------------

describe("readCache / writeCache", () => {
  let dir: string;
  let cacheFile: string;

  beforeEach(() => {
    dir = tmpDir();
    cacheFile = join(dir, "version-check.json");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns null when cache file missing", () => {
    expect(readCache(cacheFile)).toBeNull();
  });

  it("returns null for corrupt cache file", () => {
    writeFileSync(cacheFile, "not json{{");
    expect(readCache(cacheFile)).toBeNull();
  });

  it("returns null for expired cache", () => {
    const old = Date.now() - 90000 * 1000; // 25 hours ago
    writeFileSync(cacheFile, JSON.stringify({ latestVersion: "1.2.3", checkedAt: old }));
    expect(readCache(cacheFile)).toBeNull();
  });

  it("returns null when checkedAt is missing", () => {
    writeFileSync(cacheFile, JSON.stringify({ latestVersion: "1.2.3" }));
    expect(readCache(cacheFile)).toBeNull();
  });

  it("returns version when cache is fresh", () => {
    writeCache("1.5.0", cacheFile);
    const result = readCache(cacheFile);
    expect(result).not.toBeNull();
    expect(result!.latestVersion).toBe("1.5.0");
  });

  it("respects custom TTL", () => {
    const old = Date.now() - 10000; // 10 seconds ago
    writeFileSync(cacheFile, JSON.stringify({ latestVersion: "1.2.3", checkedAt: old }));
    // TTL of 5 seconds → expired
    expect(readCache(cacheFile, 5)).toBeNull();
    // TTL of 20 seconds → still valid
    expect(readCache(cacheFile, 20)).not.toBeNull();
  });

  it("writeCache creates directory if needed", () => {
    const nestedCache = join(dir, "nested", "dir", "cache.json");
    writeCache("1.0.0", nestedCache);
    expect(existsSync(nestedCache)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// shouldNotify
// ---------------------------------------------------------------------------

describe("shouldNotify", () => {
  it("returns true when patch version is newer", () => {
    expect(shouldNotify("1.0.0", "1.0.1")).toBe(true);
  });

  it("returns true when minor version is newer", () => {
    expect(shouldNotify("1.0.0", "1.1.0")).toBe(true);
  });

  it("returns true when major version is newer", () => {
    expect(shouldNotify("1.0.0", "2.0.0")).toBe(true);
  });

  it("returns false when versions are equal", () => {
    expect(shouldNotify("1.0.0", "1.0.0")).toBe(false);
  });

  it("returns false when installed is newer", () => {
    expect(shouldNotify("1.1.0", "1.0.0")).toBe(false);
  });

  it("returns false when installed patch is newer", () => {
    expect(shouldNotify("1.0.5", "1.0.3")).toBe(false);
  });

  it("returns false for invalid version strings", () => {
    expect(shouldNotify("invalid", "1.0.0")).toBe(false);
    expect(shouldNotify("1.0.0", "invalid")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// checkAndNotify
// ---------------------------------------------------------------------------

describe("checkAndNotify", () => {
  let dir: string;
  let cacheFile: string;

  beforeEach(() => {
    dir = tmpDir();
    cacheFile = join(dir, "version-check.json");
    delete process.env["CI"];
    delete process.env["ANCILIS_NO_UPDATE_CHECK"];
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    delete process.env["CI"];
    delete process.env["ANCILIS_NO_UPDATE_CHECK"];
  });

  it("does nothing when suppressed via flag", () => {
    const { io, stderr } = captureIo();
    writeCache("9.9.9", cacheFile);
    checkAndNotify("1.0.0", ["--no-update-check"], io, cacheFile);
    expect(stderr()).toBe("");
  });

  it("does nothing when suppressed via CI env", () => {
    process.env["CI"] = "true";
    const { io, stderr } = captureIo();
    writeCache("9.9.9", cacheFile);
    checkAndNotify("1.0.0", [], io, cacheFile);
    expect(stderr()).toBe("");
  });

  it("notifies when cached version is newer", () => {
    writeCache("2.0.0", cacheFile);
    const { io, stderr } = captureIo();
    checkAndNotify("1.0.0", [], io, cacheFile);
    expect(stderr()).toMatch(/Update available/);
    expect(stderr()).toMatch(/1\.0\.0 → 2\.0\.0/);
    expect(stderr()).toMatch(/npm update -g ancilis/);
  });

  it("does not notify when cached version is same or older", () => {
    writeCache("1.0.0", cacheFile);
    const { io, stderr } = captureIo();
    checkAndNotify("1.0.0", [], io, cacheFile);
    expect(stderr()).toBe("");
  });

  it("does not crash when cache file missing (fires background fetch)", () => {
    const { io, stderr } = captureIo();
    // No cache file — should not throw
    expect(() => checkAndNotify("1.0.0", [], io, cacheFile)).not.toThrow();
    expect(stderr()).toBe("");
  });
});

// ---------------------------------------------------------------------------
// fetchLatestVersion (mocked)
// ---------------------------------------------------------------------------

describe("fetchLatestVersion", () => {
  it("returns null on network error", async () => {
    // Pass a clearly unreachable URL
    const result = await fetchLatestVersion("http://127.0.0.1:0/unreachable");
    expect(result).toBeNull();
  });
});
