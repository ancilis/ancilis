/**
 * Integration tests for ANC-405: dependency scan wired into ancilis scan.
 *
 * Tests verify:
 * - DEPENDENCIES section appears in scan output
 * - CI exit code reflects severity_threshold
 * - Config controls enable/disable and ignore list
 * - Existing scan behavior unchanged when no manifests found
 */

import { describe, it, expect, vi, afterEach, beforeAll } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringify as stringifyYaml } from "yaml";
import { handleScan, runEvaluation } from "../../src/ancilis/cli/scan.js";
import { loadConfig } from "../../src/ancilis/config/index.js";
import { EvidenceStore } from "../../src/ancilis/evidence/store.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "ancilis-scan-dep-test-"));
}

/** Capture stdout/stderr from handleScan */
function captureIo() {
  const outLines: string[] = [];
  const errLines: string[] = [];
  const io = {
    stdout(m: string) { outLines.push(m); },
    stderr(m: string) { errLines.push(m); },
  };
  return {
    io,
    stdout: () => outLines.join(""),
    stderr: () => errLines.join(""),
  };
}

function writeConfig(dir: string, extra: Record<string, unknown> = {}): string {
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, stringifyYaml({
    agent: { name: "test-agent" },
    security: { mode: "audit" },
    ...extra,
  }));
  return path;
}

/** Minimal npm package-lock.json v2 with given packages. */
function writePackageLock(dir: string, pkgs: Record<string, string> = {}): void {
  const packages: Record<string, { version: string }> = {};
  for (const [name, version] of Object.entries(pkgs)) {
    packages[`node_modules/${name}`] = { version };
  }
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({
    lockfileVersion: 2,
    packages,
  }));
}

/** Mock fetch to return a single vulnerability for the first queried package. */
function mockOsvVuln(
  cveId: string,
  pkgName: string,
  cvssScore: string,
  fixedVersion?: string,
): void {
  const affected = fixedVersion
    ? [{
        package: { name: pkgName, ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: fixedVersion }] }],
      }]
    : [];

  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: vi.fn().mockResolvedValue({
      results: [{
        vulns: [{
          id: cveId,
          aliases: [],
          summary: `Test vulnerability in ${pkgName}`,
          severity: [{ type: "CVSS_V3", score: cvssScore }],
          affected,
        }],
      }],
    }),
  }));
}

/** Mock fetch to return no vulnerabilities for all queried packages. */
function mockOsvEmpty(pkgCount = 1): void {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: vi.fn().mockResolvedValue({
      results: Array(pkgCount).fill({ vulns: [] }),
    }),
  }));
}

/** Mock fetch to simulate OSV.dev being unreachable. */
function mockOsvError(): void {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network error")));
}

afterEach(() => {
  vi.restoreAllMocks();
});

// Ensure the first-run sentinel exists so human-mode tests don't get first-run
// guidance (which returns early before showing the DEPENDENCIES section).
beforeAll(() => {
  const sentinelDir = join(homedir(), ".ancilis");
  mkdirSync(sentinelDir, { recursive: true });
  writeFileSync(join(sentinelDir, ".first-run-complete"), "");
});

// ---------------------------------------------------------------------------
// DEPENDENCIES section in human output
// ---------------------------------------------------------------------------

describe("ancilis scan — DEPENDENCIES section (human output)", () => {
  it("shows 'no manifests detected' when no lockfile exists", async () => {
    const dir = makeTmpDir();
    const { io, stdout } = captureIo();

    const exitCode = await handleScan(
      { config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    expect(exitCode).toBe(0);
    expect(stdout()).toContain("No dependency manifests detected");
  });

  it("shows no-vulnerability message when scan finds no issues", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { lodash: "4.17.21" });
    mockOsvEmpty(1);

    const { io, stdout } = captureIo();
    const exitCode = await handleScan(
      { config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    expect(exitCode).toBe(0);
    expect(stdout()).toContain("DEPENDENCIES");
    expect(stdout()).toMatch(/No vulnerabilities found/);
  });

  it("shows DEPENDENCIES section with violation details", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { express: "4.17.1" });
    mockOsvVuln("CVE-2024-12345", "express", "7.5", "4.18.2");

    const { io, stdout } = captureIo();
    const exitCode = await handleScan(
      { config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    expect(exitCode).toBe(1); // violation at/above default 'high' threshold
    const text = stdout();
    expect(text).toContain("DEPENDENCIES");
    expect(text).toContain("CVE-2024-12345");
    expect(text).toContain("express");
    expect(text).toContain("4.18.2");
  });

  it("shows OSV.dev timeout message when OSV is unreachable", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { express: "4.17.1" });
    mockOsvError();

    const { io, stdout } = captureIo();
    const exitCode = await handleScan(
      { config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    // OSV unreachable → non-blocking (no exit code change from OSV error alone)
    expect(exitCode).toBe(0);
    expect(stdout()).toContain("Vulnerability lookup unavailable");
  });
});

// ---------------------------------------------------------------------------
// CI exit code with severity_threshold
// ---------------------------------------------------------------------------

describe("ancilis scan — CI exit code with severity_threshold", () => {
  it("exits 0 when only medium findings and threshold is high (CI)", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { lodash: "4.17.20" });
    // CVSS 5.0 → medium
    mockOsvVuln("CVE-2021-23337", "lodash", "5.0");

    const { io } = captureIo();
    const exitCode = await handleScan(
      {
        ci: true,
        config: writeConfig(dir, { scan: { dependencies: { enabled: true, severity_threshold: "high" } } }),
        db: ":memory:",
        projectDir: dir,
      },
      io,
    );

    expect(exitCode).toBe(0); // medium is below the high threshold
  });

  it("exits 1 when critical finding and threshold is high (CI)", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { "vulnerable-pkg": "1.0.0" });
    // CVSS 9.8 → critical
    mockOsvVuln("CVE-2024-CRIT", "vulnerable-pkg", "9.8");

    const { io } = captureIo();
    const exitCode = await handleScan(
      {
        ci: true,
        config: writeConfig(dir, { scan: { dependencies: { enabled: true, severity_threshold: "high" } } }),
        db: ":memory:",
        projectDir: dir,
      },
      io,
    );

    expect(exitCode).toBe(1);
  });

  it("exits 0 when high finding but threshold is critical (CI)", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { "semi-vuln": "1.0.0" });
    // CVSS 7.5 → high
    mockOsvVuln("CVE-2024-HIGH", "semi-vuln", "7.5");

    const { io } = captureIo();
    const exitCode = await handleScan(
      {
        ci: true,
        config: writeConfig(dir, { scan: { dependencies: { enabled: true, severity_threshold: "critical" } } }),
        db: ":memory:",
        projectDir: dir,
      },
      io,
    );

    expect(exitCode).toBe(0); // high is below critical threshold
  });

  it("exits 0 when CVE is on the ignore list (CI)", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { "some-pkg": "1.0.0" });
    // CVSS 9.8 → critical, but ignored
    mockOsvVuln("CVE-2024-IGNORED", "some-pkg", "9.8");

    const { io } = captureIo();
    const exitCode = await handleScan(
      {
        ci: true,
        config: writeConfig(dir, {
          scan: { dependencies: { enabled: true, severity_threshold: "high", ignore: ["CVE-2024-IGNORED"] } },
        }),
        db: ":memory:",
        projectDir: dir,
      },
      io,
    );

    expect(exitCode).toBe(0); // ignored CVE must not affect exit code
  });
});

// ---------------------------------------------------------------------------
// Config controls
// ---------------------------------------------------------------------------

describe("ancilis scan — config controls", () => {
  it("skips dependency scan when enabled: false", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { lodash: "4.17.20" });
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const { io, stdout } = captureIo();
    await handleScan(
      {
        config: writeConfig(dir, { scan: { dependencies: { enabled: false } } }),
        db: ":memory:",
        projectDir: dir,
      },
      io,
    );

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(stdout()).not.toContain("DEPENDENCIES");
  });

  it("uses default severity_threshold of high when not specified", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { "pkg-a": "1.0.0" });
    // CVSS 5.0 → medium — should NOT trigger exit 1 with default 'high' threshold
    mockOsvVuln("CVE-2024-MED", "pkg-a", "5.0");

    const { io } = captureIo();
    const exitCode = await handleScan(
      { ci: true, config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    expect(exitCode).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CI JSON output
// ---------------------------------------------------------------------------

describe("ancilis scan — CI JSON output", () => {
  it("includes dependencies section in CI JSON with findings", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { express: "4.17.1" });
    mockOsvVuln("CVE-2024-TEST", "express", "7.5", "4.18.2");

    const { io, stdout } = captureIo();
    await handleScan(
      { ci: true, config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    const json = JSON.parse(stdout()) as Record<string, unknown>;
    expect(json).toHaveProperty("dependencies");
    const deps = json["dependencies"] as Record<string, unknown>;
    expect(deps["status"]).toBe("violations");
    expect(typeof deps["violation_count"]).toBe("number");
    expect((deps["violation_count"] as number)).toBeGreaterThan(0);
    const findings = deps["findings"] as Array<Record<string, unknown>>;
    expect(findings).toBeInstanceOf(Array);
    const finding = findings[0]!;
    expect(finding["cve_id"]).toBe("CVE-2024-TEST");
    expect(finding["severity"]).toBe("high");
    expect(finding["fixed_version"]).toBe("4.18.2");
  });

  it("writes dependency evidence persistence failures to stderr without corrupting CI JSON", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { lodash: "4.17.21" });
    mockOsvEmpty(1);
    vi.spyOn(EvidenceStore.prototype, "store").mockRejectedValueOnce(new Error("duckdb locked"));

    const { io, stdout, stderr } = captureIo();
    const exitCode = await handleScan(
      { ci: true, config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    expect(exitCode).toBe(0);
    const json = JSON.parse(stdout()) as Record<string, unknown>;
    expect((json["dependencies"] as Record<string, unknown>)["status"]).toBe("ok");
    expect(stderr()).toContain("Warning:");
    expect(stderr()).toContain("dependency-scan evidence");
    expect(stderr()).toContain("duckdb locked");
  });

  it("CI JSON has no_manifests status when no lockfile found", async () => {
    const dir = makeTmpDir();
    // no lockfile written

    const { io, stdout } = captureIo();
    await handleScan(
      { ci: true, config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    const json = JSON.parse(stdout()) as Record<string, unknown>;
    expect((json["dependencies"] as Record<string, unknown>)["status"]).toBe("no_manifests");
  });

  it("CI JSON has disabled status when dep scanning is off", async () => {
    const dir = makeTmpDir();

    const { io, stdout } = captureIo();
    await handleScan(
      {
        ci: true,
        config: writeConfig(dir, { scan: { dependencies: { enabled: false } } }),
        db: ":memory:",
        projectDir: dir,
      },
      io,
    );

    const json = JSON.parse(stdout()) as Record<string, unknown>;
    expect((json["dependencies"] as Record<string, unknown>)["status"]).toBe("disabled");
  });

  it("CI JSON exit_code is 1 for violations", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { "bad-pkg": "0.1.0" });
    // CVSS 9.0 → critical
    mockOsvVuln("CVE-2024-BAD", "bad-pkg", "9.0");

    const { io, stdout } = captureIo();
    const exitCode = await handleScan(
      { ci: true, config: writeConfig(dir), db: ":memory:", projectDir: dir },
      io,
    );

    const json = JSON.parse(stdout()) as Record<string, unknown>;
    expect(json["exit_code"]).toBe(1);
    expect(json["posture"]).toBe("non_compliant");
    expect(exitCode).toBe(1);
  });
});

describe("ancilis scan — shared evaluation pass", () => {
  it("warns when dependency evidence persistence fails without changing posture", async () => {
    const dir = makeTmpDir();
    writePackageLock(dir, { lodash: "4.17.21" });
    mockOsvEmpty(1);
    vi.spyOn(EvidenceStore.prototype, "store").mockRejectedValueOnce(new Error("duckdb locked"));

    const config = loadConfig({ path: writeConfig(dir) });
    const originalCwd = process.cwd();
    const stderrWrites: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: unknown, ..._args: unknown[]) => {
      stderrWrites.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;

    try {
      process.chdir(dir);
      const result = await runEvaluation(config, {
        since: new Date(0).toISOString(),
        db: ":memory:",
        runDepScan: true,
      });

      expect(result.posture).toBe("compliant");
    } finally {
      process.chdir(originalCwd);
      process.stderr.write = originalWrite;
    }

    const stderr = stderrWrites.join("");
    expect(stderr).toContain("Warning:");
    expect(stderr).toContain("dependency-scan evidence");
    expect(stderr).toContain("duckdb locked");
  });
});
