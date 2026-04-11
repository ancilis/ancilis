/** Tests for TypeScript dependency vulnerability scanner — ManifestDetector, OSVClient, DependencyScanner. */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { ManifestDetector } from "../src/ancilis/deps/manifest.js";
import { OSVClient, cvssToSeverity } from "../src/ancilis/deps/osv.js";
import { DependencyScanner } from "../src/ancilis/deps/scanner.js";
import { loadConfig } from "../src/ancilis/config/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTmpDir(): string {
  const dir = join(tmpdir(), `ancilis-deps-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function rmTmpDir(dir: string): void {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* ok */ }
}

function makeConfig(de01Enabled = true, mode: "audit" | "enforce" = "audit") {
  return loadConfig({
    raw: {
      agent: { name: "test-agent" },
      security: {
        mode,
        ...(de01Enabled ? {} : { controls: { "DE-01": { enabled: false } } }),
      },
    },
  });
}

function osvResponse(vulnsPerQuery: Array<Array<Record<string, unknown>>>): string {
  return JSON.stringify({ results: vulnsPerQuery.map(vs => ({ vulns: vs })) });
}

function mockFetch(responseBody: string) {
  return vi.fn().mockResolvedValue({ text: () => Promise.resolve(responseBody) });
}

function criticalVuln(id = "GHSA-crit"): Record<string, unknown> {
  return {
    id,
    summary: "Critical vulnerability",
    severity: [{ type: "CVSS_V3", score: "9.8" }],
    aliases: ["CVE-2023-12345"],
    affected: [{
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    }],
  };
}

function highVuln(id = "GHSA-high"): Record<string, unknown> {
  return {
    id,
    summary: "High severity vuln",
    severity: [{ type: "CVSS_V3", score: "7.5" }],
    aliases: [],
    affected: [{ package: { name: "express", ecosystem: "npm" }, ranges: [] }],
  };
}

function mediumVuln(id = "GHSA-med"): Record<string, unknown> {
  return {
    id,
    summary: "Medium severity",
    severity: [{ type: "CVSS_V3", score: "5.0" }],
    aliases: [],
    affected: [],
  };
}

// ---------------------------------------------------------------------------
// ManifestDetector
// ---------------------------------------------------------------------------

describe("ManifestDetector", () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { rmTmpDir(tmpDir); });

  it("parses package-lock.json v2 packages section", () => {
    const lock = {
      lockfileVersion: 2,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.20" },
        "node_modules/express": { version: "4.18.0" },
      },
    };
    writeFileSync(join(tmpDir, "package-lock.json"), JSON.stringify(lock));
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests).toHaveLength(1);
    const names = manifests[0].dependencies.map(d => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("express");
    expect(manifests[0].dependencies.every(d => d.version !== null)).toBe(true);
  });

  it("parses package-lock.json v1 dependencies section", () => {
    const lock = {
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: "4.17.20" },
        react: { version: "18.0.0" },
      },
    };
    writeFileSync(join(tmpDir, "package-lock.json"), JSON.stringify(lock));
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests).toHaveLength(1);
    const names = manifests[0].dependencies.map(d => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("react");
  });

  it("skips root package entry (empty key) in package-lock.json v2", () => {
    const lock = {
      lockfileVersion: 2,
      packages: {
        "": { version: "1.0.0", name: "my-project" },
        "node_modules/lodash": { version: "4.17.20" },
      },
    };
    writeFileSync(join(tmpDir, "package-lock.json"), JSON.stringify(lock));
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests[0].dependencies.every(d => d.name !== "")).toBe(true);
    expect(manifests[0].dependencies).toHaveLength(1);
  });

  it("parses yarn.lock v1 format", () => {
    const content = [
      "# yarn lockfile v1",
      "",
      "lodash@^4.17.0:",
      '  version "4.17.20"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"',
      "",
      "express@^4.18.0:",
      '  version "4.18.0"',
      "",
    ].join("\n");
    writeFileSync(join(tmpDir, "yarn.lock"), content);
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests).toHaveLength(1);
    const names = manifests[0].dependencies.map(d => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("express");
  });

  it("parses pnpm-lock.yaml packages section", () => {
    const content = [
      "lockfileVersion: '6.0'",
      "",
      "packages:",
      "  /lodash@4.17.20:",
      "    resolution: {}",
      "  /express@4.18.0:",
      "    resolution: {}",
      "",
    ].join("\n");
    writeFileSync(join(tmpDir, "pnpm-lock.yaml"), content);
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests).toHaveLength(1);
    const names = manifests[0].dependencies.map(d => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("express");
  });

  it("parses package.json exact versions only", () => {
    const pkg = {
      dependencies: { lodash: "4.17.20", express: "^4.18.0" },
      devDependencies: { jest: "29.0.0", typescript: "~5.0.0" },
    };
    writeFileSync(join(tmpDir, "package.json"), JSON.stringify(pkg));
    const manifests = new ManifestDetector().detect(tmpDir);
    const names = new Set(manifests.flatMap(m => m.dependencies).map(d => d.name));
    expect(names.has("lodash")).toBe(true);
    expect(names.has("jest")).toBe(true);
    // Range versions should be excluded
    expect(names.has("express")).toBe(false);
    expect(names.has("typescript")).toBe(false);
  });

  it("returns empty list when no manifests exist", () => {
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests).toHaveLength(0);
  });

  it("detects multiple manifest formats in same directory", () => {
    writeFileSync(
      join(tmpDir, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 2, packages: { "node_modules/lodash": { version: "4.17.20" } } }),
    );
    writeFileSync(join(tmpDir, "yarn.lock"), "lodash@^4.0.0:\n  version \"4.17.20\"\n");
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests.length).toBeGreaterThanOrEqual(2);
    const formats = new Set(manifests.map(m => m.format));
    expect(formats.has("package-lock.json")).toBe(true);
    expect(formats.has("yarn.lock")).toBe(true);
  });

  it("returns empty deps for malformed JSON package-lock.json", () => {
    writeFileSync(join(tmpDir, "package-lock.json"), "not valid json{");
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests[0].dependencies).toHaveLength(0);
  });

  it("populates sourceFile on all dependencies", () => {
    const lock = {
      lockfileVersion: 2,
      packages: { "node_modules/lodash": { version: "4.17.20" } },
    };
    writeFileSync(join(tmpDir, "package-lock.json"), JSON.stringify(lock));
    const manifests = new ManifestDetector().detect(tmpDir);
    expect(manifests[0].dependencies.every(d => d.sourceFile.includes("package-lock.json"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// cvssToSeverity
// ---------------------------------------------------------------------------

describe("cvssToSeverity", () => {
  it("maps 9.0+ to CRITICAL", () => {
    expect(cvssToSeverity(9.0)).toBe("CRITICAL");
    expect(cvssToSeverity(10.0)).toBe("CRITICAL");
    expect(cvssToSeverity(9.8)).toBe("CRITICAL");
  });

  it("maps 7.0-8.9 to HIGH", () => {
    expect(cvssToSeverity(7.0)).toBe("HIGH");
    expect(cvssToSeverity(8.9)).toBe("HIGH");
  });

  it("maps 4.0-6.9 to MEDIUM", () => {
    expect(cvssToSeverity(4.0)).toBe("MEDIUM");
    expect(cvssToSeverity(6.9)).toBe("MEDIUM");
  });

  it("maps <4.0 to LOW", () => {
    expect(cvssToSeverity(0.0)).toBe("LOW");
    expect(cvssToSeverity(3.9)).toBe("LOW");
  });
});

// ---------------------------------------------------------------------------
// OSVClient
// ---------------------------------------------------------------------------

describe("OSVClient", () => {
  beforeEach(() => { vi.unstubAllGlobals(); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("returns vulns for affected package", async () => {
    const payload = osvResponse([[criticalVuln("GHSA-xxxx")]]);
    vi.stubGlobal("fetch", mockFetch(payload));
    const client = new OSVClient();
    const result = await client.queryBatch([{ name: "lodash", version: "4.17.20", sourceFile: "pkg-lock.json" }]);
    expect(result).toHaveProperty("lodash");
    expect(result["lodash"]![0]!.id).toBe("GHSA-xxxx");
    expect(result["lodash"]![0]!.severity).toBe("CRITICAL");
    expect(result["lodash"]![0]!.fixedVersion).toBe("4.17.21");
  });

  it("returns empty dict when no vulns found", async () => {
    vi.stubGlobal("fetch", mockFetch(osvResponse([[]])));
    const client = new OSVClient();
    const result = await client.queryBatch([{ name: "lodash", version: "4.17.20", sourceFile: "pkg-lock.json" }]);
    expect(result).toEqual({});
    expect(client.lastError).toBeNull();
  });

  it("sets lastError and returns empty on network failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network timeout")));
    const client = new OSVClient();
    const result = await client.queryBatch([{ name: "lodash", version: "4.17.20", sourceFile: "pkg-lock.json" }]);
    expect(result).toEqual({});
    expect(client.lastError).toContain("network timeout");
  });

  it("skips deps with null version and makes no fetch call", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const client = new OSVClient();
    const result = await client.queryBatch([{ name: "lodash", version: null, sourceFile: "package.json" }]);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(result).toEqual({});
  });

  it("uses database_specific.severity as fallback when CVSS missing", async () => {
    const vuln = {
      id: "GHSA-test",
      summary: "Test",
      severity: [],
      database_specific: { severity: "HIGH" },
      affected: [],
    };
    vi.stubGlobal("fetch", mockFetch(osvResponse([[vuln]])));
    const client = new OSVClient();
    const result = await client.queryBatch([{ name: "somepkg", version: "1.0.0", sourceFile: "pkg-lock.json" }]);
    expect(result["somepkg"]![0]!.severity).toBe("HIGH");
  });

  it("populates aliases from vuln data", async () => {
    const vuln = criticalVuln("GHSA-alias");
    vi.stubGlobal("fetch", mockFetch(osvResponse([[vuln]])));
    const client = new OSVClient();
    const result = await client.queryBatch([{ name: "lodash", version: "4.17.20", sourceFile: "pkg-lock.json" }]);
    expect(result["lodash"]![0]!.aliases).toContain("CVE-2023-12345");
  });

  it("splits large batches into multiple fetch requests", async () => {
    const callCount = { n: 0 };
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => {
      callCount.n += 1;
      return Promise.resolve({ text: () => Promise.resolve(osvResponse(new Array(1000).fill([]))) });
    }));
    const deps = Array.from({ length: 1001 }, (_, i) => ({
      name: `pkg${i}`,
      version: "1.0.0",
      sourceFile: "pkg-lock.json",
    }));
    const client = new OSVClient();
    await client.queryBatch(deps);
    expect(callCount.n).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// DependencyScanner
// ---------------------------------------------------------------------------

describe("DependencyScanner", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    vi.unstubAllGlobals();
  });
  afterEach(() => {
    rmTmpDir(tmpDir);
    vi.unstubAllGlobals();
  });

  function writePkgLock(deps: Record<string, string> = { lodash: "4.17.20" }): void {
    const packages: Record<string, { version: string }> = {};
    for (const [name, version] of Object.entries(deps)) {
      packages[`node_modules/${name}`] = { version };
    }
    writeFileSync(
      join(tmpDir, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 2, packages }),
    );
  }

  it("returns empty list when DE-01 is disabled", async () => {
    writePkgLock();
    const cfg = makeConfig(false);
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results).toHaveLength(0);
  });

  it("returns SKIP when no manifests found", async () => {
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results).toHaveLength(1);
    expect(results[0]!.controlResults[0]!.result).toBe("SKIP");
    expect(results[0]!.controlResults[0]!.controlId).toBe("DE-01");
  });

  it("returns PASS when no vulns found", async () => {
    writePkgLock();
    vi.stubGlobal("fetch", mockFetch(osvResponse([[]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results).toHaveLength(1);
    expect(results[0]!.controlResults[0]!.result).toBe("PASS");
  });

  it("returns FAIL for CRITICAL vulnerability", async () => {
    writePkgLock();
    vi.stubGlobal("fetch", mockFetch(osvResponse([[criticalVuln()]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    const failResults = results[0]!.controlResults.filter(cr => cr.result === "FAIL");
    expect(failResults.length).toBeGreaterThanOrEqual(1);
  });

  it("returns FAIL for HIGH vulnerability", async () => {
    writePkgLock({ express: "4.17.0" });
    vi.stubGlobal("fetch", mockFetch(osvResponse([[highVuln()]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    const failResults = results[0]!.controlResults.filter(cr => cr.result === "FAIL");
    expect(failResults.length).toBeGreaterThanOrEqual(1);
  });

  it("returns FLAG for MEDIUM vulnerability", async () => {
    writePkgLock();
    vi.stubGlobal("fetch", mockFetch(osvResponse([[mediumVuln()]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    const flagResults = results[0]!.controlResults.filter(cr => cr.result === "FLAG");
    expect(flagResults.length).toBeGreaterThanOrEqual(1);
  });

  it("returns FLAG on network failure (does not crash)", async () => {
    writePkgLock();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("OSV timeout")));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results).toHaveLength(1);
    expect(results[0]!.controlResults[0]!.result).toBe("FLAG");
    expect(results[0]!.controlResults[0]!.detail).toContain("OSV.dev");
  });

  it("sets sourceType to dependency_scan", async () => {
    writePkgLock();
    vi.stubGlobal("fetch", mockFetch(osvResponse([[]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results[0]!.sourceType).toBe("dependency_scan");
  });

  it("populates evidenceData fields for vuln control result", async () => {
    writePkgLock({ lodash: "4.17.20" });
    const vuln = {
      id: "GHSA-ev01",
      summary: "Test vuln",
      severity: [{ type: "CVSS_V3", score: "7.5" }],
      aliases: ["CVE-2023-99999"],
      affected: [{
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      }],
    };
    vi.stubGlobal("fetch", mockFetch(osvResponse([[vuln]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    const cr = results[0]!.controlResults[0]!;
    expect(cr.evidenceData["package"]).toBe("lodash");
    expect(cr.evidenceData["version"]).toBe("4.17.20");
    expect(cr.evidenceData["vuln_id"]).toBe("GHSA-ev01");
    expect(cr.evidenceData["severity"]).toBe("HIGH");
    expect(cr.evidenceData["fixed_version"]).toBe("4.17.21");
    expect(cr.evidenceData["aliases"]).toContain("CVE-2023-99999");
  });

  it("includes remediationHint when fixed version available", async () => {
    writePkgLock({ lodash: "4.17.20" });
    const vuln = {
      id: "GHSA-fix",
      summary: "Fixed vuln",
      severity: [{ type: "CVSS_V3", score: "9.0" }],
      aliases: [],
      affected: [{
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      }],
    };
    vi.stubGlobal("fetch", mockFetch(osvResponse([[vuln]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    const cr = results[0]!.controlResults[0]!;
    expect(cr.remediationHint).toBeDefined();
    expect(cr.remediationHint).toContain("4.17.21");
    expect(cr.remediationHint).toContain("lodash");
  });

  it("sorts results: CRITICAL before HIGH before MEDIUM", async () => {
    writeFileSync(
      join(tmpDir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 2,
        packages: {
          "node_modules/aaaa": { version: "1.0.0" },
          "node_modules/bbbb": { version: "1.0.0" },
          "node_modules/cccc": { version: "1.0.0" },
        },
      }),
    );
    // aaaa → MEDIUM, bbbb → CRITICAL, cccc → HIGH
    const payload = osvResponse([
      [mediumVuln("G-med")],
      [criticalVuln("G-crit")],
      [highVuln("G-high")],
    ]);
    vi.stubGlobal("fetch", mockFetch(payload));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    const severities = results[0]!.controlResults.map(cr => cr.evidenceData["severity"] as string);
    const critIdx = severities.indexOf("CRITICAL");
    const highIdx = severities.indexOf("HIGH");
    const medIdx = severities.indexOf("MEDIUM");
    expect(critIdx).toBeLessThan(highIdx);
    expect(highIdx).toBeLessThan(medIdx);
  });

  it("scans when DE-01 absent from config (default enabled)", async () => {
    writePkgLock();
    // Minimal config with no controls specified (all default enabled)
    const cfg = loadConfig({ raw: { agent: { name: "test" } } });
    vi.stubGlobal("fetch", mockFetch(osvResponse([[]])));
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results[0]!.controlResults[0]!.result).toBe("PASS");
  });

  it("decision is BLOCK for CRITICAL vuln in audit mode", async () => {
    writePkgLock();
    vi.stubGlobal("fetch", mockFetch(osvResponse([[criticalVuln()]])));
    const cfg = makeConfig(true, "audit");
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results[0]!.decision).toBe("BLOCK");
  });

  it("decision is ALLOW for clean scan", async () => {
    writePkgLock();
    vi.stubGlobal("fetch", mockFetch(osvResponse([[]])));
    const cfg = makeConfig();
    const results = await new DependencyScanner(cfg).scan(tmpDir);
    expect(results[0]!.decision).toBe("ALLOW");
  });
});
