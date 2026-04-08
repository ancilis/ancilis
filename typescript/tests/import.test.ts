import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SarifImporter } from "../src/ancilis/importers/sarif.js";
import { CycloneDxImporter } from "../src/ancilis/importers/cyclonedx.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "..", "shared", "fixtures");
const SARIF_FIXTURE = join(FIXTURES, "sample.sarif");
const CDX_FIXTURE = join(FIXTURES, "sample-sbom.cdx.json");

// ---------------------------------------------------------------------------
// SarifImporter
// ---------------------------------------------------------------------------

describe("SarifImporter", () => {
  it("parses sample.sarif from file path", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    expect(results).toHaveLength(1);
    const r = results[0]!;
    expect(r.sourceType).toBe("sarif_import");
    expect(r.mode).toBe("audit");
    expect(r.decision).toBe("FLAG");
    // 5 findings → 5 control results
    expect(r.controlResults).toHaveLength(5);
  });

  it("parses SARIF from string", () => {
    const content = readFileSync(SARIF_FIXTURE, "utf-8");
    const results = new SarifImporter("test-agent").parseString(content);
    expect(results).toHaveLength(1);
    expect(results[0]!.agentId).toBe("test-agent");
  });

  it("maps js/sql-injection → PR-03 (Input Validation)", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    const cr = results[0]!.controlResults.find((c) => c.evidenceData["rule_id"] === "js/sql-injection");
    expect(cr).toBeDefined();
    expect(cr!.controlId).toBe("PR-03");
    expect(cr!.controlName).toBe("Input Validation");
  });

  it("maps js/hardcoded-credentials → PR-05 (Secret Detection)", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    const cr = results[0]!.controlResults.find(
      (c) => c.evidenceData["rule_id"] === "js/hardcoded-credentials"
    );
    expect(cr).toBeDefined();
    expect(cr!.controlId).toBe("PR-05");
  });

  it("maps js/missing-rate-limiting → PR-02 (Rate Limiting)", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    const cr = results[0]!.controlResults.find(
      (c) => c.evidenceData["rule_id"] === "js/missing-rate-limiting"
    );
    expect(cr).toBeDefined();
    expect(cr!.controlId).toBe("PR-02");
  });

  it("sets FAIL for error/warning level findings", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    const errorCr = results[0]!.controlResults.find(
      (c) => c.evidenceData["level"] === "error"
    );
    expect(errorCr!.result).toBe("FAIL");
    const warnCr = results[0]!.controlResults.find(
      (c) => c.evidenceData["level"] === "warning"
    );
    expect(warnCr!.result).toBe("FAIL");
  });

  it("sets FLAG for note level findings", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    const noteCr = results[0]!.controlResults.find(
      (c) => c.evidenceData["level"] === "note"
    );
    expect(noteCr!.result).toBe("FLAG");
  });

  it("includes location in detail string", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    const sqlCr = results[0]!.controlResults.find(
      (c) => c.evidenceData["rule_id"] === "js/sql-injection"
    );
    expect(sqlCr!.detail).toContain("src/db/users.js:42");
  });

  it("returns PASS + ALLOW for a clean SARIF with no findings", () => {
    const clean = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "CleanScanner", version: "1.0" } },
          results: [],
        },
      ],
    });
    const results = new SarifImporter().parseString(clean);
    expect(results[0]!.decision).toBe("ALLOW");
    expect(results[0]!.controlResults[0]!.result).toBe("PASS");
  });

  it("decisionReason includes tool name and finding count", () => {
    const importer = new SarifImporter();
    const results = importer.parse(SARIF_FIXTURE);
    expect(results[0]!.decisionReason).toContain("CodeQL");
    expect(results[0]!.decisionReason).toContain("5");
  });

  it("falls back to PR-03 for unmapped rule IDs", () => {
    const sarif = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "FakeTool", rules: [] } },
          results: [
            {
              ruleId: "unknown/rule-xyz",
              level: "warning",
              message: { text: "something" },
            },
          ],
        },
      ],
    });
    const results = new SarifImporter().parseString(sarif);
    expect(results[0]!.controlResults[0]!.controlId).toBe("PR-03");
  });

  it("glob pattern js/sql-* matches js/sql-batch-injection", () => {
    const sarif = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "T", rules: [] } },
          results: [
            {
              ruleId: "js/sql-batch-injection",
              level: "error",
              message: { text: "batch SQL injection" },
            },
          ],
        },
      ],
    });
    const results = new SarifImporter().parseString(sarif);
    expect(results[0]!.controlResults[0]!.controlId).toBe("PR-03");
  });
});

// ---------------------------------------------------------------------------
// CycloneDxImporter
// ---------------------------------------------------------------------------

describe("CycloneDxImporter", () => {
  it("parses sample-sbom.cdx.json from file path", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    // 1 component result + 3 vulnerability results
    expect(results).toHaveLength(4);
  });

  it("first result is component inventory PASS", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    const comp = results[0]!;
    expect(comp.sourceType).toBe("cyclonedx_import");
    expect(comp.decision).toBe("ALLOW");
    expect(comp.controlResults[0]!.controlId).toBe("PR-05");
    expect(comp.controlResults[0]!.result).toBe("PASS");
  });

  it("component result includes 3 components", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    const compData = results[0]!.controlResults[0]!.evidenceData;
    expect(compData["component_count"]).toBe(3);
  });

  it("parses CycloneDX from string", () => {
    const content = readFileSync(CDX_FIXTURE, "utf-8");
    const results = new CycloneDxImporter("my-agent").parseString(content);
    expect(results[0]!.agentId).toBe("my-agent");
  });

  it("high severity vulnerability → FAIL + BLOCK", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    // CVE-2021-23337 and CVE-2022-24999 are both high severity
    const highResult = results.find((r) => r.decision === "BLOCK");
    expect(highResult).toBeDefined();
    expect(highResult!.controlResults[0]!.result).toBe("FAIL");
  });

  it("medium severity vulnerability → FLAG + FLAG decision", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    // CVE-2022-23529 is medium
    const medResult = results.find(
      (r) =>
        r.decision === "FLAG" &&
        r.controlResults[0]?.evidenceData["vuln_id"] === "CVE-2022-23529"
    );
    expect(medResult).toBeDefined();
    expect(medResult!.controlResults[0]!.result).toBe("FLAG");
  });

  it("includes vuln_id and severity in evidenceData", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    const vulnResult = results[1]!; // first vuln
    const data = vulnResult.controlResults[0]!.evidenceData;
    expect(data["vuln_id"]).toBe("CVE-2021-23337");
    expect(data["severity"]).toBe("high");
    expect(data["score"]).toBe(7.2);
  });

  it("CWE-78 (OS Command Injection) maps to PR-03", () => {
    const sbom = JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [],
      vulnerabilities: [
        {
          id: "CVE-2099-0001",
          ratings: [{ severity: "high", score: 9.0 }],
          description: "OS command injection",
          cwes: [78],
          affects: [],
        },
      ],
    });
    const results = new CycloneDxImporter().parseString(sbom);
    const vulnResult = results[1]!;
    expect(vulnResult.controlResults[0]!.controlId).toBe("PR-03");
  });

  it("CWE-798 (Hard-coded Credentials) maps to PR-05", () => {
    const sbom = JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [],
      vulnerabilities: [
        {
          id: "CVE-2099-0002",
          ratings: [{ severity: "critical", score: 9.8 }],
          description: "Hardcoded credentials",
          cwes: [798],
          affects: [],
        },
      ],
    });
    const results = new CycloneDxImporter().parseString(sbom);
    const vulnResult = results[1]!;
    expect(vulnResult.controlResults[0]!.controlId).toBe("PR-05");
  });

  it("SBOM with no vulnerabilities returns single component result", () => {
    const sbom = JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [{ name: "foo", version: "1.0", purl: "pkg:npm/foo@1.0", type: "library" }],
    });
    const results = new CycloneDxImporter().parseString(sbom);
    expect(results).toHaveLength(1);
    expect(results[0]!.decision).toBe("ALLOW");
  });

  it("source tool derived from metadata tools array", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    const detail = results[0]!.controlResults[0]!.detail;
    expect(detail).toContain("Trivy");
  });

  it("decisionReason for vulnerability includes vuln id and severity", () => {
    const importer = new CycloneDxImporter();
    const results = importer.parse(CDX_FIXTURE);
    expect(results[1]!.decisionReason).toContain("CVE-2021-23337");
    expect(results[1]!.decisionReason).toContain("high");
  });
});
