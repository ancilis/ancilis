/** CycloneDX v1.5+ SBOM importer — maps components and vulnerabilities to AKSI controls. */

import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import type { ControlResult, EvaluationResult } from "../engine/result.js";

// CWE → AKSI control mapping (subset covering most common SBOM vulnerability categories)
const CWE_CONTROL_MAP: Record<string, string> = {
  // Injection
  "CWE-89": "PR-03",   // SQL Injection
  "CWE-79": "PR-03",   // XSS
  "CWE-78": "PR-03",   // OS Command Injection
  "CWE-94": "PR-03",   // Code Injection
  "CWE-611": "PR-03",  // XXE
  "CWE-918": "PR-01",  // SSRF
  // Cryptography
  "CWE-326": "PR-04",  // Inadequate Encryption Strength
  "CWE-327": "PR-04",  // Use of Broken/Risky Algorithm
  "CWE-330": "PR-04",  // Insufficient Random Values
  "CWE-338": "PR-04",  // Weak PRNG
  // Secrets / Credentials
  "CWE-798": "PR-05",  // Hard-coded Credentials
  "CWE-259": "PR-05",  // Hard-coded Password
  "CWE-312": "PR-05",  // Cleartext Storage of Sensitive Data
  // Auth / Access
  "CWE-287": "PR-01",  // Improper Authentication
  "CWE-306": "PR-01",  // Missing Auth for Critical Function
  "CWE-862": "PR-01",  // Missing Authorization
  // Data Exfiltration
  "CWE-200": "DE-01",  // Exposure of Sensitive Information
  "CWE-359": "DE-01",  // Exposure of Private Personal Information
};

const CONTROL_NAMES: Record<string, string> = {
  "PR-01": "Prompt Injection Prevention",
  "PR-02": "Rate Limiting",
  "PR-03": "Input Validation",
  "PR-04": "Cryptographic Controls",
  "PR-05": "Secret Detection",
  "DE-01": "Data Exfiltration Prevention",
};

const DEFAULT_CONTROL = "PR-03";

function cweToControl(cwes: string[]): string {
  for (const cwe of cwes) {
    const key = cwe.startsWith("CWE-") ? cwe : `CWE-${cwe}`;
    if (key in CWE_CONTROL_MAP) return CWE_CONTROL_MAP[key]!;
  }
  return DEFAULT_CONTROL;
}

function extractCwes(vulnerability: Record<string, unknown>): string[] {
  const raw = (vulnerability["cwes"] as Array<number | string>) ?? [];
  return raw.map((cwe) => {
    if (typeof cwe === "number") return `CWE-${cwe}`;
    return String(cwe).startsWith("CWE-") ? String(cwe) : `CWE-${cwe}`;
  });
}

function sourceTool(doc: Record<string, unknown>): string {
  const meta = (doc["metadata"] as Record<string, unknown>) ?? {};
  const tools = (meta["tools"] as Record<string, unknown>[]) ?? [];
  if (tools.length > 0) {
    const t = tools[0]!;
    const name = (t["name"] as string) ?? "cyclonedx-tool";
    const version = (t["version"] as string) ?? "";
    return version ? `${name}/${version}` : name;
  }
  return "cyclonedx-import";
}

export class CycloneDxImporter {
  private readonly agentId: string;
  private readonly mode: "audit" | "enforce";

  constructor(agentId = "import", mode: "audit" | "enforce" = "audit") {
    this.agentId = agentId;
    this.mode = mode;
  }

  parse(path: string): EvaluationResult[] {
    const doc = JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
    return this._parseDoc(doc);
  }

  parseString(content: string): EvaluationResult[] {
    const doc = JSON.parse(content) as Record<string, unknown>;
    return this._parseDoc(doc);
  }

  private _parseDoc(doc: Record<string, unknown>): EvaluationResult[] {
    const results: EvaluationResult[] = [];
    results.push(this._buildComponentResult(doc));
    const vulns = (doc["vulnerabilities"] as Record<string, unknown>[]) ?? [];
    for (const vuln of vulns) {
      results.push(this._buildVulnResult(doc, vuln));
    }
    return results;
  }

  private _buildComponentResult(doc: Record<string, unknown>): EvaluationResult {
    const tool = sourceTool(doc);
    const components = (doc["components"] as Record<string, unknown>[]) ?? [];
    const meta = (doc["metadata"] as Record<string, unknown>) ?? {};
    const serial = (doc["serialNumber"] as string) ?? "";
    const specVersion = (doc["specVersion"] as string) ?? "";

    const summaryParts = [`${components.length} component(s) inventoried`];
    if (serial) summaryParts.push(`serialNumber=${serial}`);

    const metaComponent = (meta["component"] as Record<string, unknown>) ?? {};

    const controlResults: ControlResult[] = [
      {
        controlId: "PR-05",
        controlName: CONTROL_NAMES["PR-05"]!,
        result: "PASS",
        detail: `SBOM component inventory ingested from ${tool}. ${summaryParts.join(", ")}.`,
        evidenceData: {
          source_tool: tool,
          spec_version: specVersion,
          serial_number: serial,
          component_count: components.length,
          components: components.map((c) => ({
            name: (c["name"] as string) ?? "",
            version: (c["version"] as string) ?? "",
            purl: (c["purl"] as string) ?? "",
            type: (c["type"] as string) ?? "",
          })),
          metadata: {
            timestamp: (meta["timestamp"] as string) ?? "",
            component: (metaComponent["name"] as string) ?? "",
          },
        },
        durationMs: 0,
      },
    ];

    return {
      evaluationId: randomUUID(),
      actionId: `cdx-components-${randomUUID().replace(/-/g, "").slice(0, 8)}`,
      timestamp: new Date().toISOString(),
      agentId: this.agentId,
      sourceType: "cyclonedx_import",
      mode: this.mode,
      controlResults,
      decision: "ALLOW",
      decisionReason: `CycloneDX SBOM component inventory from ${tool}`,
      activeOverlays: [],
      dataClassifications: [],
      totalDurationMs: 0,
      context: { sessionId: this.agentId },
    };
  }

  private _buildVulnResult(
    doc: Record<string, unknown>,
    vuln: Record<string, unknown>
  ): EvaluationResult {
    const tool = sourceTool(doc);
    const vulnId = (vuln["id"] as string) ?? "UNKNOWN";
    const description = (vuln["description"] as string) ?? "";
    const cwes = extractCwes(vuln);
    const controlId = cweToControl(cwes);
    const controlName = CONTROL_NAMES[controlId] ?? controlId;

    const ratings = (vuln["ratings"] as Record<string, unknown>[]) ?? [];
    const firstRating = ratings[0] ?? {};
    const severity = (firstRating["severity"] as string) ?? "unknown";
    const score = (firstRating["score"] as number | null) ?? null;

    let detail = description ? `${vulnId}: ${description.slice(0, 200)}` : vulnId;
    if (cwes.length > 0) detail += ` (${cwes.join(", ")})`;

    const crResult: ControlResult["result"] =
      severity === "critical" || severity === "high" ? "FAIL" : "FLAG";

    const affects = (vuln["affects"] as Record<string, unknown>[]) ?? [];

    const controlResults: ControlResult[] = [
      {
        controlId,
        controlName,
        result: crResult,
        detail,
        evidenceData: {
          vuln_id: vulnId,
          severity,
          score,
          cwes,
          source_tool: tool,
          affects: affects.map((a) => ({
            ref: (a["ref"] as string) ?? "",
            versions: (a["versions"] as unknown[]) ?? [],
          })),
        },
        durationMs: 0,
      },
    ];

    const overallDecision: EvaluationResult["decision"] =
      crResult === "FAIL" ? "BLOCK" : "FLAG";

    return {
      evaluationId: randomUUID(),
      actionId: `cdx-vuln-${randomUUID().replace(/-/g, "").slice(0, 8)}`,
      timestamp: new Date().toISOString(),
      agentId: this.agentId,
      sourceType: "cyclonedx_import",
      mode: this.mode,
      controlResults,
      decision: overallDecision,
      decisionReason: `CycloneDX vulnerability ${vulnId} severity=${severity}`,
      activeOverlays: [],
      dataClassifications: [],
      totalDurationMs: 0,
      context: { sessionId: this.agentId },
    };
  }
}
