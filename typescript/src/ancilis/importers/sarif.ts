/** SARIF v2.1.0 importer — parses findings and maps them to AKSI controls. */

import { readFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { sharedPathFrom } from "../shared-path.js";
import type { ControlResult, EvaluationResult } from "../engine/result.js";

const CONTROL_NAMES: Record<string, string> = {
  "PR-01": "Action Authorization",
  "PR-02": "Permission Scope Enforcement",
  "PR-03": "Tool/Model Integrity & Provenance",
  "PR-04": "Data Exposure Prevention",
  "PR-05": "Context & Tenant Isolation",
  "PR-08": "Input Validation & Injection Resistance",
  "PR-09": "Controlled Code Execution & Sandbox Enforcement",
  "DE-01": "Behavioral Anomaly Detection",
};

const UNMAPPED_CONTROL = "PR-03";

interface SarifMappingEntry {
  rule_id: string;
  control_id: string;
  match?: "exact" | "glob";
}

interface SarifMappings {
  mappings: Record<string, string> | SarifMappingEntry[];
}

function loadMappings(): SarifMappingEntry[] {
  try {
    const p = sharedPathFrom(import.meta.url, "mappings", "sarif-aksi-controls.json");
    const data = JSON.parse(readFileSync(p, "utf-8")) as SarifMappings;
    if (Array.isArray(data.mappings)) {
      return data.mappings.filter((entry) => entry.rule_id && entry.control_id);
    }
    return Object.entries(data.mappings ?? {}).map(([rule_id, control_id]) => ({
      rule_id,
      control_id,
      match: rule_id.includes("*") || rule_id.includes("?") ? "glob" : "exact",
    }));
  } catch {
    return [];
  }
}

/** Match a string against a simple glob pattern (supports * and ? only). */
function fnmatch(name: string, pattern: string): boolean {
  const regex = new RegExp(
    "^" +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".") +
      "$"
  );
  return regex.test(name);
}

function mapRuleToControl(ruleId: string, mappings: SarifMappingEntry[]): string {
  for (const entry of mappings) {
    if ((entry.match ?? "exact") !== "glob" && entry.rule_id === ruleId) {
      return entry.control_id;
    }
  }
  for (const entry of mappings) {
    if ((entry.match ?? "exact") === "glob" && fnmatch(ruleId, entry.rule_id)) {
      return entry.control_id;
    }
  }
  return UNMAPPED_CONTROL;
}

function formatLocation(location: Record<string, unknown>): string {
  const phys = (location["physicalLocation"] as Record<string, unknown>) ?? {};
  const artifactLocation = (phys["artifactLocation"] as Record<string, unknown>) ?? {};
  const uri = (artifactLocation["uri"] as string) ?? "";
  const region = (phys["region"] as Record<string, unknown>) ?? {};
  const line = region["startLine"];
  if (uri && line !== undefined) return `${uri}:${line}`;
  return uri || (line !== undefined ? String(line) : "");
}

export class SarifImporter {
  private readonly agentId: string;
  private readonly mode: "audit" | "enforce";
  private readonly mappings: SarifMappingEntry[];

  constructor(agentId = "import", mode: "audit" | "enforce" = "audit") {
    this.agentId = agentId;
    this.mode = mode;
    this.mappings = loadMappings();
  }

  parse(path: string): EvaluationResult[] {
    const content = readFileSync(path);
    const fileSha256 = createHash("sha256").update(content).digest("hex");
    const doc = JSON.parse(content.toString("utf-8")) as Record<string, unknown>;
    return this._parseDoc(doc, fileSha256);
  }

  parseString(content: string): EvaluationResult[] {
    const doc = JSON.parse(content) as Record<string, unknown>;
    return this._parseDoc(doc);
  }

  private _parseDoc(doc: Record<string, unknown>, fileSha256?: string): EvaluationResult[] {
    const runs = (doc["runs"] as Record<string, unknown>[]) ?? [];
    return runs.map((run) => this._parseRun(run, fileSha256));
  }

  private _parseRun(run: Record<string, unknown>, fileSha256?: string): EvaluationResult {
    const tool = (run["tool"] as Record<string, unknown>) ?? {};
    const driver = (tool["driver"] as Record<string, unknown>) ?? {};
    const toolName = (driver["name"] as string) ?? "unknown-sarif-tool";
    const toolVersion = (driver["version"] as string) ?? "";
    const sourceTool = toolVersion ? `${toolName}/${toolVersion}` : toolName;
    const sourceProvenance: Record<string, unknown> = {
      source_format: "sarif",
      source_tool_name: toolName,
      source_tool_version: toolVersion,
    };
    if (fileSha256) {
      sourceProvenance.original_file_sha256 = fileSha256;
    }

    // Build rule-id → rule-metadata index
    const rules = (driver["rules"] as Record<string, unknown>[]) ?? [];
    const ruleIndex: Record<string, Record<string, unknown>> = {};
    for (const rule of rules) {
      const id = rule["id"] as string;
      if (id) ruleIndex[id] = rule;
    }

    const findings = (run["results"] as Record<string, unknown>[]) ?? [];
    const controlResults: ControlResult[] = [];

    for (const finding of findings) {
      const ruleId = (finding["ruleId"] as string) ?? "";
      const controlId = mapRuleToControl(ruleId, this.mappings);
      const controlName = CONTROL_NAMES[controlId] ?? controlId;

      const ruleMeta = ruleIndex[ruleId] ?? {};
      const shortDescObj = (ruleMeta["shortDescription"] as Record<string, unknown>) ?? {};
      const shortDesc =
        (shortDescObj["text"] as string) || (ruleMeta["name"] as string) || ruleId;

      const locations = (finding["locations"] as Record<string, unknown>[]) ?? [];
      const locSummary = locations.length > 0 ? formatLocation(locations[0]!) : "";
      const detail =
        `${ruleId}: ${shortDesc}` + (locSummary ? ` [${locSummary}]` : "");

      const level = (finding["level"] as string) ?? "warning";
      const crResult: ControlResult["result"] =
        level === "error" || level === "warning" ? "FAIL" : "FLAG";

      const message = (finding["message"] as Record<string, unknown>) ?? {};

      controlResults.push({
        controlId,
        controlName,
        result: crResult,
        detail,
        evidenceData: {
          rule_id: ruleId,
          level,
          source_tool: sourceTool,
          source_provenance: sourceProvenance,
          message: (message["text"] as string) ?? "",
        },
        durationMs: 0,
      });
    }

    if (controlResults.length === 0) {
      controlResults.push({
        controlId: "PR-01",
        controlName: CONTROL_NAMES["PR-01"]!,
        result: "PASS",
        detail: `No findings reported by ${sourceTool}`,
        evidenceData: { source_tool: sourceTool, source_provenance: sourceProvenance },
        durationMs: 0,
      });
    }

    const overall: EvaluationResult["decision"] = controlResults.every(
      (cr) => cr.result === "PASS"
    )
      ? "ALLOW"
      : "FLAG";

    return {
      evaluationId: randomUUID(),
      actionId: `sarif-import-${randomUUID().replace(/-/g, "").slice(0, 8)}`,
      timestamp: new Date().toISOString(),
      agentId: this.agentId,
      sourceType: "sarif_import",
      mode: this.mode,
      controlResults,
      decision: overall,
      decisionReason: `Imported from SARIF (${sourceTool}): ${findings.length} finding(s)`,
      activeOverlays: [],
      dataClassifications: [],
      totalDurationMs: 0,
      context: { sessionId: this.agentId },
    };
  }
}
