/** OSV.dev batch vulnerability lookup client. */

import type { Dependency, Vuln } from "./types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const TIMEOUT_MS = 10_000;
const BATCH_SIZE = 1_000;

// ----- Severity helpers -----

function cvssToSeverity(score: number): string {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

function extractSeverity(vulnData: Record<string, unknown>): string {
  const severities = (vulnData["severity"] as Array<Record<string, unknown>> | undefined) ?? [];
  for (const sev of severities) {
    const scoreType = sev["type"] as string | undefined;
    const scoreStr = sev["score"] as string | undefined;
    if ((scoreType === "CVSS_V3" || scoreType === "CVSS_V2") && scoreStr) {
      const score = parseFloat(scoreStr);
      if (!isNaN(score)) return cvssToSeverity(score);
    }
  }
  const dbSev = ((vulnData["database_specific"] as Record<string, unknown> | undefined)?.["severity"] as string | undefined) ?? "";
  if (dbSev) {
    const upper = dbSev.toUpperCase();
    if (upper === "CRITICAL" || upper === "HIGH" || upper === "MEDIUM" || upper === "LOW") {
      return upper;
    }
  }
  return "LOW";
}

function extractFixedVersion(vulnData: Record<string, unknown>, pkgName: string): string | null {
  const affected = (vulnData["affected"] as Array<Record<string, unknown>> | undefined) ?? [];
  for (const item of affected) {
    const pkg = item["package"] as Record<string, unknown> | undefined;
    if (pkg?.["name"]?.toString().toLowerCase() !== pkgName.toLowerCase()) continue;
    const ranges = (item["ranges"] as Array<Record<string, unknown>> | undefined) ?? [];
    for (const range of ranges) {
      const events = (range["events"] as Array<Record<string, unknown>> | undefined) ?? [];
      for (const event of events) {
        const fixed = event["fixed"] as string | undefined;
        if (fixed) return fixed;
      }
    }
  }
  return null;
}

function affectedSummary(vulnData: Record<string, unknown>): string {
  const parts: string[] = [];
  const affected = (vulnData["affected"] as Array<Record<string, unknown>> | undefined) ?? [];
  for (const item of affected) {
    const ranges = (item["ranges"] as Array<Record<string, unknown>> | undefined) ?? [];
    for (const range of ranges) {
      const events = (range["events"] as Array<Record<string, unknown>> | undefined) ?? [];
      let introduced: string | undefined;
      let fixed: string | undefined;
      for (const event of events) {
        if ("introduced" in event) introduced = event["introduced"] as string;
        if ("fixed" in event) fixed = event["fixed"] as string;
      }
      if (introduced ?? fixed) {
        parts.push(`>=${introduced ?? "0"}${fixed ? `, <${fixed}` : ""}`);
      }
    }
    if (parts.length >= 3) break;
  }
  return parts.slice(0, 3).join("; ");
}

// ----- OSVClient -----

export class OSVClient {
  private _error: string | null = null;

  get lastError(): string | null {
    return this._error;
  }

  /** Return `{ package_name: Vuln[] }` for all vulnerable packages.
   *
   * On network failure, sets `lastError` and returns `{}`.
   * Skips deps without a pinned version.
   */
  async queryBatch(
    deps: Dependency[],
    ecosystem = "npm",
  ): Promise<Record<string, Vuln[]>> {
    this._error = null;
    const versioned = deps.filter((d) => d.version !== null);
    if (versioned.length === 0) return {};

    const results: Record<string, Vuln[]> = {};
    for (let i = 0; i < versioned.length; i += BATCH_SIZE) {
      const batch = versioned.slice(i, i + BATCH_SIZE);
      const chunk = await this._queryChunk(batch, ecosystem);
      if (chunk === null) return {};
      for (const [k, v] of Object.entries(chunk)) {
        results[k] = v;
      }
    }
    return results;
  }

  private async _queryChunk(
    deps: Dependency[],
    ecosystem: string,
  ): Promise<Record<string, Vuln[]> | null> {
    const queries = deps.map((d) => ({
      package: { name: d.name, ecosystem },
      version: d.version,
    }));

    let body: Record<string, unknown>;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
      let response: Response;
      try {
        response = await fetch(OSV_BATCH_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries }),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }
      if (!response.ok) {
        this._error = `OSV.dev returned HTTP ${response.status}`;
        return null;
      }
      body = (await response.json()) as Record<string, unknown>;
    } catch (err: unknown) {
      this._error = err instanceof Error ? err.message : String(err);
      return null;
    }

    const out: Record<string, Vuln[]> = {};
    const responseResults = (body["results"] as Array<Record<string, unknown>> | undefined) ?? [];
    for (let i = 0; i < deps.length; i++) {
      const dep = deps[i]!;
      const result = responseResults[i] ?? {};
      const vulns: Vuln[] = [];
      for (const v of (result["vulns"] as Array<Record<string, unknown>> | undefined) ?? []) {
        vulns.push({
          id: (v["id"] as string | undefined) ?? "",
          summary: (v["summary"] as string | undefined) ?? "",
          severity: extractSeverity(v),
          aliases: (v["aliases"] as string[] | undefined) ?? [],
          affectedVersions: affectedSummary(v),
          fixedVersion: extractFixedVersion(v, dep.name),
        });
      }
      if (vulns.length > 0) {
        out[dep.name] = vulns;
      }
    }
    return out;
  }
}
