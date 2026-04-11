/** OSV.dev batch vulnerability lookup client. */

import type { Dependency, Vuln } from "./types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const TIMEOUT_MS = 10_000;
const BATCH_SIZE = 1000;

// ---------------------------------------------------------------------------
// CVSS → severity
// ---------------------------------------------------------------------------

export function cvssToSeverity(score: number): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

function extractSeverity(vulnData: Record<string, unknown>): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  const severityList = (vulnData.severity as Array<Record<string, string>> | undefined) ?? [];
  for (const sev of severityList) {
    const scoreType = sev.type ?? "";
    const scoreStr = sev.score ?? "";
    if ((scoreType === "CVSS_V3" || scoreType === "CVSS_V2") && scoreStr) {
      const score = parseFloat(scoreStr);
      if (!isNaN(score)) return cvssToSeverity(score);
    }
  }
  const dbSev = ((vulnData.database_specific as Record<string, string> | undefined)?.severity ?? "").toUpperCase();
  if (dbSev === "CRITICAL" || dbSev === "HIGH" || dbSev === "MEDIUM" || dbSev === "LOW") {
    return dbSev;
  }
  return "LOW";
}

function extractFixedVersion(vulnData: Record<string, unknown>, pkgName: string): string | null {
  const affected = (vulnData.affected as Array<Record<string, unknown>> | undefined) ?? [];
  for (const aff of affected) {
    const pkg = aff.package as Record<string, string> | undefined;
    if (pkg?.name?.toLowerCase() !== pkgName.toLowerCase()) continue;
    const ranges = (aff.ranges as Array<Record<string, unknown>> | undefined) ?? [];
    for (const rng of ranges) {
      const events = (rng.events as Array<Record<string, string>> | undefined) ?? [];
      for (const event of events) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function affectedSummary(vulnData: Record<string, unknown>): string {
  const parts: string[] = [];
  const affected = (vulnData.affected as Array<Record<string, unknown>> | undefined) ?? [];
  for (const aff of affected) {
    const ranges = (aff.ranges as Array<Record<string, unknown>> | undefined) ?? [];
    for (const rng of ranges) {
      const events = (rng.events as Array<Record<string, string>> | undefined) ?? [];
      let introduced: string | null = null;
      let fixed: string | null = null;
      for (const event of events) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed !== undefined) fixed = event.fixed;
      }
      if (introduced !== null || fixed !== null) {
        parts.push(`>=${introduced ?? "0"}${fixed ? ", <" + fixed : ""}`);
      }
    }
    if (parts.length >= 3) break;
  }
  return parts.slice(0, 3).join("; ");
}

// ---------------------------------------------------------------------------
// OSVClient
// ---------------------------------------------------------------------------

export class OSVClient {
  private _lastError: string | null = null;

  get lastError(): string | null {
    return this._lastError;
  }

  async queryBatch(deps: Dependency[], ecosystem = "npm"): Promise<Record<string, Vuln[]>> {
    this._lastError = null;

    const versioned = deps.filter(d => d.version !== null);
    if (versioned.length === 0) return {};

    const results: Record<string, Vuln[]> = {};
    for (let i = 0; i < versioned.length; i += BATCH_SIZE) {
      const batch = versioned.slice(i, i + BATCH_SIZE);
      const chunk = await this._queryChunk(batch, ecosystem);
      if (chunk === null) return {};
      Object.assign(results, chunk);
    }
    return results;
  }

  private async _queryChunk(
    deps: Dependency[],
    ecosystem: string,
  ): Promise<Record<string, Vuln[]> | null> {
    const queries = deps.map(d => ({
      package: { name: d.name, ecosystem },
      version: d.version,
    }));

    let body: { results: Array<{ vulns?: Array<Record<string, unknown>> }> };
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
      let resp: Response;
      try {
        resp = await fetch(OSV_BATCH_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries }),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }
      const text = await resp.text();
      body = JSON.parse(text) as typeof body;
    } catch (err: unknown) {
      this._lastError = err instanceof Error ? err.message : String(err);
      return null;
    }

    const out: Record<string, Vuln[]> = {};
    const resultList = body.results ?? [];
    for (let i = 0; i < deps.length; i++) {
      const dep = deps[i]!;
      const entry = resultList[i] ?? {};
      const vulnList = entry.vulns ?? [];
      const vulns: Vuln[] = vulnList.map(v => ({
        id: (v.id as string | undefined) ?? "",
        summary: (v.summary as string | undefined) ?? "",
        severity: extractSeverity(v),
        aliases: (v.aliases as string[] | undefined) ?? [],
        affectedVersions: affectedSummary(v),
        fixedVersion: extractFixedVersion(v, dep.name),
      }));
      if (vulns.length > 0) {
        out[dep.name] = vulns;
      }
    }
    return out;
  }
}
