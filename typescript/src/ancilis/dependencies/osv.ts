/** OSV.dev batch vulnerability lookup for npm packages. */

import type { Dependency, VulnerabilityFinding } from "./types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const TIMEOUT_MS = 10_000;
const MAX_RETRIES = 2;
const BATCH_SIZE = 1000;

type OsvSeverity = "critical" | "high" | "medium" | "low";

function cvssToSeverity(score: number): OsvSeverity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function extractSeverityAndScore(
  vuln: Record<string, unknown>
): { severity: OsvSeverity; cvssScore: number | null } {
  const severities = (vuln["severity"] as Array<Record<string, unknown>>) ?? [];

  for (const sev of severities) {
    const type = sev["type"] as string | undefined;
    const scoreRaw = sev["score"] as string | number | undefined;
    if ((type === "CVSS_V3" || type === "CVSS_V2") && scoreRaw != null) {
      const score = typeof scoreRaw === "number" ? scoreRaw : parseFloat(String(scoreRaw));
      if (!isNaN(score)) {
        return { severity: cvssToSeverity(score), cvssScore: score };
      }
    }
  }

  // Fall back to database_specific severity string
  const dbSev = (
    (vuln["database_specific"] as Record<string, unknown> | undefined)?.[
      "severity"
    ] as string | undefined
  )?.toLowerCase() as OsvSeverity | undefined;

  if (dbSev && ["critical", "high", "medium", "low"].includes(dbSev)) {
    return { severity: dbSev, cvssScore: null };
  }

  return { severity: "low", cvssScore: null };
}

function extractFixedVersion(
  vuln: Record<string, unknown>,
  pkgName: string
): string | null {
  const affected = (vuln["affected"] as Array<Record<string, unknown>>) ?? [];
  for (const aff of affected) {
    const pkg = aff["package"] as Record<string, unknown> | undefined;
    if (pkg?.["name"] !== pkgName) continue;
    const ranges = (aff["ranges"] as Array<Record<string, unknown>>) ?? [];
    for (const range of ranges) {
      const events = (range["events"] as Array<Record<string, string>>) ?? [];
      for (const event of events) {
        if (event["fixed"]) return event["fixed"];
      }
    }
  }
  return null;
}

function primaryCveId(vuln: Record<string, unknown>): string {
  const id = (vuln["id"] as string) ?? "";
  const aliases = (vuln["aliases"] as string[]) ?? [];
  // Prefer CVE identifiers
  const cve = [id, ...aliases].find((a) => a.startsWith("CVE-"));
  return cve ?? id;
}

interface OsvResponse {
  results: Array<{ vulns?: Array<Record<string, unknown>> }>;
}

async function fetchWithRetry(
  body: string,
  retriesLeft: number
): Promise<OsvResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    return (await res.json()) as OsvResponse;
  } catch (err) {
    if (retriesLeft > 0) {
      return fetchWithRetry(body, retriesLeft - 1);
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function queryChunk(
  deps: Dependency[]
): Promise<{ findings: VulnerabilityFinding[]; error: string | null }> {
  const queries = deps.map((dep) => ({
    package: { name: dep.name, ecosystem: "npm" },
    version: dep.version,
  }));

  const body = JSON.stringify({ queries });
  const response = await fetchWithRetry(body, MAX_RETRIES);

  if (!response) {
    return {
      findings: [],
      error: `OSV.dev unreachable after ${MAX_RETRIES + 1} attempts`,
    };
  }

  const findings: VulnerabilityFinding[] = [];
  const results = response.results ?? [];

  for (let i = 0; i < deps.length; i++) {
    const dep = deps[i]!;
    const vulns = results[i]?.vulns ?? [];

    for (const vuln of vulns) {
      const { severity, cvssScore } = extractSeverityAndScore(vuln);
      findings.push({
        cveId: primaryCveId(vuln),
        packageName: dep.name,
        installedVersion: dep.version,
        severity,
        cvssScore,
        fixedVersion: extractFixedVersion(vuln, dep.name),
        summary: (vuln["summary"] as string) ?? "",
      });
    }
  }

  return { findings, error: null };
}

export async function queryOsvBatch(
  dependencies: Dependency[]
): Promise<{ findings: VulnerabilityFinding[]; error: string | null }> {
  if (dependencies.length === 0) {
    return { findings: [], error: null };
  }

  const allFindings: VulnerabilityFinding[] = [];

  for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
    const chunk = dependencies.slice(i, i + BATCH_SIZE);
    const { findings, error } = await queryChunk(chunk);
    if (error) {
      console.warn(`[ancilis] OSV.dev lookup warning: ${error}`);
      return { findings: [], error };
    }
    allFindings.push(...findings);
  }

  return { findings: allFindings, error: null };
}
