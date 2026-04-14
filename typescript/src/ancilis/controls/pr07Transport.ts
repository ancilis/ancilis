/** PR-07: Transport Security evaluator. */

import type { Action } from "../engine/action.js";
import type { ControlResult } from "../engine/result.js";
import type { ResolvedConfig } from "../config/index.js";
import type { ControlEvaluator } from "../engine/evaluators/base.js";

const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

const URL_KEYS = [
  "url", "endpoint", "baseUrl", "base_url", "server",
  "host", "api_url", "ws_url", "ws", "websocket_url",
] as const;

function isLocalhost(url: string): boolean {
  try {
    const parsed = new URL(url);
    return LOCALHOST_HOSTS.has(parsed.hostname);
  } catch {
    return false;
  }
}

function extractUrls(params: Record<string, unknown>): string[] {
  const urls: string[] = [];
  for (const key of URL_KEYS) {
    const val = params[key];
    if (typeof val === "string" && val) urls.push(val);
  }
  // Also walk nested objects one level deep
  for (const val of Object.values(params)) {
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      const nested = val as Record<string, unknown>;
      for (const key of URL_KEYS) {
        const nestedVal = nested[key];
        if (typeof nestedVal === "string" && nestedVal) urls.push(nestedVal);
      }
    }
  }
  return urls;
}

export class PR07TransportEvaluator implements ControlEvaluator {
  controlId = "PR-07";
  controlName = "Transport Security";

  evaluate(action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const urlsChecked: string[] = [];
    const insecureUrls: string[] = [];
    const localhostExempt: string[] = [];

    const rawParams = action.parameters.raw as Record<string, unknown>;
    const candidateUrls = extractUrls(rawParams);

    // Also check context server_url if present
    const ctx = action.context as Record<string, unknown> | undefined;
    const serverUrl = ctx?.["server_url"];
    if (typeof serverUrl === "string" && serverUrl) {
      candidateUrls.push(serverUrl);
    }

    for (const url of candidateUrls) {
      const lower = url.toLowerCase();
      if (lower.startsWith("http://") || lower.startsWith("ws://")) {
        if (isLocalhost(url)) {
          localhostExempt.push(url);
        } else {
          insecureUrls.push(url);
          urlsChecked.push(url);
        }
      } else {
        urlsChecked.push(url);
      }
    }

    const evidence: Record<string, unknown> = {
      urls_checked: urlsChecked,
      insecure_urls: insecureUrls,
      localhost_exempt: localhostExempt,
    };

    const durationMs = performance.now() - start;

    if (insecureUrls.length > 0) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: `Insecure transport detected: ${insecureUrls.length} URL(s) use http:// or ws://.`,
        evidenceData: evidence,
        durationMs,
      };
    }

    if (candidateUrls.length === 0) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: "No URLs found in action parameters — nothing to validate.",
        evidenceData: evidence,
        durationMs,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "PASS",
      detail: "All URLs use secure transport (https:// or wss://).",
      evidenceData: evidence,
      durationMs,
    };
  }
}
