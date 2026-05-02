/** `ancilis remediate` command. */

import { loadConfig } from "../config/index.js";
import { EvidenceStore } from "../evidence/store.js";
import { parsePeriod } from "../report/generator.js";
import {
  buildRemediationRecommendations,
  renderRemediationRecommendations,
} from "../remediation/index.js";

export interface RemediateCommandOptions {
  configPath?: string;
  dbPath?: string;
  period?: string;
  sessionId?: string;
  latest?: boolean;
  controlId?: string;
}

export interface RemediateCommandResult {
  ok: boolean;
  output: string;
}

export async function runRemediate(options: RemediateCommandOptions = {}): Promise<RemediateCommandResult> {
  try {
    const config = loadConfig(options.configPath ? { path: options.configPath } : {});
    const store = new EvidenceStore(config, options.dbPath ? { dbPath: options.dbPath } : undefined);
    try {
      let sessionId = options.sessionId;
      if (sessionId === undefined && options.latest !== false) {
        const latestId = await store.latestSessionId();
        sessionId = latestId ?? undefined;
      }
      const period = options.period ?? "30d";
      const since = new Date(Date.now() - parsePeriod(period)).toISOString();
      const summary = await store.getSummary({ since, sessionId });
      const recommendations = buildRemediationRecommendations(config, summary, {
        controlId: options.controlId,
      });
      return {
        ok: true,
        output: renderRemediationRecommendations(recommendations, {
          controlId: options.controlId,
        }),
      };
    } finally {
      await store.close();
    }
  } catch (error: unknown) {
    return { ok: false, output: `Error: ${(error as Error).message ?? String(error)}` };
  }
}
