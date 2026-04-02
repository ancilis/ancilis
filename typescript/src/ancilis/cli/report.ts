/** ancilis report — posture report generation. */

import { writeFileSync } from "node:fs";
import { loadConfig } from "../config/index.js";
import { EvidenceStore } from "../evidence/store.js";
import { ReportGenerator, parsePeriod, renderTerminal, renderMarkdown, renderPdf } from "../report/index.js";

export interface ReportCommandOptions {
  period?: string;
  format?: "terminal" | "markdown" | "pdf" | "aiuc1-readiness";
  configPath?: string;
  dbPath?: string;
  outputPath?: string;
}

export interface ReportCommandResult {
  ok: boolean;
  output: string;
  outputPath?: string;
}

export async function runReport(options: ReportCommandOptions = {}): Promise<ReportCommandResult> {
  const period = options.period ?? "30d";
  const format = options.format ?? "terminal";

  try {
    const config = loadConfig(options.configPath ? { path: options.configPath } : {});
    const store = new EvidenceStore(config, options.dbPath ? { dbPath: options.dbPath } : undefined);

    try {
      const now = new Date();
      const since = new Date(now.getTime() - parsePeriod(period)).toISOString();
      const summary = await store.getSummary({ since });
      const generator = new ReportGenerator(config, summary);
      const reportData = generator.generate(period, format, { now });

      if (format === "terminal") {
        return { ok: true, output: renderTerminal(reportData) };
      }

      const markdown = renderMarkdown(reportData);
      if (format === "markdown" || format === "aiuc1-readiness") {
        if (options.outputPath) {
          writeFileSync(options.outputPath, markdown);
          return { ok: true, output: `Report written to ${options.outputPath}`, outputPath: options.outputPath };
        }
        return { ok: true, output: markdown };
      }

      const pdfPath = options.outputPath ?? "ancilis-report.pdf";
      const pdfResult = renderPdf(markdown, pdfPath);
      if (pdfResult.format === "pdf") {
        return { ok: true, output: `PDF report written to ${pdfResult.outputPath}`, outputPath: pdfResult.outputPath };
      }
      return {
        ok: true,
        output: `PDF export unavailable (${pdfResult.fallbackReason}); wrote Markdown fallback to ${pdfResult.outputPath}`,
        outputPath: pdfResult.outputPath,
      };
    } finally {
      await store.close();
    }
  } catch (err: unknown) {
    return {
      ok: false,
      output: `Error: ${(err as Error).message ?? String(err)}`,
    };
  }
}
