/** Report generation module exports. */

export { ReportGenerator, parsePeriod } from "./generator.js";
export type { ReportData, EvidenceSummary } from "./generator.js";
export { renderTerminal, renderMarkdown, renderPdf } from "./renderer.js";
export type { RenderPdfOptions, RenderPdfResult } from "./renderer.js";
