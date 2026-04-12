import * as core from "@actions/core";

export type FailOn = "critical" | "high" | "medium" | "low" | "none";
export type ReportFormat = "markdown" | "minimal" | "off";

export interface ActionInputs {
  overlays: string[];
  failOn: FailOn;
  reportFormat: ReportFormat;
  uploadSarif: boolean;
  uploadEvidence: boolean;
  platformUrl: string;
  platformToken: string;
  pythonVersion: string;
  ancilisVersion: string;
}

const VALID_FAIL_ON: FailOn[] = ["critical", "high", "medium", "low", "none"];
const VALID_REPORT_FORMATS: ReportFormat[] = ["markdown", "minimal", "off"];

export function parseInputs(): ActionInputs {
  const failOnRaw = core.getInput("fail-on") || "none";
  if (!(VALID_FAIL_ON as string[]).includes(failOnRaw)) {
    throw new Error(
      `Invalid fail-on value: "${failOnRaw}". Must be one of: ${VALID_FAIL_ON.join(", ")}`
    );
  }

  const reportFormatRaw = core.getInput("report-format") || "markdown";
  if (!(VALID_REPORT_FORMATS as string[]).includes(reportFormatRaw)) {
    throw new Error(
      `Invalid report-format value: "${reportFormatRaw}". Must be one of: ${VALID_REPORT_FORMATS.join(", ")}`
    );
  }

  const overlaysRaw = core.getInput("overlays");
  const overlays = overlaysRaw
    ? overlaysRaw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  return {
    overlays,
    failOn: failOnRaw as FailOn,
    reportFormat: reportFormatRaw as ReportFormat,
    uploadSarif: core.getBooleanInput("upload-sarif"),
    uploadEvidence: core.getBooleanInput("upload-evidence"),
    platformUrl: core.getInput("platform-url"),
    platformToken: core.getInput("platform-token"),
    pythonVersion: core.getInput("python-version") || "3.11",
    ancilisVersion: core.getInput("ancilis-version") || "ancilis",
  };
}
