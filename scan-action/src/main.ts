import * as core from "@actions/core";
import * as github from "@actions/github";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { parseInputs } from "./inputs.js";
import { installAncilis, runScan } from "./scanner.js";
import { applyThreshold } from "./threshold.js";
import { formatComment, postOrUpdateComment } from "./comment.js";
import { createAnnotations } from "./annotations.js";
import { convertToSarif } from "./sarif.js";

async function run(): Promise<void> {
  try {
    const inputs = parseInputs();

    // Install ancilis Python SDK
    await installAncilis(inputs.ancilisVersion);

    // Run scan
    core.info("Running ancilis scan...");
    const scan = await runScan({
      overlays: inputs.overlays,
      ancilisVersion: inputs.ancilisVersion,
    });

    // Set outputs
    core.setOutput("posture", scan.posture);
    core.setOutput("exit-code", String(scan.exit_code));
    core.setOutput("controls-passing", String(scan.summary.passing));
    core.setOutput("controls-failing", String(scan.summary.failing));
    core.setOutput("scan-json", JSON.stringify(scan));

    // Annotations
    createAnnotations(scan);

    // PR comment (only on pull_request events)
    if (inputs.reportFormat !== "off" && github.context.payload.pull_request) {
      const token = process.env.GITHUB_TOKEN;
      if (token) {
        await postOrUpdateComment(scan, token);
      } else {
        core.warning("GITHUB_TOKEN not set — skipping PR comment.");
      }
    }

    // SARIF output
    if (inputs.uploadSarif) {
      const sarif = convertToSarif(scan);
      const sarifPath = join(tmpdir(), `ancilis-scan-${Date.now()}.sarif`);
      writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), "utf-8");
      core.setOutput("sarif-path", sarifPath);
      core.info(`SARIF written to ${sarifPath}`);
    }

    // Apply threshold and set exit code
    const threshold = applyThreshold(scan, inputs.failOn);
    core.info(`Threshold check (fail-on: ${inputs.failOn}): ${threshold.reason}`);

    if (threshold.shouldFail) {
      core.setFailed(`Ancilis scan failed: ${threshold.reason}`);
    } else {
      core.info(`Ancilis scan complete — posture: ${scan.posture}`);
    }
  } catch (error: unknown) {
    core.setFailed((error as Error).message ?? String(error));
  }
}

run();
