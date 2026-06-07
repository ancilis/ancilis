import * as github from "@actions/github";
import * as core from "@actions/core";
import type { ScanResult, ControlResult } from "./scanner.js";

const COMMENT_MARKER = "<!-- ancilis-scan -->";

function statusEmoji(status: ControlResult["status"]): string {
  if (status === "pass") return "✅";
  if (status === "fail") return "❌";
  return "⏭️";
}

function postureEmoji(posture: string): string {
  return posture === "compliant" ? "✅" : "❌";
}

function postureLabel(posture: string): string {
  return posture === "compliant" ? "Compliant" : "Non-Compliant";
}

export function formatComment(scan: ScanResult): string {
  const emoji = postureEmoji(scan.posture);
  const label = postureLabel(scan.posture);

  const rows = scan.controls
    .map((c) => {
      const flagNote = c.flags > 0 ? ` (${c.flags} flags)` : "";
      return `| ${c.id} | ${c.name} | ${statusEmoji(c.status)} ${c.status} | ${c.evaluations} | ${c.failures}${flagNote} |`;
    })
    .join("\n");

  const tableSection =
    scan.controls.length > 0
      ? `| Control | Name | Status | Evaluations | Failures |\n|---------|------|--------|-------------|----------|\n${rows}`
      : "_No controls configured._";

  const { passing, failing, skipped, total_evaluations } = scan.summary;
  const summaryLine = `**Summary:** ${passing}/${scan.summary.total_controls} controls passing · ${total_evaluations} evaluations · Mode: ${scan.mode}${skipped > 0 ? ` · ${skipped} skipped` : ""}`;

  return [
    "## Ancilis Security Scan",
    "",
    `**Posture: ${emoji} ${label}**`,
    "",
    tableSection,
    "",
    summaryLine,
    "",
    "<details>",
    "<summary>What is this?</summary>",
    "",
    "Ancilis scans AI agent tool calls for security control compliance.",
    "[Learn more](https://ancilis.ai) · [Configure](https://docs.ancilis.ai/github-action)",
    "",
    "</details>",
    "",
    COMMENT_MARKER,
  ].join("\n");
}

export async function postOrUpdateComment(
  scan: ScanResult,
  token: string
): Promise<void> {
  const context = github.context;
  const { pull_request } = context.payload;

  if (!pull_request) {
    core.info("Not a pull request event — skipping PR comment.");
    return;
  }

  const octokit = github.getOctokit(token);
  const { owner, repo } = context.repo;
  const prNumber = pull_request.number as number;

  const commentBody = formatComment(scan);

  // Find existing ancilis comment
  let existingCommentId: number | undefined;
  for await (const response of octokit.paginate.iterator(
    octokit.rest.issues.listComments,
    { owner, repo, issue_number: prNumber, per_page: 100 }
  )) {
    for (const comment of response.data) {
      if (comment.body?.includes(COMMENT_MARKER)) {
        existingCommentId = comment.id;
        break;
      }
    }
    if (existingCommentId !== undefined) break;
  }

  if (existingCommentId !== undefined) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existingCommentId,
      body: commentBody,
    });
    core.info(`Updated existing PR comment (id: ${existingCommentId})`);
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body: commentBody,
    });
    core.info("Posted new PR comment");
  }
}
