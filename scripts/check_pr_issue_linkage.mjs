const ISSUE_ID_PATTERN = /\bANC-\d+\b/i;

function hasIssueId(value) {
  return ISSUE_ID_PATTERN.test(value ?? "");
}

function validatePullRequestIssueLinkage(title, headRef) {
  if (hasIssueId(title) || hasIssueId(headRef)) {
    return;
  }

  throw new Error(
    `Pull requests to main must include an ANC issue id (for example, ANC-1234) in either the PR title or the head branch. Received title="${title}" branch="${headRef}".`,
  );
}

const title = process.env.PR_TITLE ?? "";
const headRef = process.env.PR_HEAD_REF ?? "";

try {
  validatePullRequestIssueLinkage(title, headRef);
  console.log(`ANC issue linkage OK: title="${title}" branch="${headRef}"`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
