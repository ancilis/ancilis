const ISSUE_ID_PATTERN = /\bANC-\d+\b/i;

function hasIssueId(value) {
  return ISSUE_ID_PATTERN.test(value ?? "");
}

function isDependabotPullRequest(authorLogin, headRef) {
  return authorLogin === "dependabot[bot]" && headRef.startsWith("dependabot/");
}

function validatePullRequestIssueLinkage(title, headRef, authorLogin) {
  if (hasIssueId(title) || hasIssueId(headRef)) {
    return;
  }

  if (isDependabotPullRequest(authorLogin, headRef)) {
    return;
  }

  throw new Error(
    `Pull requests to main must include an ANC issue id (for example, ANC-1234) in either the PR title or the head branch. Received title="${title}" branch="${headRef}".`,
  );
}

const title = process.env.PR_TITLE ?? "";
const headRef = process.env.PR_HEAD_REF ?? "";
const authorLogin = process.env.PR_AUTHOR_LOGIN ?? "";

try {
  validatePullRequestIssueLinkage(title, headRef, authorLogin);
  console.log(`ANC issue linkage OK: title="${title}" branch="${headRef}"`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
