#!/usr/bin/env bash
# Apply branch protection to main as configuration-as-code.
# Idempotent: re-running with the same repo state produces the same protection.
#
# Usage:
#   ./scripts/apply-branch-protection.sh ancilis/ancilis
#   ./scripts/apply-branch-protection.sh ancilis/ancilis-one-shot
#
# Required-status-checks contexts are auto-detected from the union of
# check names seen on the last 5 PRs (any state). This means: after
# adding a new CI workflow (e.g. D3 security-scan), open at least one
# PR for it to run, then re-run this script so the new check is added
# to the required set.

set -euo pipefail

REPO="${1:?usage: $0 <owner/repo>}"

echo "[apply-branch-protection] target: $REPO"

# Auto-detect required check contexts from the union across last 5 PRs.
# `select(.)` filters out null/empty rollups (e.g. drafts with no runs).
checks=$(gh pr list --repo "$REPO" --state all --limit 5 \
  --json statusCheckRollup \
  --jq '[.[].statusCheckRollup[]?.name] | unique | .[]' \
  | sort -u)

if [ -z "$checks" ]; then
  echo "WARN: no recent PRs with check rollups found; required_status_checks.contexts will be []"
fi

contexts_json=$(echo "$checks" | jq -Rs 'split("\n") | map(select(length > 0))')

echo "[apply-branch-protection] required check contexts:"
echo "$contexts_json" | jq '.[]' | sed 's/^/  /'

cat > /tmp/branch-protection-${REPO//\//_}.json <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": $contexts_json
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": false,
  "block_creations": false
}
EOF

gh api -X PUT "repos/${REPO}/branches/main/protection" \
  -H "Accept: application/vnd.github+json" \
  --input /tmp/branch-protection-${REPO//\//_}.json \
  > /dev/null

echo "[apply-branch-protection] applied. Verifying..."
gh api "repos/${REPO}/branches/main/protection" --jq '{
  strict: .required_status_checks.strict,
  contexts_count: (.required_status_checks.contexts | length),
  enforce_admins: .enforce_admins.enabled,
  approvals: .required_pull_request_reviews.required_approving_review_count,
  linear: .required_linear_history.enabled,
  no_force: (.allow_force_pushes.enabled | not),
  no_delete: (.allow_deletions.enabled | not),
  convo_resolution: .required_conversation_resolution.enabled
}'
