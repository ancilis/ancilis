# ancilis/posture-gate-action

A composite GitHub Action that runs `ancilis scan` on pull requests, posts a posture summary comment, and blocks merge when the posture score falls below a configurable threshold.

**Type:** Composite (pure Python, no Docker, no Node.js)
**Dependency:** `ancilis>=0.1.0` (stdlib only for GitHub API calls)

---

## Quick start

```yaml
name: Posture Gate
on: [pull_request]

jobs:
  posture:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write   # needed to post comments
    steps:
      - uses: actions/checkout@v4
      - uses: ancilis/posture-gate-action@v1
        with:
          overlay: financial
          threshold: 70
```

The check status is controlled by the exit code — when the score is below the threshold the step fails, which blocks merge when the check is required.

---

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `overlay` | No | `financial` | Compliance overlay name (e.g. `financial`, `fedramp`, `hipaa`, `gdpr`) |
| `threshold` | No | `70` | Minimum posture score (0–100) required to pass |
| `api-key` | No | — | `ANCILIS_API_KEY` for authenticated scans |
| `fail-on-error` | No | `true` | Fail the check if `ancilis scan` encounters an error |
| `post-comment` | No | `true` | Post a posture summary comment on the PR |

---

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Posture score (0–100) |
| `passed` | `true` when score ≥ threshold, `false` otherwise |
| `summary` | One-line posture summary string |

---

## Examples

### Authenticated scans

Store your API key as a repository secret and pass it in:

```yaml
- uses: ancilis/posture-gate-action@v1
  with:
    overlay: financial
    threshold: 80
    api-key: ${{ secrets.ANCILIS_API_KEY }}
```

### Custom threshold per overlay

```yaml
- uses: ancilis/posture-gate-action@v1
  with:
    overlay: fedramp
    threshold: 90
```

### Use outputs in downstream steps

```yaml
- uses: ancilis/posture-gate-action@v1
  id: posture
  with:
    overlay: financial
    threshold: 70

- name: Print score
  run: echo "Score is ${{ steps.posture.outputs.score }}"
```

### Warn but never block

Set `fail-on-error: false` and `threshold: 0` to always pass while still getting the PR comment:

```yaml
- uses: ancilis/posture-gate-action@v1
  with:
    overlay: financial
    threshold: 0
    fail-on-error: false
```

### Skip PR comment in push workflows

```yaml
- uses: ancilis/posture-gate-action@v1
  with:
    overlay: financial
    threshold: 70
    post-comment: false
```

---

## How merge blocking works

The action exits with code `1` when `score < threshold`. When you configure the check as a required status check in your branch protection rules, GitHub prevents merge until the check passes. No additional configuration is needed beyond marking the job as required.

---

## PR comment

When running in a pull request context the action posts (or updates) a comment that includes:

- Posture score and threshold
- Pass / Fail status
- Per-control results table
- Link back to Ancilis

The comment is idempotent — subsequent runs update the same comment rather than posting a new one, using the `<!-- ancilis-posture-gate -->` HTML marker as the lookup key.

---

## Integration smoke test (manual)

1. Create a test repository and add this action to a workflow.
2. Open a pull request.
3. Verify the posture comment appears on the PR.
4. Lower the threshold below the current score — verify the check passes.
5. Raise the threshold above the score — verify the check fails and merge is blocked (when the check is required).
