# ancilis/scan-action

GitHub Action for AI agent security posture scanning. Wraps `ancilis scan --ci` to provide one-line CI integration for PR security checks.

## Usage

```yaml
- uses: ancilis/scan-action@v1
  with:
    fail-on: high
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `overlays` | Comma-separated overlay profiles (e.g. `financial,soc2`) | auto-detect |
| `fail-on` | Minimum severity to fail: `critical`, `high`, `medium`, `low`, `none` | `none` |
| `report-format` | PR comment format: `markdown`, `minimal`, `off` | `markdown` |
| `upload-sarif` | Write SARIF to temp file and set `sarif-path` output | `false` |
| `upload-evidence` | Upload evidence to Ancilis platform | `false` |
| `platform-url` | Ancilis platform API endpoint | — |
| `platform-token` | Ancilis platform API token | — |
| `python-version` | Python version for ancilis installation | `3.11` |
| `ancilis-version` | Ancilis SDK version to install | `ancilis` (latest) |

## Outputs

| Output | Description |
|--------|-------------|
| `posture` | `compliant` or `non_compliant` |
| `exit-code` | `0` (pass) or `1` (fail based on `fail-on`) |
| `controls-passing` | Number of passing controls |
| `controls-failing` | Number of failing controls |
| `scan-json` | Raw scan JSON from `ancilis scan --ci` |
| `sarif-path` | Path to SARIF file (when `upload-sarif: true`) |

## Examples

### Basic PR check (audit only)

```yaml
name: Ancilis Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: ancilis/scan-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Enforce on high severity

```yaml
- uses: ancilis/scan-action@v1
  with:
    fail-on: high
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Upload SARIF to GitHub Code Scanning

```yaml
- uses: ancilis/scan-action@v1
  id: ancilis
  with:
    upload-sarif: true
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.ancilis.outputs.sarif-path }}
```

### With compliance overlays

```yaml
- uses: ancilis/scan-action@v1
  with:
    overlays: financial,soc2
    fail-on: medium
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## `fail-on` Severity Levels

| Level | Fails when |
|-------|-----------|
| `none` | Never (default — audit only) |
| `low` | Any control is not passing (includes skip) |
| `medium` | Any control fails or has flagged evaluations |
| `high` | Any control fails |
| `critical` | BLOCK decisions present (enforce mode) |

## PR Comment

The action posts a comment on the PR with posture badge and per-control status table. Subsequent runs update the same comment in-place using an HTML marker.

## SARIF Upload

Set `upload-sarif: true` to generate a SARIF 2.1.0 file. Wire the `sarif-path` output to `github/codeql-action/upload-sarif` to see results in the Security tab.

## License

Apache-2.0
