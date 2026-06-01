# Contributing to Ancilis

Thanks for your interest in contributing.

## License and Contributor Grant

This project is dual-licensed: GNU Affero General Public License v3.0 or
later (AGPL-3.0-or-later) for open source use, and a separate commercial
license available from the Licensor. See [LICENSE](LICENSE) for details.

By submitting a contribution to this project (a pull request, patch, or
any other form of contribution), you agree that:

1. **AGPL grant.** You license your contribution to the public under the
   AGPL-3.0-or-later, the same terms as the rest of the project.

2. **Commercial relicensing grant.** You also grant Kevin Bauer (and any
   successor maintainer or acquirer of this project) a perpetual,
   irrevocable, worldwide, royalty-free, non-exclusive license to relicense
   your contribution under any other license, including proprietary or
   commercial licenses, for the purpose of offering commercial license
   options to users who do not wish to be bound by the AGPL.

3. **Originality.** You represent that you have the right to make these
   grants — i.e., the contribution is your original work, or you have
   authorization from the copyright holder to contribute it under these
   terms.

This grant is the equivalent of a Contributor License Agreement (CLA) for
inbound contributions and exists solely to keep the dual-license model
viable. If you cannot make these grants for any reason, do not submit the
contribution.

## Getting Started

1. Fork and clone the repo
2. Install dependencies:
   ```bash
   pip install -e ".[dev]"
   npm install
   ```
3. Create a branch for your work
4. Make your changes
5. Run tests before submitting:
   ```bash
   pytest
   npm test
   ```
6. Open a pull request against `main`

## Pull Request Scope

Open one issue per pull request. Each PR targeting `main` should map to a
single tracked issue, and the issue id must appear in either the PR title or
the head branch name using the `ANC-####` format (for example, `ANC-1234`).
PRs fail CI when both fields omit the issue id. The only exception is a real
Dependabot PR authored by `dependabot[bot]` on a `dependabot/...` branch; do
not rely on a `dependabot/...` branch name alone to bypass the rule.

## Code Style

Python: We use `ruff` for linting and formatting, `mypy` for type checking.
TypeScript: We use `eslint` and strict TypeScript compiler options.

## Reporting Issues

Open a GitHub issue. Include steps to reproduce, expected behavior, and actual behavior.

## Release Process

### npm Environment & Secrets (Maintainers Only)

Publishing to npm requires a GitHub environment named `npm` with a configured `NPM_TOKEN` secret. This must be set up by a repo admin:

1. Create an npm **Granular Access Token** at https://www.npmjs.com/settings/tokens
   - Packages: `ancilis` only
   - Permissions: **Read and write**
2. In GitHub → Settings → Environments → Create environment `npm`
   - Add deployment protection rule: **Required reviewers**
   - Add secret `NPM_TOKEN` with the token from step 1
3. The `id-token: write` permission in the workflow provides npm provenance (OIDC) — no additional secret needed for that.

The release workflow is artifact-bound: the verify job packs the tarball and uploads it as a GitHub Actions artifact, and the publish job downloads and publishes that exact tarball. Do not manually rebuild before publishing.

Both SDKs (`package.json` and `pyproject.toml`) must share the same version string. The release workflow enforces this and will fail if they diverge.
