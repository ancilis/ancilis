# Contributing to Ancilis

Thanks for your interest in contributing.

## License

This project is licensed under Business Source License 1.1. By submitting a pull request, you agree that your contributions will be licensed under the same terms. See [LICENSE](LICENSE) for details.

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
