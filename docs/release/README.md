# Release Process

This repository is intentionally Python-first for public release readiness. The TypeScript package remains preview and should only be published after its preview posture is re-reviewed.

## Versioning guidance

- Stay conservative in `0.x`.
- Use `0.1.0`-style releases for public cuts.
- Treat minor bumps as the right place for behavior changes or schema changes.
- Treat patch bumps as regressions, packaging fixes, workflow fixes, or security hardening.

## Maintainer checklist

1. Run `python -m pytest python/tests -v`.
2. Run `npm test`.
3. Run `python scripts/release_check.py`.
4. Review `CHANGELOG.md` and update the release entry.
5. Confirm the TypeScript package description still says preview unless its readiness has materially changed.
6. Tag the release as `vX.Y.Z`.
7. Let the GitHub `Release` workflow verify and publish the Python package.
8. Do not publish npm from the standard release path unless preview posture has been re-approved.

## Publish steps

### Python

1. Create and push a signed tag such as `v0.1.0`.
2. Verify the `Release` workflow passes.
3. Confirm the PyPI publish job used Trusted Publishing successfully.
4. Create the GitHub release notes from the changelog entry.

### TypeScript preview

- Run `npm run pack:smoke` manually.
- Keep preview wording intact.
- Only add an npm publish workflow after the preview audit says the package is honestly publishable.
