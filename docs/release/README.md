# Release Process

This repository is intentionally Python-first for public release readiness. The TypeScript package remains preview and should only be published after its preview posture is re-reviewed.

## Versioning guidance

- Stay conservative in `0.x`.
- Use `0.1.0`-style releases for public cuts.
- Treat minor bumps as the right place for behavior changes or schema changes.
- Treat patch bumps as regressions, packaging fixes, workflow fixes, or security hardening.

## Maintainer checklist

1. Run `python -m pytest python/tests -v`.
2. Run `npm ci --include=dev`.
3. Run `npm run security:audit:npm`.
4. Run `cd scan-action && npm ci --include=dev`.
5. Run `cd scan-action && npm run security:audit`.
6. Run `python -m pip install pip-audit`.
7. Run `npm run security:audit:python-lock`.
8. Run `npm test`.
9. Run `python scripts/release_check.py`.
10. Review `CHANGELOG.md` and update the release entry.
11. Confirm the TypeScript package description still says preview unless its readiness has materially changed.
12. Tag the release as `vX.Y.Z`.
13. Let the GitHub `Release` workflow verify and publish the Python package.
14. Do not publish npm from the standard release path unless preview posture has been re-approved.

## Dependency-security gates

Release verification fails closed on dependency advisories. These checks use the current npm and Python advisory sources at run time, so a new upstream advisory can fail a previously green release candidate. Treat that as a release blocker until the advisory is triaged, fixed, or explicitly accepted by the CTO.

- Root TypeScript SDK: `npm ci --include=dev`, then `npm run security:audit:npm`. The threshold is `high` and includes development dependencies because SDK build/test tooling is part of the release decision.
- GitHub scan action: `cd scan-action && npm ci --include=dev`, then `cd scan-action && npm run security:audit`. The threshold is `moderate` so the `undici` class of action-runtime findings is caught.
- Python lockfile: after `python -m pip install pip-audit`, run `npm run security:audit:python-lock`. This audits `requirements-lock.txt` and keeps the existing `CVE-2026-4539` ignore visible in one command.

The [ANC-1028](/ANC/issues/ANC-1028) direct-main emergency merge path is exception handling only. It does not replace normal release practice, and the next release candidate must rerun the full dependency-security checklist before publishing.

## Publish steps

### Python

1. Create and push a signed tag such as `v0.1.0`.
2. Verify the `Release` workflow passes.
3. Confirm the PyPI publish job used Trusted Publishing successfully.
4. Create the GitHub release notes from the changelog entry.

### TypeScript preview

- Run `npm run pack:smoke` manually.
- Use the `TypeScript SDK Release` workflow for npm publication when preview posture is approved.
- Preserve the artifact-bound path: the workflow builds one tarball, verifies that exact tarball, downloads it in the publish job, verifies the checksum again, then publishes the downloaded `.tgz`.
- Keep preview wording intact.
- Do not run `npm publish .` or rebuild during publish.
