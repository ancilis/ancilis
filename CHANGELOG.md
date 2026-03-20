# Changelog

All notable changes to this project will be documented in this file.

The project follows a conservative pre-1.0 release posture:

- `0.1.x`: first honest public release line for the Python SDK.
- Minor releases may still include breaking changes when required for correctness.
- Patch releases should stay backward-conscious and focus on regressions, packaging, or security fixes.

## [0.1.0] - 2026-03-20

### Added
- Artifact-based Python install verification for wheel and sdist builds.
- Release-check automation for Python artifacts and preview TypeScript package smoke checks.
- `source_type` propagation across Python action, evaluation, evidence, and schema layers.
- Additional CLI, evidence, packaging, and regression coverage.

### Changed
- Hardened Python packaging metadata and shared-asset inclusion.
- Kept the TypeScript package explicitly preview in package metadata and release workflow posture.
- Strengthened release workflows and dependency audit coverage.

### Security
- Clarified disclosure process and technical trust boundaries.
- Surfaced evidence-chain integrity failures more explicitly in release verification and reporting.
