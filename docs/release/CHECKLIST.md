# Release Checklist

- [ ] `python -m pytest python/tests -v`
- [ ] `npm test`
- [ ] `python scripts/release_check.py`
- [ ] `python -m twine check dist/*`
- [ ] Wheel install smoke test passed
- [ ] sdist install smoke test passed
- [ ] `ancilis doctor` passed from installed artifact
- [ ] `ancilis config validate` passed from installed artifact
- [ ] Shared taxonomy and control assets resolved from installed artifact
- [ ] Report/status commands handled empty evidence store cleanly
- [ ] Optional MCP dependency behavior checked
- [ ] `CHANGELOG.md` updated
- [ ] Release tag created as `vX.Y.Z`
- [ ] TypeScript package still labeled preview unless explicitly re-approved
