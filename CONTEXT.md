Current Task: Restore missing canonical root exports for public TypeScript SDK helpers.

Key Decisions:
- Treat `typescript/src/ancilis/index.ts` as the active heartbeat scope because the canonical root was missing public exports already available from submodules.
- Use a runtime root-export test in `typescript/tests/cli.test.ts` to catch package surface drift that `tsc --noEmit` does not catch for tests.
- Defer Paperclip status updates until agent auth is available in the shell (`PAPERCLIP_API_KEY` is missing).

Next Steps:
- Restore Paperclip agent auth and move the assigned issue to `in_review` with the root-export verification summary.
- If more TypeScript parity work is needed, inspect remaining type-only root exports and other package-surface drift next.
- Keep release flow artifact-bound by continuing to verify with `npm run pack:smoke` before publish-related changes.
