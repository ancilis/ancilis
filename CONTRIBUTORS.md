# Contributors

This project is built by Kevin Bauer with assistance from a fleet of AI agents
operated via [Paperclip](https://paperclip.ing). Commits to this repository
are attributed using the following scheme:

## Identity scheme

| Identity | Email | Role |
|---|---|---|
| `Kevin Bauer` | `kevin@ancilis.ai` | Solo founder; all human-authored commits, signed with GPG key `8215E961BA9E0E11` |
| `pc-cto`, `pc-arch`, `pc-ceo`, `pc-pm`, `pc-compl`, `pc-design`, `pc-devops`, `pc-pe1`, `pc-pe2`, `pc-platrev`, `pc-rev`, `pc-sdk1`, `pc-sdk2`, `pc-sdkrev`, `pc-conn1`–`pc-conn4`, `pc-connrev` | `agents@ancilis.ai` | Codex agents in specific Paperclip roles (CTO, Architect, CEO, Product Manager, Compliance Architect, Design Lead, DevOps Engineer, Platform Engineers 1/2, Platform Reviewer, Review Engineer, SDK Engineers 1/2, SDK Reviewer, Connector Engineers 1/2/3/4, Connector Reviewer) |
| `Ancilis Codex Agent` | `agents@ancilis.ai` | Fallback for any codex agent that didn't get a specific role-based override at spawn time |
| `dependabot[bot]` | GitHub Dependabot | Automated dependency security PRs |
| `Claude` | `noreply@anthropic.com` | Claude Code agent commits |

## How attribution works

- **Author** records who originated the work (the agent or human who wrote it).
- **Committer** records who landed it on the repository.
- For commits where Kevin lands work an agent produced, author is `pc-<role>` and committer is `Kevin Bauer`. This dual-attribution is intentional — it preserves the agent's authorship credit while signaling that a human reviewed and merged the work.
- Commits authored by `Kevin Bauer` are GPG-signed. Other commits are unsigned by design (agents do not hold signing keys).

## Pre-2026-04-29 history

Prior to 2026-04-29, multiple identities shared a single email (`kevin@ancilis.ai`):
- `Bedlam <kevin@ancilis.ai>` represented codex agents in earlier sessions.
- `Kevin Bauer <kevin@ancilis.ai>` represented Kevin's manual commits.
- `ancilis <kevin@ancilis.ai>` represented GitHub squash-merges of agent work.

This conflation made it impossible to distinguish agent-authored from human-authored commits in the early build period. The scheme above replaces that, going forward, with per-actor identities and a clean separation of `agents@ancilis.ai` from `kevin@ancilis.ai`. Pre-2026-04-29 commits are not retroactively rewritten because every existing branch and reference would need to be force-pushed; that destabilizes work in flight. The historical commits remain as-is, and this document records what each identity meant in that period.

