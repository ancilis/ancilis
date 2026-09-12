# SDK publication procedure

The Python and TypeScript candidates share the version in `pyproject.toml` and
`package.json`. The primary workflows accept `v<version>` tags. Manual dispatch
verifies artifacts, including when the selected ref is an existing tag. It
never publishes. The legacy `ts-v<version>` workflow only verifies artifacts.

Before any release, finish the product, dependency rights and installation,
review, required CI and installed-artifact acceptance gates. A successful local
packaging check does not establish final release acceptance.

## Exact artifacts

Python builds one sdist and derives its wheel from that sdist in an isolated
build environment. Both archives are installed and checked. TypeScript packs
once and installs that exact tarball for its smoke check. Publishing runs no
npm lifecycle scripts and does not rebuild the package.

Each primary workflow freezes `release-manifest.json`, recording the version,
source commit, runtime/toolchain and every archive member's size and SHA-256.
License, schema and shared asset entries are identified in that inventory.
The build job exports the manifest digest separately. The publisher requires
that digest, rechecks the closed file set and archive contents, and rejects
extra files, missing files, links, unsafe paths, changed bytes or mismatched
package metadata. Uploading an artifact directory is safe only after this
closed-set check; it is not permission to upload a general build directory.

## Source approval and remote protection

A separate job verifies the tagged commit is on `main`, identifies its exact
merged PR, compares the reviewed head and merge source trees, checks eligible
non-author approvals of that head, and requires successful CI for the release
commit from the configured check apps. A later failed run cannot be hidden by
an older success. API failures and incomplete pagination stop the gate.

This script verifies the ordinary release process. It runs from the tagged
workflow and cannot constrain a repository writer who changes that workflow.
It does not replace remote protection. Before release acceptance, inspect and
approve a policy restricting version-tag creation, protecting publishing
environments with required reviewers and/or appropriate deployment-branch
rules, scoping publication secrets to those environments, and binding the
PyPI trusted publisher to its protected environment. Environment names alone
do not establish protection. Referencing an absent environment can create it
without protection. No remote policy is changed by these source changes.

`release_gate.py` requires a separately authorized `RELEASE_POLICY_READ_TOKEN`
with **read-only** repository administration, contents, pull-request and checks
access. GitHub's full branch-protection endpoint requires administration read;
the ordinary workflow token must not be assumed to provide it. Missing or
inaccessible credentials stop verification. Never supply a write-enabled or
administrative bypass token as a shortcut. The workflow's own token has only
read permissions in that job. Token values are not included in evidence.

The gate enforces at least one approval and the eight current required CI
contexts. It also respects a larger live approval count and additional checks.
If a newly enabled code-owner or last-push approval policy needs additional
verification, it stops rather than approximating that policy. Docs lint and
TypeScript examples remain required release validation work even when their
names are not in branch protection.

Python retains PyPI OIDC trusted publishing. npm retains `NPM_TOKEN` with
provenance; this is token-based authentication, not npm trusted publishing.
The npm secret is referenced only by the sole publish step, after the source
and artifact gates. The verification dry run receives no publication token.

## Partial publication and recovery

Each package/version is serialized without cancelling an active publisher.
Before upload, a registry read distinguishes an absent version from an existing
version with exactly matching hashes. Authentication, rate-limit, network or
server errors are not absence. Existing different or partially uploaded Python
archives stop the workflow; nothing is overwritten, deleted or silently skipped.

If one registry succeeds and the other fails, retain both workflow artifacts,
build manifest digests and registry evidence. Re-run only the failed publish
job against its original verified artifacts. The successful registry must
still match its recorded bytes. Do not change the tag, rebuild and assume
identical contents, or increment the version to hide an unresolved partial
release. If retained artifacts or outputs are unavailable, stop for a reviewed
recovery decision.

After both registries are verified, complete clean installation, provenance,
CLI/import and the documented end-to-end workflow checks before creating the
final GitHub release and declaring launch complete. The npm workflow does not
create a GitHub release early while Python might still be incomplete. Retain
source-review evidence and digests of the environment, version-tag, branch
protection and credential-metadata reads in the final report.

References: [GitHub branch protection API](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection),
[commit and associated PR API](https://docs.github.com/en/rest/commits/commits),
[PR reviews API](https://docs.github.com/en/rest/pulls/reviews),
[check runs API](https://docs.github.com/en/rest/checks/runs),
and [npm provenance](https://docs.npmjs.com/generating-provenance-statements/).
