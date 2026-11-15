# Approved existing-release retry

The optional Bootstrap profile returns `verified-existing` only after the current release matches independently approved package bytes. It never runs hooks, creates or edits releases, uploads assets or moves aliases. Missing or ambiguous evidence is a failure to reconcile, not a request to create a release. The returned evidence concerns current observations, not who originally published the release or whether it remains unchanged later. See [ADR-0059](../decisions/ADR-0059-current-exact-release-retry.md).

The generic publish path also stops before hooks when a release already exists or the release listing fails. Its new-release operation is create-only; an uncertain error stops without an upload/overwrite fallback.

## Source integration and activation

The reusable workflow invokes `dist/release-existing-runtime.js` for the read-only operation when `verify_existing_release` is true. It dispatches before legacy downloads and target Git/hook commands, and writes only fixed `RUNNER_TEMP/approved-retry-evidence.json` verification evidence. It checks out the exact target into `release-target`, and the trusted runtime into `.bootstrap-release-runtime` from fixed repository `OMT-Global/bootstrap` at the reviewed `RELEASE_RUNTIME_COMMIT`. It verifies that checkout's commit and installs/builds it before the App key is exposed. Target-tag hooks and modules are not executed by this branch.

GitHub's [reusable workflow context documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#github-context) associates the `github` context with the caller. The implementation therefore uses an independently configured runtime commit, not `github.workflow_sha` as evidence of the called reusable source.

After this source and its dependencies land, a separate reviewed activation must select a compatible immutable `release.reusableWorkflowRef`, set `release.approvedRetry: true`, regenerate the caller with doctor/plan/apply, and establish the environment configuration below. Existing generated callers do not acquire unsupported inputs while still pinned to older reusable versions. No activation is performed by this source change.

The retry dispatch also supplies the exact tag/channel, approved preflight run, successful full-validation run, release issue and `approval_pull_number`. Current approval must be on the exact canonical manifest bytes and head. JMCTE must differ from requester/publisher actors for this attempt; the current release's historical author is not an authority input.

## Required protected environment inputs

`RELEASE_RUNTIME_COMMIT` is the reviewed full Bootstrap runtime commit. `RELEASE_APP_PRIVATE_KEY` is the dedicated App's separately provisioned RSA private key; it is exposed only to the approved operation step. The runtime creates a short-lived App JWT in memory, issues one explicitly narrowed installation token, and performs only reads afterward. Failed or ambiguous issuance is not retried. Consumer completion does not revoke the installation token; the documented ADR-0057 expiry/revocation boundary still applies.

`RELEASE_RETRY_CONFIG` is strict JSON with no defaults for identity or tool pins:

| Field | Required meaning |
| --- | --- |
| `appId`, `installationId`, `repositoryId` | Dedicated approved App/installation and Bootstrap's numeric repository ID; IDs are positive numbers except repository ID is a string |
| `runtimeCommit` | Same full commit as `RELEASE_RUNTIME_COMMIT` |
| `reviewerId`, `manifestPath`, `maxValiditySeconds` | JMCTE's numeric ID string, exact `.github/release-approvals/<name>.json` path, approved validity policy within the existing 24-hour implementation ceiling |
| `publication`, `preflight`, `validation` | Objects with numeric workflow `id` string, exact `.github/workflows/<name>.yml` `path`, and full trusted caller workflow `commit` |
| `latest` | Boolean matching the approved manifest |
| `pythonPath`, `pythonSha256`, `ghPath`, `ghSha256` | Trusted absolute executable paths and independently approved SHA-256 pins |
| `maxAssetBytes`, `maxArchiveBytes`, `maxExpandedBytes`, `maxMembers` | Positive bounded acquisition limits; members cannot exceed 10,000 |

The runtime authenticates the configured reviewer ID against the current `jmcte` GitHub user and binds the live publication attempt and full-validation run to configured workflow identities. Validation selects exactly one artifact from a complete authenticated inventory and verifies its exact ID, provider ZIP SHA-256 and run/attempt/workflow context before and after acquisition. The shared ZIP verifier accepts only `validation-evidence.json`, with limits of 1 MiB compressed, 64 KiB expanded and one member; target/repository/run/attempt and both successful checks must match. Current run/artifact identities are rechecked at later boundaries. Activation requires a validation workflow containing the additive `run_attempt` evidence stamp; old unstamped artifacts fail. The existing Linux source-capture host requirements remain mandatory; local tests do not make an arbitrary runner eligible. No real values, keys, App installation or settings are supplied here.

## Exactness and remaining work

The [release API](https://docs.github.com/en/rest/releases/releases#list-releases) exposes drafts only with push access. The runtime checks the narrowed token's current repository scope and repository push permission before a complete listing. It independently selects the release ID, then repeats by-ID metadata, assets and latest reads. The [asset API](https://docs.github.com/en/rest/releases/assets#list-release-assets) supplies SHA-256 digests; absent digests fail rather than falling back to unauthenticated download content. Provider digest equality authenticates observed asset content but does not promise a later download will remain unchanged.

The [first approved publication consumer](approved-source-publication.md) is a separate explicit operation; floating-alias promotion remains separate source and operational work. The retry branch never falls through to either. The generic hook path retains its established contract and cannot establish at-most-once execution after an uncertain hook side effect. The real #27 pilot still needs an approved first-publication path, operational identities/configuration, hosted validation, and separately authorized release/alias writes.
