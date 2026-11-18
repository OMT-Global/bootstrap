# Fleet candidate history and validation handoff

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

These private modules continue the source candidate from
`fleet-candidate-preparation.md`. They remain absent from the CLI/package index
and preserve ADR-0013's separate hook/final-check phases and ADR-0016's neutral
Git and original-checkout boundary. They provide no publisher or signer access.

## Complete public history

`acquirePreparedHistory` accepts only the genuine process-owned prepared
candidate. It checks the public repository's numeric identity, visibility,
default branch and exact prepared base head before and after acquisition.
The fixed anonymous GitHub HTTPS fetch uses neutral configuration/environment,
trusted Git/helper locations, no hooks, no redirects and bounded processes.
It never reads saved GitHub authentication or accepts an imported base bundle.

Acquisition permits one bounded pack/index pair. Unsupported metadata, shallow
boundaries, alternates, grafts and replacement refs fail. A depth-10,000 fetch
must still contain complete ancestry: `git fsck --strict` must succeed, the raw
base commit/tree and all blob identities/modes/path bytes must match the genuine
prepared base, and a self-contained v2 bundle must fit the existing 64 MiB bound.
Merge ancestry is retained; no replacement base commit is manufactured.

The owned history remains available for adding the actual signed candidate.
Candidate blobs and tree are written with raw Git operations, then the verified
raw commit is added without rewriting its identities/message/signature. The
final bundle contains that candidate and its complete base history. Original
checkouts, refs and configuration are untouched.

## Owned hook, signing request and final-check

`prepareCandidateHook(candidate, plan)` snapshots explicit branch, message,
author/committer names/emails/raw dates, hook selection and canonical public
Ed25519 SSH key metadata. It invokes the existing fixed `validateIsolatedNode`
backend in `prepared-hook` mode with the genuine history and candidate files.
The returned report must match the pinned profile/image, source/tree/base and
commit-plan digest. A caller-supplied pass flag or report cannot create a ticket.

Only this owned ticket permits `copyCandidateSigningRequest`. The request copies
the exact unsigned Git commit bytes and selected public key. It does not select
a private key, SSH agent, keyring, Git identity or signing executable. The
production signing identity/key source has not been selected or authorized.

A separately authorized trusted signer must sign those exact bytes. Given its
raw signed commit, `completeSignedCandidate` verifies the exact tree, sole
parent, author/committer identities/dates, message and SSH signature structure.
A fixed root-owned `ssh-keygen` verification operation checks the signature in
the Git namespace against the previously selected public key, without an agent
socket or original Git configuration. Signature validity proves possession of
that key; it does not establish the signer's authorization.

Only after signature verification does the fixed backend run `final-check` on
the real signed commit and candidate bundle. Its report must match the exact
candidate/source/plan and the earlier tool versions. Successful owned history
cleanup is also required before a checked result is produced. Failed operations
cannot retry signing/completion; a cleanup-only ticket remains disposable if
deletion fails, including after cancellation.

The checked result privately owns its bundle and immutable public facts. It
reports hook/final-check completion and signature verification, while keeping
`signerAuthorization: unverified`, `authority: none`, `pilot: unverified`, and
independent review/publication pending. It is a historical artifact, not a live
branch lease. It can outlive disposal/cancellation of the consumed preparation
ticket; the validation caller's own cancellation still disables result access.
The operation deadline limits in-flight work, not a new artifact retention TTL.
Explicit disposal remains available after cancellation.

## Validation limits and remaining work

Tests exercise real temporary Git merge history, raw objects and bundles,
production input validation, and real ephemeral-key SSH signing/verification.
Public transport, Linux/prlimit eligibility, trusted fixture/helper ancestry and
isolation reports are fabricated adapters. No target hook/check script runs on
the host. These tests prove composition and refusal behavior, not actual Docker
isolation, trusted Linux deployment or a passed real fleet pilot.

Before a real run, a qualified controlled host must invoke the fixed backend and
produce actual reports. The next signer consumer needs an explicitly selected
and authorized identity/key source. Subsequent consumers must bind independent
review to the exact candidate, verify current repository/policy/pilot governance,
and use the separately selected one-public-repository App publisher with manual
reconciliation after uncertain writes. This source stage authorizes no key/App
installation, credentials, release, fleet PR, rollout or issue closure.
