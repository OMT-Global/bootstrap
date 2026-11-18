# ADR-0032: Public signed provenance CLI and native review lookup

Status: Accepted

Date: 2026-11-10

Decision owners: Bootstrap maintainers
- Governing work: #63 and the public follow-up deferred by #61 / ADR-0007

## Context

The accepted public-v2 / envelope-v1 codec already signs and verifies canonical Ed25519 payloads. Its pure reviewer arrays are signer claims. The CLI previously exposed only unsigned creation and validation, and no consumer authenticated review state against GitHub. This leaves a concrete public provenance gap while the private implementation and material-gate approvals remain separate.

## Decision

The task coordinator adopts this public-only implementation following independent design assessment on 2026-11-10. Independent non-author PR approval remains required before merge. This decision grants no private-provenance or material merge-gate authority.

Add public-only `provenance sign` and `provenance verify` commands to the existing Commander group. Keep unsigned commands, codec, schemas, metadata/redaction policy, dependencies, legal bytes and managed outputs unchanged. A concrete bounded adapter calls the installed `gh api --hostname github.com graphql` using one fixed read-only query and explicit repository/PR/head variables. Public fork heads are supported through their native identity; a base repository is not confused with a fork head repository.

Use complete bounded native `latestOpinionatedReviews` plus native approval state, actual submitted commit and independent actor identity. Repeat complete reads and reject observed identity/review changes, incomplete pagination, old-head-only approvals, self approvals and malformed/ambiguous data. Do not invent a latest-by-ID or latest-comment opinion algorithm. Sign replaces claimed reviewers with this canonical observed set, verifies its own produced signature and rechecks reviewers before output. Verify authenticates strict envelope, external trust and expected subject before network access, then compares actual current reviewers. Reviewer IDs and PR number remain external verification context; no new wire metadata claims are smuggled into the manifest.

Read bounded regular local JSON/key files with no-follow/nonblocking opens, validate strict selected private JWK and unique public-only keyring shapes, and sanitize all new failures. Never pass selected key bytes to the subprocess, output or error text. Publish a complete synced staged output through an exclusive hard link; do not overwrite files or symlinks or create implicit output directories. Clean only owned staging. Local filesystem/installation trust is explicit; this is not a malicious-same-user sandbox, durable journal or key-enrollment service.

The concrete request has a 30-second bound and 1-MiB combined output bound; a lookup has a 120-second bound and two complete collections of at most 16 pages / 1,600 reviews. Failure is terminal without retries, writes to GitHub or new authority. Normal installed GitHub CLI authentication is an operator prerequisite, not a credential copied by this feature.

## Verification and limits

Meaningful regressions cover real command/codec/file round trips using ephemeral keys, a shipped-CLI/fixed-adapter process chain with owned fabricated GitHub responses, malformed input, untrusted/tampered signatures with zero lookup, reviewer replacement and stale claims, complete/moved/incomplete review pagination, native blocking/self/old opinions, transport bounds/deadline, diagnostics and existing output preservation. No live operator key, authenticated GitHub runtime or deployment is claimed by those offline tests. The POSIX executable fixture is separate from Windows qualification.

The expected commit is the PR head. A different squash merge commit is not silently accepted through tree equivalence. Reviews may change after the last read; this is observed lineage, not permanent freshness or standing merge authorization. Subject ref and execution/model/provider/prompt/timestamp fields remain signer claims; only repository, commit and reviewer set are checked against PR context. The existing Cosign AI-attestation format is not relabeled as this envelope.

Private capture, encryption, OIDC/AWS adapters, retention, approved reads and material merge enforcement remain behind ADR-0006 / #161's independent design review and explicit human implementation signoff. No workflow, settings, trusted-key distribution, live key creation, release or provider activation belongs to this public source slice. Issue #63 remains open for its complete two-repository acceptance and release/private dependencies.
