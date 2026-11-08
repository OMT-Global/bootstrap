# ADR-0009: Encrypted private provenance design for review

Status: Proposed

Date: 2026-11-08

Decision owners: Bootstrap maintainers; security reviewer and human approver pending

Governing issue: [#161](https://github.com/OMT-Global/bootstrap/issues/161)

## Context and authorization boundary

Issue #161 transfers the encrypted-private portion of #61. Its implementation gate requires an independent security review of the encryption/key-management design and explicit human sign-off. ADR-0006 and ADR-0007 preserve that boundary. Neither the independent review nor final human design sign-off is recorded for this proposal. This document prepares a concrete review target; it does not authorize implementation, remote storage, private-data capture, spending, or production use.

The existing public version-2 schema and Ed25519 envelope remain the public integrity contract. Their signatures authenticate signer claims; they do not retrieve GitHub review state or prove that a private bundle was stored. The proposed private capture must preserve those guarantees and establish its own storage and material-merge evidence.

## Confirmed preferences and remaining authority

The owner selected AWS S3 with AWS KMS, a U.S. region, 90-day retention, and `jmcte` as the approver for private reads. These are design preferences, not final sign-off on this proposal or permission to deploy or capture real evidence. `us-east-2` is the proposed region, pending explicit account/target configuration. `jmcte` is the proposed human key-policy/recovery owner; that responsibility remains to be confirmed.

For the initial pilot, propose S3 Object Lock **Governance** mode with 90-day retention and a separately controlled, audited break-glass administrator. Neither capture nor read roles receive retention-bypass privileges. Governance mode deliberately permits a specially authorized administrator to bypass retention; it is not an irreversible retention guarantee. Compliance mode is an alternative requiring explicit approval of its unshortenable retention commitment before any object is locked that way.

## Proposed design

1. Accept only a bounded, strict private-input schema containing explicitly approved evidence categories. Reject recognized credential literals before encryption, including credentials in identities and nested evidence. Treat pattern detection as defense in depth: it cannot establish that arbitrary text contains no secrets. Do not capture process environments, authentication stores, or unrestricted tool output.
2. Verify an existing signed public envelope against an explicit trusted keyring and expected repository/commit subject before accepting its binding. Bind the private envelope to that public envelope's canonical digest, repository, immutable commit SHA, and run identifier. Public schema version 2 remains unchanged; private fields, physical sink configuration, and encryption metadata do not enter public metadata.
3. Use AWS KMS client-side envelope encryption: request a fresh `AES_256` data key through `GenerateDataKey` under an approved symmetric customer-managed KMS key, then encrypt the bundle locally with AES-256-GCM and a fresh 96-bit nonce. Bind canonical header bytes, the trusted KMS key ARN, and the wrapped-key digest as authenticated additional data. Supply only non-secret domain/version/binding-digest values as KMS encryption context and require an exact context match for unwrap. Store only the KMS ciphertext key with the encrypted bundle. Require S3 SSE-KMS additionally, with a separate service-encryption key and narrowly scoped permissions; SSE-KMS alone does not satisfy client-side encryption. The reviewer must validate framing, bounds, key trust, and permission separation before acceptance.
4. Keep plaintext evidence and unwrapped data keys in the capture/read process only, without plaintext temporary files or credentials in generated configuration. Restrict their lifetime and clear mutable key buffers where practical; do not claim guaranteed erasure of JavaScript-managed memory. Crash dumps, swap, and host administration remain deployment controls to review.
5. Write ciphertext to a private, versioned AWS S3 general purpose bucket in the proposed `us-east-2` region through a logical sink enforcing conditional create-only writes. Record the exact object version and verify its SHA-256 digest plus Governance retain-until date against the 90-day policy. Object Lock protects versions; it does not by itself prevent a new current version under the same key, so bucket policy must enforce conditional writes and deny ordinary-role deletion/retention changes. Use a distinct ciphertext-verification role without client-envelope-key unwrap permission, preserving the writer's lack of stored-object read access. A successful upload response alone cannot establish retention compliance.
6. Obtain short-lived AWS STS credentials through GitHub OIDC with issuer `token.actions.githubusercontent.com`, audience `sts.amazonaws.com`, and exact approved repository/environment subject conditions. Use protected environments, controlled workflow sources, and verified execution metadata to constrain workflow/ref/head; do not assume an environment subject alone binds the workflow or commit. Separate capture/write, ciphertext verification, `jmcte`-approved trusted read broker, audit, break-glass retention administration, and key administration roles. The writer may generate keys for current capture but cannot read stored objects or call client-key `Decrypt`; the read broker cannot write payload objects, delete, relax retention, or bypass Governance. Requesters receive neither AWS read/decrypt credentials nor role-assumption capability; only the trusted broker holds the combined S3 and both KMS decrypt permissions. No long-lived AWS keys are used.
7. Produce a separately versioned, signed capture receipt only after encryption, verified protected-version storage, digest verification, and retention verification succeed. Sign a distinct private receipt domain/version over the exact repository/commit/run, public-envelope and ciphertext-envelope digests, private S3 bucket/key/version locator, capture timestamp, retain-until timestamp, Governance mode, and approved retention-policy identifier. Use the frozen `sorted-json-v1` framing and bounds in the companion design; the existing public signing format remains unchanged. Keep receipts and audit evidence in an access-controlled evidence channel; the public required check exposes status and a sanitized reason, never payload, object locations, key identifiers, or private metadata. Receipt signing trust and the evidence channel require approval before implementation.
8. Make material-change verification fail closed when capture is required and any public-signature, authenticated-review-lineage, subject, receipt, storage, or retention check fails or is absent. Recompute material classification and current-head GitHub review evidence through trusted APIs; do not trust PR-body claims or caller-supplied reviewer objects. Explicitly non-material changes follow the separately approved policy. Fork PR jobs remain read-only and GitHub-hosted; private capture runs only from an approved trusted context.
9. Route every ordinary private read through a trusted broker running only controlled code. It authenticates the requester and a scoped `jmcte` approval, obtains narrowly scoped runtime access internally, and requires a durable create-only application audit acknowledgment before releasing any plaintext; completion/failure events follow. Never vend S3/KMS credentials or presigned plaintext/decrypt access to the requester. Record authenticated actor, approved purpose, exact version/subject, and time without private payloads or credentials. Deny reads when required audit acknowledgment fails. Enable explicit CloudTrail S3 object data events and KMS/STS/administrative-event coverage, delivery monitoring, and log-integrity validation to corroborate application events and detect bypass or policy changes. CloudTrail delivery is asynchronous and cannot substitute for the synchronous application audit gate. Protect audit evidence from capture/read modification and retain it for at least the selected 90-day evidence period, subject to review. Recovery never silently bypasses audit, retention, or required capture. The broker and cloud administrators remain trusted: compromise of broker code, host, key policy, or audit administration can defeat this boundary and requires separate operational controls. Do not claim every privileged human bypass or onward copying of released plaintext is prevented.

## Decisions required before acceptance

| Decision | Current state | Evidence required |
|---|---|---|
| Permitted private evidence categories and exposure owners | Unresolved | Approved schema, bounds, classification, and capture exclusions |
| Encryption and key-management construction | Candidate only | Independent review of envelope framing, AEAD binding, wrapping, rotation, revocation, and recovery |
| Storage provider, jurisdiction, account, and spending authority | AWS S3 + KMS and U.S. selected; `us-east-2` proposed; account/target and spending pending | Confirm account/region/deployment scope; physical identifiers stay outside portable repository assets |
| Key operator, trusted key distribution, and recovery authority | `jmcte` proposed as human key-policy/recovery owner; unconfirmed | Confirm ownership, KMS key trust, rotation/recovery procedures, and independent administration boundaries |
| Retention duration, Object Lock mode, deletion, and exceptions | 90 days selected; pilot Governance mode and separate break-glass proposed | Review retention start/expiry, legal/privacy obligations, audited exception authority; Compliance requires separate immutable-lock approval |
| OIDC trust, write/read roles, and audit destination | GitHub-to-AWS OIDC proposed; `jmcte` selected to approve private reads | Confirm trusted workflow/environment, verified approval record, trusted broker/runtime, concrete IAM/key/bucket policies, audit target and negative permission tests |
| Authenticated reviewer source and material-capture gate | Unresolved | Exact-head policy, trusted execution workflow, check name, branch-rule integration, and failure behavior |
| Independent security review | Not recorded | Reviewer identity, independence qualification, exact reviewed revision/digest, findings and disposition |
| Explicit human sign-off | Not recorded | Approver identity, reviewed revision/digest, decision references, approved scope and limits |

Record approvals against the exact final design revision. A material design change after approval requires renewed review and sign-off. Acceptance of an implementation design must distinguish synthetic local testing from authorization to capture real evidence or enable a production sink.

## Suggested implementation boundary after approval

Start with a separate private-provenance module, strict schemas, injectable key-service/sink/audit interfaces, and synthetic in-memory tests. Add the approved AWS S3/KMS and GitHub OIDC adapters with contract tests, then trusted capture and required-check integration with operator documentation. Keep the current public schema/verifier unchanged unless a separate public-format decision is reviewed. See the [design and acceptance matrix](../security/private-provenance-design.md).

## Alternatives and consequences

- Storing plaintext in a private repository or artifact is insufficient: access controls do not provide the proposed independent encryption, role separation, immutable retention, and audited-read guarantees.
- Reusing Ed25519 signing keys for encryption or treating a public signature as proof of remote capture would conflate distinct trust boundaries.
- Adding private details to public version-2 metadata would violate its allowlist contract.
- Relying on SSE-KMS alone would leave plaintext accessible to ordinary S3/KMS readers and would not provide the separate client-envelope-key boundary.
- A local encryption helper alone would leave the logical sink, OIDC, audited reads, retention, and material-merge acceptance criteria incomplete.

This proposal adds no executable path or production configuration. Issue #161 remains open until the approved implementation and its acceptance evidence are delivered.
