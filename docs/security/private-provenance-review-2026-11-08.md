# Independent private-provenance design review

Governing issue: [#161](https://github.com/OMT-Global/bootstrap/issues/161).

Reviewed on 2026-11-08 by a separate Codex reviewer in the software architect role. The reviewer did not author the proposal and performed a read-only review, including the existing provenance ADRs, threat model, and AWS contracts. This is an independent automated design review, not human approval or a GitHub PR approval.

## Original reviewed artifacts

| Artifact | SHA-256 |
|---|---|
| [ADR-0009](../decisions/ADR-0009-encrypted-private-provenance.md) | `5a39a8cf8ff68f1e050502042b8aca752cf3c29d052ffdc8c798bfc20620a516` |
| [Design and acceptance matrix](private-provenance-design.md) | `cb758b04194036fc6ef7aca994cae5dfe1ced91a79b7cae2074e7ace1a04a8b2` |

## Findings and disposition

The initial design granted readers S3 GetObject and KMS Decrypt credentials while promising synchronous application auditing for every plaintext release. A credential holder could call those services directly and bypass that audit gate. The corrected design gives combined read/decrypt authority only to a trusted broker, gives requesters no AWS credentials or assumable decrypt role, and requires authenticated scoped approval from the approved read authority and durable audit acknowledgment before broker release. The reviewer re-read the corrected bytes and considered this blocker resolved.

The review also required explicit canonical framing, strict field/byte/depth bounds, fixed key/nonce/tag lengths, authenticated wrapping context, and a signed receipt binding the exact private object version, digests, capture/retain-until timestamps, and retention mode. The corrected package specifies these boundaries and synthetic negative controls.

No remaining blocker was identified to **seeking human sign-off for a synthetic-only implementation stage**: strict schemas, cryptographic envelopes, fake key/sink/audit interfaces, and fabricated-input tests. This conclusion does not establish a working implementation or production security.

## Remaining gates

On 2026-11-08, the owner explicitly approved the bounded stage with: “Approve synthetic implementation in a follow-up PR.” That approval permits strict schemas, cryptographic envelopes, injected fake key/sink/audit/approval interfaces, and fabricated-input tests in a separate PR. The stage uses the category `synthetic-fixture` only; this does not approve any real evidence category. It does not approve real data, real keys, AWS resources, deployment, or CLI/material-gate integration. The two candidate artifacts remain Proposed; the authority-wording correction below supersedes their original hashes. Real capture, AWS resources, and deployment remain separately gated on approved evidence categories, account/region and administrative ownership, authenticated read-authority/delegation and broker policies, signing trust and audit target, and exact material-classifier/required-check integration. The proposed Governance retention mode retains its explicitly documented privileged-administrator trust limit.

A material design change invalidates this exact-byte review and requires renewed review. Keep #161 open until the approved functionality and its acceptance evidence exist.

## Read-approval attribution correction

The actual owner reply was “AWS S3 + KMS; U.S. region; 90 days; you approve reads”. Earlier wording incorrectly identified `jmcte` as the selected read approver. The corrected candidate records delegated Codex approval as an interpretation/preference, leaving the concrete authenticated principal, delegation policy, and production authority unresolved. Mandatory human design/deployment sign-off remains separate, as does the merely proposed/unconfirmed `jmcte` key-policy/recovery role.

The same independent reviewer performed a narrow wording-delta review on 2026-11-08 and found no accepted/actionable findings. Cryptographic framing, key/nonce/tag bounds, receipt bindings, storage/retention, broker-only decryption, requester credential prohibition, scoped approval, audit-before-release, and role separation are unchanged. The original exact-byte review remains historical evidence; the delta review covers these revised artifacts:

| Artifact | Revised SHA-256 |
|---|---|
| ADR-0009 | `9abe22e872fc4f6dde34bd93c111b599c6649013eb72b958579245e7c5bc5a06` |
| Design and acceptance matrix | `fec947d60dcb6599b7d04545b5800126d7e83299f0625cce6a7be9ff11dd9f08` |

This correction does not enlarge the owner-approved synthetic stage or authorize production reads.
