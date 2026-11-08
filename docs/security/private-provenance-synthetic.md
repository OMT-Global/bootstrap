# Synthetic private provenance library stage

Governing issue: [#161](https://github.com/OMT-Global/bootstrap/issues/161). This is the bounded follow-up implementation authorized on 2026-11-08; [approval and independent design review](private-provenance-review-2026-11-08.md) record the scope. The [reviewed candidate design](private-provenance-design.md) and [ADR-0009](../decisions/ADR-0009-encrypted-private-provenance.md) remain Proposed; the review record separately documents the corrected read-approval attribution.

## Scope and APIs

`src/private-provenance.ts` exports `captureSyntheticPrivateProvenance` and `readSyntheticPrivateProvenance`. Both require `syntheticOnly: true` on their options and every injected adapter. The accepted input is strict `{ schemaVersion: 1, evidence: [{ category: "synthetic-fixture", text }] }`. This stage-only category does not approve production evidence. The flag and API names communicate authorized use; they cannot algorithmically prove that supplied text was fabricated. Caller-supplied clocks, expected subjects, key identifiers/keyrings, ephemeral signing keys, and adapter/approval behavior are trusted synthetic harness inputs, not authenticated production authorities.

Callers supply fabricated JSON as canonical UTF-8 bytes using the existing `canonicalizeProvenanceJson` helper. Capture takes private input, a signed public envelope, expected repository/commit/run, an explicitly trusted public keyring, a fabricated key identifier, an ephemeral receipt-signing key, capture time, and retention-policy identifier. It returns canonical signed receipt bytes only after fake storage reports the exact object digest, version, and required Governance retention. Public signature verification uses the existing verifier and additionally checks expected run equality.

Read takes receipt and public-envelope bytes, explicit public/receipt signing trust, expected subject/run, trusted key identifier, and requester/purpose/approval-reference/time. It returns the strict fabricated input after receipt/public/envelope verification, trusted fake approval, successful durable audit acknowledgment, authenticated decryption, and completion acknowledgment. The API returns no AWS credentials, key material, or direct access path. Its trusted injected approval fake must validate trusted scoped synthetic approval against requester, purpose, exact version, and access window. Merely returning a caller-supplied approval flag does not implement that contract.

The injectable `SyntheticKeyService`, `SyntheticPrivateSink`, `SyntheticReadApproval`, and `SyntheticPrivateAudit` interfaces have no built-in implementations accessing network, storage, files, authentication, or cloud services. Tests supply in-memory fakes and ephemeral keys. Interfaces model reviewed boundaries; they do not establish that a provider enforces IAM, OIDC, Object Lock, or durable auditing.

## Wire and failure behavior

Wire inputs must match canonical JSON byte-for-byte. Parsing applies byte and depth bounds before recursive canonicalization, rejects malformed UTF-8, and rejects duplicate keys and alternate JSON encodings by canonical round-trip comparison. Strict schemas reject unknown fields, noncanonical Base64, invalid sizes/timestamps, and credential-like text. The input, envelope, and receipt limits match the reviewed candidate framing.

Each capture requests a fresh 32-byte fake data key and generates a 12-byte nonce. AES-256-GCM authenticates the exact header, including public subject/run/digest, trusted key identifier, and wrapped-key digest. Private capture receipts use their distinct signing domain and bind the exact private version locator, digests, capture and retention timestamps, retention mode/policy, and subject/run. Existing public schema and signing formats are unchanged.

Capture/sign/storage/verification failures return no success receipt. Read/approval/audit/unwrap/authentication failures return no plaintext. Errors identify capture or read without printing input, adapter errors, or nested causes. Known mutable plaintext/key buffers, including adapter-transferred key buffers, are cleared in `finally`. Adapters must keep their own independent fake key copy if later unwrap needs it. This is best-effort buffer hygiene, not guaranteed erasure of JavaScript-managed strings, JWKs, runtime copies, or host memory.

## Local validation

`npm test -- tests/private-provenance.test.ts tests/provenance.test.ts --maxWorkers=1 --minWorkers=1` passed 122 tests (71 synthetic regressions and 51 existing public-provenance tests). `npm run typecheck`, `npm run build`, and `git diff --check` passed. The synthetic suite exercises wire bounds, credentials, subject/run trust, trusted re-signed receipt substitutions, inner AEAD tampering, adapter failures, key-buffer cleanup, caller mutation, nonce/key freshness, and approval/audit acknowledgment ordering. These local results establish no AWS or deployed-broker guarantees. Required branch autoreview and independent implementation review are recorded separately at closeout.

## Remaining gates

This library is not a deployed broker. Trusted broker/runtime isolation, authenticated read-authority/delegation policies, exact IAM/OIDC policies, AWS adapters/configuration, real evidence categories, administrative ownership, real audit infrastructure, rotation/recovery operations, and required-check integration remain gated. Real data, production keys, cloud resources, and deployment are outside this approval. In-memory receipts and tests cannot establish remote capture, retention, or merge readiness. Issue #161 remains open for those capabilities and their approval/validation evidence.

The `jmcte-fixture-approval` test marker is fabricated reference data, not a selected production approver or authenticated authorization. Production read-authority identity and delegation policy remain unresolved.
