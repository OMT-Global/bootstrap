# ADR-0007: Sign public provenance with Ed25519 envelopes

Status: Accepted

Date: 2026-09-24

Decision owners: Bootstrap maintainers

Material notification: [Bootstrap issue #61](https://github.com/OMT-Global/bootstrap/issues/61) and the implementing pull request

## Context

ADR-0006 deferred unifying the public schema with signed lineage to "a later issue #61 slice [that] defines canonical serialization, authenticated reviewer lineage, subject binding, and signature verification." Unsigned version-2 manifests validate shape, allowlist, and redaction, but a consumer cannot detect post-creation tampering, cannot bind a manifest to the repository/commit subject it expects, and cannot distinguish trusted signers from forgers (threat model TM-004). This slice must add no network-accessing dependencies, and the cosign/Sigstore keyless CI attestation remains a separate format produced only inside hosted workflows.

## Decision

1. A signed envelope (`envelopeVersion` 1) wraps a strict version-2 public manifest and carries an Ed25519 signature over a domain-separated canonical payload: canonical JSON with recursively sorted keys and no insignificant whitespace (`sorted-json-v1`) over `{ algorithm, canonicalization, domain, envelopeVersion, manifest, signedAt }`.
2. Keys are Ed25519 JWKs (RFC 8037) handled through `node:crypto`; there are no new dependencies and no network access. The envelope embeds the public JWK and its SHA-256 fingerprint, but trust is established only by matching that fingerprint against a caller-supplied trusted keyring.
3. Verification is fail-closed and ordered: strict envelope parse (version-2 manifests only; legacy version-1 downgrades and unknown fields rejected; at least one `approved` reviewer required), embedded-key-to-fingerprint binding, keyring trust, signature check against the trusted key rather than the embedded key, and optional expected-subject binding (repository plus immutable commit SHA).
4. Signing is library-level in this slice (`signPublicProvenance` / `verifySignedPublicProvenance` in `src/provenance.ts`); CLI and merge-gate wiring plus keyring distribution are deliberately left to follow-up work so gate semantics can be reviewed together with the material-gate acceptance criterion.
5. This decision does not authorize private sinks, encryption, retention, audited reads, or material merge gates; those remain behind ADR-0006's independent security review and explicit human approval gates.

## Consequences

- Consumers can verify integrity, signer trust, and subject binding of public manifests; tampered fields, transplanted signatures, substituted or untrusted keys, replayed timestamps, and version downgrades fail closed.
- Signatures authenticate the signer's claims: reviewer lineage remains caller-supplied until GitHub review retrieval lands, so the TM-003 gap (no authenticated GitHub review state) is narrowed but not closed.
- Keyring management is a consumer responsibility; an empty keyring trusts nothing.
- The canonicalizer and payload computation are exported (`canonicalizeProvenanceJson`, `signedProvenanceSigningPayload`) and deterministic across serialization boundaries.

## Alternatives considered

### Reuse the cosign/Sigstore keyless attestation format for local manifests

Rejected for this slice: it couples the local CLI to a network signing service, while issue #61 and the threat model call for canonical local signing and verification without new external services. The two formats stay separately documented.

### Sign raw serialized manifest bytes without domain separation

Rejected: bare manifest bytes are replayable across protocols and format versions. The domain-separated payload binds each signature to this envelope format and version.

### HMAC with a shared secret

Rejected: symmetric keys do not separate signing from verification; every verifying consumer would hold forge capability.

## Security and privacy

Private keys never leave the signer; envelopes embed only public JWKs, and the strict embedded-key schema rejects private key material (`d`) inside envelopes. Redaction is enforced before signing because signing re-parses through the version-2 schema, so credential literals cannot enter signed payloads. Verification errors identify the failed check without echoing payload contents. Keyring trust decisions are explicit caller input, never inferred from the envelope.

## Revisit conditions

Revisit when CLI or merge gates consume signed envelopes, when GitHub reviewer retrieval changes lineage semantics, before any remote private sink is enabled, or if algorithm agility beyond Ed25519 becomes necessary.
