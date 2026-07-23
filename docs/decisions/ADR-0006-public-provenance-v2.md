# ADR-0006: Make public provenance version 2 fail closed

Status: Accepted

Date: 2026-07-23

Decision owners: Bootstrap maintainers

Material notification: [Bootstrap issue #61](https://github.com/OMT-Global/bootstrap/issues/61) and the implementing pull request

## Context

Public provenance version 1 accepts arbitrary metadata keys and relies on credential-pattern detection. That is useful as an initial redaction foundation, but it cannot establish that public output contains only intentionally public fields. The local public manifest is also distinct from the existing cosign-signed AI attestation workflow, and private encryption, remote sinks, audited reads, retention, and fail-closed material gates are not implemented.

The confirmed security boundary permits only schema-allowlisted metadata in public output. Private model and tool evidence may be sensitive, literal credentials are prohibited from every output, remote storage must use short-lived OIDC with separate read and write roles, and production sink use requires independent security review plus explicit human approval.

## Decision

1. New public provenance manifests use schema version 2.
2. Version 2 uses strict object boundaries and permits only `policy`, `generator`, `aiProvider`, `aiModel`, `promptHash`, and `changeClass` metadata keys.
3. Default creation and validation are version-2-only. Historical version-1 artifacts are available through an explicit strict compatibility reader and cannot satisfy a current publication or merge gate.
4. Credential-shaped identity values fail validation. Allowlisted metadata is redacted to a typed placeholder, and the recorded replacement count must match the emitted placeholders exactly.
5. The output bound accounts for worst-case redaction expansion while input remains bounded.
6. This decision does not authorize a private sink, choose a storage provider, expose private data, approve retention exceptions, or claim that public schema output is signed.

## Consequences

- Consumers constructing current manifests must use the exported current schema version and migrate intended public metadata into the allowlisted fields.
- Safe historical version-1 artifacts remain readable, but callers must opt into that path and cannot pass them to the default publication validator.
- The public schema and the signed AI attestation remain separate until a later issue #61 slice defines canonical serialization, authenticated reviewer lineage, subject binding, and signature verification.
- Remote encryption, storage, retention, read auditing, and merge blocking remain independently reviewable work.

## Alternatives considered

### Tighten version 1 in place

Rejected because previously valid arbitrary metadata would silently change meaning under the same version.

### Let the default validator accept versions 1 and 2

Rejected because a caller could select version 1 to bypass the current allowlist.

### Remove version-1 support

Rejected because historical artifacts can remain safely readable through an explicit non-publication path.

## Security and privacy

Pattern detection is defense in depth, not a classifier for arbitrary private material. Logs, prompts, tool output, customer data, encryption material, credentials, and physical sink configuration must not be passed to the public generator. The repository threat model in `docs/security/bootstrap-threat-model.md` governs follow-up design and review.

## Revisit conditions

Revisit when the signed public format is unified with the local schema, before enabling any private remote sink, or if the allowlisted public fields require a breaking change.
