# ADR-0060: Implement approved private provenance control as inactive source components

Status: Accepted

Acceptance covers source implementation only; implementation review and production activation remain separate.

Date: 2026-11-15. Governing work: #161 and #63.

## Authority and scope

The owner approved all three decisions in the independently reviewed revision-2 design: explicitly submitted decision/review/validation summaries and enrolled Codex read authority; us-east-2, Governance, 90-day payload and separate 90-day audit metadata with JMCTE administrative ownership; and all changed PRs material with shared-head refusal and mandatory exact-PR maintainer revalidation before a later authorized merge. Read approvals are single-use and at most five minutes. JMCTE administers configuration/delegation, recovery, retention exceptions and audit oversight; the enrolled Codex workload remains the ordinary read approver.

The exact design manifest is SHA-256 `65a28732a4c0fab6f9a9a4fa29a11ca32623ea6944d1392d661b3dd103e8d82d`. Independent design review is SHA-256 `0090d97ff6b875eed45db5cf94da37730c0cf82b0fa3f66d67233be192365d9a`; owner source-only authorization is SHA-256 `a1738aae814e3ea0d83f5ca2b7c378f2584617e57992aca2c4068b1027fdc4d9`. Historical proposed ADR-0009 and synthetic-only ADR-0011 remain unchanged. The review and owner-approval records identify the accepted scope; this ADR does not reinterpret it as deployment permission.

## Decision

Add separate source APIs for canonical, purpose/owner-scoped Ed25519 read-control verification and an executable `createPrivateReadCoordinator` consumer. It verifies signed requester, delegation and Codex-approval records; binds requester, repository identity, current configuration epoch, purpose, exact subject/run/version/receipt, categories and expiry; consumes approval state conditionally; requires verified signed durable audit acknowledgments before loading and before returning plaintext; and revalidates only approved summary categories. A revocation can create a terminal tombstone before the first read, using the same deterministic delegation/approval key as initialization and consumption.

The conditional state store and authenticated observation/decrypt/audit producers are mandatory explicit ports. They are trusted fixed-runtime boundaries, not caller success booleans. This source component performs actual signature/context/state checks but does not authenticate a caller's supplied observation, implement OIDC/TLS identity acquisition, prove S3 persistence, or make fake test adapters production authorities. Fixed production composition must provide the separately authenticated current configuration pointer, enrolled requester identity, exact-version receipt/AEAD verifier, provider-enforced conditional writes and durable audit producer before activation. Missing composition remains an implementation dependency, not a successful gate.

The named consumers/producers and remaining boundaries are documented in `docs/bootstrap/private-provenance-read-control.md`. Existing public/private wire formats, cryptography and bounds remain intact; synthetic-only APIs and guards are not relaxed. No CLI, workflow, App, credential enrollment, AWS operation, configuration activation, real capture, external model transmission or merge permission is introduced.

## Tradeoffs and validation

A terminal spent/revoked/failed state is never refunded or reset. Lost acknowledgments fail closed; stuck reservations require exact-state reconciliation and a new approval rather than automatic takeover. Revocation after the spent authorization point cannot retract released bytes. Audit completion records authorization/decryption completion, not proof the recipient received the response. Cryptographic identity authenticates enrolled workloads, not a model persona. JavaScript plaintext clearing is best effort, not guaranteed host-memory erasure.

Use fabricated conditional stores, signed audit producers and ephemeral keys for meaningful concurrency, revocation, ambiguous-response, signature/scope, expiry, audit-order and leakage regressions. Repository typecheck/build/tests and required independent implementation review remain required. No IAM, live identity, remote retention, durable cloud audit or material merge enforcement qualification is claimed by local tests. #161/#63 remain open for the missing fixed consumers, live qualification and full acceptance.
