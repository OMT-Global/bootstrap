# ADR-0024: Fleet upgrade admission and offline approval authentication

Status: Accepted (admission and authentication prerequisite only)

- Date: 2026-11-09
- Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62)

Acceptance is limited to the shared admission and authentication prerequisite.

## Context

The future fleet supervisor needs one cumulative process-wide resource owner and independently authenticated installation and storage approval statements. Creating a fresh journal budget or treating parsed configuration as an executable permission would break that boundary.

The technical source contract is J0 binding freeze v3, SHA-256 `67368fb293cb9fe3fbf9f1c74290d44924993b754b7d9f323a23deb882612d4e`. Its independent closure, SHA-256 `39a59b206c2211b8baa053c6567bf817b39771d0f3f2a596afd82c9392203617`, records design review. Neither digest is source approval, a selected installation, hardware evidence or runtime proof.

## Decision

Add two private modules, absent from the package index and CLI. Admission accounts own retained logical debt in one strong pool in the canonical JavaScript global with the existing 2 GiB ceiling. The producer registers accounts and charges before dependent allocations. Closing an account revokes new charges without returning credit; failed preflights, uncertain allocations and returned data remain charged. No reset, deserialization, GC release, caller cleanup callback or independent journal counter exists. An account is resource bookkeeping and conveys no execution authority.

The canonical admission module establishes a non-configurable producer anchor on that global. Alternate module URLs and an unrecognized existing anchor fail closed instead of constructing a second pool in it. Copies of account data cannot become registered accounts. This module does not attest or coordinate worker threads or VM realms; supported single-global use remains part of the separate trusted-startup gate.

Approval authentication reads only `/etc/bootstrap/upgrade-journal/approved-installation.v1.json` and the fixed evidence directory. The closed bounded format requires exact canonical UTF-8 JSON, known fields, safe integers, strict inventory identities and internal digests. Duplicate keys, invalid encodings, unknown fields, malformed signatures and inconsistent evidence fail closed. The two ordered Ed25519 signatures cover the same complete payload with the fixed domain separator. Installation and storage approval roles require distinct code-pinned keys. The production anchor registry is empty; no caller path, key, profile, boolean or environment override can activate it. Root ownership protects the selected files and never substitutes for independent approval.

The actual producer returns an opaque `AuthenticatedApproval` fact associated with its private record. It reports only authenticated statements. Rechecking the active fixed selection cannot refresh an epoch or restore a poisoned association. Parsed JSON, copied facts and serialized capabilities do not create a registered fact.

Authentication does not inspect or attest the running installation, loaded dependencies, device, mount, hardware durability or trusted startup ordering. It cannot create `ApprovedInstallation`, an executor invocation, a durable journal boundary or a publication permit. A later private producer must consume the genuine association, perform the reviewed real measurements and trusted startup checks, and establish its own authority.

## Consequences and remaining gates

This stage supplies real authentication and accounting while keeping the remaining production ports unavailable. The approved builtin-only startup, complete installed-code measurement, concrete Linux storage measurement, fixed child launcher and strong recovery producer, Python journal and private ACK, independent cleanup support and actual native proof remain separate gates. B and future attempt wrappers must reuse this pool; their integration is unproven. No new cleanup deadline, approval TTL, neutral-review time cap or authority renewal is introduced.

The full 28 requirements, seven C2 helper baselines, two authority phases, uncapped complete installed-helper review and final executor/publication end state remain the governing contract. Synthetic files, test keys, source-copy harnesses and mocked lifecycle tests provide regression evidence only. Production has no test-key selector or synthetic activation route. Real key enrollment, storage approvals, provisioning and deployment require their own authorized review.

Measure the complete natural production diff against the actual C2 base. If it exceeds 800 lines, split only at a complete producer boundary; do not compress code, omit checks or hide shipped logic in tests. This stage does not activate a CLI flow or claim that issue #62 is complete.
