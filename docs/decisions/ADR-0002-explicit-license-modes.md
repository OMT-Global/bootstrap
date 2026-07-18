# ADR-0002: Require explicit governed license modes

Status: Accepted

Date: 2026-07-18

Decision owners: Bootstrap maintainers

Decision record: [Bootstrap issue #86](https://github.com/OMT-Global/bootstrap/issues/86) and [Flow issue #26](https://github.com/OMT-Global/flow/issues/26)

## Context

Repository visibility is not a license grant. Bootstrap previously had no first-class contract for selecting an SPDX license or projecting an approved proprietary notice, which made it unsafe to automate licensing for private products. Replacing an existing license can also affect rights already granted and cannot be treated as an ordinary generated-file update.

Bootstrap needs a deterministic, ownership-aware contract that can support public open-source repositories and private proprietary products without choosing legal terms for maintainers or obscuring third-party obligations.

## Decision

Licensing is an optional, explicit manifest policy. Bootstrap will not derive it from repository visibility.

When configured, the policy must:

1. Select either a recognized SPDX identifier from the pinned list or proprietary mode.
2. Record a verified holder, effective year or range, and a regular UTF-8 repository-local template with no symlinked path components, pinned by its exact byte-level SHA-256 with an approval reference.
3. Keep third-party dependency, asset, font, media, and incorporated-source notices separate from the first-party notice.
4. Bind each SPDX template approval and rendered SPDX declaration to the one selected identifier, reject proprietary templates that contain SPDX declarations, and substitute approved tokens without rescanning legal metadata.
5. Treat adoption of an unmanaged license, any change to existing license bytes, or any managed legal-classification change as a hard stop until approver, issue, ownership, contributor, and distribution-history evidence is bound to the exact before/after modes and content hashes.
6. Preserve managed-file ownership and fail when a managed license is edited directly or unmanaged third-party notices would be overwritten.
7. Show the exact before and after modes in plan output before apply.

The proprietary mode is a projection mechanism only. This decision does not approve a legal entity, copyright holder, or proprietary template for any downstream product.

## Consequences

- New repositories remain unlicensed until maintainers make an explicit choice.
- SPDX identifiers are validated against a pinned dependency containing the recognized SPDX license list.
- Product migrations can be prepared mechanically, but legal holder and template approval remain human gates; deleted or directly edited managed licenses must be restored first.
- Existing open-source grants are not described as revoked; distribution-history evidence remains part of any prospective transition.
- Generated third-party notices are deterministic across host locales.

## Alternatives considered

### Infer MIT for public repositories and proprietary terms for private repositories

Rejected because visibility does not grant or reserve rights and cannot substitute for an explicit legal decision.

### Store first-party and third-party terms in one generated file

Rejected because it obscures which terms apply to incorporated components and increases the risk of overwriting product-owned notices.

### Allow license replacement whenever the rendered bytes happen to match

Rejected because the declared legal classification can change even when a template produces identical bytes.

## Security and privacy

Templates and evidence references must not contain credentials, private contracts, personal addresses, or unapproved legal contacts. Bootstrap validates structure and provenance but does not author bespoke legal terms.

## Rollout

1. Land the typed policy, projection, conformance rules, fixtures, and documentation through Bootstrap issue #86.
2. Dogfood plan-only migrations for Flow and representative private products.
3. Require repository-specific holder and template approval before any downstream apply.
4. Verify GitHub license recognition for SPDX repositories and the absence of unintended OSI/SPDX detection for proprietary repositories.
