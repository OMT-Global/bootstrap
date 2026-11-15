# ADR-0052: Bind fleet pilot outcomes to a valid target

Status: Accepted

Date: 2026-11-12

Decision owner: OMT Global repository owner

Decision record: The repository owner accepted these pilot safety rules in the Bootstrap project chat on 2026-11-12. Review, PR approval and fleet rollout remain separate.

Related issue: [Bootstrap #62](https://github.com/OMT-Global/bootstrap/issues/62)

## Context

The non-mutating `upgrade-plan` uses the first sorted candidate in each repository class as a pilot and trusts the operator-provided pilot outcome. A pilot with an invalid version transition could claim `passed` and make a later candidate eligible. A passing pilot for one target version could also make a different target eligible. A failed pilot was reported as review-required even though its class batch stopped. Issue #62 requires a passing representative for each class before further rollout and a failed pilot to stop its batch.

Locale-sensitive sorting can also select different pilots for the same inventory on different hosts, causing one host to block a batch and another to consider it eligible.

## Decision

An invalid pilot remains blocked and cannot release the rest of its class. A recorded pilot failure blocks both that pilot and its class batch until remediation. A passing pilot applies only to the same target version, treating an optional leading `v` as insignificant. A later candidate with a different target is blocked and directs the operator to prepare a separate class pilot for that target. Pending and failed pilots continue to block the entire class, even when targets differ.

Order class and repository strings by JavaScript's locale-independent UTF-16 code-unit order before selecting the first candidate. Block every class containing an obviously duplicated repository in the inventory, even when duplicate rows have different classes. For this conservative check, compare repository strings after trimming outer whitespace and lowercasing; preserve the original strings in output. Do not treat this comparison as proof of remote repository identity or alias detection.

## Consequences

Rows previously reported eligible or review-required can become blocked; mixed-target inventories may require separate plans and duplicate rows must be corrected. This decision refines the pilot gate without changing the accepted [ADR-0049](ADR-0049-fleet-upgrade-inventory-validation.md) input validation rules: duplicate rows produce blocked plans instead of input rejection. It does not authenticate operator-supplied outcomes, verify repository or policy identities, detect remote aliases, create pull requests, or authorize a pilot or remote writes. Those are separate work. Required autoreview, independent GitHub approval and hosted checks remain separate gates.
