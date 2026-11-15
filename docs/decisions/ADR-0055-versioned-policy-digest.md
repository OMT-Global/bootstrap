# ADR-0055: Version Flow policy canonicalization

Status: Accepted

Date: 2026-11-12

Decision owner: OMT Global repository owner

Decision record: The repository owner accepted this versioned digest design in the Bootstrap project chat on 2026-11-12. Review, PR approval and consumer rollout remain separate.

Related issue: [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63).

## Context

The existing Flow policy digest sorts JSON object keys with the host's default locale. The same object can hash differently on different hosts. Changing the existing algorithm in place can invalidate already pinned digests, including pins outside the repositories inspected for this issue.

## Decision

Preserve existing locale-based behavior when `policy.flow.canonicalization` is absent. Permit an explicit `sorted-utf16-v1` value that sorts object keys recursively by JavaScript UTF-16 code-unit order, without Unicode normalization; keep array ordering and compact JSON serialization unchanged. A verifier uses exactly the selected algorithm and never silently retries another one. Unsupported values fail. `flowPolicyDigest` retains its legacy default and accepts the explicit algorithm for generating new pins.

## Consequences and migration

Existing pins keep their previous behavior and can still vary across locales. Operators must first deploy a Bootstrap version supporting the new field to **all readers and manifest writers**, independently verify the exact released policy, calculate its new digest with `sorted-utf16-v1`, and explicitly update both the mode and pin. The current old parser silently drops this nested field without reporting it as unknown; an old writer can therefore remove it on a manifest rewrite, and an old reader cannot enforce its semantics. In particular, matching digests for the current Flow policy do not establish that an old reader honors the new mode. Current Flow v1.0.1 has the same digest under both algorithms; this fact does not prove other policies are unaffected. No policy pin is changed automatically and no fallback makes a mismatched pin pass.

On 2026-11-12, a read-only scan returned 15 non-archived public OMT-Global repositories with no next page. Twelve root default-branch manifests were present and three absent; only Bootstrap and Flow explicitly declared `policy.flow`, both using the unchanged v1.0.1 digest. This point-in-time scan does not cover other branches, archived or private repositories, external consumers, non-root configuration, or later changes.

Independent review, actual-base autoreview, a versioned Bootstrap release and reviewed consumer migrations are separate. This change itself performs no release, policy-pin write, settings change or fleet rollout.
