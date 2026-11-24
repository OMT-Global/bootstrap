# ADR-0065 · Private repository baseline

Status: Accepted

**Date** 2026-11-24

**Decision owner** JMCTE, OMT Global

The owner approved the private repository baseline in the Bootstrap project conversation on 2026-11-24, including the maintainer fallback, runner and deployment boundaries, exception authority, and a pilot before expansion.

## Context

Flow publishes the Public Repository Standard. Private repositories share much of its governance intent and have different runner trust boundaries and GitHub plan capabilities. The fleet needs a consistent way to record those differences and distinguish verified enforcement from a compensating procedure.

## Decision

Adopt the [private repository baseline](../bootstrap/private-repository-baseline.md) for active private repositories. Require independent PR review, declared CI checks, trusted runner isolation, scoped secrets, and approval gates for stage and production. Use native merge controls where GitHub supports them. On plan-limited repositories, require an authorized maintainer to verify and record the candidate before merging.

JMCTE owns the policy and may delegate exception approval in writing. Temporary exceptions expire within 90 days. Permanent deviations require an accepted decision record.

## Consequences

Native enforcement and the maintainer fallback produce different evidence. The fallback cannot prevent direct pushes. Production stays blocked unless an enforced deployment gate can verify the exact approved candidate. Use the private pilot checklist until Bootstrap can evaluate the contract directly, then review the pilot evidence before expanding to other repositories.
