# ADR-0003: Keep issue hygiene report-first and human-decided

Status: Accepted

Date: 2026-07-18

Decision owners: Bootstrap maintainers

Decision record: [Bootstrap issue #59](https://github.com/OMT-Global/bootstrap/issues/59)

## Context

Long-lived issue backlogs need regular review, but automated closure can destroy context, hide unresolved dependencies, and turn an inactivity heuristic into a product decision. Repositories also need durable evidence that issue-lifecycle checks ran without granting scheduled automation mutation privileges.

Bootstrap already projects fork-safe pull-request governance. It needs a compatible issue-hygiene policy that reports aging consistently while preserving maintainer authority over closure and rescoping.

## Decision

Bootstrap will project a weekly and manually dispatchable issue-hygiene workflow with read-only repository permissions.

The workflow and reporter will:

1. Inventory every open issue through GitHub's paginated REST API and exclude pull requests returned by the issues endpoint.
2. Treat fewer than 30 inactive days as current, at least 30 days as a review proposal, and at least 90 days without a credible next action as a close-or-rescope proposal.
3. Recognize a next action only when its structured issue-body marker contains an outcome or evidence-shaped dependency, a valid future checkpoint, and a safe evidence reference.
4. Never comment, label, close, reschedule, or otherwise mutate an issue. Every close-or-rescope proposal requires a maintainer decision.
5. Retain a complete versioned JSON report for 30 days while bounding the human Markdown summary below GitHub's step-summary limit.
6. Exclude issue bodies and next-action outcomes from reports, escape untrusted Markdown fields, and reject evidence references that could retain credentials.
7. Fail closed when inventory, parsing, report generation, or artifact production fails.

## Consequences

- Aging is a review signal, not authority to discard work.
- Maintainers must explicitly close, rescope, or record a credible evidenced next action for old issues.
- Large repositories retain complete machine-readable evidence even when the human summary is truncated.
- Issue activity remains based on GitHub's `updated_at` timestamp; repositories can revisit that source if product-specific lifecycle signals become necessary.
- The workflow requires only `contents: read` and `issues: read` and is safe to schedule without write credentials.

## Alternatives considered

### Automatically close issues after 90 inactive days

Rejected because inactivity does not establish that an outcome is obsolete, a dependency is resolved, or retained context has no value.

### Add labels or reminder comments automatically

Rejected because report-first enforcement does not need mutation privileges, and automated comments or labels would change the issue timeline and its inactivity timestamp.

### Emit only a workflow summary

Rejected because GitHub bounds step summaries and a truncated human view is not complete audit evidence.

## Rollout

1. Project the workflow, reporter, and operator documentation only for repositories with issues enabled.
2. Run the report on schedule or by manual dispatch and inspect the retained JSON before acting on proposals.
3. Keep all mutation decisions manual until a later Accepted ADR explicitly changes this boundary.

## Security and privacy

The workflow uses no write permission and no untrusted-code execution. Reports contain only issue metadata, inactivity calculations, checkpoints, and validated evidence references; they omit bodies and outcomes. External evidence is restricted to canonical public GitHub issue, pull-request, and Actions-run URLs without userinfo, query strings, or fragments, preventing arbitrary capability URLs from entering retained artifacts.

## Revisit conditions

Revisit if GitHub changes issue pagination or step-summary limits, if repositories need a different inactivity source, or before granting any issue mutation permission.
