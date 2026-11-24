# OMT Global private repository baseline

**Policy version 1 · Accepted 2026-11-24**

## Scope

This baseline applies to active OMT Global private repositories. Use `project.bootstrap.yaml` to declare each repo’s ownership, class, applicable controls, and exceptions. Use the private profile for onboarding and drift checks. Apply approved stricter controls where a workload or data class requires them.

## Required controls

| Area | Requirement |
| --- | --- |
| Repository ownership | Name a responsible maintainer, use a valid root Bootstrap manifest, and record exactly which files Bootstrap owns. Review the generated diff before taking ownership of existing files. Keep first-party license and third-party notice decisions explicit. |
| Pull requests and CI | Use a PR for default-branch changes. Require at least one independent approval on the candidate being merged, code-owner review where applicable, and an approver other than the latest pusher. Require the repo’s declared CI checks, including `CI Gate` or an approved equivalent. Resolve blocking review feedback before merge. Reviewers verify and record any intentional required-check skip against policy. Material changes include the decision record required by the repo. |
| GitHub enforcement | Use branch protection or a ruleset wherever GitHub supports it. Require PRs, checks, and reviews, and prevent force pushes and deletion of the default branch where supported. Use the documented maintainer fallback below when GitHub’s plan prevents enforcement. |
| Workflow permissions and runners | Give each job the minimum token permissions it needs. Fork PR jobs run read-only on GitHub-hosted runners without secrets. Only trusted jobs from approved repositories and refs can use private runner pools. Match the pool to the workload. Shell-only jobs use the private shell pool when self-hosted. Required trusted native automation uses the matching self-hosted pool. Self-hosted container and browser jobs use dedicated pools with the matching capabilities. Pin third-party actions and reusable workflows to reviewed commit SHAs. |
| Security and secrets | Use a private reporting route, name a maintainer to triage findings, and use restricted credentials scoped to the job and environment. Require dependency inventory and vulnerability checks where the repo has supported dependency manifests. Require secret scanning and push protection where available. For unsupported scanning controls, record the capability evidence and use an approved equivalent that covers the same stage. A CI scan supplies detection evidence and does not enforce push-time blocking. |
| Deployments | Apply environment rules only where the repo deploys. Stage and production require one eligible human approver other than the initiator. Production deploys only from the default branch through an enforced environment or deployment system. When native branch or environment protections are unavailable, keep production deployment blocked until an approved equivalent can verify the exact commit passed the approved merge controls and received independent deployment approval. Record the exact commit or artifact and its approval. |
| Evidence | Keep private source, CI artifacts, security findings, and approval records within authorized private systems. Record the applicable profile version, default-branch SHA, CI and review evidence, settings readback, and any fallback or exception. |

Use Bootstrap’s [onboarding](onboarding.md), [managed-file ownership](managed-file-ownership.md), and [licensing](licensing.md) guidance for the shared controls.

## Maintainer fallback

When the GitHub plan demonstrably lacks a required merge control, an authorized maintainer verifies the current PR head and base, independent approval, required CI, and resolved blocking feedback immediately before merging through the PR. The maintainer records the head, review, and check links in the PR and verifies the resulting default-branch commit. Revalidate if the head or base moves.

Mark the control **verified by fallback** in the private inventory and show the GitHub enforcement gap alongside it. Maintainer verification does not prevent direct pushes or make the check atomic with the merge. An access error without plan evidence stays **unverified**. A supported control that is missing or misconfigured stays open for remediation.

## Exceptions

JMCTE is the policy owner and exception approver. The owner may delegate that authority in writing. Record the affected repository and control, rationale, compensating control, responsible maintainer, approval, governing issue, and expiry. Use Bootstrap’s typed manifest exception where the schema supports it. Link to a private record for sensitive details.

Limit temporary exceptions to **90 days**, with an explicit review before renewal. Expired exceptions block a conformant result. A permanent deviation requires an accepted decision record. Exceptions cannot authorize self-approval, secrets in fork jobs, or unreviewed production deployment. [Bootstrap exception guidance](policy-exceptions.md)

## Pilot and acceptance

Use the designated private pilot to exercise the merge fallback on an actual PR and verify any deployment gate. Keep repository-specific evidence in an authorized private system.

1. Pin the Bootstrap revision and validate the manifest. Read the current files and GitHub settings, then produce a plan that shows applicable controls and their evidence.
2. Review and merge any agreed repo changes through normal PR review. For approved settings changes, re-read live state after applying them. Exercise the fallback on a real PR if it applies.
3. Rerun the plan on the merged revision. Accept the pilot when managed files show no drift and every applicable control is verified through native enforcement, a permitted fallback, or a current approved exception. Record each outcome explicitly. Any unresolved or unverified required control keeps the repo pending. Review the pilot evidence before expanding to other repos.

Use a read-only assessment for initial inventory and periodic drift checks. Bootstrap’s current conformance command evaluates the public standard. Treat the private requirements as a pilot checklist until private conformance support exists. [Bootstrap conformance](conformance.md)

[Decision record](../decisions/ADR-0065-private-repository-baseline.md)
