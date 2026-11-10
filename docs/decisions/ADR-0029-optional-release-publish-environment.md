# ADR-0029: Optional protected release environment

Status: Accepted

Date: 2026-11-09

Governing issue: [#27](https://github.com/OMT-Global/bootstrap/issues/27).

## Context

The generated publisher selects `release-publish`, but the manifest and GitHub writer previously modeled only `dev`, `stage` and `prod`. Unknown environment configuration was discarded. Reusing the legacy private-plan fallback could create a release environment without required protections.

## Decision

Support one optional fixed `environments["release-publish"]` entry, absent by default. Require one to six explicit reviewer targets, approval and self-review prevention, and a branch array containing only the configured default branch. Do not inherit global reviewers. Preserve existing environment defaults and fallback behavior.

The remote restriction is **all protected branches**, not a default-branch allowlist. Verify that the configured default branch exists and has classic protection. GitHub evaluates the workflow's `GITHUB_REF`; this restriction does not bind `inputs.tag`. Exact release target validation and final publication approval remain separate. [Deployment rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#deployment-branches-and-tags).

Use create-or-verify semantics. Resolve valid, unique typed reviewer IDs before any GitHub mutation. Matching existing modeled protections require no environment PUT, preserving additional remote protections. Conflicting policy requires a separate reviewed change. A captured canonical HTTP 404 is insufficient because authorization failures can mask an existing environment. Require a successful, validated complete list from the same runner/profile and exact repository before permitting a create attempt: fixed 100-item pages, at most eleven pages and 1,000 items, stable counts, unique IDs and case-insensitive names, and a short or empty terminal page. Any failure, incomplete or changing list, exceeded bound, or listed `release-publish` case variant stops without a release-environment PUT. Compare existing and readback fixed names case-insensitively while retaining every modeled protection check. Other transport, framing, parsing and status failures stop; error text containing `404` does not establish absence.

Creation makes one protected PUT, then verifies the returned environment through a new GET and rechecks default-branch protection. Never retry with a weaker payload. Unknown write or verification outcomes may be partial and require inspection, without automatic cleanup or rollback.

The API is create-or-update, without atomic create-if-absent. Coordinated trusted configuration writers are required. Administrators can change or bypass policy; observation does not establish an unbypassable or permanent boundary. A future operation packet must record administrator-bypass policy and current protections. [Environment API](https://docs.github.com/en/rest/deployments/environments#create-or-update-an-environment), [administrator bypass](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#allow-administrators-to-bypass-configured-protection-rules).

## Scope and validation

The independently reviewed design enables source preparation only. Bootstrap's actual manifest leaves this entry absent. No reviewers, settings, release target, tag, assets or publication are selected here. No arbitrary environment names, custom branch/tag policy CRUD, publisher-pin changes or environment-only CLI target are introduced.

Regression coverage must prove declaration retention, strict local validation, captured-status handling, identity resolution before writes, create/verify/conflict behavior, readback failures and unchanged legacy behavior. Compare all default managed outputs, doctor results and repository plans against the parent. Use fabricated identities and captured response fixtures; local tests do not verify live protections.

See [operator guidance](../bootstrap/release-publish-environment.md) for the separate configuration and publication boundaries. Issue #27 remains open until its actual release acceptance evidence exists.
