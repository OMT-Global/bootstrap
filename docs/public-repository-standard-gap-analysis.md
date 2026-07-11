# Public Repository Standard v1 gap analysis: Bootstrap

## Outcome

Bootstrap provides a credible foundation: typed Zod parsing, v1/v2 normalization, template rendering, managed-path selection, drift hashes, plan/apply separation, fleet reconciliation PRs, GitHub policy provisioning, security/release workflows, and tests. It does not yet resolve a pinned Flow policy or enforce the requested public-repository contract. The work should extend the control plane in capability-sized slices rather than replace the renderer wholesale.

## Baseline reviewed

This analysis is based on `origin/main` at `0b549f1` on 2026-07-11. The review covered `src/`, all tests and snapshots, generated artifacts, workflow sources/callers, release scripts and documentation, the CLI, GitHub provisioning, home-profile synchronization, and `project.bootstrap.yaml`.

## What Bootstrap already implements

| Capability | Existing source | Assessment |
|---|---|---|
| Typed repository input | `src/manifest.ts`, `src/types.ts` | Strong Zod/TypeScript base with current v1/v2 normalization; target v2 shape is incompatible and needs migration. |
| Plan/apply and state | `src/render.ts`, `src/state.ts`, `src/cli.ts` | Hash-based managed-file drift and preview/apply boundary exist. |
| Generated projection | `src/archetypes.ts`, render tests/snapshots | Renders guidance, issue/PR templates, CI, security, Dependabot, release, hooks, and code assets. |
| Fleet reconciliation | `src/fleet.ts` | Can inspect repositories and open drift PRs; lacks version-aware policy upgrade semantics. |
| GitHub governance | `src/github/provision.ts` | Applies settings, protections, labels, environments, and security features with planning. |
| Release automation | reusable/caller workflows and scripts | Strong governed path and evidence artifacts; policy pins, signing, provenance lineage, and when-ready semantics remain incomplete. |
| Lightweight AI evidence | AI attestation workflow/config | Useful precursor, but not the required signed public manifest plus encrypted private bundle. |

## Required gaps and conflicts

| Standard area | Current behavior | Required Bootstrap outcome | Breaking or migration impact |
|---|---|---|---|
| Flow consumption | Policy defaults are compiled into Bootstrap; reusable refs default to `refs/heads/main`. | Load a compatible exact Flow release/SHA and reject unpinned production policy. | Existing manifests need explicit pins and offline/cache behavior. |
| Manifest v2 | Current v2 retains v1 structure and adds capabilities/agent fields. | Target identity, project, policy, documentation, quality, security, agents, provenance, release, and exceptions model. | Cannot reinterpret `version: 2` silently; migration/version negotiation is required. |
| Repository classes | `application`, `library`, `service`, `tooling`, `documentation`. | Seven required classes and human-approved deviations. | `application` and `tooling` require guided mapping. |
| Maturity | Release automation uses `none/simple/governed/regulated`; no product maturity contract. | Separate Experimental through Archived product maturity and support state. | Field naming must prevent conflation. |
| Publisher abstraction | Owner and several `OMT-Global/bootstrap` defaults are embedded in generated content. | Central publisher key/config and replaceable product-led branding. | Snapshot and documentation churn; organization defaults need precedence rules. |
| Language profiles | Four archetypes and limited Node/Python CI detection. | Targeted TypeScript, Python, Rust, Go, Swift, Terraform, Shell, SQL/SQLite, documentation, and later Axiomlang profiles. | Additive profiles; detection conflicts must be reportable. |
| Generated ownership | State hashes track rendered files, but generated content lacks a universal marker/source/version/regeneration command. | Marker metadata and direct-edit detection/blocking. | Comment syntax differs by file type; binary/strict-format files need sidecars or exemptions. |
| README contract | README is rendered but not product-class aware or validated for word count/required sections/visual. | <=1,200 words and all required landing-page sections. | Existing READMEs may contain product-owned prose; migration must avoid data loss. |
| Required artifacts | Some guidance and workflows exist; many standard docs, provenance files, ADR index, and CODE_OF_CONDUCT are absent. | Class/profile-aware complete projection. | Must distinguish centrally managed from product-owned docs. |
| Pull request policy | Approvals and linear history exist; merge commits are allowed; no size/DCO/material-lineage gates. | Squash-only, DCO, thresholds/exclusions, material independent review, Conventional titles. | Commit history and bot commits need DCO migration handling. |
| Issue hygiene | Implementation template exists; no scheduled 30/90-day enforcement. | Complete ready contract and aging automation. | Existing issues need report-only rollout before closure automation. |
| ADR enforcement | No change classifier or ADR index validation. | Trigger detection, linked ADR checks, notification, and permanent-exception rule. | Heuristics need override/exception paths to avoid false blocks. |
| Security | Dependabot, secret scanning settings, security workflow, and release checks exist; actions are not uniformly immutable and code/SBOM/private reporting are incomplete. | Full required security projection, response policy, fork-safe validation, immutable action pins. | GitHub plan limitations need explicit results; pin upgrades need automation. |
| Conformance | Drift planning exists but no general human/JSON rule engine. | Stable rule IDs, severities, remediation, JSON, and blocking exit codes. | Existing doctor/plan output should remain compatible or gain a versioned format. |
| Provenance | AI attestation stores provider/model/prompt hash artifact; no signed public run manifest or private sink. | Schema, redaction, signing/verification, logical sink, encrypted bundles, S3 adapter, retention/audit docs, fail-closed gates. | Highest security risk; needs threat model and staged local sink tests. |
| Exceptions | No typed exception lifecycle. | Approval, scope, issue, rationale, ADR, warning, and expiration enforcement. | Existing deviations need inventory and temporary records. |
| Fleet upgrades | Opens generic reconciliation PRs. | Patch/minor/major policy upgrade behavior, notifications, review/ADR gates, dry-run inventory. | Must avoid unbounded fleet mutation and validate one repo per class. |
| Dogfood | Bootstrap's manifest uses `main` refs and allows merge commits; managed paths are empty. | Strict self-conformance with pinned versions, provenance, diagrams, security and conformance checks. | Must wait for resolver/projection support; use plan before apply. |

## Current strengths to preserve

- `plan` before `apply` for repository, GitHub, and home-profile mutations.
- Explicit `repo.managedPaths` selection and fail-fast companion-file validation.
- Deterministic rendering and snapshot/regression tests.
- Separation between repository rendering, GitHub provisioning, and home-profile synchronization.
- Draft PRs for fleet drift rather than direct changes to consumers.
- Clear non-zero failures for manifest parsing and managed-path inconsistency.

## Migration risks

- **Version collision:** current and target manifests both say v2. A schema/profile discriminator or staged v3 carrier may be needed before the final target name is adopted.
- **Destructive generation:** rendering README and policy files over product-owned content can lose information; migration needs ownership discovery and previewed diffs.
- **Self-hosting loop:** Bootstrap cannot require a policy release that does not exist yet. A checked-in immutable bootstrap seed with verified digest is needed.
- **Workflow supply chain:** replacing branch refs with SHAs improves security but needs an automated update mechanism and readable provenance.
- **False-positive ADR/material detection:** file-path heuristics alone are insufficient; PR declarations and evidence must be validated together.
- **DCO history:** enforcing sign-off on all historical commits would block every existing repository; enforcement should apply to contributed commits in the PR range.
- **Provenance secrecy:** private bundles can leak credentials through tool output unless allowlisted redaction and negative fixtures are comprehensive.
- **GitHub feature variance:** conformance must distinguish unsupported, misconfigured, waived, and passing controls.

## Independently mergeable implementation lanes

| Order | Bootstrap lane | Concrete outcome | Dependencies |
|---|---|---|---|
| 1 | Compatibility and resolved contract | Characterization fixtures, pinned Flow loader, target types, precedence rules, explicit current-v2 migration. | Flow policy bundle |
| 2 | Exceptions and notifications | Typed exception validation/expiry plus material-action and hard-stop hooks. | Lane 1 |
| 3 | Class and language profiles | Required repository classes, maturity, publisher defaults, language detection and toolchain resolution. | Lane 1 |
| 4 | Ownership-aware projection | Marker strategy and templates for README, AGENTS, contribution/security/conduct/license/CODEOWNERS, issue/PR forms, provenance docs, ADR index. | Lanes 1 and 3 |
| 5 | Conformance core | Human and JSON reports for drift, required artifacts, README/diagram, pins, exceptions, class/profile deviations, with stable exits/remediation. | Lanes 1-4 |
| 6 | PR, ADR, and issue gates | PR-size exclusions, DCO, title, independent review, ADR trigger declarations, and 30/90-day issue automation. | Flow rule IDs and Lane 5 |
| 7 | Security projection | Immutable actions, code/dependency/secret scanning, SBOM, private reporting, response policy, and fork-safe workflows. | Lanes 4-5 |
| 8 | Provenance | Public schema/generator/signing, redaction, encrypted bundles, logical sink, S3-compatible adapter, audit and fail-closed merge gate. | Lanes 1, 5, and threat model |
| 9 | Release projection | SemVer, Conventional Commits, immutable tags/pins, changelog proposal, agent publication, notification, and postpublish verification. | Lanes 1, 5, 7, and 8 |
| 10 | Fleet policy upgrades | Dry-run inventory and patch/minor/major upgrade PR gates. | Lanes 1-9 |
| 11 | Dogfood and migration pilot | Plan/apply Flow and Bootstrap, validate first representative repo per class, document outcomes. | All prior lanes |

The implementation-ready issue set is:

- [#54 resolved contract](https://github.com/OMT-Global/bootstrap/issues/54), [#55 exceptions and notifications](https://github.com/OMT-Global/bootstrap/issues/55), and [#56 class/language profiles](https://github.com/OMT-Global/bootstrap/issues/56)
- [#57 ownership-aware projection](https://github.com/OMT-Global/bootstrap/issues/57), [#58 conformance](https://github.com/OMT-Global/bootstrap/issues/58), and [#59 PR/ADR/issue gates](https://github.com/OMT-Global/bootstrap/issues/59)
- [#60 security](https://github.com/OMT-Global/bootstrap/issues/60), [#61 provenance](https://github.com/OMT-Global/bootstrap/issues/61), and [#64 release projection](https://github.com/OMT-Global/bootstrap/issues/64)
- [#62 fleet upgrades](https://github.com/OMT-Global/bootstrap/issues/62) and [#63 dogfood](https://github.com/OMT-Global/bootstrap/issues/63)

Every behavioral lane begins with failing tests. Each issue states problem, outcome, scope, non-goals, acceptance criteria, tests, security, documentation, dependencies, and human decision points. The larger projection, security, and provenance capabilities must land as small dependent pull requests within their issue; their acceptance criteria are not permission for a single oversized change.

## Recommended first slice

After Flow publishes the initial policy schema, implement Lane 1 only: characterize current manifests, resolve a pinned local policy fixture, and emit the read-only contract without changing rendered files. This is the smallest safe foundation for subsequent work.
