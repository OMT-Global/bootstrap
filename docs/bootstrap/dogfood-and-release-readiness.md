# Dogfood and release readiness

This records the remaining acceptance work for [#63](https://github.com/OMT-Global/bootstrap/issues/63) and [#27](https://github.com/OMT-Global/bootstrap/issues/27). A preparation PR does not complete either issue: #63 requires applied conformance in Flow and Bootstrap, and #27 requires a successful real release.

## Evidence baseline

Inspected on 2026-11-08:

- Bootstrap source: [`7bb026dce82996a30ea38428fa9919613e9977c7`](https://github.com/OMT-Global/bootstrap/tree/7bb026dce82996a30ea38428fa9919613e9977c7).
- Flow has a published immutable [v1.0.1 policy release](https://github.com/OMT-Global/flow/releases/tag/v1.0.1). Its [public repository standard bundle](https://github.com/OMT-Global/flow/blob/v1.0.1/policies/public-repository-standard-v1.json) declares policy version `1.0.0`; the release version and embedded policy version are distinct.
- Bootstrap's [release collection](https://api.github.com/repos/OMT-Global/bootstrap/releases) was empty. Its [workflow-dispatch run inventory](https://api.github.com/repos/OMT-Global/bootstrap/actions/runs?event=workflow_dispatch&per_page=100) contained only an Issue Hygiene Report, with no governed release runs.
- [Issue #27's last recorded preflight attempt](https://github.com/OMT-Global/bootstrap/issues/27#issuecomment-4978266464) failed before dispatch because its reusable reference was invalid. This is historical failure evidence, not a successful pilot.
- Flow's [current manifest](https://github.com/OMT-Global/flow/blob/main/project.bootstrap.yaml) restricts Bootstrap ownership to two issue forms and preserves product-owned policy and security guidance. Its existing licensing comments cite the stewardship decision in [Flow #26](https://github.com/OMT-Global/flow/issues/26).

Remote observations can change. Refresh the relevant refs, settings, reviews, and workflow results before applying or publishing.

## Changes prepared in this PR

Bootstrap now declares `policy.flow` for `refs/tags/v1.0.1` and loads the byte-preserved local snapshot in `policy/flow-public-standard.json`. The snapshot matches the file retrieved at source commit [`504c79e59689f906a234e7145ee5752588b438b3`](https://github.com/OMT-Global/flow/blob/504c79e59689f906a234e7145ee5752588b438b3/policies/public-repository-standard-v1.json). The public tag object is `6878b46c5e80a22a3acaa3ed550d307106c1ee7d`. This records an immutable source and verified content digest; it does not attest successful signature verification. GitHub reported the tag signature as `verified=false`, `reason=no_user` during inspection.

The Flow migration fixture comes from [`669d095891a2fa2c9772735edf3e9cdf44c1214f`](https://github.com/OMT-Global/flow/blob/669d095891a2fa2c9772735edf3e9cdf44c1214f/project.bootstrap.yaml). Offline migration tests preserve both repositories' non-policy contracts and selected generated outputs, including Flow's product-owned security and existing legal approval boundary. A changed bundle fails against the pinned digest. No broad ownership sidecar or applied-conformance claim is added.

Focused validation: `npm test -- tests/dogfood.test.ts tests/policy.test.ts --maxWorkers=1 --minWorkers=1` passed ten tests. Before adding the pin, the new Bootstrap resolution regression failed because `manifest.policy.flow` was absent.

## Dogfood acceptance matrix

| #63 acceptance | Observed status | Required evidence to finish |
| --- | --- | --- |
| No production workflow or policy pin targets `main` | Baseline workflow pins are immutable; this PR adds the Bootstrap policy pin; Flow adoption remains pending | Record exact compatible Flow and Bootstrap sources for both repositories; validate every production caller and resolved policy |
| Generated artifacts have ownership metadata and no direct edits | Bootstrap has no tracked `.bootstrap/managed-files.json`; Flow preserves narrow, explicitly declared managed paths | Review ownership inventory, resolve drift without discarding product-owned content, apply the authorized projection, and commit the sidecar |
| READMEs, diagrams, security, DCO, provenance, and conformance pass | Bootstrap's deterministic local conformance has two blockers; complete two-repository evidence is absent | Capture full checks and explicit artifact audits for each repository, including signed public provenance and applicable private-provenance gates |
| Live GitHub settings match the resolved contract | Not verified by local conformance | Capture authorized settings and capability observations, compare them with each resolved contract, apply scoped changes, and re-read live state |
| Flow-first plan/apply and migration outcomes recorded | No outcome record in #63 | Complete Flow before Bootstrap; record source/target SHAs, reviewed plans, exceptions, applied results, and CI links |

Read-only baseline command:

```sh
node --import tsx src/cli.ts conform --manifest project.bootstrap.yaml --target . --json
```

At the inspected Bootstrap baseline this returned exit `1`: seven passing results, seven unverified remote-capability warnings, and two blockers:

- `PRS-LICENSE-001`: `LICENSE` exists without an explicit license policy.
- `PRS-OWNERSHIP-001`: `.bootstrap/managed-files.json` is absent.

This conformance core does not establish the whole #63 contract. Its local success would still need README/diagram, DCO, provenance, applied-state, and live-settings evidence.

## Scoped migration sequence

1. Refresh both default branches and their open PRs. Inventory product-owned versus generated paths; preserve Flow's existing restricted ownership and Bootstrap's reviewed local conventions.
2. Run doctor, then plan for Flow. Resolve the compatible immutable Flow release with its verified bundle digest and review the exact manifest changes. A compatible policy pin alone requires no additional human hard stop under the existing issue authorization.
3. Preserve existing license terms and previously granted rights. Bootstrap's unmanaged MIT `LICENSE` requires explicit adoption evidence before adding a managed license policy, even if the rendered bytes remain identical. Use the existing [licensing contract](licensing.md) for the approved template, holder, exact before/after hashes, ownership/contributor/distribution evidence, and approving reference. Do not invent approval, change legal text, or copy Flow's repository-specific approval to Bootstrap.
4. Review the complete Flow plan, apply only the selected repository projection, then require an unchanged second plan. Capture conformance, applicable full tests, security CI, DCO, provenance, and remote settings. Any permanent exception or license/ownership change retains its explicit human gate.
5. Repeat doctor, reviewed plan, scoped apply, and idempotence for Bootstrap after Flow passes. Do not apply the broad default plan merely to create an ownership sidecar.
6. Record migration outcomes and any remaining fleet risks in #63. Close it only when every acceptance row has evidence for both repositories.

A disposable Bootstrap preview resolved the released Flow bundle with `flowPolicyDigest` to:

```text
ref: refs/tags/v1.0.1
policy version: 1.0.0
canonical SHA-256: 52877f4225a192c6ac2250a7f289f479be83a923ce15152c517db77ab0d5249d
```

The preview added a manifest-local, digest-pinned immutable snapshot and `policy.flow`, then called `loadResolvedFlowPolicy` and `planRepo`. Relative to the same baseline projection, only the rendered manifest and ownership sidecar contents changed. The committed snapshot is input data, not an editable replacement policy authority; updates must retrieve a released immutable source, recheck its digest, and preserve [ADR-0001's](../decisions/ADR-0001-public-repository-standard-v1.md) pinned-source boundary.

The baseline plan already proposed fourteen file changes, including README, AGENTS, CODEOWNERS, onboarding, and workflow updates. Those changes predate the candidate Flow pin and require separate inspection. No apply, home sync, legal-file change, GitHub setting change, or live repository migration was performed for this preview.

## Required GitHub evidence

Capture the seven controls accepted by the [conformance capability snapshot](conformance.md): code scanning, Dependabot alerts, Dependabot security updates, dependency graph, private vulnerability reporting, push protection, and secret scanning. Dependency-graph evidence must also record the verified `DEPENDENCY_REVIEW_ENABLED` activation state. Preserve `unsupported`, `misconfigured`, and `unverified` distinctions; a local pass is not remote verification.

Separately compare repository features, merge methods, branch protection/rulesets, required checks, approval/code-owner/last-push rules, reviewer targets, and environment branch/approval gates against the resolved manifest. Record API/CI evidence and observation time. Keep any sensitive capability material outside public repositories.

## Release caller readiness repair

The inspected repository uses restricted default workflow permissions. All four governed callers now explicitly delegate the permissions required by their pinned reusable workflows at the calling job, so dispatch does not depend on permissive repository defaults. Generated public preflight/validation callers request 90 days of evidence retention; private callers retain their 365-day request, subject to the configured repository limit. The old public 365-day request was misleading: the pinned `actions/upload-artifact` implementation warns and clamps excessive retention to `GITHUB_RETENTION_DAYS`; it is not by itself proof that upload would fail. These repairs still need a successful remote non-publishing preflight and validation before release pilot completion.

## Release pilot acceptance matrix

| #27 acceptance | Observed status | Required evidence to finish |
| --- | --- | --- |
| At least one exact tag completes the upgraded workflow | No governed release run recorded | Successful preflight, full validation, publish, and postpublish for one exact target SHA |
| GitHub Release has generated notes and expected assets | No Bootstrap GitHub Release | Release URL, reviewed notes, asset inventory, preflight-package checksum verification, and evidence artifacts |
| Floating tags move only after successful publish | No pilot evidence | Exact tag SHA plus before/after major and minor tag SHAs, showing promotion followed successful publication |
| Repo-specific gaps are logged | Earlier blockers have repair PRs | Record the final outcome in #27 and link any remaining gaps |

The [release train contract](release-train-contract.md) and [evidence schema](release-evidence-schema.md) define the execution order. Before publishing, choose the intended candidate version/channel and target SHA, check existing remote tags/releases, and verify that the exact tag will not be rewritten. The existing historical `v1.0.0` reference is not permission to move that tag or publish an unreviewed target.

Run preflight and full validation for the same target SHA, retain their run IDs and package, then create the exact tag and publish using those proven inputs. Verify release notes, assets/checksums, postpublish evidence, and floating tags. Record approvals and material-action notifications required by the repository's gates. Package-specific hooks and CI must actually exercise Bootstrap's TypeScript checks; generic placeholder artifacts are not evidence of a publishable Bootstrap build.

The requested consolidation PR can prepare and validate these changes. A release publication, tag mutation, or real two-repository rollout needs its concrete reviewed target and the applicable authorization; this document records no such completion or approval.
