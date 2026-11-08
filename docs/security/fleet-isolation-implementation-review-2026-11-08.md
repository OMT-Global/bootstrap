# Independent isolated-backend implementation review

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62). This is the backend stage described by [ADR-0013](../decisions/ADR-0013-isolated-node-validation-backend.md); it enables no fleet CLI, signing, push, PR creation, or live rollout.

On 2026-11-08 a separate software-architect reviewer who did not author these modules independently checked the implementation against the reviewed isolation design. No accepted/actionable source findings remained in that original snapshot or the later planned-identity/materialized-entry delta reviewed below. This records automated implementation review, not independent GitHub approval or successful Docker confinement.

| Original reviewed artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `df78c16d3e6e00e7b17ab1d8b17a779c000478539aa02a812e4365b757023a67` |
| `src/isolation/node-validation.ts` | `7cae2d4639dbdf427be5a4725b2ad4c00cf2563b8db3c8573ce1899e6010fbdb` |
| `src/isolation/setup.ts` | `4b97e1db58aa374c9604d304cfb023f6f1d7b61160c1b8c6f727be70973b1c40` |

The review checked explicit regular-file data inputs, strict public registry/integrity/size policy, immutable image selection, offline cache preparation, isolated environment/network/filesystem/resource controls, read-only prepared source/index, independent fresh hook/check phases, actual container exit-state inspection, bounded output, cancellation/cleanup, and aggregate dependency-preparation deadline. The `prepared-hook` phase binds the base and staged tree. The separate `final-check` phase verifies a supplied candidate's exact parent, raw UTF-8 message, and independently reconstructed source tree before running checks at that candidate as clean HEAD.

The backend performs no original-checkout or host Git operation. It returns evidence bindings, not authority for the future supervisor to sign an untrusted tree. That supervisor must independently construct/verify/sign the frozen raw tree and preserve its own reviewed credential boundary before publication.

Meaningful local regressions cover source/path/package/hook/archive boundaries and lifecycle faults. A trailing-slash regular-file path test initially failed and was fixed. Controlled-Docker-CLI tests exercise false-success container exit codes, partial creation/start failures, cancellation, the fixed watchdog deadline, output overflow, and cleanup failures. Those tests do not establish actual Docker enforcement.

At the original reviewed revision, ten actual Docker acceptance cases were required through the registered full-validation route or the later standalone manual workflow; the revised suite below contains twelve. They exercise fabricated operator environment/file/socket and host Git-configuration canaries, network isolation, immutable source/index, hook failures/mutation, exact final-candidate binding, actual cancellation cleanup, and Bootstrap's real locked offline checks. Local collection skips these cases; enabling the required flag fails on the unsupported local host rather than silently skipping. No local runtime or VM was installed or started. Image metadata and passing local tests do not establish runtime readiness: record actual image/tool/cache/adversarial results at the exact published implementation head before the backend is described as proven.

## Trusted Docker executable delta

Self-review identified an introduced boundary flaw in the initial Docker lookup: an absolute PATH entry could still belong to repository-controlled npm/direnv bins. A forged Docker program would execute on the host before any container existed. The corrected profile accepts only `/usr/bin/docker` or `/usr/local/bin/docker`, resolves its canonical path, and requires a regular root-owned executable and root-owned directory ancestry with no group/world write access. Missing or untrusted tools block; there is no PATH fallback or caller override.

The separate reviewer confirmed this narrow resolver delta clean at the then-reviewed historical controller hash above. Replacing only that resolver and its `stat` import reconstructs the original reviewed controller hash `0714d4a1d92d40a0cdfa65b124876d989a746bb1d3d93652e2ceffaa83c317cb`; the other modules are unchanged. The old resolver failed the controlled PATH-shadowing regression, and the fixed resolver passes. Unit transport substitution lives entirely in Vitest mocks; no production bypass was added. At that prior revision, local full validation passed 432 tests, with ten actual Docker tests explicitly skipped on the unsupported host. Hosted runtime evidence remains required.

## Planned hook context and materialized-entry delta

Status: independent narrow source delta review clean on 2026-11-08 at the exact hashes below; runtime evidence remains pending.

The supported context is now explicit: a normal root-directory, no-editor, all-prepared-files-staged, single-parent commit. A trusted supervisor must supply planned public author and committer name, email, and raw Git date with no defaults or inference from DCO text. Hook replay exports the prepared `.git/index`, empty `GIT_PREFIX`, `GIT_EDITOR=:`, both planned identities/dates, and a sanitized local Git user matching the planned committer. Final-check verifies exact raw author/committer headers as well as parent, message, and tree. A `commitPlanSha256` binds the shared plan fields across hook and final-check evidence. Partial commits, merges, amendments, editor sessions, and subdirectory-prefix contexts remain unsupported.

A real minimal-Git observation established the selected context and nested identity semantics; the old helper failed the regression for missing fields. New local profile regressions cover explicit identity validation, plan binding, and materialized bounds. The source inventory is bounded by 10,000 total file/directory entries and depth 32, rather than counting only files while allowing unbounded intermediate directories.

| Current independently reviewed frozen artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `2aace91c91e7cf1aa3ee30f04cd2eb4d2997072eef3c808a3df79f431ded8566` |
| `src/isolation/node-validation.ts` | `9a902ac496fc925b6d6ecff833f5c56cb715bb357122a0a0fcbd9ac4fc18a909` |
| `src/isolation/setup.ts` | `b08568193c419239a4e2b2399192caf9b2edff80942db807e3b3315f720e7701` |

Twelve actual Docker acceptance cases are now collected. The positive case checks the explicit hook environment, nested Git identities, conditional scanner marker, and plan hash across independently populated hook/final phases. Wrong author and committer cases join parent/message/tree rejection before target-check startup. The harness constructs an unsigned synthetic candidate with the exact planned identity environment; this does not claim a production signature. Strict test TypeScript and generated-probe syntax checks pass. Full local validation passes 514 tests, with twelve Docker cases explicitly skipped on this unsupported host; typecheck, build, 43 action pins, staged secret scanning, and whitespace checks pass. The required Docker flag fails closed; no local runtime was installed or started. The independent reviewer read the real-Git and materialized-entry failing-old/passing-fixed evidence and found no remaining actionable delta issue. Final branch autoreview and hosted confinement results remain separate gates before calling this revised implementation ready.
