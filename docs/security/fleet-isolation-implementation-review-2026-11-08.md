# Independent isolated-backend implementation review

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62). This is the backend stage described by [ADR-0013](../decisions/ADR-0013-isolated-node-validation-backend.md); it enables no fleet CLI, signing, push, PR creation, or live rollout.

On 2026-11-08 a separate software-architect reviewer who did not author these modules independently checked the implementation against the reviewed isolation design. No accepted/actionable source findings remained in that original snapshot or the later planned-identity/materialized-entry delta reviewed below. Those clean snapshots and the reviewed runtime storage/dependency/logging delta precede the executable-mount delta and its remaining runtime gate below. This records automated implementation review, not independent GitHub approval or successful Docker confinement.

| Original reviewed artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `df78c16d3e6e00e7b17ab1d8b17a779c000478539aa02a812e4365b757023a67` |
| `src/isolation/node-validation.ts` | `7cae2d4639dbdf427be5a4725b2ad4c00cf2563b8db3c8573ce1899e6010fbdb` |
| `src/isolation/setup.ts` | `4b97e1db58aa374c9604d304cfb023f6f1d7b61160c1b8c6f727be70973b1c40` |

The review checked explicit regular-file data inputs, strict public registry/integrity/size policy, immutable image selection, offline cache preparation, isolated environment/network/filesystem/resource controls, read-only prepared source/index, independent fresh hook/check phases, actual container exit-state inspection, bounded output, cancellation/cleanup, and aggregate dependency-preparation deadline. The `prepared-hook` phase binds the base and staged tree. The separate `final-check` phase verifies a supplied candidate's exact parent, raw UTF-8 message, and independently reconstructed source tree before running checks at that candidate as clean HEAD.

The backend performs no original-checkout or host Git operation. It returns evidence bindings, not authority for the future supervisor to sign an untrusted tree. That supervisor must independently construct/verify/sign the frozen raw tree and preserve its own reviewed credential boundary before publication.

Meaningful local regressions cover source/path/package/hook/archive boundaries and lifecycle faults. A trailing-slash regular-file path test initially failed and was fixed. Controlled-Docker-CLI tests exercise false-success container exit codes, partial creation/start failures, cancellation, the fixed watchdog deadline, output overflow, and cleanup failures. Those tests do not establish actual Docker enforcement.

At the original reviewed revision, ten actual Docker acceptance cases were required through the registered full-validation route or the later standalone manual workflow; the then-revised identity suite contained twelve. The current storage delta expands that suite to fourteen below. They exercise fabricated operator environment/file/socket and host Git-configuration canaries, network isolation, immutable source/index, hook failures/mutation, exact final-candidate binding, actual cancellation cleanup, and Bootstrap's real locked offline checks. Local collection skips these cases; enabling the required flag fails on the unsupported local host rather than silently skipping. No local runtime or VM was installed or started. Image metadata and passing local tests do not establish runtime readiness: record actual image/tool/cache/adversarial results at the exact published implementation head before the backend is described as proven.

## Trusted Docker executable delta

Self-review identified an introduced boundary flaw in the initial Docker lookup: an absolute PATH entry could still belong to repository-controlled npm/direnv bins. A forged Docker program would execute on the host before any container existed. The corrected profile accepts only `/usr/bin/docker` or `/usr/local/bin/docker`, resolves its canonical path, and requires a regular root-owned executable and root-owned directory ancestry with no group/world write access. Missing or untrusted tools block; there is no PATH fallback or caller override.

The separate reviewer confirmed this narrow resolver delta clean at the then-reviewed historical controller hash above. Replacing only that resolver and its `stat` import reconstructs the original reviewed controller hash `0714d4a1d92d40a0cdfa65b124876d989a746bb1d3d93652e2ceffaa83c317cb`; the other modules are unchanged. The old resolver failed the controlled PATH-shadowing regression, and the fixed resolver passes. Unit transport substitution lives entirely in Vitest mocks; no production bypass was added. At that prior revision, local full validation passed 432 tests, with ten actual Docker tests explicitly skipped on the unsupported host. Hosted runtime evidence remains required.

## Planned hook context and materialized-entry delta

Status: independent narrow source delta review clean on 2026-11-08 at the exact hashes below; runtime evidence remains pending.

The supported context is now explicit: a normal root-directory, no-editor, all-prepared-files-staged, single-parent commit. A trusted supervisor must supply planned public author and committer name, email, and raw Git date with no defaults or inference from DCO text. Hook replay exports the prepared `.git/index`, empty `GIT_PREFIX`, `GIT_EDITOR=:`, both planned identities/dates, and a sanitized local Git user matching the planned committer. Final-check verifies exact raw author/committer headers as well as parent, message, and tree. A `commitPlanSha256` binds the shared plan fields across hook and final-check evidence. Partial commits, merges, amendments, editor sessions, and subdirectory-prefix contexts remain unsupported.

A real minimal-Git observation established the selected context and nested identity semantics; the old helper failed the regression for missing fields. New local profile regressions cover explicit identity validation, plan binding, and materialized bounds. The source inventory is bounded by 10,000 total file/directory entries and depth 32, rather than counting only files while allowing unbounded intermediate directories.

| Prior independently reviewed frozen artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `2aace91c91e7cf1aa3ee30f04cd2eb4d2997072eef3c808a3df79f431ded8566` |
| `src/isolation/node-validation.ts` | `9a902ac496fc925b6d6ecff833f5c56cb715bb357122a0a0fcbd9ac4fc18a909` |
| `src/isolation/setup.ts` | `b08568193c419239a4e2b2399192caf9b2edff80942db807e3b3315f720e7701` |

Twelve actual Docker acceptance cases are now collected. The positive case checks the explicit hook environment, nested Git identities, conditional scanner marker, and plan hash across independently populated hook/final phases. Wrong author and committer cases join parent/message/tree rejection before target-check startup. The harness constructs an unsigned synthetic candidate with the exact planned identity environment; this does not claim a production signature. Strict test TypeScript and generated-probe syntax checks pass. Full local validation passes 514 tests, with twelve Docker cases explicitly skipped on this unsupported host; typecheck, build, 43 action pins, staged secret scanning, and whitespace checks pass. The required Docker flag fails closed; no local runtime was installed or started. The independent reviewer read the real-Git and materialized-entry failing-old/passing-fixed evidence and found no remaining actionable delta issue. Final branch autoreview and hosted confinement results remain separate gates before calling this revised implementation ready.

## Continuous storage, fresh dependency, and daemon-log delta

Status: independent implemented source delta review clean on 2026-11-08 at the exact hashes below; actual hosted Docker proof and final branch autoreview remain pending.

| Prior independently reviewed frozen delta artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `585355fc0a51e60eff78ac83a45955564a19830ff89d8f3547c563029e563da4` |
| `src/isolation/node-validation.ts` | `fae9ff0f16f1e9a71cfab2eeb96e689c0c41d535a27f8c1bb70edbed6e2ef8c1` |
| `src/isolation/setup.ts` | `62c0e15743108f70d8fe2dce33bc4be540cf5607077cf1a345d6712b330cf1fb` |

The controller starts a trusted inert `-storage` container before data copy and keeps all three local-driver tmpfs volumes mounted through preparation and target execution. It checks keeper liveness before preparation, each phase, and successful evidence; workers are removed before the keeper and volumes. Both the keeper timer and host watchdog use the same absolute 60-minute backend-call deadline. Every created container explicitly disables daemon logs; the supervisor retains bounded attached output. Writable preparation creates reserved mount directories. Each fresh hook/check phase copies the pristine cache and performs its own locked offline install with lifecycle scripts disabled before invoking target code. The [design addendum](fleet-isolation-design.md#runtime-storage-dependency-and-logging-refinement) cites the relevant Docker/Moby contracts.

The revised Docker suite contains fourteen acceptance cases. The positive fixture imports the real locked public `picocolors` dependency in both phases without a repository install command, while its lifecycle sentinel remains absent. Two new short cases inspect the actual keeper/worker configuration and named local tmpfs volumes, kill the keeper while a hook/check is held, release the otherwise successful target, and require rejection plus complete cleanup. They prove storage-death handling once run, not natural 60-minute expiry. Actual Docker remains unavailable locally; no runtime or VM was installed or started. The integration file passes strict standalone TypeScript; local collection reports fourteen explicitly skipped Docker cases with the required runtime flag unset. The generated Node probe parses and the historical proposal prefix remains exact. Full local validation passes 520 tests, typecheck, build, 43 action pins, secret scanning, and whitespace checks. The independent reviewer confirmed the implemented delta clean after reading the old-controller four-failure negative control and the corrected keeper, expiry, logging, dependency, and cleanup checks. A committed WIP branch may now be handed off solely for exact-head hosted proof. A PR/readiness claim requires the actual hosted run and final autoreview to succeed.

## Installed dependency executable-mount delta

Status: independent implemented-source delta review clean on 2026-11-08 at the exact hashes below. Actual direct compiler-bin execution, kernel mount-flag assertions, complete exact-head hosted acceptance, and final branch autoreview remain pending.

| Current independently reviewed executable-mount artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `585355fc0a51e60eff78ac83a45955564a19830ff89d8f3547c563029e563da4` |
| `src/isolation/node-validation.ts` | `ff38857db0045c9a6e1fc081a0d26e24419571c9f9a3eeca74e2570705118ce5` |
| `src/isolation/setup.ts` | `62c0e15743108f70d8fe2dce33bc4be540cf5607077cf1a345d6712b330cf1fb` |

The diagnostic hosted [run 42513237799](https://github.com/OMT-Global/bootstrap/actions/runs/42513237799) at `6ee55af` reached Bootstrap's final-check target after successful hook replay, synthetic candidate construction, and offline dependency installation. Its remaining failure was `tsc: Permission denied`. This is partial evidence, not a passing runtime gate. The fixture's missing `.git/info` directory had been repaired explicitly, and test-only bounded pass-through spawn diagnostics preserved the real execution and failure while exposing the target error. The diagnostic regression passes using a real Node child with oversized output, ANSI/NUL, a fabricated redaction marker, and exit 23; it verifies bounded sanitized reporting and preservation of the original failure.

The independently reviewed implemented source change is confined to executable support on the fixed hook/check dependency tmpfs. An internal helper boolean defaults to non-executable; its `node_modules` call site enables execution, and every other Docker `--tmpfs` remains explicitly `noexec`. Sizes, ownership, `nosuid`/`nodev`, read-only source/index, network, privileges, credentials, resource bounds, and timeouts are unchanged. The positive fixture uses existing committed public lock metadata for TypeScript 5.9.3 alongside picocolors 1.1.1 and directly invokes `./node_modules/.bin/tsc --version` in both phases. Actual held hook/check tests inspect configured tmpfs flags and kernel mountinfo to constrain execution to the dependency tmpfs among these mounts. No production fallback, public capability option, project dependency, or node-script execution bypass is introduced. Strict standalone integration TypeScript, generated-probe parsing, and whitespace checks pass. The local scoped suite passes its real-child diagnostic regression and explicitly skips fourteen Docker cases; the original reviewed proposal prefix remains exact. Exact-head hosted results remain pending, and the profile remains unproven until the complete hosted suite passes.
