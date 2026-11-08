# Independent isolated-backend implementation review

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62). This is the backend stage described by [ADR-0013](../decisions/ADR-0013-isolated-node-validation-backend.md); it enables no fleet CLI, signing, push, PR creation, or live rollout.

On 2026-11-08 a separate software-architect reviewer who did not author these modules independently checked the implementation against the reviewed isolation design. No accepted/actionable source findings remained in that original snapshot or the later planned-identity/materialized-entry delta reviewed below. Those clean snapshots and the reviewed runtime storage/dependency/logging delta precede the executable-mount refinements and their remaining runtime gate below. This records automated implementation review, not independent GitHub approval or successful Docker confinement.

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

Status: historical dependency-only implemented-source delta independently reviewed clean on 2026-11-08 at the exact hashes below. The subsequent hosted result and explicit temporary-helper amendment are recorded in the next section; complete runtime acceptance and final branch autoreview remain pending.

| Prior independently reviewed dependency-only artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `585355fc0a51e60eff78ac83a45955564a19830ff89d8f3547c563029e563da4` |
| `src/isolation/node-validation.ts` | `ff38857db0045c9a6e1fc081a0d26e24419571c9f9a3eeca74e2570705118ce5` |
| `src/isolation/setup.ts` | `62c0e15743108f70d8fe2dce33bc4be540cf5607077cf1a345d6712b330cf1fb` |

The diagnostic hosted [run 42513237799](https://github.com/OMT-Global/bootstrap/actions/runs/42513237799) at `6ee55af` reached Bootstrap's final-check target after successful hook replay, synthetic candidate construction, and offline dependency installation. Its remaining failure was `tsc: Permission denied`. This is partial evidence, not a passing runtime gate. The fixture's missing `.git/info` directory had been repaired explicitly, and test-only bounded pass-through spawn diagnostics preserved the real execution and failure while exposing the target error. The diagnostic regression passes using a real Node child with oversized output, ANSI/NUL, a fabricated redaction marker, and exit 23; it verifies bounded sanitized reporting and preservation of the original failure.

The independently reviewed implemented source change is confined to executable support on the fixed hook/check dependency tmpfs. An internal helper boolean defaults to non-executable; its `node_modules` call site enables execution, and every other Docker `--tmpfs` remains explicitly `noexec`. Sizes, ownership, `nosuid`/`nodev`, read-only source/index, network, privileges, credentials, resource bounds, and timeouts are unchanged. The positive fixture uses existing committed public lock metadata for TypeScript 5.9.3 alongside picocolors 1.1.1 and directly invokes `./node_modules/.bin/tsc --version` in both phases. Actual held hook/check tests inspect configured tmpfs flags and kernel mountinfo to constrain execution to the dependency tmpfs among these mounts. No production fallback, public capability option, project dependency, or node-script execution bypass is introduced. Strict standalone integration TypeScript, generated-probe parsing, and whitespace checks pass. The local scoped suite passes its real-child diagnostic regression and explicitly skips fourteen Docker cases; the original reviewed proposal prefix remains exact. Exact-head hosted results remain pending, and the profile remains unproven until the complete hosted suite passes.

## Bounded executable temporary-helper amendment

Status: the coordinator adopted the explicit bounded amendment, and an independent architect confirmed the implemented-source delta clean on 2026-11-08 at the exact hashes below. Actual direct temporary-helper execution, updated kernel mount flags, complete exact-head hosted acceptance, and final branch autoreview remain pending.

| Prior independently reviewed temporary-helper artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `585355fc0a51e60eff78ac83a45955564a19830ff89d8f3547c563029e563da4` |
| `src/isolation/node-validation.ts` | `176bb99e19246280bbc25360428d7e33eeee2a80033cd45416ecdbbda6bea028` |
| `src/isolation/setup.ts` | `62c0e15743108f70d8fe2dce33bc4be540cf5607077cf1a345d6712b330cf1fb` |

The actual hosted [run 42514419157](https://github.com/OMT-Global/bootstrap/actions/runs/42514419157) at `3cd19549ab81eccdd23e6e311f84cc5f31847fef` executed all fourteen Docker cases, with thirteen passing and Bootstrap's full check failing. The diagnostic observer regression also passed, making fourteen passed and one failed of fifteen total. Direct locked compiler execution and the then-current dependency-only mount assertions passed. Bootstrap then reported fifty temporary-helper failures across six suites. Those partial results identify the next permission boundary; they do not establish readiness.

The amendment permits execution on the existing 256 MiB `/tmp` only in actual hook/check containers, alongside the existing executable dependency mount. Preparation `/tmp` remains 256 MiB and `noexec`; keeper `/tmp` remains 1 MiB and `noexec`; installer/cache/build tmpfs remain `noexec`. There is no quota increase, TMPDIR change, new mount, frozen-check change, or timeout change. UID, ownership, `nosuid`/`nodev`, capabilities, network isolation, read-only source/index, resources, cleanup, and code-owned capability selection remain fixed.

The shared positive probe now directly executes a fresh mode-0755 shebang helper under `/tmp` in both phases and verifies its phase argument and UID 1000, cleaning only its fresh directory in `finally`. It retains direct TypeScript-bin execution, package imports, lifecycle suppression, and host/source/index/socket/network canaries. Live Docker inspection and kernel mountinfo must show executable target `/tmp` and dependencies, non-executable target cache/build mounts, and non-executable keeper `/tmp`, with unchanged quotas and ownership. Strict standalone integration TypeScript, generated-probe/helper parsing, and whitespace checks pass. The scoped local suite passes the real-child diagnostic regression and explicitly skips fourteen Docker cases; the historical proposal prefix remains exact. New exact-head hosted acceptance remains pending, and the implementation remains unproven until the complete runtime gate passes.

## Six-tool immutable image amendment

Status: independent implemented source/config/test delta review clean at the exact hashes below after the coordinator adopted the material Microsoft-image/six-tool design. Actual new-image acceptance and final full-branch autoreview remain pending.

| Prior independently reviewed six-tool artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `faaba43ef0656d907fd217feb17fb424b8ae28969340ff7895a629d4ee88e0f3` |
| `src/isolation/node-validation.ts` | `bc69470ff0e3100bc39ddd5cf6af477382a176f0fa20f2d57b9194dc001f8a16` |
| `src/isolation/setup.ts` | `7b38153cb286a36cdd595f02bdf16d0b3cb45c77c55fd9ffc896949f7e4a4d3f` |
| `tests/isolated-validation-docker.test.ts` | `ac6bd4548eb0acfbcb5f72a207149c588b8ba0f22a551832262a649e6ab5a75e` |

The prior hosted [run 42515442371](https://github.com/OMT-Global/bootstrap/actions/runs/42515442371) at `bd9adb4` executed the compiler, temporary helpers, and Bootstrap checks; its remaining twelve failures were the real verifier's missing jq. This is partial evidence at the old image, not runtime acceptance of the new candidate. The amendment selects `mcr.microsoft.com/devcontainers/javascript-node@sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6` and adds explicit jq version/functional preflight alongside Bash/Git/Python/Node/npm. The [image record](node-npm-linux-v1-image.md) retains the observed Node patch difference, root/passwordless-development defaults, inherited public environment, OCI identities, and incomplete feature-material/signature limits.

The shared positive hook/check probe executes jq version and fixed JSON behavior, verifies kernel `NoNewPrivs=1`, and requires an actual `sudo -n id -u` process to fail without reporting UID 0. It keeps all compiler, temporary-helper, package-import, host/source/index/socket/network, mount, cleanup, and full Bootstrap cases. The report must include exactly six version fields. The manual workflow pulls the same immutable new image; action pins, permissions, and runtime boundaries are unchanged. Strict standalone integration TypeScript, generated-probe/helper parsing, manual-workflow structural checks, and whitespace checks pass. The scoped suite passes its real-child diagnostic unit and explicitly skips fourteen actual Docker cases. The original proposal prefix and four recorded source-snapshot hashes are verified; public OCI config inventory agrees with the research record. The independent reviewer checked the exact image agreement, six-tool/preflight ordering, failure regressions, documented image defaults/provenance limits, and bounded scoped renderer repair and found no remaining actionable delta issue. Local Docker remains unavailable; no runtime or VM is installed or started, and the new image is not yet proven.

## Historical complete runtime proof and public parent integration

[Full Release Validation run 42518271937](https://github.com/OMT-Global/bootstrap/actions/runs/42518271937) succeeded at exact head `4f3bcf72ac3a6176cc298a374e73d5474b82f857` on the GitHub-hosted `ubuntu-latest` runner, job `128845962529`. It passed the 526-test ordinary suite with fourteen explicit Docker skips, then the separate fifteen-case suite containing all fourteen actual Docker acceptance cases and the observer control. Bootstrap's frozen offline fast checks, typecheck/build, full wrapper, cleanup assertions, and reported evidence upload succeeded. This records complete runtime evidence for that historical implementation head.

The backend then incorporated the published public [PR #206](https://github.com/OMT-Global/bootstrap/pull/206) parent at `e40248bd057a04f53b18c48300be65cea829e5ce` through configured-signed, DCO merge commit `9a6d741d8641d5eed823dffc6c04f3af2de3af5c`. The merge preserved the three backend module hashes in the current review table. Its diff against that parent remains seventeen backend paths and 439 counted source/config lines.

The combined public tree passes 752 local tests with fourteen explicit Docker skips, typecheck, build, 45 action pins, source scanning, and whitespace checks. Doctor passes; the extended script is byte-identical to its current renderer projection and unchanged in the plan. Twelve other repository-plan entries remain unapplied. Complete hosted acceptance for this combined tree and final full-branch autoreview against the actual public parent are pending.

## Published managed-policy parent and final review base

[Full Release Validation run 42521019872](https://github.com/OMT-Global/bootstrap/actions/runs/42521019872) succeeded at exact public-parent integration head `6189e6e9dfef458a8520698aaf8e20f0ef98dce6`: 752 ordinary tests with fourteen explicit Docker skips, followed by all fifteen separate acceptance cases containing the fourteen real Docker cases and observer control. This is historical proof for that exact tree.

The backend subsequently merged the published, reviewed [PR #207](https://github.com/OMT-Global/bootstrap/pull/207) parent at `4d0a05ce70ce543549d51652893a0ad409f1cc00` through configured-signed, DCO merge commit `b7e2b266f14908c28d00c5738f60679d304fb854`. Its only integration adaptation passes `loadResolvedFlowPolicy` context into the backend entrypoint test's renderer call. The managed parent files and the three core backend module hashes are preserved. The intended backend diff against that actual parent remains seventeen paths and 439 counted source/config lines.

The final-base local gate passes 800 tests with fourteen explicit Docker skips, typecheck/build, 45 action pins, source scans, and whitespace checks. Doctor passes, and the extended script is byte-identical to its verified-context renderer projection and unchanged in the plan. Thirteen unrelated repository-plan entries remain unapplied. Exact final-base hosted acceptance and full-branch autoreview against `origin/codex/managed-security-policy` remain pending.

## Cleanup-completion lifecycle delta

The final full-branch review identified a lifecycle gap: the controller detached its whole-operation timer and caller cancellation listener before cleanup, so cancellation or deadline expiry during successful cleanup could still release success evidence. The coordinator accepted this correction within the existing backend lifecycle contract. On 2026-11-08 the independent architect reviewed the frozen source and regression delta below and found no remaining actionable delta issue. This is an automated source review, not GitHub approval or runtime proof of this changed controller.

| Current cleanup-reviewed artifact | SHA-256 |
|---|---|
| `src/isolation/node-profile.ts` | `faaba43ef0656d907fd217feb17fb424b8ae28969340ff7895a629d4ee88e0f3` |
| `src/isolation/node-validation.ts` | `5954a2e145cc0d4bb0fd1cd293e0e61138ff86adab24a5cfdffaaf1f608662e1` |
| `src/isolation/setup.ts` | `7b38153cb286a36cdd595f02bdf16d0b3cb45c77c55fd9ffc896949f7e4a4d3f` |
| `tests/isolated-validation.test.ts` | `2b4673d7908844d282c24c8c15932f3fad74298c13ac9b1e011e6f8c90113500` |

Cancellation and watchdog guards now remain attached through every independent cleanup attempt, including removal of the host transfer directory. Cleanup commands retain their separate 30-second budgets and receive no cancellation signal, so expiry cannot suppress later removals. Before releasing evidence, the controller checks the timeout latch, the absolute wall clock even if its timer callback was delayed, and caller cancellation. It preserves an earlier primary failure, appends any cleanup failure as secondary context, and always detaches the guards afterward. No public API, profile, authority, resource quota, or timeout budget changes.

Three controlled regressions hold a real fixture CLI child during keeper removal and separately trigger caller cancellation, a live watchdog callback, or elapsed wall time with an unfired watchdog. Each returned false success against the prior controller hash `bc69470ff0e3100bc39ddd5cf6af477382a176f0fa20f2d57b9194dc001f8a16`. The corrected cases reject success while requiring every container and volume removal, host-directory cleanup, and final guard detachment. All thirty focused lifecycle cases pass, including the existing success, cancellation, failure, and secondary-cleanup-error cases.

The full local gate passes 803 tests with fourteen explicit Docker skips, typecheck/build, 45 action pins, source scans, and whitespace checks. Doctor passes all eleven checks; the extended script remains byte-identical to its verified-context projection and unchanged in the plan, with thirteen unrelated entries left unapplied. The intended branch still has seventeen paths and 442 counted source/config lines. Earlier exact-head hosted results remain historical evidence; this changed controller requires a new exact-head hosted acceptance run and final full-branch autoreview against `origin/codex/managed-security-policy`.
