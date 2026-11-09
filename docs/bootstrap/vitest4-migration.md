# Node 20 development toolchain migration

Governing issue: [#63](https://github.com/OMT-Global/bootstrap/issues/63). Stage B is prepared on exact public [Stage A PR #214](https://github.com/OMT-Global/bootstrap/pull/214) commit `d387e78ae492f21fcbfc0f35395ba7c8a4de1f9c`. That reference is the actual public parent, not a claim that #214 is merged or that the complete dogfood/issue acceptance is finished. Root owns the source commit, formal review and publication gates.

## Dependency boundary

Stage A selected Vite 7.3.7, esbuild 0.28.1, PostCSS 8.5.23, NanoID 3.3.18 and source-map-js 1.2.2 while retaining Vitest 3.2.7. The paired Vite update makes the chosen esbuild version compatible with its declared parent range. Stage A left three inherited development-only audit groups; the prior baseline had eight.

Stage B adopts exact Vitest 4.1.12 and the complete frozen lock, retaining those five project-local constraints. Tinypool/vite-node are absent. The complete package/lock diff is 611 additions plus deletions; known final source/config changes total 629, including every lock line. All five direct production ranges, eight complete production records/integrities, unrelated development roots, scripts/bin/engines, MIT and notice bytes remain unchanged. No partial lock, forced out-of-range edge, global tool update or size exception is used.

Only Bootstrap's own `ci.customScripts.fast` and `extended` lose minWorkers, keeping maximums two/one, order, failure propagation, immutable image and native flag. The actual renderer derives the two scripts, manifest and sidecar. Both project-owned adjunct workflows remove only minWorkers; the Node20 focused five-file list, Node20.20.2 pin, Ubuntu24.04, actions, permissions and timeouts remain. Shared/default Vitest2 behavior, Vitest configuration, pool/concurrency settings, runner/resource policy and release pins are unchanged. The [versioned Vitest4 migration](https://v4.vitest.dev/guide/migration) and [maxWorkers contract](https://v4.vitest.dev/config/maxworkers), plus actual installed help/types, were checked; unversioned Vitest5 semantics were not used.

## Genuine local producer history

This feature worktree started with no owning state. Actual doctor returned ten OK checks and the expected unauthenticated-GitHub warning under isolated HOME. The real repo-only baseline plan was 50 unchanged outputs/49 claims. The real target plan rejected script updates from mutable sidecar-only authority; a render preview was not treated as an admitted plan.

After root reviewed the exact local command, 59 checked source-only backups and effects, the actual unchanged baseline apply created this worktree's own state: SHA-256 `21a430d47557106bf65edeb843dc266b3bce3af3dfb0ec9af9cc45f15f1868c2`, 50 bindings agreeing with 49 claims plus sidecar. Its real replan was 50 unchanged. The actual target plan then admitted four updates/46 unchanged. Root separately authorized the target source/local migration; actual repo apply derived only the manifest, fast/extended scripts and sidecar, updating real own state to SHA-256 `a1d4cbd65b096b8034c626ddc47ee9452cbe6376b923248ae2f0456577db74a7`.

Only three of the same 49 claimed hashes changed; the sidecar itself is the fourth managed update. All other 46 managed outputs and protected README/source hooks/legal data retain bytes/modes. Genuine fixed-point plans and actual state/binding receipts are captured. No other worktree's state, Git metadata, auth or home profile was copied; no manual sidecar/state hash edit created authority. This establishes this worktree's actual producer event, not a reconstruction of missing historical events elsewhere.

## Actual local checks

Used existing Node20.20.2/npm10.8.2 with empty task HOME/config/cache and no inherited auth/proxy/SSH-agent state. `npm ci --ignore-scripts --engine-strict --no-audit --no-fund` used the official registry. Package lifecycle hooks and Node/npm/global-tool upgrades were excluded; explicit build/test commands exercised the locked development patches.

- Full ordinary Vitest4 suite: **1,074 passed / zero failed / 48 files**; 16 expected skips (15 opt-in Docker cases and one Linux-only filename case).
- Focused release/ownership/workflow and own-command regressions: **131 passed / nine files / zero skips**.
- Root typecheck/build, strict typing of the two changed tests, CLI help/CommonMark import, 45 action pins, managed-shell syntax and complete installed graph passed.
- Full strict src/tests/test comparison found **30 inherited diagnostics in both Vitest3 baseline and Vitest4**, with byte-identical normalized output and **zero new diagnostics**. The actual changed-test strict check has zero errors. No suppressions/type weakening or speculative API adaptations were added; only the two intentionally changed own-script argv expectations needed edits.
- All 55 installed package tarballs/versions match the frozen identities. The virtual graph has 106 nodes including root, 152 dependency/peer edges, 133 present edges satisfying actual parent ranges and 19 absent optional peers; zero graph/engine/source errors.
- Fresh public-parent and candidate TypeScript5.9.3 builds produce 68 byte-identical production JavaScript/declaration files. All 34 source maps have equivalent mapping data and source contents; relative locations differ because the fresh baseline output is in TMP. The 24 default render/golden assertions pass with unchanged snapshots and shared generator sources.
- The pinned upstream actionlint1.7.7 Darwin tool was checksum-verified and extracted only into TMP; both changed workflows pass with baseline-identical empty diagnostics. No global install/PATH/config or repository dependency change was made for that verifier.

Full and runtime-only audits at `2026-11-09T09:26:18.249548+00:00` both exited zero with no reported findings. These are timestamped local graph observations, not proof of vulnerability absence. Stage A's three inherited groups are resolved in this prepared Stage B graph.

## Remaining gates

The complete 18-row acceptance matrix distinguishes local evidence from future checks. A final actual-base model review, new exact-head hosted/full-profile evidence, independent human PR approval and later authorized merge remain required. No Docker/Linux confinement, prlimit/prctl/Cosign/native reviewer/provider, CI dispatch, settings/home/cloud, release/tag or registry publication ran locally. The immutable 9b77 callee still independently runs bare npm check after its validate script; no cap or package-script rewrite hides that contract.

The dependency-review variable remains inactive/unverified under its existing decision; no provisioning/activation occurred here. No old C2 or broker531 runtime proof/failure is repurposed as evidence for this new toolchain. See [ADR-0025](../decisions/ADR-0025-vitest4-development-toolchain.md) and the [factual development inventory](third-party-inventory.md). Complete #63 and the overall issue-consolidation goal remain open until their remaining gates are satisfied.
