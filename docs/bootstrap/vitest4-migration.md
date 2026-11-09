# Development toolchain remediation stages

Governing issue: [#63](https://github.com/OMT-Global/bootstrap/issues/63). This document records Stage A preparation and the remaining Stage B work. Stage A is based on the published source-release prerequisite `e551f5a2180fdbee05d1d36141a9473b38e41a9a`. Complete review against that actual base and exact-head CI are required before readiness. No publication, merge, policy waiver or completed O2 remediation is implied.

## Stage A: compatible development dependency patches

Stage A retains Vitest 3.2.7 and the existing worker flags, scripts, Node requirement, CI templates and pins. Five explicit project-local npm overrides select compatible patched development dependencies: Vite 7.3.7, esbuild 0.28.1, PostCSS 8.5.23, NanoID 3.3.18 and source-map-js 1.2.2. Vite's parent update is necessary: the old Vite 7.3.1 esbuild range does not accept 0.28.1; Vite 7.3.7 does. Actual published parent ranges and the complete virtual graph were independently checked before source preparation. These pins require future maintenance when upstream compatibility or advisory data changes.

The complete package and lock update is 733 added/deleted lines measured by Git Myers, with every lock line included. It preserves all five direct production dependency ranges and all eight complete nonroot production lock records/integrities, unrelated direct development dependencies, package scripts/bin/engines, MIT LICENSE and existing notice bytes. Only the package/lock and factual inventory/migration documents belong to this stage. Managed outputs, ownership state and generated controls are not applied or imported.

## Remaining findings

The inherited baseline reported eight development dependency audit groups (one low, one moderate, four high, two critical). Stage A leaves three development-only groups: @vitest/mocker (moderate), tinypool (critical), and the vitest critical meta finding. Their four unique advisories are [GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9), [GHSA-qxg6-89mg-rqv8](https://github.com/advisories/GHSA-qxg6-89mg-rqv8), [GHSA-5gmw-xhrv-c9v3](https://github.com/advisories/GHSA-5gmw-xhrv-c9v3) and [GHSA-85c8-ppgw-ccpr](https://github.com/advisories/GHSA-85c8-ppgw-ccpr). The baseline and Stage A runtime-only audits report zero; these observations do not establish absence of vulnerabilities or complete behavioral reachability analysis. Registry results can change and must be timestamped at review.

## Local validation

Preparation uses the existing Node 20.20.2/npm 10.8.2 distribution and an isolated HOME, npm cache and empty user/global configs. Dependency installation is fixed-lock `npm ci --ignore-scripts --engine-strict --no-audit --no-fund` against the official registry, with no inherited auth/proxy/SSH-agent state. Package lifecycle scripts and Node/npm/global-tool upgrades are excluded; the locked development patches are under test. Real ordinary Git and ephemeral SSH fixtures are permitted; Docker/Linux confinement, native reviewer/provider probes and operator release actions are excluded.

Local checks passed on macOS arm64 using Node 20.20.2/npm 10.8.2:

- `npm run typecheck`, strict typing of the three current source-release/ownership test files, and `npm run build`.
- Full unchanged Vitest 3 suite with `--maxWorkers=2 --minWorkers=1`: 1,074 passed across 48 files, zero failed, 16 expected skips (15 opt-in Docker cases and one Linux-only filename case).
- Focused source-release/postpublish/ownership/publish/reusable suite: 115 passed across six files, zero skips.
- Built CLI `--help` and the existing built CommonMark statement-extraction import check.
- All 45 action pins, repository all-file scan, planned-parent whitespace check and `npm ls --all --json`.
- All 64 installed-package versions and independently rehashed official-registry tarballs match the lock; 49 optional platform packages remain uninstalled. Package, lock and LICENSE bytes were unchanged by installation.

The dependency graph is unchanged by this planned-parent refresh, so no new install, resolver or audit ran. The existing full and runtime audits were captured at 2026-11-09T08:12:34.064228+00:00: full audit exit 1 records the expected three development groups; runtime audit exit 0 records zero. Both commands used `--json --package-lock-only --ignore-scripts --audit-level=low`, with `--omit=dev` for runtime. Audit exit 1 is finding data, not a failed install or transport retry. The prepared package SHA-256 is `e03b1fe800e8141272969ae17a0899abf1a161d7330bbf5d6a6e7e2aeacc7dff`; complete lock SHA-256 is `359aeec053571c4b5ec154de4e19ee30e8316a71e6370cf010f9ee2a2ceabbb6`.

These results establish ordinary local compatibility at the planned parent. They do not prove Docker/Linux isolation or native reviewer/provider behavior. The formal actual-public-base model review and exact-head remote CI remain subsequent gates.

## Stage B remains separate

The reviewed resolver experiment reaches a zero full/runtime registry audit with Vitest 4.1.12 and the Stage A constraints, removes Tinypool/vite-node, and changes 611 complete package/lock lines relative to Stage A. That experiment does not authorize source adoption or establish runtime compatibility. Stage B needs an explicitly assigned source migration, actual source/config budget, Bootstrap-only worker flag adaptation through existing custom-script controls, unchanged downstream Vitest 2 defaults, complete ordinary Node 20 tests, strict test typing, build/CLI imports, genuine hosted full evidence and real managed-output/state derivation where required. No minimum-worker or shared template change is included in Stage A.

The source-release stack, its immutable callee pins, the approved 47 managed paths plus legal outputs/sidecar, and the frozen older broker-lane failure remain outside this dependency patch. No failure attribution or historical proof is rewritten by the new graph.

## Independent main-base refresh, 2026-11-09

The Stage A package and complete lock are now prepared independently on main commit `334272f8fb2d9e1b0e3de0739b3f44fc7c90eeb7`, without the unmerged #211 release-source changes. This carries the same five dependency overrides and all prior Stage A documentation. The `e551f5a` base, 1,074-test results and audit/package-install observations above are historical evidence from the original stacked #214 lane; they do not validate this independent checkout or describe a fresh audit. Fresh checks, audit observations, actual-base review and exact-head CI belong to the replacement PR's validation record.

One separate test configuration line sets Vitest's shared orchestration default to 15 seconds. Original test bodies, production phase/operation/download/cleanup and child-process limits, worker flags and the CI job deadline stay unchanged. The complete conservative package/lock/configuration diff is 734 added/deleted lines; documents remain included in review. Stage B and later dependency remediation remain separate work and are not replaced by this Stage A refresh. No release, settings, home, native-runtime or ownership-state apply is performed.


## Independent main Stage B migration

This Stage B source starts at accepted main `d68051b9` (the PR230 tree). The complete preceding Stage A document and PR230 addenda remain intact as history. The exact original PR216 package and full lock select Vitest 4.1.12/Vite 7.3.8 while retaining the other four override constraints. Tinypool/vite-node are absent; all eight production records and existing runtime ranges/scripts/bin/engines remain unchanged. The complete source/configuration delta is 637 additions plus deletions including all 615 lock lines; effective governance counts 22. No lock hunk is omitted from review.

Only Bootstrap's `ci.customScripts.fast` and `extended` lose the obsolete `minWorkers` option. The actual existing renderer derives the manifest, fast/extended scripts and sidecar; both adjunct workflows remove only that option. Worker maximums remain two/one. Node20.20.2, Ubuntu24.04, the Node20 focused five-file list, immutable image, native require flag, actions, permissions, ordering/failure propagation and job/child/product deadlines remain unchanged. The shared fifteen-second Vitest default and downstream generator defaults remain unchanged. The [versioned Vitest 4 migration](https://v4.vitest.dev/guide/migration) and [maxWorkers contract](https://v4.vitest.dev/config/maxworkers) describe the selected major. No Vitest 5 contract or new generator API is adopted.

### Actual repository-only producer sequence

A frozen accepted producer was built from this main source using official Node20.20.2 and an anonymous public-lock, lifecycle-disabled install. The actual built CLI doctor ran first under empty task HOME, reporting ten OK checks and the expected unauthenticated-GitHub warning. Direct `planRepo(await loadManifest(absoluteManifest), absoluteTarget)` then returned exactly 50 unchanged outputs/49 claims with owning state absent; no general CLI plan or invented repo-only flag was used.

After source-only backups and exact source/build/input/legal/mode guards, official `node <frozen-producer>/dist/cli.js apply repo --manifest <target>/project.bootstrap.yaml --target <target>` physically rewrote the 50 identical outputs and genuinely created this worktree's own state last. Its real replan returned 50 unchanged. An external manifest differing only by the two custom-script removals then produced an admitted four-update/46-unchanged plan. Official repo apply with that external manifest derived only the manifest, fast/extended scripts and sidecar, followed by another 50-unchanged fixed point. Only three of the same 49 claimed hashes changed; other 46 claims and all protected README/three release hooks/legal bytes and modes remain exact.

No state was copied or seeded. Observed absence, real producer execution and complete resulting bindings establish provenance; an identical historical digest alone supplies no authority. These producer events confer no test, model-review, hosted-CI or native qualification credit. Final doctor and direct fixed-point evidence must follow the new toolchain validation.

### Fresh validation and historical limits

The replacement PR records actual-head `bash scripts/ci/run-fast-checks.sh`, the two meaningful argv suites (`npm test -- --run tests/bootstrap-ci.test.ts tests/isolation-validation-entrypoint.test.ts --maxWorkers=2`), strict changed-test/config typing, build/CLI, pins, scanner, whitespace, complete installed graph and fresh full/production audits. Local execution excludes real Docker/full-profile/native qualification. The ordinary Darwin skips remain 15 opt-in Docker cases and one Linux-only filename case; eligible Linux CI runs the latter. No result is inferred before its command completes.

Original PR216 at `b13e1c0d841dd6d468be3433196591d3e9f21991` retains the earlier 1,074/48-file results, thirty inherited strict diagnostics, zero audits, tarball/graph observations and original `a1d4` state history. Those records are historical, not fresh proof for this main-based source. Its statements calling `9b77` current or dependency review inactive also describe the original stacked lane. Actual main retains release ref `913b298fab0fb008796011d940ee7362a347659d`, without the unmerged strong-preflight true flag. The existing 913 callee independently runs bare npm check after its validation hook; no package-script or cap rewrite hides that contract. This migration changes no GitHub settings.

Fresh full and production audits may report later residuals; retain and explain them rather than reusing old zero claims. Exact-head hosted functional/full evidence, complete actual-base autoreview, independent human approval and protected merge remain subsequent gates. No actual profile activation, provider/settings/home apply, release/tag or registry publication is included. Remaining issue 63 work stays separately tracked. See [ADR-0025](../decisions/ADR-0025-vitest4-development-toolchain.md).
