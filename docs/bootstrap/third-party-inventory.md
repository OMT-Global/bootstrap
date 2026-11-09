# Third-party inventory for the dogfood adoption review

Governing issue: [#63](https://github.com/OMT-Global/bootstrap/issues/63). Status: original six-record owner confirmation retained; four factual parser-dependency additions prepared for ordinary PR review. Repository projection and complete dogfood migration remain pending.

The original six-record inventory was captured from `package-lock.json` at `114149bc10a2a4c8da908bc5e6b2ed00f7abd5f9`, lockfile SHA-256 `427deeee262b41d70691d42b549c0d5e67c8ff881d3a327ea290128eeea51a92`. Its 135 package entries include four runtime dependencies, 57 installed development/build/test entries, and 74 entries not installed on the inspected platform. No dependency versions or legal files were changed in that original capture. The new [CommonMark statement workstream](security-response-markdown.md) adds the four runtime records below; the current lockfile is the authority for the resulting graph.

## Runtime dependencies

| Installed package | Package-declared license | Exact inspected legal file SHA-256 | Source |
|---|---|---|---|
| commander 14.0.3 | MIT | `04512a63dce4d2d506ad612dc0bd7681ccf6e3655f7b6eaef7dfac8323d1ec0b` | [commander](https://github.com/tj/commander.js) |
| spdx-license-list 6.12.0 | CC0-1.0 | `8cd7214d7e3455e136f3298b6be7cb7e5e105cd3299cfe22e5eb12161e50432c` | [spdx-license-list](https://github.com/sindresorhus/spdx-license-list) |
| yaml 2.9.1 | ISC | `5bba27375d93e9119f76c1015f7672cf9ad5f70952296e0842fb2243d6376869` | [yaml](https://github.com/eemeli/yaml) |
| zod 4.6.7 | MIT | `3f1189b28e3866e0d979968d466b78f813f76827cfdca1fbb124cc0a5c8841f8` | [zod](https://github.com/colinhacks/zod) |
| commonmark 0.31.2 (new direct) | BSD-2-Clause, with embedded component notices | `6cc4b9b28cf68e5bd20f9e94859a85cde35095ef4f9d0f7385b0b6166642f50b` | [official registry metadata](https://registry.npmjs.org/commonmark/0.31.2) |
| entities 3.0.1 (new transitive) | BSD-2-Clause | `cb992345949ccd6e8394b2cd6c465f7b897c864f845937dbf64e8997f389e164` | [official registry metadata](https://registry.npmjs.org/entities/3.0.1) |
| mdurl 1.0.1 (new transitive) | MIT | `6b6a356c4337e2446841f30f3cdf7e7023af8c5260b5e347c0f987b9f6aa2644` | [official registry metadata](https://registry.npmjs.org/mdurl/1.0.1) |
| minimist 1.2.8 (new transitive) | MIT | `435a6722c786b0a56fbe7387028f1d9d3f3a2d0fb615bb8fee118727c3f59b7b` | [official registry metadata](https://registry.npmjs.org/minimist/1.2.8) |

Actual legal files preserve the Commander/TJ Holowaychuk, YAML/Eemeli Aro, and Zod/Colin McDonnell notices and spdx-license-list's CC0 text. The original approved records retain the applicable texts and attribution; these package assertions are not an independent ownership or legal conclusion. Installed metadata for those original four packages declares no runtime dependencies. The exact new commonmark dependency resolves entities, mdurl, and minimist through the normal lockfile, without unnecessary direct dependencies or overrides.

The new records preserve each complete installed `LICENSE` file, including its final newline in the raw manifest; the existing manifest loader normalizes surrounding notice whitespace. commonmark is not an all-MIT package: its file contains the BSD terms, an MIT polyfill notice, and notices identifying upstream benchmark/spec materials. mdurl preserves both its initial MIT text and separate Joyent/Node notice. No upstream benchmark or specification fixtures are copied into Bootstrap. These four additions are factual dependency-review preparation under [ADR-0014](../decisions/ADR-0014-commonmark-security-response-statements.md), rather than a claim that the owner confirmed a new ten-record inventory.

## Incorporated Flow source

The policy snapshot comes from Flow release v1.0.1 at `504c79e59689f906a234e7145ee5752588b438b3`. That release tree has no LICENSE/NOTICE/COPYING file. Flow's current [MIT license](https://github.com/OMT-Global/flow/blob/669d095891a2fa2c9772735edf3e9cdf44c1214f/LICENSE) names OMT Global; its exact hash is `e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052`.

The policy Git blob `0867c061fba5e689394030821e898abf9db7edcc` is unchanged between the release and that current licensed source, and the local snapshot is byte-identical. The [Flow manifest fixture](https://github.com/OMT-Global/flow/blob/669d095891a2fa2c9772735edf3e9cdf44c1214f/project.bootstrap.yaml) reproduces current upstream with one source-attribution comment. Both are recorded as incorporated-source inventory entries. The current assertion and byte identity supported the owner's review; this document does not infer a historical license grant or copy Flow's repository-specific approvals to Bootstrap.

## Development and distribution scope

The original 57 installed development/build/test entries were inventoried separately. Vite, Vitest, and Rollup include bundled-component notices; TypeScript includes `ThirdPartyNoticeText.txt`. Preserve those full files if the corresponding distributions are shipped. Four installed entries lacked root legal files: the two installed platform esbuild packages, the platform Rollup package, and stackback. Noninstalled optional-platform entries have lock metadata only and require distribution-specific review.

The parser workstream adds exact development dependency `@types/commonmark` 0.27.10. Its complete installed `LICENSE` is MIT, 1,141 bytes, SHA-256 `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383` ([official registry metadata](https://registry.npmjs.org/@types%2fcommonmark/0.27.10)). It remains in this development inventory and is not one of the ten production notice records. If development tooling is distributed, preserve its complete applicable legal files and perform the corresponding distribution review.

The package is private, builds with TypeScript, and declares no code bundler. Current release artifacts are placeholder notes/metadata and contain neither dependencies nor a CLI package. A bounded repository search found no binary media/font/image assets; this is not a comprehensive rights audit. Generated archetype dependency references do not establish that those third-party implementations are incorporated here.

## Stage A development dependency patches

The #63 O2 Stage A update keeps the existing Vitest 3.2.7 family and patches only its compatible development build/CSS graph: Vite 7.3.7, esbuild 0.28.1, PostCSS 8.5.23, NanoID 3.3.18 and source-map-js 1.2.2. The package and complete lock came from the separately reviewed, anonymous official-registry resolution. All five direct runtime ranges, eight complete production lock entries/integrities, first-party MIT bytes and the existing ten production notice records are unchanged. This is factual development inventory preparation, not a new legal ownership confirmation or authorization to distribute development tools.

The resolved Stage A lock has 114 entries including the root; optional platform entries are metadata until installed on a matching platform. The isolated local Node 20.20.2/npm 10.8.2 install on macOS arm64 installed 64 packages (eight production and 56 development), leaving 49 optional platform entries absent. Every downloaded installed-package tarball was independently rehashed to its locked SHA-512 integrity; no missing nonoptional package or installed-version mismatch was found. Platform-specific counts do not establish installation or execution on Linux. The earlier installed-package counts above describe their original capture and are not this graph's inventory. Preserve complete Vite/Vitest/Rollup component notices and other applicable legal files if the development distributions are shipped; the lock's declared license fields do not substitute for a distribution-specific legal review.

Stage A intentionally leaves three inherited development-only npm audit groups: @vitest/mocker (moderate), tinypool (critical), and vitest (critical through its dependency findings). They cover four unique advisory IDs; the two critical groups do not mean two production dependencies are vulnerable. Runtime-only audit reports zero at the recorded observation. The later Vitest 4 migration must resolve the remaining groups and establish behavioral compatibility; this stage does not complete O2 remediation. See [the migration evidence and remaining gates](vitest4-migration.md).

## Adoption boundary

The owner-approved original inventory has six records: the original four runtime packages and the two Flow source records. The prepared current production inventory has ten factual records after adding four parser runtime dependencies. The four additions are ordinary PR-reviewed dependency attribution, not an extension of the owner confirmation. A separate development/build/test inventory is available for distribution review. The owner confirmed the prepared inventory and byte-identical MIT adoption on 2026-11-08 with “Yes confirmed”. No empty inventory or unknown future distribution is approved. This preparation does not apply the repository projection or create `THIRD_PARTY_NOTICES.md`. Neither that output nor an ownership sidecar existed at the addition boundary. If a target acquires existing notices before application, honor the actual unmanaged-output gate or exact SHA-bound `thirdPartyNoticesTransition` approval/reconciliation gate; do not reuse the original six-record approval or seed artificial state.

The [byte-identical MIT adoption record](bootstrap-license-adoption-proposal.md) documents the actual owner confirmation, exact approved license/template hashes, and Flow source attribution basis. Review the exact emitted notices, run doctor and a repo-only plan, preserve LICENSE bytes, apply only the authorized projection after the remaining ownership/config decisions, and verify idempotence/conformance. The Flow-first migration and live capability evidence remain required by #63.

## Independent Stage A refresh, 2026-11-09

The package and lock from #214 are being validated independently against main `334272f8fb2d9e1b0e3de0739b3f44fc7c90eeb7`. The Stage A installed-package counts, rehashed tarballs and audit results above remain timestamped historical observations; they are not fresh installation, current vulnerability-absence or new legal-ownership claims. The replacement PR records its own validation and audit results. This refresh preserves all production ranges, production lock records, existing legal outputs and the original inventory text; it does not import ownership state or include the unmerged release-source component.
