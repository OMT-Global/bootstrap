# Third-party inventory for the dogfood adoption review

Governing issue: [#63](https://github.com/OMT-Global/bootstrap/issues/63). Status: factual preparation; inventory/distribution-scope and adoption approval pending.

The inventory was captured from `package-lock.json` at `114149bc10a2a4c8da908bc5e6b2ed00f7abd5f9`, lockfile SHA-256 `427deeee262b41d70691d42b549c0d5e67c8ff881d3a327ea290128eeea51a92`. Its 135 package entries include four runtime dependencies, 57 installed development/build/test entries, and 74 entries not installed on the inspected platform. No dependency versions or legal files were changed.

## Runtime dependencies

| Installed package | Package-declared license | Exact inspected legal file SHA-256 | Source |
|---|---|---|---|
| commander 14.0.3 | MIT | `04512a63dce4d2d506ad612dc0bd7681ccf6e3655f7b6eaef7dfac8323d1ec0b` | [commander](https://github.com/tj/commander.js) |
| spdx-license-list 6.12.0 | CC0-1.0 | `8cd7214d7e3455e136f3298b6be7cb7e5e105cd3299cfe22e5eb12161e50432c` | [spdx-license-list](https://github.com/sindresorhus/spdx-license-list) |
| yaml 2.9.1 | ISC | `5bba27375d93e9119f76c1015f7672cf9ad5f70952296e0842fb2243d6376869` | [yaml](https://github.com/eemeli/yaml) |
| zod 4.6.7 | MIT | `3f1189b28e3866e0d979968d466b78f813f76827cfdca1fbb124cc0a5c8841f8` | [zod](https://github.com/colinhacks/zod) |

Actual legal files preserve the Commander/TJ Holowaychuk, YAML/Eemeli Aro, and Zod/Colin McDonnell notices and spdx-license-list's CC0 text. A prospective notices projection must retain the applicable texts and attribution; these package assertions are not an independent ownership or legal conclusion. Installed metadata for these four packages declares no runtime dependencies.

## Incorporated Flow source

The policy snapshot comes from Flow release v1.0.1 at `504c79e59689f906a234e7145ee5752588b438b3`. That release tree has no LICENSE/NOTICE/COPYING file. Flow's current [MIT license](https://github.com/OMT-Global/flow/blob/669d095891a2fa2c9772735edf3e9cdf44c1214f/LICENSE) names OMT Global; its exact hash is `e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052`.

The policy Git blob `0867c061fba5e689394030821e898abf9db7edcc` is unchanged between the release and that current licensed source, and the local snapshot is byte-identical. The [Flow manifest fixture](https://github.com/OMT-Global/flow/blob/669d095891a2fa2c9772735edf3e9cdf44c1214f/project.bootstrap.yaml) reproduces current upstream with one source-attribution comment. Record both as incorporated-source inventory entries. The current assertion and byte identity are evidence for the owner's review; this document does not infer a historical license grant or copy Flow's repository-specific approvals to Bootstrap.

## Development and distribution scope

The 57 installed development/build/test entries were inventoried separately. Vite, Vitest, and Rollup include bundled-component notices; TypeScript includes `ThirdPartyNoticeText.txt`. Preserve those full files if the corresponding distributions are shipped. Four installed entries lacked root legal files: the two installed platform esbuild packages, the platform Rollup package, and stackback. Noninstalled optional-platform entries have lock metadata only and require distribution-specific review.

The package is private, builds with TypeScript, and declares no code bundler. Current release artifacts are placeholder notes/metadata and contain neither dependencies nor a CLI package. A bounded repository search found no binary media/font/image assets; this is not a comprehensive rights audit. Generated archetype dependency references do not establish that those third-party implementations are incorporated here.

## Adoption boundary

The proposed production inventory has six records: the four runtime packages and the two Flow source records. A separate development/build/test inventory is available for distribution review. No empty inventory is approved, and this document does not apply a license policy or create `THIRD_PARTY_NOTICES.md`.

Finish the [byte-identical MIT adoption proposal](bootstrap-license-adoption-proposal.md) only after the owner supplies the template/adoption approver, ownership/contributor/distribution review, intended distribution scope, and the applicable Flow grant basis. Then review the exact emitted notices, run doctor and a repo-only plan, preserve LICENSE bytes, apply only the authorized projection, and verify idempotence/conformance.
