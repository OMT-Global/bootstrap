# Bootstrap MIT license adoption

Status: owner-approved policy preparation; repository projection and full dogfood migration remain pending.

Governing issue: [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63).

## Approved result

The manifest now declares the existing first-party license as `mode: spdx`, `identifier: MIT`, holder `OMT Global`, years `2026`. The pinned [template](../../legal/mit-license.txt) renders every byte of the current [LICENSE](../../LICENSE), including its copyright line and final newline. Bootstrap's management classification changes from `existing-unclassified` to `spdx:MIT`; the published terms, holder wording, years, and historical grants stay unchanged.

Git history records the license's introduction in [commit b9e6b8eca06452ea27e3d00707ce935a28975da6](https://github.com/OMT-Global/bootstrap/commit/b9e6b8eca06452ea27e3d00707ce935a28975da6), “Add MIT license (#15),” on 2026-05-05. The legal file has no later tracked changes. That history records file provenance; the ownership and review declarations below are the owner's confirmation, not an independent legal assessment.

| Artifact | Exact SHA-256 | Bytes |
| --- | --- | ---: |
| Existing and rendered `LICENSE` | `e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052` | 1,067 |
| `legal/mit-license.txt` template | `0a6aa4a08352ee287faa69276561dc15e1c8a0929c2b2db34a56c7663250271a` | 1,092 |

The template replaces only the single byte sequence `Copyright (c) 2026 OMT Global` with `Copyright (c) {{copyright_years}} {{copyright_holder}}`. Every other byte stays unchanged. Rendering those tokens with the approved values reproduces the existing bytes and SHA-256 above. No SPDX header is inserted into the legal text; the manifest binds the template to `MIT`.

## Human approval record

In this Bootstrap task on 2026-11-08, the user confirmed “OMT Global is the entity.” The user subsequently answered “Yes confirmed” to the rights-review, byte-identical MIT adoption, and prepared six-record notice inventory approval. The manifest records that owner confirmation under `jmcte` for template adoption, ownership, contributor/assignment review, and distribution-history review. These are transparent owner declarations; no independent counsel, reviewer, or legal conclusion is invented.

The [licensing contract](licensing.md#existing-license-hard-stop) still enforces exact before/after hashes even when rendered bytes match. Removing the transition record, changing `LICENSE`, or changing the pinned template remains blocked. The transition records `existing-unclassified` to `spdx:MIT`, with the same `e512083a…` source and output hash. The approval authorizes this exact preparation; it supplies no new permission to overwrite unrelated managed content or change runner policy.

## Approved third-party inventory

The manifest contains six source records with complete inspected legal texts: Commander 14.0.3 (MIT), spdx-license-list 6.12.0 (CC0-1.0), YAML 2.9.1 (ISC), Zod 4.6.7 (MIT), the Flow policy snapshot, and the Flow manifest test fixture. The four runtime records retain their package license-file paths and exact SHA-256 hashes. CC0's tabs are escaped in YAML and restored by schema parsing, preserving every legal word and whitespace character in the notice text without triggering source indentation warnings. No license content is removed to reduce the diff.

Both Flow entries attribute the immutable, currently MIT-licensed source at [`669d095891a2fa2c9772735edf3e9cdf44c1214f`](https://github.com/OMT-Global/flow/tree/669d095891a2fa2c9772735edf3e9cdf44c1214f) and retain its complete OMT Global MIT text. The policy entry also records the v1.0.1 release commit `504c79e59689f906a234e7145ee5752588b438b3` and unchanged Git blob `0867c061fba5e689394030821e898abf9db7edcc`. This uses the identical content from a current licensed source; it does not assert a retrospective grant at the older release. The fixture's sole addition is its upstream-source attribution comment. Upstream repository-specific approvals remain test data and do not approve Bootstrap changes.

The factual [inventory preparation](third-party-inventory.md) describes the captured packages and distribution boundaries; it records the approval and remaining application/distribution boundaries. Development/build/test tooling remains a separate inventory. A future artifact that bundles such tooling or changes dependencies requires distribution-specific notice review; this six-record approval does not approve an empty inventory or unknown future payloads.

## Verification and application boundary

Four focused adoption regressions failed before the manifest policy existed and pass with it. They verify byte-identical projection, the complete six-record attribution output without writes, preservation of the actual installed runtime legal texts, immutable Flow attribution, the required adoption evidence, and rejection of changed license/template bytes. The manifest passes the existing schema; the pure `projectLicensePolicy` preview emits the existing license hash and separate notices in memory or disposable output only.

No `applyRepo`, ownership sidecar, repository notices projection, GitHub mutation, or home sync is performed by this preparation. `LICENSE` remains unchanged. No additional human legal fields remain pending for this exact approved preparation; the complete ownership/README/runner contract still requires its own review before a repo projection. Keep #63 open until the Flow-first application, idempotence, full conformance, and live capability checks pass.
