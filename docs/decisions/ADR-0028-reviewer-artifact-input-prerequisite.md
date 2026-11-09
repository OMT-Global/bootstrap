# ADR-0028: Inert public reviewer artifact inputs

Status: Accepted

Scope: Public data prerequisite only. No verifier or runtime is activated.

Date: 2026-11-09

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

## Context

The reviewed artifact prerequisite at `771aa67e03bd5ecd56d3d7af279883d23b6edf39` contains verifier code and six captured public Sigstore JSON inputs. Integrating it with the reviewed release/toolchain parent `b13e1c0d841dd6d468be3433196591d3e9f21991` requires preserving the Vitest 4 command while retaining artifact verification. Its original natural source count is 798 lines; two generated managed-file hash replacements add four lines, making 802 against the repository's 800-line PR limit.

## Decision

Separate the six immutable public inputs as one coherent data prerequisite. Copy their bytes and Git modes exactly from `771aa67e03bd5ecd56d3d7af279883d23b6edf39`. The three candidate files remain complete readable 73-line indented UTF-8 JSON; the three `raw/` files retain the official converter's original one-line bytes. Their natural source count is 222 lines. No formatting, compression, truncation or exclusion changes reduce that count. The later verifier integration retains its complete semantic scope and has a projected natural count of 580 lines, including the four generated hash-change lines; its actual PR count must be checked after preparation.

Candidate files `scripts/ci/reviewer-artifact-bundles/{package,native,bwrap}.json` are the future fixed verifier inputs. The matching `raw/` files independently preserve public official-converter acquisition evidence and are never runtime candidates. The candidates preserve every parsed RAW member, type, ordering and proof/checkpoint, replacing only the existing signed-entry-timestamp leaf with the original SHA-pinned legacy bundle's SET. A strict parser and byte equality do not establish cryptographic trust. The future verifier must retain its independent pinned offline Cosign checks of the original SET and supplemental inclusion proof.

These are the previously captured public bytes from [preparation run 42543713399](https://github.com/OMT-Global/bootstrap/actions/runs/42543713399), not newly acquired inputs. That historical run at `3654fc2d8015a285d30fc53b31375b6aea07f2ea` recorded three successful offline signature checks and cleanup. This prerequisite independently checks the copied identities and their pure parser/normalization relationship; it performs no new signature verification.

| Artifact | Candidate bytes / SHA-256 | RAW bytes / SHA-256 |
| --- | --- | --- |
| package | 10474 / `2b02dffae24ea92c8dda61a466d2e182958272cd60272d4d5d4105ca6a5038f0` | 9770 / `b58fbbc748b7c2473903a4cf895339bc0a4a47a4596d22378c9f82d680887af8` |
| native | 10494 / `1c92b7154e5bbd76ec2b6b5fd4e7aeb5dedfdc862b619df22649a1443d37d67b` | 9790 / `2b12002aeb9f3ca20b6c52836da6c2e75db8041e9a5f955da8b77ebf51dd9dab` |
| bwrap | 10494 / `fbd20983759d802697db32d9c8fc2eb5f31edc3afad89ddbb95296b023f9f315` | 9790 / `8356e501c58b80758db8f226ebb5c2801b03666c85bc72d27a35bcdca1ec6da8` |

## Validation and limits

Validate exact bytes, regular-file modes and strict duplicate-free JSON against the existing reviewed verifier's pure audit and normalization functions, using the locally retained SHA-pinned public legacy bundles. Preserve all parent tracked files, the 49 managed-file records and their sidecar byte-for-byte. No new executable test duplicates the copy operation.

This change adds no verifier code, manifest, managed sidecar, dependency, hook, workflow or activation change. It performs no download, metadata preparation, native execution, provider request, authentication access or new Cosign run. Native reviewer support, complete review receipts and governed fleet execution remain unproven; issue #62 stays open. The later verifier PR must supply its own complete actual-base review and validation before activation.
