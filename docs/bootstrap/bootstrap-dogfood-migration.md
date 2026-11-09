# Bootstrap local dogfood migration

The owner-approved repository-only migration for [#63](https://github.com/OMT-Global/bootstrap/issues/63) selects 47 generated paths plus LICENSE and THIRD_PARTY_NOTICES.md. The generated ownership sidecar binds those 49 outputs; genuine local state also binds the sidecar, for 50 managed outputs in total.

README.md and scripts/release/{prep,build,postpublish}.sh remain project-owned, unselected and byte/mode-identical. The current AGENTS review rule and `* @jmcte @athena-omt` CODEOWNERS line are preserved exactly. Ordinary hosted CI selects Ubuntu 24.04; governed reusable release runner/input contracts retain their existing pin and behavior. The postpublish-required-preflight opt-in remains absent.

## Application evidence

Flow was applied first at reviewed Flow PR39 source `45746f4e384ba64bc61ce22a765d47d88e15c776`, using Bootstrap PR206's renderer, and reached the same unchanged five-output projection both in its feature worktree and an independently created clean public clone. No prior authentication or local state was copied; all 83 tracked Flow files stayed unchanged.

Bootstrap application used a separate feature worktree and a fresh owning git-admin state path. Doctor passed, the exact plan was reviewed, existing changed targets were backed up, and a genuine first repository apply installed the reviewed 50 outputs. It preserved the first-party MIT LICENSE exactly:

`e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052`

That first real application exposed the retained-class-record reload bug. The narrow normalizer correction restored the original selected class/history and two unchanged plans without another application or any manual state/sidecar write. The original first-installed bytes and genuine state remain recorded separately in the task's validation evidence.

Strict whitespace validation then exposed literal TABs in the YAML encoding of an existing CC0 notice. A reviewed serializer correction escapes only TAB-bearing scalars while preserving every parsed/normalized value. After backing up the two outputs and existing genuine state, a second real apply changed only the manifest representation and derived sidecar. Final installed hashes are:

| Artifact | SHA-256 |
| --- | --- |
| project.bootstrap.yaml | `944358102c8ed2fd45f976848d9666e13d0caf2938ec680d9fdff9517a5cce41` |
| .bootstrap/managed-files.json | `31c27b49961289a258755375ece6c9b49faedaac8d20b950c32e37aec1cdc211` |
| THIRD_PARTY_NOTICES.md | `010af23399dfec698d83e7e370a09b54927dcda2afdb78619285a238b3bd655f` |
| genuine bootstrap-state.json | `e61ca1d4da11fb4ff1aa5a4e3b1f78d0ffa3ce47ae9bdb5cb703bf7c2d06cf72` |

All other 48 installed outputs and modes remained identical. All 49 sidecar claims and 50 genuine-state bindings match actual installed bytes; the manifest roundtrips and two successive plans contain exactly 50 unchanged outputs. State was created/updated only by the real renderer, never copied or manually fabricated.

The normalized legal contract and original owner-confirmation fields are unchanged. The confirmation covers the original six-record notice inventory; four later parser runtime notices remain factual attribution, with original package license digests and full substantive text verified. Canonical normalization trims source-final newlines as before; it does not broaden the confirmation.

## Remaining gates

Read-only observations captured on 2026-11-08 at 21:25 UTC confirm the existing default-branch JavaScript/TypeScript CodeQL success, Dependabot alerts and private reporting. Local applied conformance reports 13 passing results, two warnings and three blockers: automatic security fixes, secret scanning and push protection are disabled. Dependency graph remains unverified; dependency review activation remains absent and was not enabled. Local SPDX recognition remains unverified even though repository metadata identifies MIT.

All four changed workflows pass actionlint 1.7.7. Its 11 whole-repository diagnostics are exactly identical to public backend base `d70e5188baecfcf60e60dbc57d56a1e616290a83`, confined to unchanged release-publish/security-pr workflows; no unrelated contract change or lint waiver was introduced.

Required local source checks and the final immutable review/CI evidence are recorded in the PR. Actual Docker tests remain a distinct hosted acceptance gate; ordinary macOS test runs deliberately skip them. Independent GitHub approval and separately authorized settings/release operations remain necessary. No merge, tag, release, home sync, cloud deployment or private-data operation is included here.
