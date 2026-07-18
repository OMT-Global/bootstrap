# Licensing policy and projection

Bootstrap treats licensing as an explicit legal configuration, not a consequence of repository visibility. A private repository without `license` remains unlicensed by Bootstrap; it is never assigned MIT or another open-source license automatically.

Bootstrap copies an approved repository-local template into `LICENSE`, substitutes only the declared copyright holder, year or year range, and (for open source) SPDX identifier, and generates `THIRD_PARTY_NOTICES.md` as a separate inventory. Bootstrap does not draft legal terms or fetch private contract text.

## Decision matrix

| Situation | Manifest mode | Bootstrap behavior | Required human gate |
| --- | --- | --- | --- |
| New open-source repository | `spdx` with one identifier | Projects the approved SPDX template and reports local recognition as unverified | Confirm template and verify GitHub detection after publication |
| New private commercial repository | `proprietary` | Projects the counsel-approved proprietary template | Confirm holder, years, and template approval reference |
| Private repository without a license decision | omitted | Does not create or infer a license; conformance blocks | Legal/stewardship decision |
| Existing license matches the configured template | explicit matching mode | Adopts it without rewriting legal text | Review the manifest and template provenance |
| Existing license would change | explicit replacement mode | Hard-stops until transition evidence is present | Legal approval plus ownership, contributor, and distribution-history evidence |
| License policy is removed after Bootstrap managed it | omitted | Hard-stops; Bootstrap will not delete the license | Choose an explicit replacement mode and complete legal review |

## Manifest contract

```yaml
license:
  mode: proprietary
  holder: OMT Global LLC
  holderVerification: legal-entity:OMT-Global-LLC
  years: "2026"
  template:
    path: legal/proprietary-license.txt
    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    approval: legal-template:P-1
  thirdPartyNotices:
    - name: Example Font
      kind: font
      license: OFL-1.1
      source: assets/fonts/example
```

An SPDX policy uses `mode: spdx`, adds one `identifier`, such as `MIT`, and records the same value as `template.spdxIdentifier`. That binding prevents a template approved for one license from being relabeled as another, and any literal SPDX declaration in the rendered file must also match it. The approved template must contain `{{copyright_holder}}` and `{{copyright_years}}`; an SPDX template may also use `{{spdx_identifier}}`. Bootstrap substitutes supported tokens in one pass and preserves every other approved template byte exactly. Templates must be regular, singly linked UTF-8 files with no symlinked path components, must physically remain inside the target repository, cannot alias any selected managed or generated state output even on case-insensitive filesystems, and must match an exact byte-level SHA-256 pin. Existing `LICENSE` files must also be valid UTF-8, while transition decisions and hashes bind their exact bytes, including a leading BOM. Interpolated holder, approval, reference, and notice metadata rejects Unicode control, format, and separator characters; only notice bodies may span multiple LF-delimited lines. These constraints keep the reviewed source text versioned and prevent Bootstrap from inventing, downloading, silently changing, or spoofing terms.

Third-party entries are sorted deterministically. Their `kind` is one of `dependency`, `asset`, `font`, `media`, or `incorporated-source`. An optional `notice` preserves attribution or other required text. An existing unmanaged `THIRD_PARTY_NOTICES.md` is never overwritten; its obligations must first be reconciled into the manifest.

## Existing-license hard stop

Changing an existing license requires a `transition` block:

```yaml
  transition:
    approvedBy: legal-reviewer
    issue: OMT-Global/flow#26
    ownership: Verified copyright ownership record
    contributors: Contributor and assignment review complete
    distributionHistory: Historical grants and distributions recorded
    fromMode: existing-unclassified
    fromContentSha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    toMode: proprietary
    toContentSha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

The mode and content hashes bind this evidence to one exact prospective adoption or file change; stale evidence cannot authorize later holder, template, terms, identifier, or mode changes. An existing unmanaged `LICENSE` requires adoption evidence even when its bytes already match the requested rendering, because Bootstrap cannot infer prior legal classification from the new policy. A missing or modified managed `LICENSE` must be restored before a transition can be planned. This evidence does not revoke prior grants, relicense third-party material, or resolve unclear contributor rights. Ambiguity remains a human legal blocker.

Bootstrap records the managed license mode and exact content hash in the tracked ownership sidecar as well as local state. The mutable sidecar is a reviewable ownership claim and can preserve fail-closed removal protection, but it cannot independently authorize an overwrite or deletion and does not prove prior legal classification. A clean clone without the current local baseline therefore requires exact adoption/transition evidence in the manifest, even when tracked bytes match; changing managed notices also requires a trusted local baseline or explicit migration. Existing root files named `LICENSE` or `LICENCE` with suffixes or extensions (for example `LICENSE.md` and `LICENSE-MIT`), `COPYING` variants such as `COPYING.LESSER`, `UNLICENSE` variants, and equivalent legal files must be reconciled into the canonical `LICENSE` before Bootstrap can manage licensing.

Existing `LICENSE` and `THIRD_PARTY_NOTICES.md` outputs must be regular, singly linked files that physically remain in the repository. Bootstrap rejects symlinks, dangling links, hard links, devices, and other non-regular output aliases before reading or planning changes.

`bootstrap plan` prints the exact before/after mode and every file mutation. `bootstrap conform` reports stable license, template, encoding, notice, transition, and recognition rule IDs. Proprietary notices are always reported as non-SPDX and non-OSI; SPDX recognition remains a warning until GitHub's published community profile is checked.

## Migration fixtures

- Button King represents a currently unlicensed private repository: plan creates an explicitly approved proprietary notice and separate third-party inventory without changing the source repository during validation.
- Pocket Parade represents an existing MIT repository: any prospective proprietary replacement remains blocked until the transition evidence and legal review are complete. Historical MIT grants remain intact.
