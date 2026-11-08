# Bootstrap MIT license adoption proposal

Status: Proposed; entity confirmed, adoption approval and supporting evidence pending.

Governing issue: [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63).

## Exact proposed result

Declare the existing first-party license as `mode: spdx`, `identifier: MIT`, holder `OMT Global`, years `2026`. Preserve every byte of the current [LICENSE](../../LICENSE), including its copyright line and final newline. This proposal changes Bootstrap's management classification from `existing-unclassified` to `spdx:MIT`; it requests no change to the published terms, holder wording, years, or historical grants.

Git history records the license's introduction in [commit b9e6b8eca06452ea27e3d00707ce935a28975da6](https://github.com/OMT-Global/bootstrap/commit/b9e6b8eca06452ea27e3d00707ce935a28975da6), “Add MIT license (#15),” on 2026-05-05. The current file has no later tracked changes. That history establishes provenance of the file, not legal ownership or contributor assignments.

| Artifact | Exact SHA-256 | Bytes |
| --- | --- | ---: |
| Existing and proposed rendered `LICENSE` | `e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052` | 1,067 |
| Proposed `legal/mit-license.txt` template | `0a6aa4a08352ee287faa69276561dc15e1c8a0929c2b2db34a56c7663250271a` | 1,092 |

The candidate template is defined exactly by replacing the single byte sequence `Copyright (c) 2026 OMT Global` in the existing file with `Copyright (c) {{copyright_years}} {{copyright_holder}}`. Every other byte stays unchanged. Rendering those two tokens with the proposed holder and year reproduces the existing 1,067 bytes and SHA-256 above. No SPDX header is inserted into the legal text; the manifest binds the template to `MIT`.

## Approval package

The user confirmed in this Bootstrap task on 2026-11-08: “OMT Global is the entity.” This resolves the entity identification only. It does not establish ownership, contributor assignments, distribution history, or approval to adopt the template.

The [licensing contract](licensing.md#existing-license-hard-stop) requires approved adoption evidence even when the rendered bytes match. The following values remain human decisions; repository history or a passing byte comparison cannot supply them:

- Confirm authority to adopt this exact file/template pair into Bootstrap management, and record the actual approver and approval reference.
- Record ownership, contributor/assignment review, and distribution-history evidence, preserving previously granted MIT rights.
- Review the prepared [third-party inventory](third-party-inventory.md) and intended distribution scope before projecting `THIRD_PARTY_NOTICES.md`; the four runtime packages and two Flow source records are not an approved empty inventory.

The prospective manifest fragment below deliberately contains `null` approval/evidence fields. It is a review checklist, not an applicable manifest. Replace them only with verified records after approval; do not use “pending” strings to satisfy schema checks.

```yaml
license:
  mode: spdx
  identifier: MIT
  holder: OMT Global
  holderVerification: "User confirmation in Bootstrap task, 2026-11-08: OMT Global is the entity"
  years: "2026"
  template:
    path: legal/mit-license.txt
    sha256: 0a6aa4a08352ee287faa69276561dc15e1c8a0929c2b2db34a56c7663250271a
    spdxIdentifier: MIT
    approval: null # Pending approval of this exact template digest.
  thirdPartyNotices: null # Pending reviewed component inventory.
  transition:
    from:
      mode: existing-unclassified
      licenseSha256: e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052
    to:
      mode: spdx:MIT
      licenseSha256: e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052
    approvedBy: null
    issue: https://github.com/OMT-Global/bootstrap/issues/63
    ownership: null
    contributors: null
    distributionHistory: null
```

## Verification and application boundary

Preparation verified the exact token substitution, SHA-256 hashes, byte counts, and byte equality using a disposable local candidate. No template/adoption approval, license manifest entry, legal template, or `LICENSE` edit was applied to this repository.

After the missing records are supplied, add the pinned template and completed manifest fragment on the feature branch. Run doctor, inspect the repo-only plan, confirm the `LICENSE` diff is empty, review the separate notices inventory, then apply only the authorized repo target. Re-run plan for idempotence and conformance, and verify published GitHub license detection. Stop if the source license hash or intended output hash differs from this approval package. Keep #63 open until the full Flow-first dogfood acceptance criteria and live capability checks also pass.
