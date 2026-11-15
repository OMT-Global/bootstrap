# ADR-0056: Case-aware GitHub issue label definitions

Status: Proposed

Governing issue: [#63](https://github.com/OMT-Global/bootstrap/issues/63).

## Context

GitHub resolved `priority:P1` and `priority:p1` to the same existing Flow label during a read-only inspection. Bootstrap currently treats them as distinct when merging explicit labels with Flow governance defaults. A default can therefore target an explicitly configured existing label with different metadata.

## Proposed decision

Compare trimmed label names using JavaScript's locale-independent `toLowerCase` when combining explicit definitions and Flow defaults. Preserve the first spelling and metadata; explicitly configured names precede and override matching defaults. Reject manifests that explicitly define different spellings with the same lowercased name. Preserve existing first-entry behavior for exact duplicate names.

This changes operator-facing validation: manifests previously accepted with explicitly configured case variants must be corrected. The owner selected preserving existing label names, colors, and descriptions for Bootstrap and Flow; this decision does not itself change GitHub labels or settings.

The comparison does not prove GitHub's complete Unicode name-equivalence rules. The observed collision uses ASCII `P`/`p`; other provider differences can require reconciliation. Independent review, PR checks, and any separately authorized live reconciliation remain necessary.
