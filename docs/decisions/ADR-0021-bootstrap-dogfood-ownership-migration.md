# ADR-0021: Apply Bootstrap's approved ownership boundary

Status: Accepted

Date: 2026-11-08

Decision owners: Bootstrap maintainers

Decision record: the repository owner approved the concrete 47-path managed boundary, project-owned README and three release hooks, and ordinary Ubuntu 24.04 CI selection for [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63). The task coordinator reviewed the exact target plans before both local repository applications. This accepts the bounded local migration and necessary manifest roundtrip/encoding repairs, not live GitHub settings, home/cloud changes, merges, tags, or releases.

## Context

Flow's unchanged reviewed feature source reached a genuine local fixed point first. Bootstrap then needed its control plane reconciled with existing Athena ownership, preserved authoritative agent review guidance, and an explicit managed-file inventory. Initial adoption also exercised two previously hidden manifest serialization defects: canonical reload dropped the already-declared legacy class migration record, and literal tab-bearing notice text produced YAML whitespace errors.

## Decision

1. Select exactly the approved 47 rendered paths, plus the separately governed LICENSE and third-party notices. Keep README.md and scripts/release/{prep,build,postpublish}.sh project-owned, unselected and byte/mode-identical. Preserve current AGENTS.md and CODEOWNERS byte-for-byte by reconciling the generator's review-rule line and the manifest's existing Athena owner.
2. Use genuine current-renderer repository apply with fresh worktree-local state, scoped backups and installed-byte verification. Never copy prior state/sidecars as authority. The first application installed 50 outputs and established genuine state; its sidecar claims 49 outputs, excluding itself and the four project-owned files.
3. Retain only a consistent declared legacy-to-canonical class migration record across normalization and serialization. Accept the emitted legacy from enum, preserve the owner's already-chosen canonical target, and reject contradictory or incomplete records. Do not infer a new class. This restores the documented retained record and first-application fixed point without changing any first-installed byte or state.
4. Escape only tab-bearing YAML scalars using the supported double-quoted scalar form. Preserve all parsed manifest/normalized legal values and no-tab default bytes. After review of the exact two-output plan, a second genuine apply updates only the manifest representation and derived sidecar; the other 48 outputs/modes and all normalized values remain identical.
5. Keep the postpublish preflight-forwarding opt-in absent and retain the existing immutable shared release pin. The generator prerequisite adds a compatible optional input, rendered here without enabling forwarding. Project-specific strict release hooks and forwarding require a separately reviewed immutable generated-workflow pin and adoption stage.

## Validation and limits

Verify all 50 installed hashes, all 49 sidecar claims, genuine state bindings, manifest roundtrip and two all-unchanged plans. Regression controls cover the authoritative rule, installed boundary, retained class record/fresh apply, inconsistent record rejection, tab roundtrip/strict whitespace and unchanged no-tab archetypes. Full tests, actual Node 20 affected checks, action pins, full-file scanning and changed-workflow actionlint are required; installed Codex review and independent GitHub approval remain later gates.

Live read-only conformance observations still block on disabled automatic security updates, secret scanning and push protection. Dependency graph remains unverified, and local GitHub license recognition remains a warning. Do not waive those controls or claim the entire dogfood issue complete from local repository application.
