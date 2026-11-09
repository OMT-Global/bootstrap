# ADR-0019: Repository-source release assets and approved-preflight binding

Status: Accepted

Date: 2026-11-08

Governing issues: #27 and #63

Acceptance covers source-hook preparation only, under the owner-approved project-ownership boundary. It does not supply independent PR approval or authorize a release, tag or publication.

## Context

The generic release hooks emit placeholders or check only that a release exists. Bootstrap's private npm package is not a declared registry distribution. The owner approved project ownership of the README and prep/build/postpublish hooks, while other rendered paths and legal outputs remain managed.

## Decision

Prepare four real repository-source/control-plane assets from the checked-out commit: a versioned source archive, its SHA-256 digest, committed reviewed notes, and an actual source/asset manifest. Use the existing governed wrapper environment and artifact directory. Require supported path-safe version syntax before constructing paths. Consume notes from the commit and verify their bytes again before building.

Require channel/version promotion maturity to agree in prep, build and postpublish: stable/maintenance use an unsuffixed version, while rc/beta use a prerelease already accepted by the existing version grammar. Preserve valid cross-label prereleases; exact channel-name/suffix matching is not established policy. This input consistency guard does not supply publication or environment approval.

Bind postpublish verification to the independently selected `PREFLIGHT_RUN_ID` package, its repository/version/channel/target evidence and successful source checks. Require byte identity for all four published assets, then validate manifest source identity, inventory, digests and sizes. Self-consistency of unapproved replacement assets is insufficient.

The current publish reusable supplies that input. Adopt the reviewed public reusable commit `9b77eaaa3ed9ad2da35ec1af9fe13d1563c7cce4` with `release.postpublishRequiresPreflight: true`; its additive optional input supports the generated standalone caller's required selection. Preserve the parent 47-path ownership boundary and derive caller/manifest/sidecar updates through the renderer. The previous `913b298fab0fb008796011d940ee7362a347659d` standalone contract cannot receive the new input. Missing approval evidence must fail closed rather than infer authority from published bytes.

## Consequences

The hooks become testable source preparation without choosing a release version, changing npm metadata, publishing assets, creating tags, promoting aliases or changing GitHub environments. No old preview notes/assets are adopted as final evidence. Final publication still requires a concrete reviewed eligible target, actual package digests, successful exact-target evidence and explicit authorization. Existing release side effects are not transactionally rolled back by a later verification failure.
