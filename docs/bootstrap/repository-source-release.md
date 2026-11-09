# Repository-source releases

Bootstrap's product-owned prep/build/postpublish hooks prepare a repository-source/control-plane distribution. They do not publish the private npm package, choose a release version, create a tag, authorize publication, or promote compatibility tags. The selected release must still meet the governed release workflow, independent review, environment and explicit publication approval requirements.

## Prepare reviewed source assets

For the selected `vMAJOR.MINOR.PATCH` version (optionally `-rc.N` or `-beta.N`), generate and review the release notes, then commit them as `release-notes/<version>.md`. Reconcile the notes' generation basis with the final reviewed source. The repository intentionally contains no fabricated candidate notes or approved release target in this hook preparation change.

The source hooks require prerelease channels (`rc` or `beta`) to use one of the supported prerelease suffixes, and stable/maintenance channels to use an unsuffixed version. This checks promotion maturity; it does not introduce a requirement that the two prerelease channel labels match their suffix names.

The preflight wrapper passes its existing `VERSION`, `CHANNEL`, `GITHUB_REPOSITORY` and `ARTIFACT_DIR` environment. Prep reads notes from the checked-out commit, ignoring uncommitted replacements, and rejects absent, empty, whitespace-only (including Unicode whitespace) or placeholder text. Build checks that the prepared notes still equal that same commit's versioned notes and archives the checked-out commit with `git archive`.

The four custom release assets are:

- `bootstrap-<version>-source.tar.gz`, with a versioned top-level directory containing tracked source.
- Its `.sha256` digest file.
- `RELEASE_NOTES.md`, containing the committed reviewed notes.
- `artifact-manifest.json`, identifying the actual repository, version, channel, source commit/tree, distribution and asset sizes/digests.

The existing reusable preflight adds its standard `SHA256SUMS` and `release-evidence.json` files. No untracked local state or dependency cache is archived. Existing LICENSE content is preserved as tracked source; preparing these hooks changes no legal bytes or ownership grants.

## Verify the selected approved package

The publish reusable already provides `PREFLIGHT_RUN_ID` and `CHANNEL` to the postpublish hook. The hook resolves the exact version tag, downloads that selected run's `release-package`, and verifies the evidence's run/repository/version/channel/target identity and successful prep/preflight/build checks. The complete GitHub Release custom-asset inventory must contain exactly the four approved names, with no extra, missing or duplicate asset. GitHub's automatically generated source archive links are separate from that uploaded asset inventory. The hook then requires all four published asset byte streams to equal the approved package before checking the manifest's own inventory, source tree, hashes and sizes. A release-side manifest recomputed around substituted bytes cannot supply approval.

A missing or unavailable selected package blocks verification. Verification failure is reported after a release may have been created/uploaded; it does not roll back an already published release. The existing workflow promotes aliases only after successful verification.

This adoption selects `release.postpublishRequiresPreflight: true` and the reviewed public reusable-workflow commit `9b77eaaa3ed9ad2da35ec1af9fe13d1563c7cce4`. That commit supports the optional preflight-run input; the generated standalone dispatch requires the operator to select it and forwards it to the verifier. The shared pin also moves the existing preflight, full-validation and publish callers to that exact reviewed ancestor. Missing approval evidence still fails closed; the hook never guesses the approved run from published assets. The old `913b298fab0fb008796011d940ee7362a347659d` standalone reusable cannot receive this input and is not used by the opted-in caller.

## Validation and adoption boundary

`tests/repository-source-release.test.ts` runs fabricated fixture repositories, unsigned fixture commits/tags and controlled fake downloads in the normal Vitest lane. It exercises source inventory/legal preservation, committed notes, path-safe versions, approval identity, missing evidence, failed source checks, and changed or self-consistently substituted release assets. Tests use no real operator credentials, remote release, tag publication or settings changes.

The parent ownership migration selects the approved 47 rendered paths plus legal outputs and sidecar; these three hooks and README remain project-owned. This adoption preserves that boundary and uses only renderer-produced caller/manifest/sidecar changes. A fresh worktree establishes its own genuine state from an unchanged public baseline before changing managed outputs; local state is never copied from another checkout. Choosing a release, generating the final eligible assets, collecting successful exact-target remote evidence and authorizing publication remain separate steps.
