# Governed Release Train

This repository uses release maturity level `governed`.

## Manual Flow

1. Open a release train issue with `.github/ISSUE_TEMPLATE/release_train.yml`.
2. Create or update the `release/{major}.{minor}` release branch.
3. Run `Release Preflight` with the candidate version, channel, target ref, and release issue.
4. Copy the successful preflight run ID into the release issue.
5. Run `Full Release Validation` against the same target ref.
6. Copy the successful validation run ID into the release issue.
7. Create the exact release tag only after validation evidence exists.
8. Run `Release Publish` with the tag, preflight run ID, validation run ID, channel, and release issue.
9. Run or review `Release Postpublish`, then close or supersede the release issue.

Publish must consume the artifact bundle proven by preflight. If the preflight artifact cannot be downloaded or its recorded target SHA differs from the tag SHA, publish must fail instead of rebuilding.

## Customization

Repo-specific behavior belongs in these hook scripts:

- `scripts/release/prep.sh`
- `scripts/release/preflight.sh`
- `scripts/release/validate.sh`
- `scripts/release/build.sh`
- `scripts/release/publish.sh`
- `scripts/release/postpublish.sh`

The generated defaults do not require secrets and do not publish external packages.
