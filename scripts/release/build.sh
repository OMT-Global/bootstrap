#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?Candidate version is required.}"
: "${CHANNEL:?Release channel is required.}"
: "${GITHUB_REPOSITORY:?Repository is required.}"
semver='(0|[1-9][0-9]*)'
[[ "$VERSION" =~ ^v${semver}\.${semver}\.${semver}(-(rc|beta)\.[0-9]+)?$ ]] || { echo "Invalid source-release version." >&2; exit 1; }
case "$CHANNEL" in rc|beta|stable|maintenance) ;; *) echo "Invalid release channel." >&2; exit 1 ;; esac
artifact_dir="${ARTIFACT_DIR:-dist/release}"
[[ -s "$artifact_dir/RELEASE_NOTES.md" ]] || { echo "Run release prep with reviewed notes first." >&2; exit 1; }
target_sha="$(git rev-parse HEAD)"
target_tree="$(git rev-parse HEAD^{tree})"
git show "$target_sha:release-notes/${VERSION}.md" | cmp - "$artifact_dir/RELEASE_NOTES.md" || { echo "Prepared notes do not match the committed source." >&2; exit 1; }
archive="bootstrap-${VERSION}-source.tar.gz"
git archive --format=tar.gz --prefix="bootstrap-${VERSION}/" "$target_sha" > "$artifact_dir/$archive"
node - "$artifact_dir" "$GITHUB_REPOSITORY" "$VERSION" "$CHANNEL" "$target_sha" "$target_tree" "$archive" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const [directory, repository, version, channel, sourceCommit, sourceTree, archive] = process.argv.slice(2);
const digest = name => createHash('sha256').update(fs.readFileSync(path.join(directory, name))).digest('hex');
fs.writeFileSync(path.join(directory, archive + '.sha256'), digest(archive) + '  ' + archive + '\n');
const assets = [archive, archive + '.sha256', 'RELEASE_NOTES.md'].map(name => ({ name, sha256: digest(name), bytes: fs.statSync(path.join(directory, name)).size }));
fs.writeFileSync(path.join(directory, 'artifact-manifest.json'), JSON.stringify({ schema_version: 1, repository, version, channel, distribution: 'repository-source-control-plane', source_commit: sourceCommit, source_tree: sourceTree, assets }, null, 2) + '\n');
NODE
