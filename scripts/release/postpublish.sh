#!/usr/bin/env bash
set -euo pipefail

tag="${1:?Exact release tag is required.}"
: "${GITHUB_REPOSITORY:?Repository is required.}"
: "${PREFLIGHT_RUN_ID:?Approved preflight run ID is required.}"
: "${CHANNEL:?Release channel is required.}"
semver='(0|[1-9][0-9]*)'
[[ "$tag" =~ ^v${semver}\.${semver}\.${semver}(-(rc|beta)\.[0-9]+)?$ ]] || { echo "Invalid source-release version." >&2; exit 1; }
[[ "$PREFLIGHT_RUN_ID" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid approved preflight run ID." >&2; exit 1; }
case "$CHANNEL" in
  rc|beta) [[ "$tag" == *-rc.* || "$tag" == *-beta.* ]] ;;
  stable|maintenance) [[ "$tag" != *-* ]] ;;
  *) echo "Invalid release channel." >&2; exit 1 ;;
esac || { echo "Release channel and version maturity must agree." >&2; exit 1; }
archive="bootstrap-${tag}-source.tar.gz"
target_sha="$(git rev-parse --verify "refs/tags/$tag^{commit}")"
target_tree="$(git rev-parse --verify "refs/tags/$tag^{tree}")"
verification_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/bootstrap-release-verify.XXXXXX")"
trap 'rm -rf "$verification_dir"' EXIT
approved_dir="$verification_dir/approved-preflight"
mkdir -p "$approved_dir"
gh run download "$PREFLIGHT_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-package --dir "$approved_dir"
gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json assets --jq '[.assets[].name]' >"$verification_dir/published-asset-names.json"
gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$verification_dir" \
  --pattern "$archive" --pattern "$archive.sha256" \
  --pattern artifact-manifest.json --pattern RELEASE_NOTES.md
node - "$verification_dir" "$GITHUB_REPOSITORY" "$tag" "$target_sha" "$archive" "$approved_dir" "$PREFLIGHT_RUN_ID" "$CHANNEL" "$target_tree" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const [directory, repository, version, sourceCommit, archive, approvedDirectory, preflightRunId, channel, sourceTree] = process.argv.slice(2);
const evidence = JSON.parse(fs.readFileSync(path.join(approvedDirectory, 'release-evidence.json'), 'utf8'));
if (evidence.schema_version !== 1 || evidence.preflight_run_id !== preflightRunId || evidence.repo !== repository || evidence.version !== version || evidence.channel !== channel || evidence.target_sha !== sourceCommit) throw new Error('Approved preflight evidence does not match the requested run, repository, version or target commit.');
if (['prep', 'preflight', 'build'].some(check => evidence.checks?.[check] !== 'passed')) throw new Error('Approved preflight package does not record successful source-release checks.');
const approvedAssets = [archive, archive + '.sha256', 'artifact-manifest.json', 'RELEASE_NOTES.md'];
const publishedAssets = JSON.parse(fs.readFileSync(path.join(directory, 'published-asset-names.json'), 'utf8'));
if (!Array.isArray(publishedAssets) || publishedAssets.some(name => typeof name !== 'string') || JSON.stringify(publishedAssets.sort()) !== JSON.stringify([...approvedAssets].sort())) throw new Error('Published release asset inventory does not match the approved source distribution.');
for (const name of approvedAssets) {
  if (!fs.readFileSync(path.join(directory, name)).equals(fs.readFileSync(path.join(approvedDirectory, name)))) throw new Error('Release asset digest or size mismatch against approved preflight package: ' + name);
}
const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'artifact-manifest.json'), 'utf8'));
if (manifest.schema_version !== 1 || manifest.repository !== repository || manifest.version !== version || manifest.channel !== channel || manifest.source_commit !== sourceCommit || manifest.source_tree !== sourceTree || manifest.distribution !== 'repository-source-control-plane') throw new Error('Release artifact identity does not match the approved source distribution.');
const expected = [archive, archive + '.sha256', 'RELEASE_NOTES.md'];
if (JSON.stringify(manifest.assets.map(asset => asset.name).sort()) !== JSON.stringify(expected.sort())) throw new Error('Release asset inventory does not match the source distribution.');
for (const asset of manifest.assets) {
  const contents = fs.readFileSync(path.join(directory, asset.name));
  if (createHash('sha256').update(contents).digest('hex') !== asset.sha256 || contents.length !== asset.bytes) throw new Error('Release asset digest or size mismatch: ' + asset.name);
}
console.log('Verified source distribution ' + version + ' at ' + sourceCommit + ' against approved preflight ' + preflightRunId);
NODE
