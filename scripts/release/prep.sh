#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?Candidate version is required.}"
semver='(0|[1-9][0-9]*)'
[[ "$VERSION" =~ ^v${semver}\.${semver}\.${semver}(-(rc|beta)\.[0-9]+)?$ ]] || { echo "Invalid source-release version." >&2; exit 1; }
notes="release-notes/${VERSION}.md"
notes_file="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bootstrap-release-notes.XXXXXX")"
trap 'rm -f "$notes_file"' EXIT
source_commit="$(git rev-parse --verify HEAD)"
git show "$source_commit:$notes" >"$notes_file" || { echo "Committed, reviewed release notes are required: $notes" >&2; exit 1; }
[[ -s "$notes_file" ]] || { echo "Reviewed release notes cannot be empty." >&2; exit 1; }
if grep -qF "Generated placeholder release notes." "$notes_file"; then
  echo "Placeholder notes cannot be published." >&2
  exit 1
fi
artifact_dir="${ARTIFACT_DIR:-dist/release}"
mkdir -p "$artifact_dir"
cp "$notes_file" "$artifact_dir/RELEASE_NOTES.md"
