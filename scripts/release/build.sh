#!/usr/bin/env bash
set -euo pipefail

artifact_dir="dist/release"
mkdir -p "${artifact_dir}"

if [[ ! -f "${artifact_dir}/artifact-manifest.json" ]]; then
  cat >"${artifact_dir}/artifact-manifest.json" <<JSON
{
  "schema_version": 1,
  "note": "Default bootstrap-generated release artifact manifest. Replace this with repo-specific build output when publishable assets exist."
}
JSON
fi

if [[ ! -f "${artifact_dir}/RELEASE_NOTES.md" ]]; then
  {
    echo "# Release Notes"
    echo
    echo "Generated placeholder release notes. Replace during release prep."
  } >"${artifact_dir}/RELEASE_NOTES.md"
fi

echo "Prepared release artifact directory ${artifact_dir}."