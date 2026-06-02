import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const repoRoot = process.cwd();

function read(relativePath: string): string {
  return readFileSync(new URL(relativePath, `file://${repoRoot}/`), 'utf8');
}

describe('governed release hook guards', () => {
  it('uses fail-closed branches for release hook execution', () => {
    const workflowPaths = [
      '.github/workflows/release-preflight-reusable.yml',
      '.github/workflows/full-release-validation-reusable.yml'
    ];

    for (const workflowPath of workflowPaths) {
      const contents = read(workflowPath);
      expect(contents).toContain('if [[ -x "$');
      expect(contents).not.toContain('&& "$');
      expect(contents).not.toContain('&& prep_status=passed');
      expect(contents).not.toContain('&& preflight_status=passed');
      expect(contents).not.toContain('&& build_status=passed');
      expect(contents).not.toContain('&& validate_status=passed');
    }

    const archetypes = read('src/archetypes.ts');
    expect(archetypes).toContain('if [[ -x "$PREP_SCRIPT" ]]; then');
    expect(archetypes).toContain('if [[ -x "$PREFLIGHT_SCRIPT" ]]; then');
    expect(archetypes).toContain('if [[ -x "$BUILD_SCRIPT" ]]; then');
    expect(archetypes).toContain('if [[ -x "$VALIDATE_SCRIPT" ]]; then');
    expect(archetypes).not.toContain('[[ -x "$PREP_SCRIPT" ]] && "$PREP_SCRIPT" && prep_status=passed');
    expect(archetypes).not.toContain('[[ -x "$PREFLIGHT_SCRIPT" ]] && "$PREFLIGHT_SCRIPT" && preflight_status=passed');
    expect(archetypes).not.toContain('[[ -x "$BUILD_SCRIPT" ]] && "$BUILD_SCRIPT" && build_status=passed');
    expect(archetypes).not.toContain('[[ -x "$VALIDATE_SCRIPT" ]] && "$VALIDATE_SCRIPT" && validate_status=passed');
  });

  it('binds publish provenance to the tag sha and requested run ids', () => {
    const workflow = read('.github/workflows/release-publish-reusable.yml');
    expect(workflow).toContain('gh run download "$PREFLIGHT_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-package --dir "$ARTIFACT_DIR"');
    expect(workflow).toContain('[[ "$evidence_target_sha" == "$tag_sha" ]] || { echo "Preflight evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(workflow).toContain('[[ "$evidence_preflight_run_id" == "$PREFLIGHT_RUN_ID" ]] || { echo "Preflight evidence run ID does not match the requested preflight run." >&2; exit 1; }');
    expect(workflow).toContain('gh run download "$VALIDATION_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-evidence-validation --dir "$VALIDATION_ARTIFACT_DIR"');
    expect(workflow).toContain('[[ "$validation_target_sha" == "$tag_sha" ]] || { echo "Validation evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(workflow).toContain('[[ "$validation_run_id" == "$VALIDATION_RUN_ID" ]] || { echo "Validation evidence run ID does not match the requested validation run." >&2; exit 1; }');
    expect(workflow).toContain('[[ "$validation_repo" == "$GITHUB_REPOSITORY" ]] || { echo "Validation evidence repo does not match the current repository." >&2; exit 1; }');
    expect(workflow).toContain("gh run view \"$VALIDATION_RUN_ID\" --repo \"$GITHUB_REPOSITORY\" --json conclusion --jq '.conclusion' | grep -qx success");
    expect(workflow).toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS" ]] || { echo "Missing preflight SHA256SUMS manifest." >&2; exit 1; }');
    expect(workflow).toContain('RELEASE_ASSET_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/release-assets.XXXXXX")"');
    expect(workflow).toContain("while read -r asset_sha asset_path; do");
    expect(workflow).toContain('[[ "$asset_path" != *"release-evidence.json" && "$asset_path" != *"validation-evidence.json" ]] || continue');
    expect(workflow).toContain('cp -p -- "$PREFLIGHT_ARTIFACT_DIR/$asset_path" "$RELEASE_ASSET_DIR/$asset_name"');
    expect(workflow).toContain('release_assets+=("$RELEASE_ASSET_DIR/$asset_name")');
    expect(workflow).toContain('[[ ${#release_assets[@]} -gt 0 ]] || { echo "No release assets were staged for upload." >&2; exit 1; }');
    expect(workflow).not.toContain('find "$PREFLIGHT_ARTIFACT_DIR" -maxdepth 1 -type f \( ! -name release-evidence.json ! -name validation-evidence.json \) -exec cp -p {} "$RELEASE_ASSET_DIR" \;');

    const archetypes = read('src/archetypes.ts');
    expect(archetypes).toContain('gh run download "$PREFLIGHT_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-package --dir "$ARTIFACT_DIR"');
    expect(archetypes).toContain('[[ "$evidence_target_sha" == "$tag_sha" ]] || { echo "Preflight evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(archetypes).toContain('[[ "$evidence_preflight_run_id" == "$PREFLIGHT_RUN_ID" ]] || { echo "Preflight evidence run ID does not match the requested preflight run." >&2; exit 1; }');
    expect(archetypes).toContain('gh run download "$VALIDATION_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-evidence-validation --dir "$VALIDATION_ARTIFACT_DIR"');
    expect(archetypes).toContain('[[ "$validation_target_sha" == "$tag_sha" ]] || { echo "Validation evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(archetypes).toContain('[[ "$validation_run_id" == "$VALIDATION_RUN_ID" ]] || { echo "Validation evidence run ID does not match the requested validation run." >&2; exit 1; }');
    expect(archetypes).toContain('[[ "$validation_repo" == "$GITHUB_REPOSITORY" ]] || { echo "Validation evidence repo does not match the current repository." >&2; exit 1; }');
  });
});
