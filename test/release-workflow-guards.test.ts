import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { renderManagedFiles } from '../src/archetypes.js';
import { normalizeManifest } from '../src/manifest.js';
import { describe, expect, it } from 'vitest';

const repoRoot = process.cwd();

function read(relativePath: string): string {
  return readFileSync(new URL(relativePath, `file://${repoRoot}/`), 'utf8');
}

function publishScript(rendered: boolean): string {
  const contents = rendered
    ? renderManagedFiles(normalizeManifest({ project: { name: 'release-fixture', owner: 'acme' },
      archetype: { kind: 'generic-empty' }, release: { enabled: true, maturity: 'governed' } }))
      .find((file) => file.path === '.github/workflows/release-publish-reusable.yml')!.contents
    : read('.github/workflows/release-publish-reusable.yml');
  const matches = YAML.parse(contents).jobs.publish.steps.filter((step: any) => step.name === 'Publish proven release artifact');
  expect(matches).toHaveLength(1);
  return matches[0].run;
}

// Execute the actual workflow shell with entirely local command fixtures. Any
// unrecognized Git/GitHub operation fails; no provider command can run.
function executePublish(script: string, overrides: Record<string, string> = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'publish-guard-'));
  const log = path.join(root, 'calls');
  writeFileSync(log, '');
  const bin = path.join(root, 'bin');
  mkdirSync(bin);
  // Also catch provider commands launched by a Node child process, which does
  // not inherit the shell functions below.
  for (const name of ['gh', 'git']) writeFileSync(path.join(bin, name),
    `#!/bin/bash\nprintf 'unexpected-provider:${name}\\n' >> "$CALL_LOG"\nexit 96\n`, { mode: 0o700 });
  mkdirSync(path.join(root, 'artifacts'));
  writeFileSync(path.join(root, 'artifacts', 'sentinel'), 'unchanged');
  for (const name of ['publish', 'postpublish']) writeFileSync(path.join(root, name),
    `#!/bin/bash\nprintf '${name}:%s\\n' "$*" >> "$CALL_LOG"\n`, { mode: 0o700 });
  const fixture = String.raw`
node() {
  if [[ "$1" == "$APPROVED_RUNTIME_ROOT/dist/release-existing-runtime.js" ]]; then
    printf 'runtime:%s:%s:%s:%s\n' "$TAG" "$PREFLIGHT_RUN_ID" "$VALIDATION_RUN_ID" "$APPROVAL_PULL_NUMBER" >> "$CALL_LOG"
    printf '{"kind":"verified-existing"}\n'
    return "$RUNTIME_STATUS"
  fi
  "$REAL_NODE" "$@"
}
git() {
  printf 'git:%s\n' "$*" >> "$CALL_LOG"
  [[ "$1" == rev-parse && "$2" == "$TAG^{commit}" ]] || return 91
  printf '%s\n' "$TARGET_SHA"
}
gh() {
  printf 'gh:%s\n' "$*" >> "$CALL_LOG"
  case "$1 $2" in
    'run download')
      [[ "$4" == --repo && "$5" == "$GITHUB_REPOSITORY" && "$6" == --name && "$8" == --dir ]] || return 92
      mkdir -p "$9"
      if [[ "$3" == "$PREFLIGHT_RUN_ID" && "$7" == release-package ]]; then
        printf '{"target_sha":"%s","preflight_run_id":"%s"}\n' "$PREFLIGHT_SHA" "$PREFLIGHT_EVIDENCE_RUN" > "$9/release-evidence.json"
        printf 'fixture artifact\n' > "$9/artifact.txt"
        printf 'fixture notes\n' > "$9/RELEASE_NOTES.md"
        printf '%s artifact.txt\n%s release-evidence.json\n' "$DIGEST" "$DIGEST" > "$9/SHA256SUMS"
      elif [[ "$3" == "$VALIDATION_RUN_ID" && "$7" == release-evidence-validation ]]; then
        printf '{"target_sha":"%s","validation_run_id":"%s","repo":"%s"}\n' "$VALIDATION_SHA" "$VALIDATION_EVIDENCE_RUN" "$VALIDATION_REPOSITORY" > "$9/validation-evidence.json"
      else return 93; fi ;;
    'run view') [[ "$3" == "$VALIDATION_RUN_ID" ]] || return 94; printf 'success\n' ;;
    'api --paginate') printf '%s\n' "$EXISTING_RELEASES" ;;
    'release create') [[ "$3" == "$TAG" ]] || return 95 ;;
    *) return 96 ;;
  esac
}
`;
  try {
    const result = spawnSync('/bin/bash', ['-c', fixture + script], { cwd: root, encoding: 'utf8', timeout: 10_000,
      env: { PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`, REAL_NODE: process.execPath, CALL_LOG: log,
        GITHUB_REPOSITORY: 'fixture/repo', GITHUB_RUN_ID: '103', TAG: 'v1.2.3-rc.1', CHANNEL: 'rc', TAG_PREFIX: 'v',
        PREFLIGHT_RUN_ID: '101', VALIDATION_RUN_ID: '102', APPROVAL_PULL_NUMBER: '4', RELEASE_ISSUE: '27',
        VERIFY_EXISTING_RELEASE: 'false', REQUIRE_RELEASE_ISSUE: 'true', REQUIRE_SIGNED_TAG: 'false',
        REQUIRE_POSTPUBLISH_VERIFICATION: 'true', CREATE_GITHUB_RELEASE: 'true', UPDATE_MAJOR_TAG: 'false', UPDATE_MINOR_TAG: 'false',
        PUBLISH_SCRIPT: path.join(root, 'publish'), POSTPUBLISH_SCRIPT: path.join(root, 'postpublish'),
        ARTIFACT_DIR: path.join(root, 'artifacts'), RELEASE_NOTES_FILE: path.join(root, 'notes', 'RELEASE_NOTES.md'),
        RUNNER_TEMP: root, APPROVED_RUNTIME_ROOT: path.join(root, 'approved-runtime'), RUNTIME_STATUS: '0',
        TARGET_SHA: 'a'.repeat(40), PREFLIGHT_SHA: 'a'.repeat(40), VALIDATION_SHA: 'a'.repeat(40), DIGEST: 'b'.repeat(64),
        PREFLIGHT_EVIDENCE_RUN: '101', VALIDATION_EVIDENCE_RUN: '102', VALIDATION_REPOSITORY: 'fixture/repo',
        EXISTING_RELEASES: '[[]]', ...overrides } });
    expect(result.error).toBeUndefined();
    return { status: result.status, stderr: result.stderr, calls: readFileSync(log, 'utf8').trim().split('\n').filter(Boolean),
      sentinel: (() => { try { return readFileSync(path.join(root, 'artifacts', 'sentinel'), 'utf8'); } catch { return null; } })() };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

describe.each([['checked-in', false], ['generated generic', true]] as const)('%s publish dispatch guards', (_name, rendered) => {
  it.each([0, 17])('retry runtime status %i never falls through to hooks or publication', (status) => {
    const result = executePublish(publishScript(rendered), { VERIFY_EXISTING_RELEASE: 'true', RUNTIME_STATUS: String(status) });
    expect(result.status).toBe(status);
    expect(result.calls).toEqual(['runtime:v1.2.3-rc.1:101:102:4']);
    expect(result.sentinel).toBe('unchanged');
  });
  it('rejects a missing retry issue before runtime or any publication operation', () => {
    const result = executePublish(publishScript(rendered), { VERIFY_EXISTING_RELEASE: 'true', RELEASE_ISSUE: '' });
    expect(result.status).not.toBe(0); expect(result.calls).toEqual([]); expect(result.sentinel).toBe('unchanged');
  });
  it('keeps generic creation bound to the requested tag and only staged assets', () => {
    const result = executePublish(publishScript(rendered));
    expect(result.status, result.stderr).toBe(0);
    const creations = result.calls.filter((call) => call.startsWith('gh:release create '));
    expect(creations).toHaveLength(1);
    expect(creations[0]).toContain('gh:release create v1.2.3-rc.1 ');
    expect(creations[0]).toMatch(/\/release-assets\.[^/]+\/artifact\.txt --repo fixture\/repo --notes-file /);
    expect(creations[0]).toContain('--prerelease --latest=false');
    expect(creations[0]).not.toMatch(/release-evidence\.json|validation-evidence\.json/);
    expect(result.calls).toContain('publish:'); expect(result.calls).toContain('postpublish:v1.2.3-rc.1');
    expect(result.calls.findIndex((call) => call.startsWith('gh:api --paginate '))).toBeLessThan(result.calls.indexOf('publish:'));
    expect(result.calls.indexOf('publish:')).toBeLessThan(result.calls.indexOf(creations[0]!));
    expect(result.calls.indexOf(creations[0]!)).toBeLessThan(result.calls.indexOf('postpublish:v1.2.3-rc.1'));
    expect(result.calls.some((call) => call.startsWith('unexpected-provider:'))).toBe(false);
    expect(result.calls.some((call) => /runtime:|gh:release (upload|edit|delete)|git:(push|tag)/.test(call))).toBe(false);
  });
  it.each([
    { PREFLIGHT_SHA: 'c'.repeat(40) }, { PREFLIGHT_EVIDENCE_RUN: '999' },
    { VALIDATION_SHA: 'c'.repeat(40) }, { VALIDATION_EVIDENCE_RUN: '999' }, { VALIDATION_REPOSITORY: 'other/repo' },
    { EXISTING_RELEASES: '[[{"id":1,"tag_name":"v1.2.3-rc.1","draft":false}]]' },
    { EXISTING_RELEASES: '[[{"id":1,"tag_name":"v1.2.3-rc.1","draft":true}]]' },
    { EXISTING_RELEASES: '{}' }
  ])('rejects mismatched evidence or existing/ambiguous releases before hooks/writes: %j', (overrides) => {
    const result = executePublish(publishScript(rendered), overrides);
    expect(result.status).not.toBe(0);
    expect(result.calls.some((call) => /^(publish:|postpublish:|runtime:|gh:release |git:(push|tag))/.test(call))).toBe(false);
  });
});

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
    expect(archetypes).toContain('cat >"$ARTIFACT_DIR/release-evidence.json" <<JSON');
    expect(archetypes).not.toContain('cat >"$RELEASE_ASSET_DIR/release-evidence.json" <<JSON');
  });

  it('binds publish provenance to the tag sha and requested run ids', () => {
    const workflow = read('.github/workflows/release-publish-reusable.yml');
    const buildScript = read('scripts/ci/run-release-build.sh');
    expect(workflow).toContain('gh run download "$PREFLIGHT_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-package --dir "$PREFLIGHT_ARTIFACT_DIR"');
    expect(workflow).toContain('[[ "$evidence_target_sha" == "$tag_sha" ]] || { echo "Preflight evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(workflow).toContain('[[ "$evidence_preflight_run_id" == "$PREFLIGHT_RUN_ID" ]] || { echo "Preflight evidence run ID does not match the requested preflight run." >&2; exit 1; }');
    expect(workflow).toContain('gh run download "$VALIDATION_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-evidence-validation --dir "$VALIDATION_ARTIFACT_DIR"');
    expect(workflow).not.toContain('"$ARTIFACT_DIR/validation"');
    expect(workflow).not.toContain('"$ARTIFACT_DIR"/*');
    expect(workflow).toContain('[[ "$validation_target_sha" == "$tag_sha" ]] || { echo "Validation evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(workflow).toContain('[[ "$validation_run_id" == "$VALIDATION_RUN_ID" ]] || { echo "Validation evidence run ID does not match the requested validation run." >&2; exit 1; }');
    expect(workflow).toContain('[[ "$validation_repo" == "$GITHUB_REPOSITORY" ]] || { echo "Validation evidence repo does not match the current repository." >&2; exit 1; }');
    expect(workflow).toContain("gh run view \"$VALIDATION_RUN_ID\" --repo \"$GITHUB_REPOSITORY\" --json conclusion --jq '.conclusion' | grep -qx success");
    expect(buildScript).toContain('validation-evidence.json');
    expect(buildScript).not.toContain('find "${artifact_dir}" -maxdepth 1 -type f ! -name SHA256SUMS | sort');
    expect(workflow).toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS" ]] || { echo "Missing preflight SHA256SUMS manifest." >&2; exit 1; }');
    expect(workflow).toContain('while read -r asset_sha asset_path; do');
    expect(workflow).not.toContain('find "$ARTIFACT_DIR" -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 >>"$ARTIFACT_DIR/SHA256SUMS"');
    expect(workflow).toContain('RELEASE_ASSET_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/release-assets.XXXXXX")"');
    expect(workflow).toContain('[[ "$RELEASE_ASSET_DIR" != "$PREFLIGHT_ARTIFACT_DIR" && "$RELEASE_ASSET_DIR" != "$VALIDATION_ARTIFACT_DIR" ]] || { echo "Release asset staging directory must be isolated from evidence download directories." >&2; exit 1; }');
    expect(workflow).toContain('resolve_preflight_asset()');
    expect(workflow).toContain('if ! release_notes_source="$(resolve_preflight_asset "$RELEASE_NOTES_FILE")"; then');
    expect(workflow).toContain('cp -p -- "$release_notes_source" "$RELEASE_NOTES_FILE"');
    expect(workflow).toContain("while read -r asset_sha asset_path; do");
    expect(workflow).toContain('if ! asset_source="$(resolve_preflight_asset "$asset_path")"; then');
    expect(workflow).toContain('cp -p -- "$asset_source" "$RELEASE_ASSET_DIR/$asset_name"');
    expect(workflow).toContain('release_assets+=("$RELEASE_ASSET_DIR/$asset_name")');
    expect(workflow).toContain('[[ ${#release_assets[@]} -gt 0 ]] || { echo "No release assets were staged for upload." >&2; exit 1; }');
    expect(workflow).not.toContain('find "$PREFLIGHT_ARTIFACT_DIR" -maxdepth 1 -type f \( ! -name release-evidence.json ! -name validation-evidence.json \) -exec cp -p {} "$RELEASE_ASSET_DIR" \;');
    expect(workflow).not.toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/$asset_path" ]] || { echo "Missing preflight release asset: $asset_path" >&2; exit 1; }');
    expect(workflow).toContain('release_args=("$TAG" "${release_assets[@]}" --repo "$GITHUB_REPOSITORY" --notes-file "$RELEASE_NOTES_FILE")');
    expect(workflow).toContain('gh release create "${release_args[@]}"');
    expect(workflow).not.toMatch(/gh release (?:upload|edit|delete)\b|--clobber/);
    expect(workflow).toContain('Existing or ambiguous release: use approved exact-match retry or reconcile manually.');
    expect(workflow).not.toContain('gh release upload "$TAG" "$ARTIFACT_DIR"/*');
    expect(workflow).not.toContain('gh release create "$TAG" "$ARTIFACT_DIR"/*');

    const archetypes = read('src/archetypes.ts');
    expect(archetypes).toContain('gh run download "$PREFLIGHT_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-package --dir "$PREFLIGHT_ARTIFACT_DIR"');
    expect(archetypes).toContain('[[ "$evidence_target_sha" == "$tag_sha" ]] || { echo "Preflight evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(archetypes).toContain('[[ "$evidence_preflight_run_id" == "$PREFLIGHT_RUN_ID" ]] || { echo "Preflight evidence run ID does not match the requested preflight run." >&2; exit 1; }');
    expect(archetypes).toContain('resolve_preflight_asset()');
    expect(archetypes).toContain('if ! release_notes_source="\\$(resolve_preflight_asset "$RELEASE_NOTES_FILE")"; then');
    expect(archetypes).toContain('cp -p -- "$release_notes_source" "$RELEASE_NOTES_FILE"');
    expect(archetypes).toContain('if ! asset_source="\\$(resolve_preflight_asset "$asset_path")"; then');
    expect(archetypes).toContain('cp -p -- "$asset_source" "$RELEASE_ASSET_DIR/$asset_name"');
    const rendered = renderManagedFiles(normalizeManifest({ project: { name: 'release-fixture', owner: 'acme' },
      archetype: { kind: 'generic-empty' }, release: { enabled: true, maturity: 'governed' } }))
      .find((file) => file.path === '.github/workflows/release-publish-reusable.yml')!.contents;
    expect(rendered).toContain('release_args=("$TAG" "${release_assets[@]}" --repo "$GITHUB_REPOSITORY" --notes-file "$RELEASE_NOTES_FILE")');
    expect(rendered).toContain('gh release create "${release_args[@]}"');
    expect(rendered).not.toMatch(/gh release (?:upload|edit|delete)\b|--clobber/);
    expect(rendered).toContain('Existing or ambiguous release: use approved exact-match retry or reconcile manually.');
    expect(archetypes).toContain('gh run download "$VALIDATION_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-evidence-validation --dir "$VALIDATION_ARTIFACT_DIR"');
    expect(archetypes).not.toContain('"$ARTIFACT_DIR/validation"');
    expect(archetypes).not.toContain('"$ARTIFACT_DIR"/*');
    expect(archetypes).toContain('[[ "$validation_target_sha" == "$tag_sha" ]] || { echo "Validation evidence target SHA does not match tag SHA." >&2; exit 1; }');
    expect(archetypes).toContain('[[ "$validation_run_id" == "$VALIDATION_RUN_ID" ]] || { echo "Validation evidence run ID does not match the requested validation run." >&2; exit 1; }');
    expect(archetypes).toContain('[[ "$validation_repo" == "$GITHUB_REPOSITORY" ]] || { echo "Validation evidence repo does not match the current repository." >&2; exit 1; }');
    expect(archetypes).not.toContain('gh release upload "$TAG" "$ARTIFACT_DIR"/*');
    expect(archetypes).not.toContain('gh release create "$TAG" "$ARTIFACT_DIR"/*');
  });
});
