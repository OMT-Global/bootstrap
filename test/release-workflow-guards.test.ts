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
});
