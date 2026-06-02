import { describe, expect, it } from 'vitest';

import { renderManagedFiles } from '../src/archetypes.js';
import { normalizeManifest } from '../src/manifest.js';

describe('release postpublish rendering', () => {
  it('fails closed when the postpublish hook is missing or not executable', () => {
    const manifest = normalizeManifest({
      version: 1,
      project: { name: 'example', owner: 'octo-org' },
      archetype: { kind: 'node-ts-service' },
      release: { enabled: true, maturity: 'governed' }
    });

    const rendered = renderManagedFiles(manifest);
    const workflow = rendered.find((file) => file.path === '.github/workflows/release-postpublish-reusable.yml');

    expect(workflow).toBeDefined();
    expect(workflow?.contents).toContain('if [[ -x "$POSTPUBLISH_SCRIPT" ]]; then');
    expect(workflow?.contents).toContain('Postpublish verification hook is missing or not executable');
    expect(workflow?.contents).not.toContain('|| true');
  });
});
