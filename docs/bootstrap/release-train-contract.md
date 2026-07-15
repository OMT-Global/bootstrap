# Governed Release Train Contract

Bootstrap supports four release maturity levels:

| Level | Name | Behavior |
| ---: | --- | --- |
| 0 | `none` | No managed release files are generated. |
| 1 | `simple` | Existing tag-triggered SemVer release workflow remains available. |
| 2 | `governed` | Adds release preflight, full validation, publish orchestration, postpublish verification, and release evidence. |
| 3 | `regulated` | Uses governed release flow plus stricter gates where supported, including signed tag verification when required. |

Backwards compatibility is intentional: `release.enabled: true` without `release.maturity` is treated as `simple`, and `release.enabled: false` is treated as `none`.

## Configure

```yaml
release:
  enabled: true
  maturity: governed
  reusableWorkflowRepo: OMT-Global/bootstrap
  reusableWorkflowRef: d9c5bc7e50f4bcc97e4b4d3d2efc64e4ab3dca50
```

Governed repos receive thin caller workflows for preflight, validation, publish, and postpublish verification. Package-specific behavior belongs in hook scripts under `scripts/release/`.

## Manual Release Flow

1. Open a release train issue.
2. Create or update the release branch.
3. Run `Release Preflight` and record `preflight_run_id`.
4. Run `Full Release Validation` and record `validation_run_id`.
5. Create the exact tag after validation evidence exists.
6. Run `Release Publish` with the tag, `preflight_run_id`, and `validation_run_id`.
7. Verify postpublish evidence and close or supersede the release issue.

Publish must consume the artifact bundle from the preflight run. If the preflight artifact cannot be downloaded, or if evidence does not match the tag SHA, publish fails rather than rebuilding.

## Secrets

Generated hooks are safe no-ops by default. Production credentials belong in GitHub environments, secrets, packages, or OIDC configuration, not in manifests or generated scripts.
