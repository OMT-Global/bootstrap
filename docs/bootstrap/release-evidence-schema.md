# Release Evidence Schema

Governed releases emit machine-readable evidence into `dist/release/`.

Minimum release evidence:

```json
{
  "schema_version": 1,
  "repo": "OMT-Global/example",
  "version": "v1.2.3",
  "channel": "stable",
  "target_ref": "release/1.2",
  "target_sha": "full_sha",
  "release_issue": "123",
  "preflight_run_id": "123456789",
  "validation_run_id": "123456790",
  "publish_run_id": "123456791",
  "artifacts": [{ "name": "example-v1.2.3.tar.gz", "sha256": "..." }],
  "checks": {
    "prep": "passed",
    "preflight": "passed",
    "build": "passed",
    "full_validation": "passed",
    "publish": "passed",
    "postpublish": "passed"
  }
}
```

Expected files:

- `dist/release/release-evidence.json`
- `dist/release/postpublish-evidence.json`
- `dist/release/SHA256SUMS`
- `dist/release/RELEASE_NOTES.md`

Evidence links the release issue, target SHA, workflow run IDs, artifact checksums, release notes, and postpublish status so a release can be audited without relying on local operator state.
