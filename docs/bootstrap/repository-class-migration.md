# Repository class migration

Flow's Public Repository Standard v1 has seven canonical repository classes:
`cli`, `library`, `service`, `infrastructure`, `github-action`,
`specification`, and `documentation`.

Existing Bootstrap manifests may still use `application` or `tooling`. These
legacy names never map silently. Declare the chosen canonical target alongside
the legacy value, then regenerate the manifest to retain the migration record:

```yaml
repo:
  class: tooling
  classMigration:
    target: cli
```

An `application` may map to `service`, `library`, or another canonical class
only after the repository owner selects the real product boundary. A `tooling`
repository commonly maps to `cli`, but an infrastructure control plane may map
to `infrastructure` instead.

`project.maturity` describes the product lifecycle (`experimental` through
`archived`). It is intentionally independent from `release.maturity`, which
selects the release-automation profile.
