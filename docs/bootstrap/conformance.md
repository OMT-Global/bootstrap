# Conformance core

`bootstrap conform` produces deterministic, versioned JSON and human output for
the Public Repository Standard conformance core. Each result includes a stable
rule ID, severity, classification, evidence, and remediation. Blocking findings set exit code
`1`; warnings remain distinct and return `0`.

The core validates repository class and product maturity, required managed
artifacts, immutable action pins, language-profile conflicts, typed exceptions,
licensing, and the managed-file ownership sidecar. Classification is explicit:

- `conformant`: the control is present and valid;
- `misconfigured`: the control is available but missing or invalid;
- `unsupported`: the current GitHub plan cannot provide the control;
- `waived`: a typed, approved, current exception governs the deviation;
- `unverified`: local evidence cannot establish the remote state.

## GitHub capability snapshot

Remote capability evidence stays deterministic and offline: capture it through
an authorized GitHub inspection, store it outside the repository when it may be
sensitive, and pass the versioned JSON snapshot to conformance.

```json
{
  "schemaVersion": 1,
  "observations": [
    {
      "control": "secret-scanning",
      "status": "supported",
      "evidence": "enabled",
      "remediation": "Keep secret scanning enabled."
    },
    {
      "control": "push-protection",
      "status": "unsupported",
      "evidence": "current plan does not expose the control",
      "remediation": "Upgrade the plan or retain a typed approved waiver."
    }
  ]
}
```

```sh
bootstrap conform \
  --manifest project.bootstrap.yaml \
  --target . \
  --github-capabilities /path/to/github-capabilities.json \
  --json
```

Malformed snapshots fail before evaluation. `unsupported` produces a warning;
`misconfigured` is blocking. Waivers come only from validated manifest
exceptions, never from the observation file.

## Canonical waiver targets

An exception changes a governed deviation to severity `pass` and classification
`waived` only when both its policy and scope match a canonical target:

| Control | `policy` | `scope` |
| --- | --- | --- |
| Required managed artifacts | `repository-files` | `repo.managed-artifacts` |
| Action and reusable-workflow pins | `supply-chain` | `github.workflows.actions` |
| Language-profile conflict | `language-profile` | `repo.profile` |
| GitHub capability observation | `github-capability` | `github.<control>` |

Repository classification retains its existing target:
`repository-classification` / `repo.class`. Exception-validation results report
whether the exception record itself is conformant; they are not labeled as a
waiver unless they are applied to a matching control.

Pinned action and Docker references retain a safe, single-line readable version
or release label. This label may use non-SemVer identifiers such as `bookworm`,
`alpine:3.20`, or `release/2026-07`; placeholder comments such as `TODO` are not
release metadata.
