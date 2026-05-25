# Bootstrap Vision

Version: 0.1

Bootstrap is the control plane for creating, governing, and keeping OMT-Global repositories consistent.

Its job is to turn repo setup, GitHub policy, CI templates, PR templates, release defaults, and portable Codex profile assets into explicit, reviewable configuration.

## Who It Serves

- Maintainers creating or repairing OMT-Global repos.
- Agents that need a single source of truth before applying policy changes.
- Repositories that should share governance without copy-paste drift.

## Product Principles

- `project.bootstrap.yaml` is the source of truth.
- Prefer `plan` before `apply`.
- Generated assets should be reproducible and reviewable.
- GitHub plan limits and policy blockers must be reported honestly.
- Portable profiles must exclude auth state, sessions, caches, and machine-local secrets.

## Near-Term Direction

- Keep managed templates aligned across active repos.
- Make PR validation rules consistent.
- Improve merge automation documentation and checks.
- Support stricter review policy where GitHub plan capabilities allow it.

## Non-Goals

- Do not silently mutate GitHub settings without a manifest-backed plan.
- Do not make bootstrap depend on one machine's local state.
- Do not paper over billing or ruleset limitations.
