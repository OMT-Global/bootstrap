# new-project-setup
Manifest-driven bootstrap CLI for repo governance, agent setup, and split CI.

This repository was bootstrapped with a manifest-driven baseline for:

- GitHub governance and environments
- repo-local AGENTS and CLAUDE instructions
- split fast and extended CI
- Codex and Claude home profile sync

## Bootstrap Metadata

- Owner: `OMT-Global`
- Visibility: `public`
- Default branch: `main`
- Archetype: `generic-empty`

## First Pass

1. Review `project.bootstrap.yaml`.
2. Run `project-bootstrap plan --manifest ./project.bootstrap.yaml`.
3. Apply repo, GitHub, and home setup in that order.
4. Confirm branch protection points at the `CI Gate` status.

## Claude Code

This bootstrap can prepare these Claude workflows:

- First-party Claude Code on the web via `claude.ai/code` and `bash scripts/claude-cloud/setup.sh`
- Interactive containerized work via `.devcontainer/devcontainer.json` and `bash scripts/claude/setup-devcontainer.sh`
- Remote GitHub-hosted automation via `.github/workflows/claude.yml`

The full checklist is in `docs/bootstrap/claude-environment.md`.

## Repository URL

- https://github.com/OMT-Global/new-project-setup
