# Codex Home Profile

- Keep portable project-bootstrap assets in sync from the bootstrap repo.
- Treat `project.bootstrap.yaml` as the control plane for new-repo setup.
- Do not copy auth state, sessions, caches, or machine-local secrets into portable Codex profiles.
- Prefer `plan` before `apply` when provisioning GitHub policy or home profile changes.
- Before opening or updating a PR, use the `autoreview` skill against the intended PR diff and actual base. Verify findings, fix accepted in-scope findings, rerun affected tests and autoreview after edits, and proceed only when no accepted/actionable findings remain. Record the final command and result in the PR; if autoreview is unavailable or cannot complete, stop and report the blocker.
