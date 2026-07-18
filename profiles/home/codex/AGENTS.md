# Codex Home Profile

- Keep portable project-bootstrap assets in sync from the bootstrap repo.
- Treat `project.bootstrap.yaml` as the control plane for new-repo setup.
- Do not copy auth state, sessions, caches, or machine-local secrets into portable Codex profiles.
- Prefer `plan` before `apply` when provisioning GitHub policy or home profile changes.
- For a task that may open or update a PR, request autoreview network access before implementation and, for a private repository, explicit authorization to send the forthcoming intended PR diff to the external reviewer. At closeout, use the `autoreview` skill against the actual base. Verify findings, fix accepted in-scope findings, rerun affected tests and autoreview after edits, and proceed only when no accepted/actionable findings remain. Record the final command and result in the PR; if authorization is declined or autoreview is unavailable or cannot complete, stop and report the blocker.
