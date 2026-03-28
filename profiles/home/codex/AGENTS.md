# Codex Home Profile

- Keep portable project-bootstrap assets in sync from the bootstrap repo.
- Treat `project.bootstrap.yaml` as the control plane for new-repo setup.
- Do not copy auth state, sessions, caches, or machine-local secrets into portable Codex profiles.
- Prefer `plan` before `apply` when provisioning GitHub policy or home profile changes.
