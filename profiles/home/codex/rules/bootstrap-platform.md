# Bootstrap Platform Rule

- Shell-safe jobs must use `[self-hosted, linux, shell-only, private|public]`.
- Native OMT repos must use self-hosted runners for required automation; Docker, service-container, browser, and `container:` workloads require a dedicated self-hosted runner pool with matching capability labels.
- Stage and prod environments require reviewer gates and prevent self-review by default.
