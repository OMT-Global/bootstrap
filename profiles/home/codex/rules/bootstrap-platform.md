# Bootstrap Platform Rule

- Shell-safe jobs may use `[self-hosted, synology, shell-only, private|public]`.
- Docker, service-container, browser, and `container:` workloads remain on GitHub-hosted runners.
- Stage and prod environments require reviewer gates and prevent self-review by default.
