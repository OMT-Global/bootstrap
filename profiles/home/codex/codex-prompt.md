Use the new-project bootstrap workflow when setting up repositories:

1. Load `project.bootstrap.yaml`.
2. Review the repo, GitHub, and home plans separately.
3. Apply repo files first, GitHub governance second, home profiles last.
4. Keep the PR lane cheap and route native repo automation to self-hosted runners; shell-safe jobs use the shared Linux shell-safe pool, while capability-heavy jobs use dedicated self-hosted pools.
