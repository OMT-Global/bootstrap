# GitHub-hosted CI images

`ci.githubHostedImage` optionally selects `ubuntu-latest` or `ubuntu-24.04` for ordinary GitHub-hosted CI jobs. Omitting it preserves the existing `ubuntu-latest` output and normalized manifest bytes.

```yaml
ci:
  runnerPolicy: github-hosted-first
  githubHostedImage: ubuntu-24.04
```

The setting applies to the generated PR, extended-validation, issue-hygiene, and Claude jobs when they run on GitHub-hosted runners. It also selects the Linux runner for public dependency review, SBOM, and advanced CodeQL analysis, and the supported `runs-on` input of the simple release caller. Swift CodeQL keeps its macOS runner.

Runner capability routing and private/public self-hosted pool labels are unchanged. Public security jobs remain on GitHub-hosted runners; pull-request events and token permissions retain their existing restrictions. This field does not add an execution platform or an arbitrary runner expression.

Governed release callers, generated governed reusable release workflows, and shared AI-attestation callers keep their existing runner/input contracts and immutable references. The setting cannot override the implementation of a remotely pinned reusable workflow. Change those contracts separately with compatible reviewed workflow pins.

For Bootstrap's dogfood migration, the owner approved preserving its ordinary Ubuntu 24.04 jobs and a project-owned README plus `scripts/release/{prep,build,postpublish}.sh`. This source prerequisite only adds the image setting. The manifest ownership selection, repository plan/apply, sidecar verification, and real release hooks are separate follow-ups; no settings, merge, or release publication occurs here.
