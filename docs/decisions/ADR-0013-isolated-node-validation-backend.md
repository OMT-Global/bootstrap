# ADR-0013: Isolate Node validation before fleet executor integration

Status: Accepted

Date: 2026-11-08

Decision owners: Bootstrap maintainers

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62)

## Context

The prepared fleet executor ran repository-controlled checks and commit hooks in the authenticated operator context. Verified public origin, a clean checkout, and a current default-branch SHA do not grant target code access to cross-repository credentials, home files, agent sockets, or the network. The executor was extracted from the consolidation lane and preserved separately while this boundary is addressed.

A separate software-architect agent independently reviewed the [frozen isolation proposal](../security/fleet-isolation-design.md) at SHA-256 `b44c9b9b7f9e53a68b19430ae1607d1e39de94fbd1b4c76de5012088894ef6ca` and found no architecture blocker to this bounded backend stage. This records coordinator adoption of that architecture after an independent automated review. It does not replace exact-head GitHub approval or establish that the implementation confines code successfully.

## Decision

Implement one code-owned `node-npm-linux-v1` profile for Linux/amd64, pinned to the official Node Bookworm image `docker.io/library/node@sha256:6b9d4ea31e614e29f364bf75758458731eb1e105b80c99667438dd6b3fe262e0`. Probe Bash, Git, Python 3, Node 24, and npm in that exact image before any target-controlled phase. A missing/incompatible runtime or tool blocks; no host-shell, VM-start, or networked-validation fallback is permitted.

The backend accepts only explicitly frozen public source and sanitized Git data from a future trusted supervisor. It must not import the original checkout's Git/configuration, ignored files, credentials, home, caches, or sockets. Dependency preparation accepts only bounded public npm-registry archives with verified SHA-512 integrity; download them as inert data without authentication or redirects. Cache preparation and installation run offline with lifecycle scripts disabled. No target code executes online.

Run validation and required-hook replay in independent fresh containers with networking disabled, a read-only root and prepared source/index, non-root target execution, no Linux capabilities, no-new-privileges, explicit resource/tmpfs/source/download/output bounds, and cleanup on every exit path. Permit only profile-owned writable temporary/dependency/build locations. Do not bind-mount host paths or accept target-provided Docker arguments. Killing a client process alone is insufficient cleanup.

The initial hook contract supports no executable hook or a regular in-repository `.githooks/pre-commit`, bound to the prepared source/index/base. Other effective executable hooks, external hook paths, unsupported toolchains, workspaces, private dependencies, and authentication-bearing npm configuration fail closed. The backend exposes distinct `prepared-hook` and `final-check` phases. The first binds the hook to base HEAD and the prepared index; the second verifies the supplied final candidate has exactly the expected parent, message, and raw prepared tree before running checks with that candidate as clean HEAD. The backend never treats a sandbox-produced tree or claimed digest as authority to sign or publish.

This stage supplies the backend and tests only. The separate supervisor integration must construct a disposable publication repository, independently verify the frozen raw tree, replay required hooks in isolation, create/sign the exact commit through trusted Git plumbing, validate that exact final commit, and perform create-only publication after review. Repository hooks/filters/fsmonitor/remote helpers must never execute in the credentialed host context. The original checkout remains unchanged.

## Validation and activation boundary

The separate [implementation review](../security/fleet-isolation-implementation-review-2026-11-08.md) records exact source hashes and its remaining runtime-evidence boundary. Run meaningful local regression tests and required branch autoreview, then actual hosted Docker tests on the exact reviewed revision. Before the new standalone workflow is registered on the default branch, dispatch the existing [Full Release Validation](../../.github/workflows/full-release-validation.yml) caller from the backend branch with `release_profile=full`; its reviewed extended script requires the Docker suite. The new [manual hosted workflow](../../.github/workflows/fleet-isolation-validation.yml) is a post-merge convenience route, not an assumed pre-merge dispatch capability. Actual image/tool probes, locked offline installation, validation, hook behavior, hostile environment/file/socket/network canaries, immutable prepared source, timeout cleanup, and unsupported-input guards are required evidence. Argument spies and a passing unit suite do not establish confinement.

Local Docker was unavailable while the design was prepared. Runtime readiness remains pending until the real hosted suite passes. Acceptance of this architecture neither enables a fleet apply command nor authorizes live target mutation, remote settings, signing/publishing operations, merge automation, or a production rollout. Keep #62 open through supervisor integration and its acceptance evidence.

## Consequences

- The first profile deliberately supports a smaller runtime surface than the eventual polyglot fleet inventory.
- Docker/kernel, selected image, and trusted supervisor/tooling remain trust boundaries; this does not claim resistance to their compromise.
- Other toolchains, private registries, broader hook lifecycles, macOS sandboxing, and runtime provisioning need separate reviewed profiles.
- Missing evidence, unsupported behavior, and incomplete cleanup remain explicit failures rather than implicit permission to run on the host.
