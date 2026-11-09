# Fleet isolation backend

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62). [ADR-0013](../decisions/ADR-0013-isolated-node-validation-backend.md) accepts the bounded architecture; the [review record](../security/fleet-isolation-design.md#independent-review-and-backend-stage-disposition) distinguishes that decision from runtime evidence.

This is the backend stage. It does not expose a fleet apply command, construct a signed publication commit, push branches, open PRs, or complete #62. The previously prepared executor remains outside the safe consolidation lane until its separate supervisor integration uses a proven isolated backend.

## Supported boundary

The initial profile is `node-npm-linux-v1`, requiring a Linux/x64 supervisor and a local Linux/amd64 Docker daemon at `unix:///var/run/docker.sock` with an empty CLI configuration. Remote Docker contexts are unsupported. The profile uses the code-owned immutable Microsoft Dev Containers image `mcr.microsoft.com/devcontainers/javascript-node@sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6`. Bash, Git, Python 3, Node 24, npm, and jq must execute successfully, including a fixed real jq JSON transform, before target scripts run. The [image provenance record](../security/node-npm-linux-v1-image.md) records the observed tag, OCI identities, source-chain limits, and Node patch difference. Source/package metadata about the image is not a substitute for those probes.

The Docker executable must resolve from `/usr/bin/docker` or `/usr/local/bin/docker` to a regular root-owned file and root-owned, non-group/world-writable canonical directory chain. Repository-controlled PATH entries are never searched; another installation location is unsupported by this first profile.

Inputs come from an explicitly frozen public-source snapshot and sanitized Git data. Never pass a live source checkout's `.git`, ignored files, authentication, home, caches, environment, or sockets. The profile rejects unsupported toolchains, workspaces, private/Git/file dependencies, authentication-bearing npm configuration, and unsupported effective hooks. It does not start or install a local container runtime and never falls back to host execution.

The code-owned limits are explicit:

| Surface | Limit |
|---|---|
| Source | 10,000 total file/directory entries, path depth 32, 512 MiB total |
| Public Git bundle | 64 MiB |
| Package / lock JSON | 1 MiB / 16 MiB; `package-lock.json` is the sole root lock, root `npm-shrinkwrap.json` is unsupported |
| Candidate branch | 4,096 ASCII bytes |
| Copied input storage | 1,536 MiB; 65,536 inodes |
| Prepared source / Git storage | 2 GiB |
| Pristine cache / each phase cache | 1 GiB each |
| Dependency archives | 1,000 archives, 64 MiB each, 512 MiB total |
| Execution | 15 minutes per phase, 60 minutes absolute per backend call; 2 CPUs, 4 GiB memory, 256 PIDs |
| Phase temporary storage | 256 MiB; executable only in actual hook/check containers |
| Storage keeper | 0.1 CPU, 64 MiB memory/swap, 16 PIDs, 1 MiB non-executable temporary filesystem |
| Download | 30 seconds per archive |
| Retained Docker output | 8 MiB across the run |

The input volume retains the complete 512 MiB source, 512 MiB archive and 64 MiB bundle budgets together. Its generated manifest is finite: branch names have a 4,096-byte ASCII limit; other strings, paths and entry counts already have explicit limits. Even allowing six JSON bytes per input byte, 10,000 path descriptors plus the remaining fields fit below 256 MiB. At most 11,003 regular files add less than 44 MiB of 4 KiB page tails, including setup and manifest. Thus 1,536 MiB exceeds the full payload, generated data and page-rounding bound without reducing accepted source, path or archive budgets. The input-only inode limit covers at most 11,007 materialized objects including its root. Inode/dentry kernel memory and host/cgroup charging remain separate resources; this storage calculation does not prove a whole-run RAM bound. The actual kernel mount/options and complete pipeline remain part of required Linux acceptance.

The 2 GiB source volume reserves space for the 512 MiB worktree and its separately written loose Git objects, the retained 64 MiB base pack, and tree/index/page/temporary bookkeeping. A conservative engineering envelope including 1.2 times payload plus per-entry object/tree reserve, worktree/object page tails, index/lock data, pack indexes and fixed temporary room is below 1.67 GiB under the documented entry/path bounds. This is sizing headroom, not a theorem for every Git representation, filesystem or whole-run memory use; process buffers and kernel accounting still face the unchanged 4 GiB worker limit.

The pristine cache and each fresh phase cache have matching 1 GiB quotas. This leaves finite space beyond the 512 MiB compressed archive budget for content/index page tails, one archive's compressed restaging, temporary extraction, install metadata and logs. The seed content/index estimate alone is about 520 MiB under 4 KiB allocation; it is not the complete npm install footprint. `npm cache add` can extract a tarball to read its manifest, so compressed download bounds do not bound expansion. Large expansions, dependency graphs, logs, build output or aggregate memory pressure can still exhaust a quota and fail closed; no payload budget is reduced and no access widens. Root shrinkwrap is rejected before package-lock parsing so preparation and both installs use the validated root graph; an ordinary nested filename remains inert source data.

The cache, input, source, temporary, dependency, and build filesystems also have fixed bounds in the profile. An unsupported write location or exhausted bound fails rather than widening access. A trusted inert `-storage` container continuously holds all three Docker local-driver tmpfs volumes from before data copy through completion. It uses the same non-root, network-disabled, read-only-root, capability-free controls as the worker containers. The supervisor verifies its live state before preparation, before each phase, and before returning evidence; death or deadline expiry blocks success. The host watchdog and keeper timer share the same absolute deadline from backend entry.

Actual hook/check containers explicitly permit execution on `/repo/project/node_modules` for installed tools and on the existing 256 MiB `/tmp` for temporary native/script helpers created by normal repository tests. Preparation keeps its 256 MiB `/tmp` non-executable; the keeper keeps its 1 MiB `/tmp` non-executable. Installer, npm-cache, and build tmpfs mounts also remain explicitly `noexec`. All retain their listed sizes, ownership, `nosuid`, and `nodev` settings. This is a fixed internal profile choice; callers cannot choose executable mount paths. Prepared source/index remain read-only, and network, credentials, privileges, resources, and timeouts keep their existing boundary.

Every created container explicitly uses `--log-driver none`; bounded attached output is the report path. This avoids an unbounded daemon log alongside the supervisor output budget. Cleanup removes workers first, the keeper last, then volumes.

The trusted supervisor must supply explicit planned public author and committer identities, including raw Git dates (`epoch timezone`). There is no default identity, ambient configuration fallback, or inference from the DCO. The supported hook context is root-directory, no-editor, all-staged, and single-parent only; partial commits, amendments, merges, editor sessions, and subdirectory-prefix contexts need a later reviewed profile. Hook replay exports `.git/index`, empty `GIT_PREFIX`, `GIT_EDITOR=:`, both planned identities/date values, and a sanitized local Git user matching the planned committer.

The declared comparison is `git --git-dir=.git -c core.hooksPath=.githooks commit --file=<public-message>` with the frozen `.git/COMMIT_EDITMSG` already prepared. The hook phase dispatches `git --git-dir=.git -c core.hooksPath=.githooks hook run pre-commit`, so Git provides `GIT_DIR=.git` and nested Git sees the enabled `.githooks` configuration. Preparation retains disabled hooks; the command-scoped override activates only the authorized hook. This is the fixed profile's invocation contract, with no promise of arbitrary ambient-message or OS/process introspection equivalence.

The expected pipeline is:

1. Validate the supported source, package/lock, hook, and profile inputs and freeze their exact bytes/modes.
2. Download bounded public registry tarballs as inert data, reject redirects or credentials, and verify SHA-512 integrity.
3. Populate a disposable cache and verify the exact lock offline with lifecycle scripts disabled. Create the reserved empty `node_modules` and `dist` mount points before mounting the prepared source read-only.
4. Run the explicit `prepared-hook` phase against the base HEAD and prepared read-only index. After the future supervisor independently constructs/signs the exact public candidate, run the separate `final-check` phase with that candidate object as clean HEAD, verifying its exact raw author/committer identities/dates, parent, message, and prepared tree. Each phase uses a fresh, independent network-disabled container, copies the pristine cache, and installs its own exact dependencies with `npm ci --offline --ignore-scripts` before invoking the hook or check. Prepared source and sanitized Git/index data remain read-only; only bounded temporary, cache, dependency, and build locations are writable.
5. Remove each container and its ephemeral storage after success, failure, timeout, cancellation, or partial startup. Cleanup errors remain visible and cannot establish successful validation.

No host path is bind-mounted. Target code receives fixed execution-related environment overrides, no fleet credentials or host agent sockets, no Linux capabilities, and no external network route. The remaining public image environment is trusted image input, not a cleared environment; its six inherited names are documented in the image record. Numeric UID/GID 1000, the fixed entrypoint/PATH/HOME/npm configuration, read-only root, and no-new-privileges override the image's development defaults. Actual acceptance must show `sudo -n id -u` fails under `NoNewPrivs=1` despite the image's passwordless configuration. The first hook contract permits only no hook or the regular in-repository `.githooks/pre-commit`; do not silently skip other required hooks. The future trusted supervisor must independently reconstruct and sign its own exact tree rather than accepting sandbox-produced Git objects as publication authority.

## Required runtime proof

Before the new standalone workflow is registered on the default branch, use the existing registered [Full Release Validation](../../.github/workflows/full-release-validation.yml) caller. The backend branch's reviewed `ci.customScripts.extended` projection runs normal fast checks, then pulls the pinned image and requires the Docker suite only when `RELEASE_PROFILE=full`. This preserves cheap ordinary PR checks; another profile prints an explicit non-execution message.

After local checks and independent source-delta review, dispatch the existing caller from a committed WIP backend branch with its exact target SHA. Complete final branch autoreview after hosted proof and any resulting fixes; a PR/readiness claim requires both gates:

```sh
gh workflow run full-release-validation.yml --repo OMT-Global/bootstrap \
  --ref codex/fleet-isolation-backend \
  -f target_ref=<reviewed-40-character-commit-SHA> -f release_profile=full
```

The new manual [Fleet Isolation Validation](../../.github/workflows/fleet-isolation-validation.yml) workflow is a post-merge convenience route once registered. It runs on GitHub-hosted Ubuntu with read-only repository permission, exact-head checkout, and no production fleet credentials. Both routes set `BOOTSTRAP_REQUIRE_ISOLATION_TESTS=1`; unavailable Docker or skipped confinement tests must fail.

Record its exact head SHA, image digest, all six actual tool versions, jq functional result, privilege-block result, offline-cache result, and hostile integration-test results in the PR validation evidence. The suite must demonstrate that fabricated operator environment/file/socket canaries and an outside workspace cannot be read or changed, external networking is blocked, supported hooks really run, failed or mutating hooks block, both fresh phases can import a locked public dependency and directly execute both the locked compiler through `node_modules/.bin` and a fresh helper under bounded `/tmp` without running lifecycle scripts, storage-keeper loss blocks evidence in both phases, and containers/volumes are cleaned up on failure/cancellation. The suite inspects the actual keeper mounts, confinement settings, resource limits, disabled daemon logging, and both configured and kernel-visible executable flags for each phase tmpfs. Natural 60-minute expiry is covered by controlled-clock regressions; the hosted death cases kill the keeper to keep the run bounded. Host Git configuration canaries must cover any host Git reads; testing only pre-commit/pre-push hooks is insufficient for supervisor integration.

At design time, local Docker/Podman was unavailable and no VM/runtime was installed or started. Until the hosted suite succeeds at the exact implementation head, describe the profile as unproven. A successful backend test run does not authorize live fleet execution: supervisor integration, exact-commit review/checks, and an explicitly inspected target allowlist remain separate gates.

## Failure and recovery

Treat unsupported input, incomplete offline cache, unexpected prepared-source writes, missing tools, startup failure, storage-keeper loss, timeout, and cleanup failure as blockers. Preserve sanitized phase/reason evidence without printing target output as trusted text or exposing credentials. The API accepts an `AbortSignal` and force-cleans its named containers/volumes before returning cancellation. Abrupt supervisor loss or SIGKILL cannot guarantee a `finally` block executes; inspect resources carrying the `bootstrap.isolation` label and any reported credential-free scratch recovery state before retrying. Never reset or clean the original checkout to make a failed run appear successful.
