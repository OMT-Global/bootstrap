# ADR-0022: Synthetic native reviewer platform probe

Status: Accepted

Scope: Source and CI prototype only. Native Linux support remains unproven until the exact hosted run passes.

Date: 2026-11-08

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

## Context

A controlled reviewer must keep authentication outside its tools' readable filesystem policy. Codex 0.167.0 writes refreshed FILE OAuth credentials by creating locks and a sibling temporary and replacing the destination. A readonly single-inode mount cannot support that persistence. The existing API-key-in-FILE mode does not refresh and is the bounded candidate tested here. No operator credential is inspected or provisioned.

Native restricted Linux execution requires bubblewrap/user namespaces. Compatibility with Docker's unchanged default seccomp, dropped capabilities and no-new-privileges cannot be inferred from a successful backend test or source inspection.

## Decision

Add a synthetic-only probe to the existing full-validation entrypoint, after normal checks and actual backend Docker tests. Standard, smoke and fast profiles perform no new download or container activity. The existing entrypoint acceptance test keeps all previous ordering/failure assertions and adds the Python step and its failure propagation; this required seventh path supplements the original six-file implementation scope.

Use the complete official Codex 0.167.0 Linux amd64 musl package from source commit `086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a`, archive SHA-256 `3bbf75e83de6b58aed28f2cf6e33ad423ec31fd4700a1457b94be557ea5a7c6e`. Exact size/hash limits apply to every download. Verify package, extracted CLI and bubblewrap signatures offline with fixed Cosign 3.1.4, exact workflow identity/issuer, transparency evidence and the SHA-bound root-signing snapshot at `c9bda74ad2221f938f7d2e0295ca3aad2da710a8`. Reject archive links/devices, unsafe paths, unsupported modes, duplicates, collisions or expansion beyond 2 GiB/4096 members/depth 32. Preserve the complete package, its notices and voice license inventory, plus pinned Codex, bubblewrap and ripgrep notices.

Delegate acquisition, extraction and all three mandatory offline signature checks to the fixed sibling `reviewer-artifacts.py` module at the accepted ADR0023 boundary. Call its default `stage()` exactly once with a fresh private empty owned directory and the original absolute 15-minute host deadline; never call metadata preparation or a standalone acquisition CLI first. Preserve its returned verified context, complete package/notices, artifact evidence, retained bundle bytes and public provenance without rewriting them. Host and artifact environments and clocks remain separately cleared and bounded.

Build only an ephemeral public-input image on the existing immutable MCR six-tool base. No registry image is published, package installer runs, workflow/pin changes, real authentication, helper source vendoring or new service is introduced.

The host supervisor remains outside each owned PID/cgroup namespace. Each fixture uses readonly root, no network, all capabilities dropped, no-new-privileges, the ordinary numeric UID/GID, memory 2 GiB/swap zero, 128 PIDs, two CPUs, a 256 MiB/16384-inode noexec tmpfs, bounded hard resource limits and bounded output. The 15-minute prototype deadline has independent bounded cleanup. These timings do not alter production backend or broker limits.

Run mechanical admission, byte exhaustion, inode exhaustion and detached-descendant teardown before the native sandbox canary. The native canary proves allowed workspace reads and denied private reads, writes and network. Its first failure returns unsupported/native-sandbox, stops all later cases, and leaves mock/provider request counts zero. No capability, seccomp, AppArmor, sysctl or inner-sandbox relaxation is selected here.

Only after that gate, individually mount one newly generated fake auth inode readonly and an adjacent independently generated public configuration file readonly. Do not mount a whole home, copy auth into the runtime directory, use environment-key fallback or read an operator's home. Native login-status output may reveal masked key fragments; capture/classify/discard it privately under a strict cap. Accept only API-file mode; reject OAuth/unknown and reject auto/keyring configuration before native auth or mock launch.

The API fixture uses the actual native CLI against one test-owned loopback Responses mock in a network-none container. It clears inherited environment credentials, checks that the bearer came from the fake FILE, handles the native authenticated WebSocket 426-to-SSE fallback, counts all requests and requires schema-valid output. Persistence negatives verify readonly inode metadata/bytes and parent contents. No OpenAI service or real key is used.

Emit a public `CONTROLLED_REVIEWER_EVIDENCE` UTF-8 JSON wire line capped at 65536 bytes including its prefix and LF. Check the compact encoding and any bounded failure fallback before output; retain only bounded valid fallback context and the omitted compact-byte size/hash. Save the same checked compact JSON bytes plus LF in the ignored local report. Bind actual checkout head, repository/run, public assets/source hashes, image, completed cases and cleanup. The host owns container/image removal and the entire temporary root, including staged public artifacts and fabricated auth files. Its independent 60-second aggregate cleanup clock bounds removal; success is emitted only after removal and verified temporary-root absence. Cleanup failure takes precedence over runtime or artifact success. The existing immutable callee's generic evidence artifact is unchanged; the custom record is visible in the bounded job log. Missing/failed mandatory cases cannot report success.

Retain at most six fixed command-phase records for image history and the first mechanical case, with exit status, whether that status was observed before supervisor cleanup, and byte counts/hashes for stream bytes admitted by the existing combined bound. EOF flags distinguish complete streams from bounded prefixes. Fixed first-case event and host-stage flags distinguish Docker CLI, fixture protocol and host cgroup validation boundaries without attributing an unobserved cause. Emit no argv, stdout/stderr text, paths, environment or socket content; later native/auth cases remain uninstrumented. These diagnostics cannot recover stderr discarded by an earlier run.

## Validation and limits

Mac validation consists of source compilation, archive/URL/status/config negatives, manifest projection and entrypoint/full repository checks. The host process-group negative exposed EPERM when signaling an already-exited Python child on Mac, including outside the filesystem sandbox. It is explicitly Linux-only; the mandatory Linux path executes output/deadline/group controls before any native/auth/mock activity. No local process-control or Docker support is claimed.

No production review API, receipt, signing capability, executor CLI, publication authority or actual installed-autoreview integration is added. The runner does not have the external helper installed; a direct native/mock success would not establish a complete autoreview receipt or permit fleet publication. Operator OAuth support remains unavailable under this selected mount profile. Future integration and any launch-profile amendment require their own concrete review.
