# ADR-0017: Bounded fleet host brokers

Status: Accepted

- Scope: Private broker prerequisites; runtime acceptance remains required
- Date: 2026-11-08
- Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62)

## Context

The data helpers in ADR-0016 prove raw Git consistency and audit an original checkout without selecting its configuration as execution authority. A later supervisor also needs independently authenticated public history, bounded host transport, the selected generator signing identity, and create-only publication. These are separate authorities from the isolated backend and its target-code checks.

The independently reviewed transport design is identified by SHA-256 `632f8f3fa6ba0b9eeb7c1cf72747ca3eb657128bd0bc4c12bd3309f74e573866`. Its implementation seam and narrow provider protocol amendment are identified by `1dff4c40a0a204036bc2224889efd958a1ab3ea22b5ff6333cdb83e70772ad14`; the audit/buffer admission amendment is `efb5e81a35a1e63eae6aea3f0c3abbb828bf6dd2ad962e7c6c9ff2e89f44f506`. These identify reviewed design inputs, not provider approval or runtime evidence.

## Decision

Add private fixed-operation host, transport, signing and publication modules. The package index and CLI expose none of them. No target hook or check runs on the host, and no operator apply path is enabled by this stage. Original checkout configuration, objects, branches and authentication are never imported into publication.

The initial transport profile requires Linux x64, a nonroot matching real/effective/saved/filesystem UID, no inherited/permitted/effective/ambient capabilities, adequate inherited ceilings, and process headroom. Fixed system Git, its HTTPS helper and `prlimit` must have root-owned non-writable executable ancestry without setid bits. Missing or unsupported prerequisites block without installation or an unrestricted retry.

Anonymous canonical GitHub metadata must bind public repository identity, actual default branch and exact approved base. Certificate verification is explicit; unsupported ambient Node TLS/CA/runtime overrides block before any request. Trusted ordinary platform roots and the loaded Node runtime remain host prerequisites. Redirects and authentication inheritance are disabled. A fresh repository fetches that exact base using protocol 0, `--keep`, positive depth 10,000, no tags/submodules/maintenance/commit graph/FETCH_HEAD. Positive depth blocks Git's dumb-HTTP walker. Acceptance requires one bounded pack/index pair, optional small keep file, bounded known metadata, no loose/alternate/promisor/shallow/other storage, full strict connectivity, and raw commit/tree/blob verification through the unchanged helper. Incomplete or oversized history is unsupported.

Every fixed child operation has bounded binary output and owned process-group cancellation. The Linux limits are 64 MiB per regular file, 60 CPU seconds, 1 GiB address space, 64 descriptors, 128 real-UID processes/threads and no core dump, with a 90-second wall deadline. FSIZE is per-file; CPU/address limits are per-process. NPROC is a real-UID backstop and may refuse work when other processes consume the budget. These are not a filesystem quota, cgroup or whole-host allocation guarantee. Raw source remains bounded by the existing 512 MiB/10,000-entry/32-component profile; returned self-contained bundles are bounded to 64 MiB.

A private additive 2 GiB admission ledger reserves concurrent packed, snapshot/read/copy/framing, expanded loose-object, materialized, index/lock, replacement, metadata and bundle representations before inspection or trusted writes. Blob acquisition charges chunks, concatenation output and the helper's private copy before decompression. Immutable cached inventory facts size helpers without creating an unreserved sizing copy. Known Git objects use the conservative bound `2*n + 4096`, with explicit tree/index/temporary allowances. Packed size never stands in for expanded helper storage. Audit/copy buffer charges stay held; temporary helper storage releases only after serialized confirmed cleanup. Uncertain cleanup retains the charge. This logical ceiling can reject a source that individually fits the source profile and makes no RSS or GC quota claim.

The named original-audit wrapper reserves before any original read/helper creation, requires the selected default symbolic HEAD before and after, and delegates raw commit/index/tree/file comparison to the unchanged helper. Detached or another branch at the same base is unsupported. Each original file is fstat-checked against its verified per-file byte bound before allocation/read, so an oversized dirty original does not become an allocation allowance. Private untracked contents are never read; unknown-name/index/config/ref buffers have independent bounded reservations.

Signing captures only safe explicit standard global and selected generator-common configuration, preserving effective local identity and SSH choice. The generator must match the approved raw commit and clean tracked source/index; unsupported includes/worktree/injected overrides, other formats, private-key paths, custom SSH signer programs or configured trust policy block. Only an existing regular singly linked ed25519 public `.pub` plus existing owned agent socket is supported. Already-loaded trusted runtime dependencies and ignored build outputs remain part of the generator runtime trust assumption.

Freeze author equal to committer, one UTC date, base, branch, message/DCO and supported hook before validation. Sign only the independently bound prepared tree with fixed `commit-tree` and the captured agent capability. Parse exact raw tree, sole parent, identities, dates, message and SSH signature headers; verify with the copied selected public key, scoped single-key allowed signers, fixed principal and Git namespace. Only this signing operation receives the socket.

Publication supports a fixed trusted GitHub CLI and a narrow existing standard-file, static, nonrefreshing github.com profile. No credentials are copied. Unsupported keyring/refresh/endpoint/alias/override contexts block. A bounded credential wrapper authorizes only `get` for exact HTTPS host and repository path before invoking gh. It recognizes only the two standard optional capability declarations, strips them, and negotiates no state/authtype/refresh output. Missing, duplicate, unknown or mismatched fields yield no credential and invoke no provider. All provider operations use minimal publication-only environment.

Push uses the literal repository URL, explicit candidate-to-ref refspec and empty expected lease. A successful result must also report the exact new branch, because Git may report an already-existing identical branch as up to date without evaluating the lease. Structured draft creation/readback binds repository, actual default base, branch, head SHA and URL. Cancellation/disconnect can mean an uncertain push. Operational failures retain truthful candidate/ref/recovery location and known PR URL; cleanup never resets or overwrites remote state.

## Acceptance and later integration

Default tests prove fixed-operation flow and real Git/ephemeral SSH semantics without operator credentials. Darwin simulations are explicitly not Linux enforcement evidence. Full validation separately requires actual Linux resource, file-shape/large-object, admission and real backend composition tests with fabricated data and ephemeral test keys. Required-mode tests fail closed when prerequisites are missing. Existing backend-only Docker proof cannot satisfy these new gates.

The later executor must still enforce genuine current-generator fixed-point ownership, exact original-state preservation, policy/pilot/batch governance, prepared hook → trusted signing → final candidate checks → required independent review → create-only publication. These private capabilities do not grant an exception to those gates. No merge, settings, home profile, deployment, release or live fleet operation is authorized by this ADR.

Primary mechanism references: [Git fetch](https://git-scm.com/docs/git-fetch), [Git credentials](https://git-scm.com/docs/git-credential), [create-only lease](https://git-scm.com/docs/git-push), [Linux limits](https://man7.org/linux/man-pages/man2/getrlimit.2.html), [GitHub CLI configuration](https://cli.github.com/manual/gh_config).
