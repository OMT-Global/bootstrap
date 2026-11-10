# ADR-0031: Agent-free generator source capture

Status: Accepted

Scope: Internal source prerequisite for [issue #62](https://github.com/OMT-Global/bootstrap/issues/62); runtime activation and full issue acceptance remain gated.

## Context

ADR-0013 and ADR-0016 keep target-controlled hooks and Git configuration outside trusted host authority. Governed upgrade preparation also needs an exact trusted generator source identity. The unmerged broker prototype combines that source audit with SSH signing-key and agent selection, making a read-only preflight depend on signing setup.

The complete governed fleet route remains unfinished. This decision covers its real source-audit producer and fixed host support; it does not enable fleet execution or establish the complete installed review runtime.

## Decision

Add internal `capturePublicGenerator(root, expectedCommit)` with no package export or CLI registration. Its actual controlled Git operations audit ordinary or linked Git layout, config restrictions, the exact raw HEAD, bounded object/index metadata, every tracked source byte and executable mode, and untracked-file eligibility. Hooks, filters, fsmonitor, includes and credential helpers do not execute from the audited checkout. Temporary Git config, worktree, index and ignore processing belong to a separate private directory.

The operation requires no `user.name`, `user.email`, `gpg.format`, `user.signingkey`, public-key file or `SSH_AUTH_SOCK`. It selects only the supported fixed Linux Git/prlimit tools. Later G02 `captureGeneratorSigning` is the named next source consumer and must perform fresh source capture plus its own strict identity/key/agent selection. A source capture grants no signing or publication permission.

Return only a frozen source-commit, tree and source-hash projection. A private registry binds that actual result to the existing verified raw snapshot; copied objects or JSON cannot import that producer identity. Configuration bytes, local paths, ignored files, keys and sockets are not part of the public result. Source and parser limits apply before each bounded read and before the snapshot's owned copy. Retained material still needs the later attempt owner's explicit accounting.

Preserve the existing seven data helpers byte-for-byte. The extracted host support retains bounded reads, trusted executable ancestry, neutral environment, owned process groups and fixed-operation configuration. Its dedicated Git primitive has a fixed 30-second deadline; the audit context has a 15-minute lifetime. Generic 90-second host operations do not extend either bound. Cancellation or failed owned cleanup prevents a completed capture, with a fixed redacted error.

## Evidence limits and remaining work

This proves a checked raw tracked-source/lock snapshot, not the identity of ignored `dist`, `node_modules`, loaded JavaScript/native code or the running OS. Trusted immutable installation/build/tooling remains a distinct deployment assumption and qualification input. The expected commit must come from trusted configuration; this producer does not independently establish GitHub visibility or authorize a caller-supplied commit.

Real Git and filesystem tests cover source/config/layout drift, hidden index changes, canaries, bounds, cancellation, cleanup and public-result ownership. Darwin flow tests simulate only Linux eligibility/prlimit; they provide no Linux kernel or confinement evidence. The complete broker, exact signing, isolated backend, unchanged full review helper, authentic pilot evidence, create-only publication and final runtime qualification remain separate prerequisites. No issue closure, provider action, settings change, release, new process-wide allocation certificate or hardware-journal guarantee follows from this source stage.
