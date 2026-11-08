# Private fleet supervisor data helpers

These helpers prepare the host data boundary for [#62](https://github.com/OMT-Global/bootstrap/issues/62). [ADR-0016](../decisions/ADR-0016-controlled-fleet-supervisor-host-boundary.md) records this bounded stage. No new CLI or fleet apply API is exposed.

`verifyGitSnapshot` checks a complete regular-file inventory against raw Git tree/commit identities and copies all source bytes into private storage. `openDataRepository` materializes those bytes through raw Git plumbing in a fresh neutral repository. Neither function authenticates a GitHub repository or establishes that a base is current, public, policy-compatible or approved.

`auditCheckout` checks an ordinary local checkout against that snapshot and a separately verified literal GitHub HTTPS origin. It does not run a Git process in the original checkout or select its configuration, objects, hooks or local state. Staged changes, raw dirty bytes, unsupported layouts, private ignore rules and non-ignored untracked files block. Nothing is reset, cleaned or repaired. Fixed errors omit original paths, configuration values and process stderr.

The supported source domain consists of UTF-8 regular files with Git modes `100644` and `100755`. Unsafe relative names, `.git` variants, reserved build/dependency roots, unsupported byte paths, file/directory collisions, resource overflows and filesystem aliases block. Original tracked/metadata links, FIFOs, devices and sockets cannot supply bytes. Ignored untracked contents remain unread.

The returned original-state fingerprint is a local audit aid; keep it with local operator evidence. It is not an authenticated capture receipt or a substitute for independent visibility, provenance, review or confinement proof. Dispose of each fresh data repository after its owning operation, including failures.

Before restoring the executor, the parent backend still needs successful actual hosted Docker tests and a clean full-diff review. The executor must independently verify live public source, establish legitimate fresh Bootstrap state from an unchanged projection, freeze its target files, replay the supported hook in isolation, sign through the selected trusted broker, validate that exact candidate in isolation, review it and publish through create-only ref protection. This helper stage grants none of those later actions.
