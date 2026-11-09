# ADR-0016: Controlled fleet supervisor host boundary

Status: Accepted

- Date: 2026-11-08
- Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62)

Acceptance is limited to the private helper prerequisite.

## Context

Governed upgrade preparation must inspect an original checkout without executing its Git configuration, filters, hooks, helpers or scripts. The isolated Node backend has a separate runtime acceptance gate. Introducing an operator apply command before that gate would join distinct authorities prematurely.

The host boundary and this helper split received independent design review. The accepted host-contract artifact has SHA-256 `8bbec96cc60851132d5df8080b08f75e925d4cc5ed2214bcdd73d9d7d5fbb8ea`; the concrete data-helper design has SHA-256 `7f93863be524814a634b390170832f09fce8d8308f711226c54dd8fb6759e416`. These identify reviewed design inputs, not GitHub approval or runtime proof.

## Decision

Add private Git-data and checkout-audit modules. They remain absent from the package index and CLI. There is no signer, network transport, provider broker, target-code runner, Bootstrap state import or operator apply path in this stage.

A copied regular-file inventory is bound to independently reconstructed Git tree and raw commit object IDs. The runtime-branded snapshot owns its bytes privately. Returned file copies cannot alter the verified source. This proves object consistency; the later executor must independently authenticate the public repository, live default commit and ancestry. An arbitrary bundle is not unpacked on the host.

Fresh staging uses a fixed, root-owned Git executable, a neutral private working directory, explicit minimal environment and empty configuration/template/hooks. Raw blobs, NUL-framed index entries and the exact base commit are written without checkout, `git add`, attribute conversion or original objects/configuration. Files and directories are created exclusively so distinct raw paths cannot silently merge through filesystem aliases.

Original checkout support starts with ordinary `.git` directories. Linked gitdirs, includes, worktree overrides, alternates, split/sparse metadata, unsupported hooks and private ignore authority block. Metadata and tracked files are opened with no-follow/nonblocking flags and checked as bounded regular singly-linked files before reading. Directory paths are checked without following symlinks. Paths use fatal UTF-8 and byte roundtrips; Git output retains NUL framing and byte order.

Raw HEAD, index entries and tracked bytes/modes must match the verified base. This catches changes hidden by index flags. Untracked enumeration is streaming and bounded and never reads private contents; ignore classification comes only from the verified public projection. Config is parsed through bounded standard input with includes disabled, so original configuration is never selected as Git authority or copied into parser files. Errors contain fixed redacted reasons.

The helper inherits the Node profile's 10,000-entry, 32-component and 512 MiB source bounds. Additional limits are 4 KiB HEAD/loose refs, 1 MiB config/packed refs/raw commits, 16 MiB index, 8 MiB child output, 30 seconds per Git command and 15 minutes per data repository. Owned process groups are terminated on cancellation, output overflow or deadline; no agent socket is inherited.

## Consequences and remaining gates

The original checkout is read-only throughout preparation. Its local audit fingerprint is not a public provenance receipt and must not be copied into a PR body as evidence of private configuration. No concurrent filesystem-replacement immunity is claimed.

Later integration must establish a genuine current-generator fixed point in fresh public staging before applying a target manifest. It must preserve the separately reviewed hook → trusted signing → final candidate check → independent review → create-only publication order. Signing capabilities, credential handling, public identity/visibility/ancestry, policy/pilot/batch governance, recovery and actual Docker integration remain outside this prerequisite. Their future implementation and GitHub approvals cannot be inferred from these helpers or local tests.
