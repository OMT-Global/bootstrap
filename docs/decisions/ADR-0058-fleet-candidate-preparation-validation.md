# ADR-0058: Prepare and validate one exact public fleet candidate

Status: Accepted

Date: 2026-11-15

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

Decision owner: Bootstrap maintainers/coordinator, for this bounded source stage.
The coordinator adopts this source component after separate-agent review of the
complete combined implementation and decision found no actionable defects.
Model-family independence is unproved. Required autoreview, independent GitHub
approval and operational authority remain separate; this is no deployment grant.

## Context

Accepted ADR-0013 supplies the isolated Node backend; ADR-0016 supplies private
raw-Git and original-checkout helpers. Both explicitly leave the supervisor
integration outside their initial implementation acceptance. Inventory and owned
policy observations cannot themselves authorize signing, publishing or pilots.

ADR-0037 supplies owned public policy observations and the inventory consumer;
ADR-0052 defines the accepted target-bound pilot rules.

The owner has selected a dedicated short-lived GitHub App capability scoped to
one approved public repository and human reconciliation after uncertain writes.
The owner has accepted target-bound pilot safety rules. Those decisions remain
unchanged. Production commit signer identity/key source has not been selected.

## Bounded decision

Add private source modules, absent from the package index and CLI, that connect
genuine owned policy/generator/raw-Git inputs to an exact candidate and to the
existing isolated validation phases. Preserve original checkout contents and Git
metadata; execute no target hooks, scripts, filters or helpers in its host context.

Require the current renderer/state fixedpoint in fresh neutral staging before
target application. Preserve unrelated raw bytes, modes and Git identities. Use
the actual renderer for managed manifests; permit only the two policy pin scalar
edits in a supported project-owned manifest. Reload and verify the target
fixedpoint and independently compute the raw candidate tree before proceeding.

Acquire anonymous fixed-origin public Git history with existing controlled-host
and process limits. Bind numeric repository identity/default head before and
after acquisition; reject shallow or unsupported metadata and require complete
valid ancestry. Match raw base/tree/blob identity to the genuine prepared source.
Do not replace the base with a fabricated consistency commit.

Snapshot an explicit branch/message/author/committer/hook plan and canonical
public Ed25519 SSH key metadata. Invoke the fixed isolated prepared-hook backend
and bind its actual result to the exact source, tree, base, plan and pinned image.
Only the resulting owned ticket releases the unsigned commit bytes. It selects
no private key, SSH agent, keyring or inferred signing identity.

An external, separately authorized trusted signer supplies the actual raw signed
commit. Verify exact tree, sole parent, author/committer identities/dates and
message, then verify its SSH signature against the selected public key. Signature
validity is not signer authorization. Build the genuine candidate/history bundle
and invoke the fixed backend's final-check phase on that exact commit. Require
matching evidence and successful owned cleanup before returning a checked result.

Maintain cleanup-only ownership after failed cleanup; prohibit signing/completion
reuse while allowing disposal retries after cancellation. A completed checked
result is a historical immutable artifact that may outlive disposal of its input
preparation ticket. Its validation caller's cancellation still disables access;
the operation deadline is not a new artifact-retention TTL.

All results continue to report no authority, unverified pilots and signer
authorization, and pending independent review/publication. No policy/pilot
eligibility, signer authorization or App capability is inferred from JSON or
synthetic tests. Do not introduce the old prototype's offline keys, saved gh
authentication, journal or cumulative-allocation ledger as prerequisites.

## Evidence and consequences

Independent review covered the full combined source diff and this decision.
The real-Git/ephemeral-signature tests establish composition and
refusal behavior; fabricated HTTP/host/Docker adapters do not establish trusted
Linux runtime or Docker confinement. Keep real execution qualification separate.

This source decision adds no operator command, installed App, credential access,
GitHub mutation, production signer, rollout or passed pilot. It does not change
the owner-selected publisher/recovery or pilot policies. Production signer
configuration, actual runtime qualification, candidate review and App publication
remain separate work. Source completion can be demonstrated with fabricated
provider integration tests; App deployment or a real fleet mutation is not an
additional issue-acceptance requirement. This component does not by itself
complete the integrated governed publisher, so issue #62 remains open.
