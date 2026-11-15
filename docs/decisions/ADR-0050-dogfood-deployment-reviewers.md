# ADR-0050: Stage and production deployment reviewers

Status: Accepted

Date: 2026-11-11

Decision owner: OMT Global repository owner

Decision record: The owner selected `jmcte` and `athena-omt` for stage and production deployment reviews in both Bootstrap and Flow in the Bootstrap project chat. Source review, GitHub approval, and changes to live settings remain separate.

Related issue: [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63)

## Context

Bootstrap's stage and production manifest entries list only `jmcte`. Flow's normalized entries require approval but list no reviewers. With self-review prevention, a deployment initiated by the sole listed reviewer cannot be approved by that same identity.

## Decision

For stage and production in both repositories, list the named GitHub users `jmcte` and `athena-omt` as deployment reviewers, require approval, and prevent self-review. Keep development's existing open policy and the existing stage and production branch policies. Do not add either user to global pull-request reviewer settings or change CODEOWNERS as a consequence of this decision.

GitHub requires one eligible listed reviewer to approve; the list does not require both to approve. A deployment initiator cannot approve their own deployment when the self-review rule is effective. This record authorizes the named account identities; it does not assert that an account is a human or prove its availability.

## Consequences and limitations

Adding a second reviewer expands who can approve a deployment while reducing the chance that a requester has no eligible alternative. Existing administrator bypass remains unchanged; this decision does not claim that the gate prevents a permitted administrator from bypassing it. Bootstrap's `main` production manifest entry maps to GitHub's protected-branches policy, not necessarily to a literal `main`-only filter.

Manifest changes do not themselves update live environments. Before any settings change, separately review and authorize the exact environments, recheck identity and permissions, preserve existing branch policies and administrator-bypass state, and verify each readback. A configuration readback is not proof that a deployment gate was exercised. No deployment or release is authorized by this decision.
