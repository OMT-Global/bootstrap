# Optional release-publish environment

Bootstrap supports an optional `environments["release-publish"]` entry for the environment named by the generated publisher. It is absent by default, including in Bootstrap's own manifest. The existing `dev`, `stage` and `prod` settings retain their behavior.

The entry requires one to six explicit user or team reviewers, `requireApproval: true`, `preventSelfReview: true`, and `branches` containing exactly the configured default branch. Global reviewer defaults are not inherited. User names and organization/team targets resolve to unique valid IDs before the GitHub writer makes changes; GitHub determines their eligibility. Only one listed reviewer needs to approve a deployment. [Environment API](https://docs.github.com/en/rest/deployments/environments#create-or-update-an-environment).

The branch array expresses **protected branches generally** in the remote API. It is not an exact default-branch allowlist. The writer verifies that the default branch exists with classic protection; unknown or ruleset-only proof stops. GitHub evaluates deployment ref restrictions against the workflow's `GITHUB_REF`, rather than the publisher's `inputs.tag` or later checkout. Exact tag, ancestry, source and asset validation remain part of the separate publication packet. [Deployment rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#deployment-branches-and-tags).

## Create or verify

A matching existing environment causes no environment PUT. Additional protections are preserved and reported as outside this capability's management. A conflict requires a separately reviewed policy change.

Only an actual captured HTTP 404 with valid expected error JSON from the fixed environment GET permits one protected create-or-update attempt. Permission, transport, malformed response and ambiguous status failures stop. Text mentioning `404` is insufficient. A successful write is followed by a GET verifying the exact reviewer identities, self-review prevention and protected-branch flags, then another protection check. No bare-environment fallback is used. Unknown write or verification outcomes may be partial; inspect before any retry.

The API does not provide atomic create-if-absent. Coordinate trusted configuration writers to avoid an intervening administrator change. Administrators can bypass protection by default and can change settings later; this capability does not manage or verify bypass policy. The later operation packet must record its selected bypass policy. Protection observations can become stale. [Environment API](https://docs.github.com/en/rest/deployments/environments#create-or-update-an-environment), [administrator bypass](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#allow-administrators-to-bypass-configured-protection-rules).

## Authorization and operation sequence

1. Prepare the optional source declaration with explicitly selected reviewers and policy, then review local doctor and plan results. A local policy check does not verify live protection.
2. Prepare a concrete settings packet: exact repository, current protections, resolved reviewer IDs and eligibility, administrator-bypass policy, dispatch ref, one environment payload and expected readback. Obtain authorization for that operation.
3. Apply only the authorized target and verify it. **An environment-only authorization must not invoke `apply github` or `--apply-github`**: that writer also changes repository, organization, security, branch and label settings. Use a separately reviewed narrow manual API plan for an environment-only grant.
4. Separately review and authorize release publication using merged source, exact version/channel/tag, approved notes and assets, successful exact-target preflight/full runs and the postpublish/alias effects. Refresh protection evidence before dispatch.

This source capability selects no actual reviewers, changes no live settings, and authorizes no tag, Release, alias or artifact publication. [ADR-0029](../decisions/ADR-0029-optional-release-publish-environment.md) records the bounded design; [issue #27](https://github.com/OMT-Global/bootstrap/issues/27) retains the real release acceptance contract.
