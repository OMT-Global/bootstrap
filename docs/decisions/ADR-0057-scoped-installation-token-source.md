# ADR-0057: Scoped GitHub installation token source boundary

Status: Accepted

Date: 2026-11-15

Governing issues: [#27](https://github.com/OMT-Global/bootstrap/issues/27) and [#62](https://github.com/OMT-Global/bootstrap/issues/62).

The task coordinator adopts this inactive source component under the owner's selected dedicated Bootstrap release App and one-public-repository fleet App directions. Required code review, independent current-head PR approval and operational authorization remain separate. This is not approval to install an App, access keys, issue a real token or publish anything.

## Context

ADR-0051 accepts a supplied read capability but deliberately excludes its issuer. Publication consumers additionally need an authenticated App identity, explicit one-repository issuance, checked grants and expiration, and a way to recheck the selected public repository before protected operations. Successful public reads alone do not establish those facts.

## Decision

Add `withScopedInstallationToken` as an internal helper with no CLI, workflow or package-index registration. Trusted runtime code supplies an already-issued App JWT, expected numeric App/installation/repository IDs, canonical repository name, purpose and consumer. Inputs are captured before asynchronous work. The helper does not read authentication from environment variables, files, Git configuration, agents or keychains, and it does not generate keys or JWTs.

Authenticate the App with the fixed GitHub API endpoint, require its expected ID, then make one token-issuance attempt for an explicit single-entry `repository_ids` list. Release grants are `contents:write`, `actions:read` and `pull_requests:read`; fleet PR grants are `contents:write` and `pull_requests:write`. Accept only the requested grants and optional `metadata:read`. Request no workflow or administration permission and never fall back to installation-wide defaults.

Require exact selected-repository evidence and a canonical valid expiration in the issuance response. Missing evidence fails even if GitHub otherwise considers the response successful. The accepted remaining lifetime is at least 30 seconds and at most 3,660 seconds, retaining GitHub's nominal one-hour limit with a bounded clock margin. Clock integrity remains a trusted-runtime prerequisite.

Before entering the consumer, use the issued token to read its accessible repository inventory. Require exactly one expected numeric ID and canonical name, public visibility and no pagination. Give the consumer an expiration copy and a closure that repeats this observation with the captured token and checks expiration before and after the read. That endpoint establishes current repository access, not current token permission introspection, App-wide installation scope, immutable visibility or exclusive writer authority.

All requests use fixed HTTPS GitHub API origins, reject redirects, and bound deadlines and response bodies. Parse strict JSON with duplicate-key rejection. Errors expose a fixed sanitized message. A failed or ambiguous issuance attempt is not retried; absence of a returned usable token does not prove that the provider created none.

## Lifecycle and authority limits

The consumer is trusted and must invoke the provided check at each protected boundary. Returning from or rejecting the consumer neither revokes the issued token nor invalidates a retained check. Both remain usable until expiration or provider revocation; callback duration is not a credential lease. The later trusted runtime owns credential disposal/revocation and reconciliation after uncertain issuance. JavaScript strings and copied bearer values cannot be reliably erased by this helper.

No target repository code or untrusted callback may execute in this credential-bearing boundary. This helper does not supply hook isolation, human release approval, protected targets, independent review, pilot eligibility, signing authority or permission to perform writes. Candidates that need additional workflow permission are unsupported by this grant set; no caller may silently broaden it.

Named consumers are the separately reviewed release publisher and create-only fleet PR publisher. They must bind these checks to their actual candidate/approval state, preserve the selected manual reconciliation policy after uncertain writes, and establish deployment identities before real use. This source stage does not close either governing issue.

## Validation

Use fabricated responses and credentials to test exact issuance bodies, App and repository identity, permission rejection, response limits, redirects, expiration, input capture, repeated visibility checks, callback behavior and sanitized failures. A retained-check test records the explicit post-completion lifetime and simulated provider revocation. These tests do not establish a deployed installation, real token authority or production runtime isolation.
