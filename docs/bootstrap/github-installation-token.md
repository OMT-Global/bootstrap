# Scoped GitHub installation token source

Governing issues: #27 (release) and #62 (fleet PR publication). This inactive
source helper implements part of the selected GitHub App credential design. No
CLI or workflow invokes it. Local tests use fabricated responses and tokens.

`withScopedInstallationToken` requires trusted App and installation IDs, an
already-issued App JWT, the expected repository ID and canonical `owner/name`,
a purpose, and a trusted consumer. It verifies the authenticated App ID, then
requests one installation token with an explicit one-entry `repository_ids`
list. Release tokens request `contents:write`, `actions:read`, and
`pull_requests:read`; fleet PR tokens retain `contents:write` and
`pull_requests:write`. No workflow or administration grant is requested.

GitHub documents scoped permissions and the one-hour lifetime when
[generating an installation token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).
The release reader needs the read grants for
[artifact downloads](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact)
and [PR review lookup](https://docs.github.com/en/rest/pulls/reviews#list-reviews-for-a-pull-request).
The helper rejects unexpected grants, missing requested grants, invalid expiry,
or incomplete repository metadata in the issuance response. These checks are a
deliberately conservative acceptance policy; a successful API response without
the required evidence is not treated as sufficient authority.

Before invoking the consumer, the helper uses the issued token to read
`GET /installation/repositories?per_page=100&page=1`. It requires a complete
single-repository result with the expected numeric ID and canonical name,
`private:false`, and no pagination. The consumer receives the token, an expiry
Date copy, and a module-provided `assertRepositoryAccess()` function. Each call
rechecks expiry and current repository visibility, with the same captured token,
target and transport. Changes to the caller's input or the exposed Date cannot
change those captured values. A failed check throws a sanitized error; it does
not renew the token or retry issuance.

Consumer completion does not revoke the token or invalidate a retained
`assertRepositoryAccess()` function. The token and retained check remain usable
after completion, subject to the original expiry and GitHub revocation or access
changes. The trusted runtime owns credential disposal and any provider
revocation; completion is not a credential-lifetime boundary.

The [installation repository inventory](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation)
does not expose token permissions or expiration. Those facts remain bounded by
the validated issuance response and local clock. The inventory proves current
access to the one selected public target, not the App's complete installation
scope, a permanent permission grant, or exclusive release-writer authority.

The consumer and runtime remain trusted and must call the supplied check before
protected operations. Callback completion alone does not prove that a check was
used. Human release approval, target protection, writer coordination, hook
isolation, receipt signing/storage, and actual workflow integration remain
separate. This source does not generate keys/JWTs, install an App, authorize a
real credential operation, or grant permission to publish a release.
