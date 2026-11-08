# Dogfood GitHub capability evidence

Governing issue: [#63](https://github.com/OMT-Global/bootstrap/issues/63).

Captured 2026-11-08 at 15:24–15:27 UTC (09:24–09:27 America/Chicago) through authenticated, read-only GitHub REST and GraphQL requests. Both repositories are public and use `main`. This is a point-in-time observation, not approval to change settings or a claim that the dogfood migration is complete. No alert contents, credentials, or secret values were requested.

## Seven public security controls

| Control | Bootstrap | Flow | Evidence and next action |
|---|---|---|---|
| Code scanning | Supported and operating | Supported and operating | Successful default-branch CodeQL analyses exist for the configured languages; see exact analyses below. This is semantic execution evidence, rather than an inference from an empty HTTP 200 response. |
| Dependabot alerts | Enabled | Enabled | `GET /repos/OMT-Global/{repo}/vulnerability-alerts` returned HTTP 204 for each repository, the enabled-state response. |
| Dependabot security updates | Misconfigured: disabled | Enabled | `GET /repos/OMT-Global/{repo}/automated-security-fixes` returned HTTP 200 with `enabled:false, paused:false` for Bootstrap and `enabled:true, paused:false` for Flow. Bootstrap requires an authorized settings repair and reinspection. |
| Dependency graph | Unverified | Unverified | Each SBOM request returned HTTP 404 `Not Found`; GraphQL returned zero dependency manifests. Neither response establishes supported-and-enabled graph operation or a plan limitation. Verify graph enablement and a populated manifest/SBOM before recording support. Dependency-review activation also remains unverified, as described below. |
| Private vulnerability reporting | Enabled | Enabled | `GET /repos/OMT-Global/{repo}/private-vulnerability-reporting` returned HTTP 200 with `enabled:true` for both. |
| Secret scanning | Misconfigured: disabled | Enabled | The repository metadata's `security_and_analysis.secret_scanning.status` was `disabled` for Bootstrap and `enabled` for Flow. No plan-limit error was observed; do not classify the disabled Bootstrap configuration as unsupported. |
| Push protection | Misconfigured: disabled | Enabled | The repository metadata's `security_and_analysis.secret_scanning_push_protection.status` was `disabled` for Bootstrap and `enabled` for Flow. Bootstrap requires an authorized settings repair and reinspection. |

The repository metadata also reports auto-merge and delete-branch-on-merge enabled for both repositories. GitHub recognizes the published `LICENSE` as MIT in both; that recognition does not authorize Bootstrap to adopt or replace an unmanaged license.

### Code scanning: exact execution evidence

- Bootstrap: [analysis 2114941709](https://api.github.com/repos/OMT-Global/bootstrap/code-scanning/analyses/2114941709), created 2026-11-06 at 19:59:58 UTC; `refs/heads/main`, commit `7bb026dce82996a30ea38428fa9919613e9977c7`, category `/language:javascript-typescript`, `.github/workflows/security.yml:codeql`, empty `error` and `warning`. This matches the manifest's configured JavaScript/TypeScript language.
- Flow: [analysis 2119251979](https://api.github.com/repos/OMT-Global/flow/code-scanning/analyses/2119251979), created 2026-11-07 at 20:22:00 UTC; `refs/heads/main`, commit `669d095891a2fa2c9772735edf3e9cdf44c1214f`, category `/language:python`, dynamic default setup, empty `error` and `warning`. This matches the manifest's configured Python language. [Analysis 2119251904](https://api.github.com/repos/OMT-Global/flow/code-scanning/analyses/2119251904) also covers `/language:actions` at the same commit.

These successful analyses establish that code scanning is currently usable on these repositories. Historical failed runs or older plan-limit reports must not override this current evidence. They do not establish results for a future PR head.

### Dependency graph and dependency-review activation

The [Bootstrap SBOM endpoint](https://api.github.com/repos/OMT-Global/bootstrap/dependency-graph/sbom) and [Flow SBOM endpoint](https://api.github.com/repos/OMT-Global/flow/dependency-graph/sbom) each returned HTTP 404 `Not Found`. The following read-only GraphQL fields returned `totalCount:0, nodes:[]` for each repository:

```graphql
repository(owner: "OMT-Global", name: "bootstrap") {
  dependencyGraphManifests(first: 10) {
    totalCount
    nodes { filename parseable exceedsMaxSize }
  }
}
```

The same query was made with `name:"flow"`. Empty manifest connections do not prove graph enablement; an unavailable SBOM does not by itself prove a GitHub plan limitation.

The [Bootstrap repository variable](https://api.github.com/repos/OMT-Global/bootstrap/actions/variables/DEPENDENCY_REVIEW_ENABLED) and [Flow repository variable](https://api.github.com/repos/OMT-Global/flow/actions/variables/DEPENDENCY_REVIEW_ENABLED) each returned HTTP 404 `Not Found`. The named [organization variable](https://api.github.com/orgs/OMT-Global/actions/variables/DEPENDENCY_REVIEW_ENABLED) could not be inspected: HTTP 403, requiring organization-admin or Actions-variables permission. Therefore repository-level activation is absent, while an inherited organization value remains unverified. No `dependencyReviewEnabled:true` observation is warranted.

The [capability snapshot contract](conformance.md) has no `unverified` observation enum. Omit the dependency-graph observation from a machine snapshot until graph and activation evidence are established; conformance will report that missing observation as an explicit warning. Do not substitute `unsupported` or `supported` to make the report green.

## Live governance compared with the resolved manifests

| Surface | Bootstrap | Flow |
|---|---|---|
| Required PR checks | Strict/up-to-date `CI Gate`; matches manifest | Strict/up-to-date `CI Gate`; matches manifest |
| Approvals | One, stale-review dismissal, code-owner review, approval after the latest push; matches manifest | Same controls; matches normalized manifest defaults |
| History/admin enforcement | Linear history and administrator enforcement enabled | Same |
| Code owners | Live `* @jmcte @athena-omt`; manifest declares only `@jmcte`. Preserve the additional live reviewer until the manifest catches up under review. | Live `* @OMT-Global/omt-codeowners`; manifest supplies no code-owner entries. Record and reconcile this ownership difference before applying generated ownership files. |
| `dev` environment | No required reviewers; matches open development policy | No required reviewers; matches normalized open development policy |
| `stage` environment | Required reviewer `jmcte`, self-review prevented; matches manifest | No reviewer rule. Normalized policy requests approval and self-review prevention but has no reviewer targets; resolve reviewer ownership before applying. |
| `prod` environment | Required reviewer `jmcte`, self-review prevented, protected-branch deployment policy; matches the current generator's projection of `[main]` | Protected-branch deployment policy but no reviewer rule; normalized policy requests approval/self-review prevention with no reviewer targets. Resolve reviewer ownership first. |

Both branch-protection responses reported signature enforcement disabled. Their current manifests do not request signature enforcement, so this observation is not an added governance requirement. The environment implementation maps a sole default-branch selector to GitHub's protected-branch policy; it does not create a literal `main`-only custom policy.

Sources (all returned HTTP 200 unless a different status is stated above): [Bootstrap repository](https://api.github.com/repos/OMT-Global/bootstrap), [Flow repository](https://api.github.com/repos/OMT-Global/flow), [Bootstrap branch protection](https://api.github.com/repos/OMT-Global/bootstrap/branches/main/protection), [Flow branch protection](https://api.github.com/repos/OMT-Global/flow/branches/main/protection), [Bootstrap CODEOWNERS](https://github.com/OMT-Global/bootstrap/blob/7bb026dce82996a30ea38428fa9919613e9977c7/CODEOWNERS), [Flow CODEOWNERS](https://github.com/OMT-Global/flow/blob/669d095891a2fa2c9772735edf3e9cdf44c1214f/CODEOWNERS), [Bootstrap environments](https://api.github.com/repos/OMT-Global/bootstrap/environments), [Flow environments](https://api.github.com/repos/OMT-Global/flow/environments), [Bootstrap manifest](https://github.com/OMT-Global/bootstrap/blob/7bb026dce82996a30ea38428fa9919613e9977c7/project.bootstrap.yaml), and [Flow manifest](https://github.com/OMT-Global/flow/blob/669d095891a2fa2c9772735edf3e9cdf44c1214f/project.bootstrap.yaml).

## Remaining evidence

Reinspect after any approved repair. Capture populated dependency-graph evidence and the effective activation variable with sufficient permission. Reconcile code-owner and environment-reviewer declarations before remote application. Then run conformance using the freshly captured snapshot and the actual migrated source revision. These read-only observations do not close #63, attest a new PR, or replace the required Flow-first migration and live CI evidence.
