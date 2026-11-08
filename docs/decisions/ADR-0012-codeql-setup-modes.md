# ADR-0012: Explicit CodeQL setup modes with observed coverage

Status: Accepted

Date: 2026-11-08

Decision owners: Bootstrap maintainers

Decision record: the task coordinator adopts the backward-compatible contract reviewed by a separate software-architect agent for [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63). Acceptance selects the implementation contract; independent PR approval and exact-head checks remain required. It is not human approval to change remote settings or deploy anything.

## Context

Flow already uses GitHub CodeQL default setup for Actions and Python. Requiring an additional advanced workflow would conflict with that working setup and could lose existing coverage. GitHub documents that default setup blocks advanced CodeQL uploads, can use self-hosted execution, and can remain enabled after language validation fails without producing scans. Configuration alone therefore cannot establish functioning hosted coverage. [GitHub default-setup documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning).

## Decision

1. Add optional `ci.codeqlSetup: advanced | default`. Omission retains advanced mode and remains omitted when serialized, preserving existing manifests. `ci.codeqlLanguages` may include `actions` only in default mode; advanced Actions projection needs its own supported implementation.
2. Default mode removes only the advanced CodeQL job from Bootstrap's security workflow. Dependency review, SBOM generation, trusted-event conditions, read-only fork checks, immutable pins, private reporting, and capability checks remain enforced. GitHub owns the native default-setup triggers; they are separate from the generated workflow's event lanes. An unexpected advanced CodeQL job in explicit default mode is blocking.
3. Explicit default mode requires a supported `code-scanning` capability observation with strict `defaultSetup` evidence: configured state, all declared languages successfully analyzed, and observed GitHub-hosted execution. Missing evidence is blocking and unverified. Disabled, partial, unsuccessful, or non-hosted coverage is a blocking misconfiguration. There is no implicit mode fallback. Observed configured default setup also blocks an advanced-mode declaration because those uploads conflict.
4. `defaultSetup` is valid only on the `code-scanning` observation. Its state is `configured` or `not-configured`, `languages` records verified successful coverage, and `githubHosted` is a boolean. Only configured state, complete coverage, and `true` satisfy default mode. Existing advanced snapshots without this optional object remain valid.
5. Retain the existing trusted capability-snapshot boundary: an authorized operator records point-in-time observations and their supporting run/configuration evidence. This is not cryptographic attestation or automatic API collection. A configuration language list alone is insufficient; collectors must verify successful analysis for every declared language and the actual executor boundary. Fresh live evidence is needed before declaring a migration complete.
6. Use `contents: read` for the managed SBOM artifact job. Its pinned Anchore action uploads a workflow artifact, with release-asset upload explicitly disabled and dependency-snapshot upload disabled by the immutable action’s default. Its [workflow-artifact implementation](https://github.com/anchore/sbom-action/blob/66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c/src/github/GithubClient.ts#L167) uses `@actions/artifact` rather than a repository-write API; this contract does not need repository write permission. Keep artifact generation/upload and all event/isolation checks. The pinned [action inputs](https://github.com/anchore/sbom-action/blob/66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c/action.yml) distinguish these upload paths.

The [operator guide](../bootstrap/codeql-setup-modes.md) records the manifest and trusted-observation shapes. It remains Bootstrap product documentation rather than a link emitted into every consumer repository.

## Consequences and validation

Default mode can describe Flow's existing provider without changing its remote configuration, legal or product ownership, or Actions/Python coverage. Advanced consumers retain their current CodeQL projection and validation; the deliberate SBOM permission reduction is independent of setup mode. No security control is waived and no exception is created.

Regressions must cover omitted/explicit advanced equivalence, default rendering, Actions language constraints, complete and missing/failed/partial/non-hosted observations, conflicting modes, unexpected CodeQL jobs, and unchanged dependency-review, SBOM, and fork failures. The independent PR review remains separate from this decision record. This work performs no settings apply, release publication, or production deployment.
