# CodeQL Setup Modes

This Bootstrap operator guide describes the contract for [the Flow-first dogfood migration](https://github.com/OMT-Global/bootstrap/issues/63). It is product-owned documentation, separate from the generated consumer security model.


Omit `ci.codeqlSetup` to retain advanced mode, or declare `advanced` explicitly. Declare `default` only when preserving verified GitHub default setup. The optional field remains omitted during serialization when absent; no repository is silently switched between modes. GitHub blocks advanced CodeQL uploads while default setup is configured. [GitHub setup behavior](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning).

For Flow's existing language coverage, the reviewed manifest shape is:

```yaml
ci:
  codeqlSetup: default
  codeqlLanguages: [actions, python]
```

GitHub owns native default-setup triggers. Their successful coverage and hosted execution require captured evidence; they do not inherit the generated workflow’s event conditions. The generated advanced CodeQL and SBOM jobs retain their trusted-push/schedule boundary.

`actions` is supported here only for default setup. Advanced mode retains its existing supported language matrix and checks. An unexpected advanced CodeQL job remains blocking in default mode. Choosing default mode omits only that job: dependency-review activation, SBOM artifacts, trusted events, fork isolation, secret exclusion, private reporting, and the other capability observations remain required.

Supply a `code-scanning` observation through the existing capability snapshot. The following shows the required positive shape, not evidence that any live repository has passed:

```json
{
  "control": "code-scanning",
  "status": "supported",
  "evidence": "Authorized configuration and successful analysis/run evidence",
  "remediation": "Restore verified hosted default setup and complete coverage",
  "defaultSetup": {
    "state": "configured",
    "languages": ["actions", "python"],
    "githubHosted": true
  }
}
```

Record `languages` from successfully analyzed coverage, not merely the configuration response. Confirm every declared language and the actual GitHub-hosted executor from authorized analysis/run evidence. GitHub's [configuration API](https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-default-setup-configuration) supplies configuration state; it cannot by itself prove that analysis succeeded or that a run used hosted isolation.

Missing default-mode proof blocks as unverified. Unsupported or disabled scanning, `not-configured` state, missing language coverage, unsuccessful analysis, or `githubHosted: false` cannot satisfy default mode. An observed configured default setup also blocks advanced mode. The strict `defaultSetup` object is allowed only on `code-scanning`; legacy advanced snapshots remain compatible when it is absent. Observations remain trusted, point-in-time operator evidence, not cryptographic attestation. Refresh actual settings, successful coverage, and run evidence before claiming migration closure.

The managed SBOM job uses `contents: read` while generating/uploading its workflow artifact. Release-asset upload stays explicitly disabled; dependency-snapshot upload stays disabled by the immutable action’s default. The pinned [workflow-artifact path](https://github.com/anchore/sbom-action/blob/66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c/src/github/GithubClient.ts#L167) uses `@actions/artifact`. This permission choice does not disable SBOM generation or authorize a different upload path. See [ADR-0012](../decisions/ADR-0012-codeql-setup-modes.md).
