# ADR-0061: Preserve configured transport while removing governance credential arguments

Status: Accepted

Date: 2026-11-15

Governing issue: #63

## Context

The owner selected preservation of configured proxy and TLS support for the PR governance credential-transport repair on 2026-11-11. The previous workflow passed a Basic authorization header to `git config` as an argument and stored it in a temporary repository's configuration. Both governance API fetch paths passed a bearer authorization header as a curl argument.

This decision implements that existing direction. It does not select new credentials, permissions, destinations, deployment settings, pagination rules or HTTP retry/redirect policy.

## Decision

- Prefix each authenticated Git fetch directly with a shell environment assignment and reference that variable through `git --config-env=http.extraHeader=BOOTSTRAP_GIT_AUTH_HEADER`. Never pass the assignment through an external `env` command or write the header into Git configuration files.
- Supply each curl authorization header through stdin using the Bash builtin `printf` and `curl --header @-`. Keep the existing curl options, API URLs and request ordering.
- Preserve the runner's existing Git configuration sources, curl configuration and transport environment. Do not clear the process environment, suppress Git system/global configuration, disable curl configuration, or override proxy/CA/TLS/redirect settings as part of this repair.
- Update the Bootstrap generator and its two managed outputs together, with matching ownership hashes.

## Consequences and validation

The credential is absent from the identified process-argument and temporary Git-config sinks. The job already receives `GITHUB_TOKEN` in its environment; this change does not claim isolation from the same user, privileged processes or deliberately configured diagnostic logging. Existing runner configuration remains trusted.

Fabricated tests must inspect the complete Git/curl argument vectors, confirm the temporary repository contains no credential, verify both Git fetch paths receive their effective header while retaining transport settings, and check curl header delivery and failure propagation. A local HTTPS/proxy fixture must demonstrate configured CA trust and redirects and reject the same certificate when that CA is removed. No real credentials or remote endpoints are required for these tests.

The root coordinator adopted this bounded implementation on 2026-11-15 under the owner's existing transport choice after a separate agent's read-only review found no actionable source defects. The reviewer did not author the scoped files; model-family independence remains unproved. Required autoreview, current-head GitHub approval and CI remain separate publication gates. Operational authorization and deployed-workflow evidence remain separate from source adoption, which does not complete #63's other acceptance requirements.
