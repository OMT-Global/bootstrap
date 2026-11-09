# ADR-0020: Opt-in standalone postpublish preflight contract

- Status: Accepted
- Date: 2026-11-08
- Governing issue: #27

## Context

A repository-specific postpublish verifier may need an explicit approved preflight run. The existing standalone postpublish caller does not accept or forward that run ID, and its approved reusable pin does not declare the input. Sending a new argument to that old pin would fail workflow validation. Existing generic callers and normalized manifests must remain compatible.

## Decision

Add optional string input `preflight_run_id`, default empty, to the generated reusable postpublish contract and forward it as `PREFLIGHT_RUN_ID` to the verification hook.

Add the strict boolean selector `release.postpublishRequiresPreflight`, with default-off behavior. Preserve an omitted selector in normalized output. Omitted or false preserves the exact legacy standalone caller bytes. True adds a required dispatch input and forwards the explicitly supplied run ID to the selected reusable.

Enable the selector only in a later reviewed adoption with an immutable reusable pin that supports the new optional input. Do not infer approved evidence from the latest run or workflow name. Preserve publish's existing forwarding, generic hooks, runner and permission contracts.

## Consequences

Old callers remain valid with the new reusable, and default callers remain valid with the old reusable. Opted-in callers require a supporting pin; the generator does not remotely discover its capabilities. Hook validation of run identity and evidence remains a separate contract. This prerequisite changes source and tests only, without adopting a new pin, applying generated files, or running a release.
