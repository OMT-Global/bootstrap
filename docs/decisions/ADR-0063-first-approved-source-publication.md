# ADR-0063: First approved source-distribution publication

Status: Accepted

Date: 2026-11-15

Governing issue: [#27](https://github.com/OMT-Global/bootstrap/issues/27).

The coordinator adopts this bounded source consumer after independent design review under the owner's selected dedicated Bootstrap App, exact-manifest JMCTE approval/actor separation, exact-state retries and manual reconciliation of uncertain writes. The follow-up protection qualification implements the already selected operational protection prerequisite without expanding App grants. This is source adoption, not a human release approval, real credential authorization, App installation, settings change, deployment or pilot. Separate-agent review was performed; model-family independence is unproved.

## Decision

`publishNewBootstrapSourceRelease` is the concrete trusted workflow consumer. It reuses the scoped installation-token issuer, authenticated current manifest review, bounded preflight/full-validation acquisition and exact source-package checks. JMCTE differs from requester/publisher actors; requester and publisher need not differ from one another. It checks the approved snapshot's exact executable `scripts/release/publish.sh` bytes against the supported known no-op hook and does not execute that hook. Changed, missing or custom hooks are unsupported for this Bootstrap profile. Generic generated callers retain their hook contract.

One attempt creates one owned draft, uploads exact copied approved asset bytes once each, verifies the unique draft and captured release/asset IDs, publishes that draft once, then verifies the same published ID and assets against current approval. Release name equals the approved tag. Notes, prerelease/latest state, signed tag/commit, complete asset inventory/provider digests, live token scope and successful validation remain mandatory. A `latest:false` package without authenticated existing full latest evidence fails before any write; this bounded slice does not relax the existing retry verifier for a first-ever prerelease.

Any uncertain write or later failed verification stops for manual reconciliation. No retry, overwrite, deletion, rollback or adoption of another attempt's draft is available. The result may leave a partial draft or published release. `verified-created` records this attempt's observed created IDs; it is not a durable signed creation receipt, universal hook reservation or exclusive-writer guarantee. Existing published releases remain the separate read-only ADR-0059 operation.

## Operational protection qualification

A narrow release App cannot assume omitted ruleset bypass actors means none. GitHub documents that full bypass visibility requires write access to the ruleset. The runtime does not request administration permission or obtain an administrator token.

The reviewed protected deployment configuration must instead contain exact non-secret administrator qualification bytes and their SHA-256, alongside the configured qualifier identity. Qualification binds the current package approval hash, repository numeric/canonical identities, App and installation, exact tag/signed object/commit, publication run/attempt/workflow commit, operation, observed time and expiry. Maximum validity is ten minutes. It records a full security projection of one active exact-tag ruleset with creation/deletion/update restrictions, no exclusions and explicitly administrator-observed empty bypass actors.

The runtime captures that configuration once, verifies all bindings and expiry, and repeatedly authenticates the current visible ruleset projection, provider update timestamp and signed tag object before writes and final success. Missing qualification, stale records, mismatch or visible bypass stops. The qualification bytes/hash must originate from the reviewed protected configuration, never caller inputs, target code or artifacts. The hash detects mismatch; it does not authenticate arbitrary environment values or prove the named administrator actually supplied them.

Current hidden bypass state remains unobservable to the App. Matching visible fields/update timestamps is not proof of every hidden bypass-only change. Deployment requires the administrator to qualify the complete ruleset and keep protection unchanged through the bounded operation; any administrative change requires requalification. Administrators can still alter protections after an observation. The no-tag-creation condition depends on enforced restrictions and App non-bypass under this explicit operational assumption, not on a tag read alone. Missing real qualification is an activation blocker, not a source-test success flag.

## Compatibility and limits

`release.approvedPublication: true` exposes an optional, default-false `publish_new_source_release` dispatch selector only for a compatible reusable pin. Selecting both publication and existing-release verification fails. The approved path enters the isolated runtime before legacy downloads, target Git operations or hooks. Trusted runtime build precedes key exposure. Default generated callers and the read-only retry contract retain their previous behavior. No current manifest selector, workflow/runtime pin, key or settings are activated here.

Floating aliases are a separate future consumer with separately authorized exact refs/target. This publisher never moves them or runs target postpublish hooks. Independent implementation review, required autoreview, CI and current-head GitHub approval precede publishing source. Operational configuration, real exact package review, authorized hosted rehearsal, actual release and alias pilot remain necessary to close #27.
