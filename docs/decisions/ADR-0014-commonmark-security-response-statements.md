# ADR-0014: Bounded CommonMark security response statements

Status: Accepted

Date: 2026-11-08

Decision owners: Bootstrap maintainers

Decision record: the task coordinator selects the frozen design independently reviewed for [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63). Acceptance selects this implementation contract; independent implementation review, PR approval, and exact-head checks remain required. It authorizes no remote settings change, legal conclusion, or rewrite of Flow's existing policy.

## Context

Flow owns its `SECURITY.md` and publishes response targets in an immutable, digest-pinned policy bundle. Bootstrap's generic 3/10-day timing text does not describe Flow's released 2-business-day acknowledgement and 7-calendar-day triage targets. The existing `repo.docs.security: false` boundary preserves product ownership while the repository must still meet its real response and security controls.

A prior experiment removed Markdown/HTML fragments and compared remaining lines. Independent review found that removal manufactured statements from inline examples, raw HTML was mistaken for ancestry, and an email autolink could hide later real promises. Further regex fixes could not establish a reliable grammar. The rejected implementation and all regression evidence remain on the saved `codex/dogfood-pre-markdown-ast` branch; they are not the new implementation.

## Decision

1. Parse the original bounded document with exact runtime dependency `commonmark` 0.31.2, the JavaScript reference implementation. Load its CommonJS entry through Node's `createRequire(import.meta.url)` with `typeof import("commonmark")` types and `smart: false`. Pin `@types/commonmark` 0.27.10 for development. Validate the actual application/import path on Node 20; do not infer support from a newer local runtime.
2. Adopt the explicit HTML-free statement grammar in the [operator guide](../bootstrap/security-response-markdown.md). Any HTML AST node anywhere makes the response document unsupported. Only complete plain-text paragraphs under document/list/item ancestry qualify. Inline formatting, links, code, quotes, and headings cannot be stripped or flattened into statements. Soft/hard breaks become ASCII spaces; comparison uses ASCII whitespace and ASCII-only case folding. One paragraph represents one complete promise.
3. Read the product-owned file through a bounded no-follow, nonblocking opened-handle path before any legacy reader. Require a regular singly linked file, fatal UTF-8, and guaranteed handle closure. Enforce the documented byte, line, per-line, node, depth, and candidate limits without partial acceptance or truncation. Fixed diagnostics disclose no source text, path, OS error, or stack. The repository target directory remains the trusted containing boundary.
4. Integrate only for `repo.docs.security: false` with a declared Flow bundle. Preserve immutable-reference, canonical-digest, compatible-version, and strict four-positive-safe-integer target verification. Compare the complete acknowledgement, triage, critical, high, and coordinated-disclosure commitments. Invalid policy or unsupported input blocks; neither selects a generic-reader or timing fallback. Managed/default and no-policy security behavior remains unchanged.
5. Retain every other reporting, fallback-contact, Dependabot, workflow, fork, CodeQL-mode, SBOM, action-pin, capability, ownership, license, and exception check. Introduce no public export, CLI flag, manifest field, exception, or settings operation. This statement grammar proves neither prose intent nor an operational SLA.
6. Record all four added runtime dependency notices factually: commonmark, entities, mdurl, and minimist. Preserve complete installed LICENSE files, including commonmark's embedded polyfill/benchmark/spec notices and mdurl's separate Joyent notice. Do not vendor the upstream benchmark/spec fixtures. Keep the development type package in a separate inventory. Preserve all first-party MIT bytes and approval fields. The owner's earlier confirmation applies to its original six-record inventory and byte-identical MIT adoption, and is not extended to these additions.

## Alternatives

Retaining generic timing text would leave Flow's stronger approved clocks incorrectly blocked. Adding more text-removal rules repeats the demonstrated structural errors. Rendering/sanitizing HTML or introducing another parser would add a second interpretation without supplying the required whole-paragraph AST boundary. A runtime reference parser with one documented eligibility grammar supplies the needed structure directly.

## Consequences and validation

The product-owned branch supports existing Flow plain list paragraphs and ordinary contact autolinks. Raw HTML becomes explicitly unsupported, including cases that the rejected experiment treated as harmless. This is a deliberate grammar change documented and tested separately; it is not an HTML sanitizer or an assertion of DOM context.

The runtime graph gains four packages, with exact resolved versions and integrities in the real lockfile. The initial factual production notice inventory grows from six records to ten. No notices or ownership sidecar existed when this inventory was prepared. If an application target has acquired existing notices, its actual unmanaged-output or SHA-bound managed-notice transition gate must still be satisfied. No artificial per-package approval field or counterfeit reconciliation is introduced.

Required evidence includes the three latest accepted witnesses, meaningful saved code/HTML/quote/limit regressions, genuine autolinks, exact whole-paragraph eligibility, safe reader/link/FIFO behavior, malformed policy and independent-control failures, complete attribution hashes, Node 20 import/application tests, typecheck/build, repository checks, independent implementation review, and actual-base autoreview. Ordinary PR review remains the publication gate; this ADR itself performs no apply or deployment.

The new project-owned `node20-compatibility.yml` workflow supplies minimum-major compatibility proof using exact Node 20.20.2 and pinned checkout/setup actions on a read-only hosted PR job. Its source remains outside generated ownership. Existing `ci.additionalWorkflows` metadata cannot express this job, so it is not used as a pretend generator configuration.

If historical or current Bootstrap ownership metadata still claims `SECURITY.md` after selecting the product-owned policy branch, conformance blocks for a manual ownership migration. It skips that leaf in generic ownership reads and withholds the generic planner while blocked; unrelated security, legal, profile, capability, and other managed-file checks continue. A reviewed, backed-up migration must preserve the product policy bytes. The checker neither edits ownership state nor deletes claims or transfers ownership implicitly.
