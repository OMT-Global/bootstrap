# ADR-0011: Implement a synthetic-only private provenance library stage

Status: Accepted

Date: 2026-11-08

Decision owners: Bootstrap maintainers

Governing issue: [#161](https://github.com/OMT-Global/bootstrap/issues/161).

## Authority and boundary

After the independent design review, the owner explicitly approved: “Approve synthetic implementation in a follow-up PR.” This decision accepts only that bounded stage: strict schemas, cryptographic envelopes, injected fake key/sink/audit/approval interfaces, and fabricated-input tests. It does not accept or deploy the full [Proposed ADR-0009](ADR-0009-encrypted-private-provenance.md). The separate design-review record preserves the original hashes and a narrow independent review of the corrected read-approval attribution; the cryptographic and broker requirements remain unchanged.

## Decision

Implement separately named synthetic capture/read APIs requiring explicit synthetic markers and the stage-only `synthetic-fixture` category. These markers communicate permitted use, not automated proof that arbitrary input is fabricated. All authority, clocks, key identifiers/keyrings, and adapter behavior remain trusted harness inputs.

Use the reviewed bounded canonical wire framing, AES-256-GCM with fresh 32-byte data keys/12-byte nonces/16-byte tags, authenticated subject/run/public-envelope binding, and distinct signed private receipt domain. Validate exact-version/digest/retention observations through fake interfaces. The trusted fake approval and durable audit acknowledgments must precede plaintext release; failures return no success receipt or plaintext and sanitize adapter details. Preserve existing public schemas and signature behavior.

Provide no built-in AWS, network, filesystem capture, OIDC, broker deployment, CLI, or material-merge-gate integration. Tests use generated ephemeral keys and in-memory fakes. Buffer clearing is best effort and does not claim erasure of JavaScript-managed strings/JWKs or host memory.

## Validation and remaining work

Independent implementation review found no accepted/actionable findings in the frozen code and tests. Focused validation passed 71 new synthetic tests and 51 existing public-provenance tests, typecheck, and build. The follow-up must also pass required branch autoreview and live PR checks at its actual base/head.

Real evidence categories, AWS account/admin/runtime policies, authenticated read approvals, real audit/retention/rotation controls, signing trust, remote adapters, and required-check integration remain separately gated. This stage and its receipts cannot establish production capture or close #161.
