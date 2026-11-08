# Independent review of the synthetic implementation

Governing issue: [#161](https://github.com/OMT-Global/bootstrap/issues/161). The owner approved this bounded follow-up stage on 2026-11-08. Production use and the remainder of #161 remain gated.

A separate Codex software-architect reviewer, who did not author the implementation, reviewed the complete frozen implementation, tests, export, stage documentation, and approval record against parent `114149bc`. No accepted or actionable findings remained. This records an independent automated implementation review, not a GitHub approval or production validation.

| Reviewed code artifact | SHA-256 |
|---|---|
| `src/private-provenance.ts` | `6a72f2cfe6ed1b8e2671d3d0ec3f1dfffd7fa9dfa151314fbd64d5bb3a4227fa` |
| `tests/private-provenance.test.ts` | `67d72bf9c236488de57a549d52abbe060a49363eb9170619e3ce52263cce834b` |

The review checked strict canonical framing, public subject/run trust, 32-byte keys/12-byte nonces/16-byte GCM tags and authenticated headers, exact-version/digest/retention receipt bindings, sanitized failures, trusted fake approval, and durable audit acknowledgments before plaintext release. The supplied validation passed 71 new synthetic tests plus 51 existing public-provenance tests, typecheck, build, and whitespace checks. Inner tamper tests update and re-sign the outer receipt so they reach authenticated-decryption checks rather than failing only on receipt hashes.

The stage contains no cloud/network/filesystem adapters, CLI, deployment, real evidence categories, or merge-gate integration. Harness flags, clocks, key identities/keyrings, and fake authority behavior are trusted test inputs. They do not establish actual authentication, remote retention, or durable production auditing. Both exact reviewed design documents remain unchanged. Rebase onto the updated parent carries the parent's separate release fixes; it does not change the reviewed cryptographic code or its tests.

The review bundle scanner initially misclassified two references to generated ephemeral test-key members. Two ordinary local aliases now pass the same objects to the same calls. The independent reviewer verified the exact 4+/2− diff preserves values, object identity, assertions, credential fixtures, and coverage; the cryptographic source hash above is unchanged. The 122 focused tests and typecheck passed again. No scanner policy or review scope was bypassed.
