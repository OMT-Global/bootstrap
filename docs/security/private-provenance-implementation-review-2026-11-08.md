# Independent review of the synthetic implementation

Governing issue: [#161](https://github.com/OMT-Global/bootstrap/issues/161). The owner approved this bounded follow-up stage on 2026-11-08. Production use and the remainder of #161 remain gated.

A separate Codex software-architect reviewer, who did not author the implementation, reviewed the complete frozen implementation, tests, export, stage documentation, and approval record against parent `114149bc`. No accepted or actionable findings remained. This records an independent automated implementation review, not a GitHub approval or production validation.

| Current code artifact after the reviewed deltas below | SHA-256 |
|---|---|
| `src/private-provenance.ts` | `b07515572e02bbbc6ec2594f1893df25430a2da6842fc3eb818a4c12043b858a` |
| `tests/private-provenance.test.ts` | `e80b64c4121514e68bfcf6a2539e023cfbafcab117a3c1f088abcb694abf42af` |

The review checked strict canonical framing, public subject/run trust, 32-byte keys/12-byte nonces/16-byte GCM tags and authenticated headers, exact-version/digest/retention receipt bindings, sanitized failures, trusted fake approval, and durable audit acknowledgments before plaintext release. The supplied validation passed 71 new synthetic tests plus 51 existing public-provenance tests, typecheck, build, and whitespace checks. Inner tamper tests update and re-sign the outer receipt so they reach authenticated-decryption checks rather than failing only on receipt hashes.

The stage contains no cloud/network/filesystem adapters, CLI, deployment, real evidence categories, or merge-gate integration. Harness flags, clocks, key identities/keyrings, and fake authority behavior are trusted test inputs. They do not establish actual authentication, remote retention, or durable production auditing. The candidate design’s authority-wording correction is covered separately in the design-review record. Rebase onto the updated parent carries the parent's separate release fixes; it does not change the reviewed cryptographic code or its tests.

The review bundle scanner initially misclassified two references to generated ephemeral test-key members. Two ordinary local aliases now pass the same objects to the same calls. The independent reviewer verified the exact 4+/2− diff preserves values, object identity, assertions, credential fixtures, and coverage; the executable cryptographic implementation is unchanged. The later neutral approval-comment correction changes the source hash only; it does not change executable behavior. The 122 focused tests and typecheck passed again. No scanner policy or review scope was bypassed.

## Parser plaintext-buffer hygiene delta

Branch autoreview identified two owned mutable plaintext copies in canonical parsing that were not cleared. The correction clears the parser snapshot in `finally`, including failures, and compares canonical strings without allocating the second plaintext buffer. Fatal UTF-8 validation and BOM rejection remain explicit; duplicate keys, noncanonical input, depth/byte bounds, and caller-buffer preservation remain enforced. Six observable buffer-allocation regressions failed against the original parser and pass with the fix.

The separate software-architect reviewer independently checked this exact source/test delta and the neutral approval comment, found no accepted/actionable findings, and verified the current hashes above. No wire format, cryptographic, public verifier, approval/audit interface, or deployment contract changes. Focused validation now passes 128 tests (77 synthetic and 51 existing public tests), typecheck, build, and whitespace checks. JavaScript strings and runtime-owned copies remain outside best-effort mutable-buffer clearing guarantees.
