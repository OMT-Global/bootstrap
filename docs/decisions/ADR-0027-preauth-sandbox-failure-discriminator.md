# ADR-0027: Pre-auth sandbox failure discriminator

Status: Accepted

Scope: Dormant source-only, failure-only diagnostic amendment. Native Linux support remains unproven. The host is not registered in CI; this does not authorize a hosted retry, profile change, publication or merge.

Date: 2026-11-09

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

## Context

The exact-head full attempt at `4420ca12b422eee49f267e90b20f64a158506f46` passed ordinary checks, required Docker checks, three signature checks and the mechanical, byte, inode and detached cases. It returned a failed sandbox case and successful cleanup, with zero provider requests. The existing generic `native-sandbox` outcome does not distinguish GO consumption, version admission, local canary setup, native invocation or listener checks. No particular CLI or kernel cause is established, and discarded private output cannot be recovered.

This is a later host-stage amendment to ADR-0022. ADR-0026, the published dormant producer prerequisite, remains unchanged as historical evidence. Root adopted this bounded contract after independent design review. Source/test validation cannot supply runtime support, human approval or publication authority.

The later exact-head attempt at `a683d8e21da3a9a7bd29a51245ca79d3ce6e72b3` produced `sandboxFailure: {"stage":"sandbox-exit","exitCode":1}` with cleanup successful and no later auth/API/persistence execution. ADR-0022 now supersedes automatic host registration with a dormant source prerequisite. Its sole policy correction adds read access to the immutable public `/opt/codex` installation for both sandbox and API callers; all other native arguments, canary predicates and private-output handling stay intact. This explicitly supersedes the earlier policy-byte and registration preservation statements below. The discriminator contract itself is unchanged, and a valid failure record establishes no native support.

## Decision

Add the optional `sandboxFailure` member only to the fixture’s failed sandbox result and the host’s overall failed schema1 evidence. This is an explicit additive failure-only wire amendment. Successful fixture results, overall success and every case row retain their existing fields. Legacy failed sandbox events without this member remain valid.

The value is a builtin object with exactly `stage`, optionally `exitCode`. Stage is a builtin string in the closed set below. An exit code is a builtin integer in `[-255,255]`, excluding booleans, and is permitted only at `version-exit` or `sandbox-exit` after that particular native call actually returned. Missing code means no bounded returned code is reported; it does not mean zero. The discriminator contains no native output or output hashes/lengths, classifiers, exception text, paths, argv, environment, socket data, PIDs or credentials.

| Stage | Observation boundary |
| --- | --- |
| `gate` | Parsed sandbox case, before gate; no readiness or GO-consumption claim. |
| `dispatch` | Gate returned, before case dispatch; no sandbox/native-entry claim. |
| `version-call` | Before the unchanged version helper; no process-start claim. |
| `version-exit` | Version helper returned, before its exit-zero predicate; optional actual code. |
| `version-stdout` | Exit-zero passed, before the unchanged stripped stdout predicate. |
| `version-stderr` | Correct stdout passed, before the unchanged empty-stderr predicate. |
| `workspace-setup` | Version admission passed, before existing public/private canary setup. |
| `loopback-control` | Before the existing socket controls and inner command construction. |
| `sandbox-call` | Before unchanged policy/argument construction and sandbox helper call. |
| `sandbox-exit` | Sandbox helper returned, before its exit-zero predicate; optional actual code. |
| `listener-postcheck` | Sandbox exit-zero passed, before existing timeout/accept checks. |
| `listener-close` | Only an actual exception from the existing listener close operation. |

One owned phase map replaces its contents on every transition, clearing stale exit data. The actual top-level entry clears it before parsing; only sandbox enables gate/dispatch tracking. Successful case completion clears it before success emission. Every other case remains untraced even if a pure test reuses stale module state.

Split the existing combined version predicate into the same three ordered predicates. Failed exit still prevents stdout/stderr evaluation, and wrong stdout prevents stderr evaluation. Preserve `native()` bytes, policy and argument lists, all existing predicates, bounds and case ordering. A successful listener close makes no phase write. Only its own exception records `listener-close`, clears any old code and is re-raised with the existing exception precedence. The listener try/finally remains in its existing location.

## Host validation and retention

Use a separate initially empty builtin map passed only to the sandbox case. Reserve the member on every event: its presence requires a failed sandbox result with phase `native-sandbox` and exact builtin integer request count zero. Reject wrong event/case/success/phase/count, malformed objects, unknown stages, extra keys, type-confused or out-of-range codes, and codes on other stages before retaining anything. Existing unrelated extra-field tolerance remains.

A gate report may be the first event before READY and claims only coarse gate failure. Otherwise require the validated READY/group and normal READY-then-result sequence. All non-gate stages require that admitted sequence. No GO, cgroup, stopped-container or cleanup requirement is weakened. Copy only validated primitive values into the owned map before later host postchecks. Once captured, another result event is rejected and cannot replace the first snapshot.

The main failure path may retain that snapshot even when host postchecks, removal or aggregate cleanup later fail. It reports fixture progress, not successful host postchecks. Existing overall reason and cleanup precedence remain authoritative. No field is attached to a returned case row or overall success; later auth/status/API/persistence cases never receive the map.

The largest compact addition, including comma and member wrapper, is 58 bytes. The existing UTF-8 prefix+JSON+LF limit of 65536 bytes still applies, and the existing bounded fallback may omit the optional observation. No progress event, raw-output fallback or diagnostic authority protocol is introduced.

## Validation and limits

Pure regressions exercise actual sandbox and top-level handler code with fabricated native, filesystem and socket adapters; actual native/resource/socket/provider work is forbidden. Preserve all prior producer coverage and 149 host cases, except the explicitly amended sandbox branch of the old privacy expectation. Cover all stages, code bounds and clearing, predicate order, actual close-exception precedence, stale state, privacy, legacy absence, reserved-field rejection, first-snapshot retention across host failures, unchanged success/case schemas and UTF-8 cap/fallback behavior. Paired baseline/current controls must show the missing producer/host observation without relying on a new-keyword TypeError.

Keep the immutable artifact inputs, Dockerfile, launch arguments, resources, outputs, clocks and cleanup unchanged. The dormant scope intentionally restores the manifest, generated extended entrypoint and entrypoint acceptance test to producer base `48a01693` and adds only the public installation read grant described above. Measure the complete six-path actual-base diff naturally; retain ceilings of 470 whole host lines plus at most 80 fixture changed lines, not an executed count or permission to compress code.

New source requires ordinary validation, complete actual-base independent review, signed publication and exact-head preflight before root may authorize one new full hosted attempt. Never rerun unchanged `4420ca12`. A failed run with a valid discriminator is diagnostic evidence, not native support. All mandatory native cases and cleanup must genuinely pass before runtime support or CI activation is claimed. The dormant source PR instead requires its complete pure/ordinary validation and independent review; those results supply no native runtime credit. Further output classification or a launch-profile amendment requires its own evidence, scope decision and review.
