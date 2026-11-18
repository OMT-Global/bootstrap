# Fleet runtime policy and native CI observations

This source component supplies two concrete producers for the authenticated fleet governance consumer in #62. It does not register a fleet command or grant signing, review, App, publication, or rollout authority.

`captureRuntimePolicy` requires the genuine captured generator and reads its exact current public controller manifest. The returned owned handle binds the strict reserved `fleetRuntime` projection, source commit, manifest digest, parent cancellation, and actual request/byte totals. Parsing JSON or copying its public facts cannot create the handle. Missing signer/review/App/state configuration stays explicit; shared manifest/CLI registration belongs to the later runtime integration.

`observeManagedCi` consumes a genuine public policy observation and verifies the named generated extended-validation profile, exact workflow, native Actions run, attempt, jobs, check runs, step results, completed timestamps and repeated stable evidence. An optional historical commit is verified as an ancestor of the current head with complete bounded history, its exact immutable manifest/policy, matching trusted published policy and rendered workflow before native CI is accepted. Current head/repository stability remains checked around the operation. Historical comparison supports at most 250 commits; unsupported or incomplete evidence never produces a successful owned CI handle.

Both producers report actual requests and received response bytes so their governance consumer can charge one operation-wide budget. Native readers retain their individual request, response-size, aggregate-byte, deadline and cancellation limits. Public metadata is evidence, not a capability; only the fixed producers create owned results. The CI result remains pending/failed/unsupported/incomplete unless the full native verification succeeds.

Validation uses fabricated public responses with real parsing/rendering and native read/count handling. Existing public policy tests also use real temporary Git. No live pilot, key, model, App, Docker execution or GitHub mutation is claimed. Accepted ADR0062 records the source architecture; later components consume these exact producers to enforce cohort, human-decision, signer, independent-review and publication requirements.

Run the focused checks with:

```sh
npx vitest run tests/upgrade-runtime-policy.test.ts tests/upgrade-pilot-ci.test.ts tests/upgrade-policy.test.ts
npm run typecheck
npm run build
```
