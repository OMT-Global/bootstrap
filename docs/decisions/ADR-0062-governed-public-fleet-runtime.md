# ADR-0062: Governed public fleet runtime

Status: Accepted

Date: 2026-11-15

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

Decision owner: Bootstrap maintainers/coordinator, within existing owner choices.

The coordinator adopted the independently reviewed revision 3 design on 2026-11-15.
The exact adopted design SHA-256 is `6b4757e90e9839bb8fadc926957890eaa1b797c52b07cf6f754e0a42bbccdeaf`.
Separate-agent review found no remaining blocking design issue after its three
corrections and required-capture clarification; model-family independence is
unproved. This records source architecture and no new approver role or policy
relaxation. Implementation review, autoreview, GitHub approval and all operational
credentials, App installation, execution, publication and rollout remain separate.
Draft #231 stays open until a concrete reviewed replacement is publicly reviewable.

## 1. Concrete scope

Add `bootstrap upgrade-public-repository --request <json> [--publish] [--json]` and a corresponding `runGovernedUpgrade` library operation. Without `--publish`, collect current public inventory and return the selected repository's plan and missing gates. Do not run target hooks, sign, call a model, acquire write credentials, or write to GitHub in default mode. Keep the existing `upgrade-plan` and `inventory-public-fleet` behavior.

Explicit publish mode operates on exactly one selected numeric public repository identity and one target policy. It completes source preparation, isolated hook execution, trusted signing, isolated final checking, independent native review, current governance rechecks, one create-only branch push, and one PR creation. It never enables auto-merge, merges, changes settings/visibility/ownership, writes pilot outcomes, updates existing branches/PRs, or starts a second repository. Patch eligibility is reported; repository merge policy remains authoritative.

The implementation must have concrete fixed production adapters. Test adapters are available only in tests through module substitution or an internal constructor absent from CLI/package exports; neither arbitrary callback producers nor JSON pass flags become production authority.

## 2. Required order and owned results

```text
complete current discovery + owned policy observation + supported governance
  -> raw public Git snapshot + current generator capture
  -> prepareObservedUpgrade (original checkout read-only)
  -> prepareCandidateHook (actual fixed isolated backend)
  -> authorized signer signs only copyCandidateSigningRequest bytes
  -> completeSignedCandidate (signature + actual isolated final check)
  -> reviewCheckedCandidate (separate native reviewer, strict report, cleanup)
  -> policy-required signed public provenance and approved record-location contract
  -> current identity/policy/pilot/exception/review/provenance recheck
  -> one-repository App broker + publication attempt marker
  -> create absent branch with exact signed objects
  -> verify branch/head + recheck current governance
  -> create one PR + verify exact returned PR
```

Each success producer returns an opaque same-process handle whose private registry retains the exact candidate and inputs. `CheckedCandidate` continues to mean signature validity and completed validation, not signer authorization or review. Add separate `AuthorizedSignature`, `ReviewedCandidate`, `GovernedCandidate`, and `PublicationSession` associations; public facts describe these results but cannot reconstruct them. Do not add boolean `approved`, `pilotPassed`, `reviewClean`, or `installationValid` bypasses. A failed/cancelled/consumed handle cannot advance or be revived by copied JSON.

The CLI still needs a genuine initial source acquisition consumer: `verifyGitSnapshot` validates supplied raw objects but does not fetch them. Extract the fixed anonymous public Git acquisition/object-audit mechanics from `upgrade-history.ts` into an internal shared producer bound to the current numeric repository/head observation. Use it to acquire complete raw commit/tree/blob bytes, call `verifyGitSnapshot`, then feed `prepareObservedUpgrade`; reuse the same audited mechanics for later history acquisition. Do not reconstruct a signed commit from lossy REST fields, execute target checkout configuration, or substitute a caller-supplied consistency snapshot for verified public origin/history.

## 3. Operator inputs versus verified evidence

The request JSON selects repository slug/id, local read-only original checkout, generator source/commit, target immutable policy ref/digest, exact branch/message/author/committer plan, and locators for public governance evidence. These are claims to verify, never authority. Paths remain private operational inputs and are excluded from PR bodies and public provenance.

Trusted orchestrator configuration is derived from its owner-controlled `project.bootstrap.yaml` policy, not the target PR's proposed files or arbitrary target configuration. A frozen runtime projection may carry non-secret broker/profile identifiers and public identity bindings. Add only the minimum reviewed manifest schema needed for these selections; do not serialize secrets into the manifest. The CLI must not accept arbitrary executables, shell commands, remote origins, Git arguments, tokens, provider URLs, or trust-anchor overrides.

| Trusted configuration | Producer evidence required before use |
| --- | --- |
| Selected public repository numeric id and one-repository execution permission | Fresh GitHub public visibility, canonical name/id, default branch/head and complete fleet/class selection; changes invalidate preparation. |
| Authorized SSH signing principal and public-key fingerprint; opaque signer key reference | Fixed signer adapter returns the exact raw signed commit after the hook; current validation verifies it against the authorized fingerprint and complete commit plan. A matching signature alone never authorizes an otherwise unapproved key. |
| Native reviewer profile, independent execution principal/session, approved helper/model selection | Fixed reviewed launcher preflight, exact workspace audit, real child terminal state, strict clean report and completed cleanup. Author and reviewer cannot be the same agent execution. Unproved model-family provenance is recorded as the owner-accepted non-blocking limitation. |
| Authorized governance actors/roles and public record locations | Native GitHub user/review/comment identities, immutable record id/content hash and exact scope; retrieve and validate, do not trust names or supplied conclusions. Reuse already approved actor policy rather than silently choosing new authorities. |
| Dedicated GitHub App identity/installation selection and broker key reference | Broker authenticates the selected App/installation; mints and validates a token for exactly the selected repository and explicit required permissions/expiry. A pasted token string is insufficient. |
| Operator-owned attempt-record directory | Checked private path outside target checkout, exclusive repository-wide unresolved-attempt barrier, successful record write/flush before remote mutation. Records are recovery evidence, not reusable authorization. |

Physical keys, App ids, installations, and live reviewer credentials are deployment configuration. Source types, validation and fabricated tests need none. Missing deployment values block publish mode with fixed actionable reasons while dry-run still works.

## 4. Governance and pilots

Reuse `planFleetPolicyUpgrades` and ADR-0052's exact version, ordering, duplicate, failed/pending and target-bound pilot rules. Feed it verified public repository/class/version observations, not caller-authored inventory authority. Complete numeric identity/alias checks precede representative selection. A partial fleet scan cannot establish that the selected repository is the first representative.

The first representative may have its own pilot PR prepared, reviewed and published while later class members remain blocked. This does not convert a pending pilot into passed. No subsequent class candidate becomes publishable until the representative's target-bound outcome is authenticated. A failed pilot blocks that pilot and its class until authenticated remediation is recorded. A failed/pending different target cannot be bypassed by changing the proposed batch.

Add an owned cohort consumer that preserves the authenticated original complete inventory/cohort, numeric repository identities/classes, selected representative, original increasing source-to-target transition, and target version/digest. The public governance record identifies that cohort; current discovery is retained separately. After the pilot merges, its current policy legitimately equals the target. Verify the exact historical transition, actual merged pilot, current target binding and applicable CI, then release the remaining members through the cohort consumer. Do not feed an invented old version back as the pilot's current inventory row, apply a general equal-version bypass to the existing planner, drop the completed pilot and silently choose a new first member, or exclude a pending/failed representative by selecting a different cohort. Added/removed/reclassified repositories or changed scope require explicit cohort reconciliation before further publication. Existing `upgrade-plan` keeps its current input semantics; this is a new authenticated runtime consumer, with a complete lifecycle regression.

Add a concrete public governance evidence reader for pilot outcomes, remediation, exception decisions, and major-change notification/accepted ADR. A caller supplies only locators. The reader binds GitHub numeric actor identity and approved role, repository id, class, exact target version and digest, candidate/merged commit, and relevant validation evidence. Re-read selected records before writes; changed/deleted/revoked/ambiguous evidence blocks. Use bounded same-origin public GitHub GETs and complete pagination. No new cryptographic receipt/key enrollment is necessary for these GitHub-authenticated records.

A pilot pass must reference the actual representative candidate and relevant CI evidence, not a green job name or a free-form `passed` field. Reuse the reviewed `observeManagedCi` producer if its source is reconciled; its named profile supports only the actual generated inline extended-validation workflow. Otherwise implement that exact existing contract before claiming pilot verification. Current combined source contains its ADR text but does not contain that function. Unsupported workflows remain blocked, not accepted through generic green summaries. A pass for another target/digest cannot release a class.

The concrete reusable CI source is `fleet-policy-ci-stage/src/upgrade-pilot-ci.ts` (`observeManagedCi`, `readOwnedCiObservation`); `fleet-approval-stage/src/upgrade-approval-read.ts` supplies `observeUpgradeDecision` and strict decision predicates. Port their small producers onto the current `PublicObservationRead(signal, repository, token?)` and owned policy types. Do not carry their older public-read/policy/generator stack or user `gh` file-auth provider. CI observations still need the new representative-pilot/batch consumer; they do not themselves authorize a pass.

Minor upgrades retain independent review. Major upgrades additionally require evidence of notification and an accepted ADR before PR creation. Exception-bearing upgrades require the configured human decision. Permanent exceptions, major policy deviations, and ownership/visibility changes retain issue #62's human decision boundaries; this source route does not perform ownership/visibility changes.

The program verifies externally recorded outcomes; it does not post approvals, notifications or pilot passes on a person's behalf. A future live pilot is required before actually releasing its real class, not automatically a new prerequisite for implementing or testing the source.

## 5. Signer and independent reviewer

`signCandidateHook(ticket, signerPolicy)` accepts a genuine prepared-hook ticket, obtains its exact unsigned bytes, verifies the selected key/principal against trusted policy, calls one fixed bounded signer adapter, and passes raw signed bytes to `completeSignedCandidate`. Key material and signer capability never enter target containers or reviewer workspaces. No ambient SSH agent, default key discovery, target-selected `gpg.program`, or target Git configuration is used. Tests use an ephemeral Ed25519 key through the same request/verification protocol.

Prefer a native review consumer over a new external approval-envelope protocol. `reviewCheckedCandidate(checked, reviewPolicy)` must reconstruct the exact complete signed history from `copyCheckedCandidateBundle`, verify candidate/base/tree/plan/key identities, run the distinct reviewer against that workspace, strictly validate its result, audit unchanged candidate/helper inputs, and await cleanup before returning a `ReviewedCandidate`.

Reusable unpublished source exists in `fleet-review-native-settlement`: `openControlledReviewWorkspace`, `auditControlledReviewWorkspace`, and `runOwnedNativeReview`. Adapt the workspace Git/object/signature checks to genuine `CheckedCandidate` ownership. Do not cherry-pick the old preparation/capsule/admission graph. The existing native function returns only exit status, stream counts/hashes and a cleanup deadline; **it is not a review-completion producer**. Implement the bounded report parser and outcome owner. Exit zero, absent output, `scoped-clean` text scraped from a log, or a caller-provided success flag is insufficient.

The selected launch profile must be explicit and reviewed: current approved reviewer settings are `gpt-6.1-sol`, high reasoning, no fallback. The legacy profile pins a specific helper and old `gpt-5.6-sol` selection and requires a delegated cgroup. Reconcile its launcher with the current settings; never retain old model access or its fallback by accident. Preserve resource ownership, cancellation/settlement and helper-input checks. No App token or App/signing key is available to target/reviewer code. If the native host/profile cannot meet its contract, publish mode stops; it never falls back to the ordinary authenticated host shell or a fabricated pass.

Bind review to exact base/candidate/source/tree/commit-plan and the final-validation recipe/result. Require a terminal successful clean report with no unresolved actionable findings. Any accepted source fix restarts preparation, signing, final validation and review. The review producer has a separate agent/session from the author; model-family independence stays explicitly unproved where applicable. Its output is pre-publication review evidence, not a GitHub approval on the eventual PR; that PR still needs its ordinary independent approval and required checks before merge.

Freeze a versioned native result contract during implementation review: bounded UTF-8 JSON with known fields, terminal completion, findings with stable id/severity/location/actionable status, and the exact helper's schema/version. The owner supplies and checks operation/base/candidate/plan/helper/model/session bindings from the actual launch and workspace audits; a report cannot assert its own trusted identity. Unknown schema/field, duplicate identity, invalid location, partial output, nonterminal status or any actionable finding blocks. Set explicit byte/node/depth/finding limits and reject overflow rather than truncating. Do not add a caller-selected finding suppression list.

## 6. GitHub App and publication transport

`openPublicationSession(governed, appPolicy)` runs only after validation and review succeed. A fixed trusted broker authenticates the selected App and installation and requests an installation token with `repository_ids: [exactId]` and explicit least permissions. Validate returned App/installation/repository identity, actual expiry and granted permissions; reject broad or mismatched capability. The source broker can accept an opaque signer/key reference through its reviewed private channel; never a key in a CLI argument or target manifest.

The normal permission set is metadata read, contents write and pull_requests write. Current token helper #262/ADR-0057 deliberately does not grant workflows write; its existing release/fleet profiles and permission validation remain unchanged. Implement a separate opt-in fixed fleet-workflow-update profile as a reviewed source delta. Derive its need from the owned exact raw base-to-candidate diff, including deletions, both sides of renames and mode changes under `.github/workflows/**`; no caller boolean selects the grant. Request workflows write only when that exact diff needs it and the trusted profile authorizes it. Reject insufficient installation grants without fallback or escalation. Never request administration, secrets, checks-write, issues-write or broader repository access. App installation/permission changes remain separate operational actions.

Preserve the exact SSH-signed raw commit by pushing Git objects from a disposable controlled publication repository. GitHub's REST create-commit endpoint documents a PGP signature input, so it is not a substitute for transporting the existing SSH commit. Reuse bounded trusted Git, empty target hooks/configuration/templates, the known HTTPS helper and a fixed `https://github.com/<verified-repository>.git` origin. Target hooks, filters, credential helpers or executable configuration never run here.

Pass the token only through a reviewed private credential channel to the fixed Git process/helper; never embed it in argv, remote URLs, temporary Git config, report text or a target child environment. The fixed credential helper validates exact HTTPS host/path and serves only the selected session. Specify and test its pipe/descriptor lifetime, child access, cancellation and redaction. Native networking/TLS settings come only from reviewed trusted transport configuration; target Git config and arbitrary redirect/proxy commands cannot alter authority. Preserve TLS verification and fixed-origin redirect refusal.

Push exactly `<candidateCommit>:refs/heads/<generatedBranch>` with `--porcelain` and explicit `--force-with-lease=refs/heads/<generatedBranch>:`. The empty expectation prevents replacement of an existing ref, but Git may report an already-identical ref as UPTODATE before lease evaluation. Therefore exit zero plus matching readback is insufficient. Parse bounded porcelain output under the fixed locale and require exactly one matching requested-ref NEW-ref (`*`) status; reject UPTODATE (`=`), every other status, extra ref records, malformed/truncated output or ambiguity and require reconciliation. Forbid every other force/mirror/delete/refspec form. Preliminary branch absence is diagnostic only. An existing branch, including a same-commit branch created by another actor after that preliminary check, must never be adopted as this operation's creation.

After confirmed push, independently read the exact branch and commit, recheck the current base/policy/governance, and POST one PR for that exact head and default base. Do not automatically edit or adopt an existing PR. Verify returned repository/id/head/base/branch and read back the created PR; preserve its URL if later verification fails. PR body uses the generated template and includes policy diff, exact tests/validation, exceptions/decisions, pilot status, public provenance, independent review and limitations. Do not include raw native logs, private paths, auth state or original checkout fingerprints.

## 7. Failure and retry state

Define a deterministic operation id from numeric repository id, base commit, candidate commit, target policy binding and reviewed publication intent. Use that id in the branch and immutable attempt record. Independently acquire an exclusive unresolved-attempt barrier keyed only by numeric repository id, before preparing a publication attempt. A leftover barrier blocks every new candidate/target/cohort for that repository until explicit human reconciliation; changing a timestamp, signature, candidate hash, operation id or branch suffix cannot bypass it. Store the exact operation/candidate inside the barrier record. Dry-run may still inspect and report the block.

| State | Next permitted action | Failure behavior |
| --- | --- | --- |
| `planned` | Return dry-run or enter explicitly authorized local preparation | No publication capability exists. |
| `prepared` / `hook-complete` | Authorized signing then final check | Dispose owned resources; never publish partial data. |
| `checked` | Distinct native independent review | Findings/malformed output/uncertain cleanup stop; invalidate downstream authority. |
| `reviewed` | Fresh governance and public identity checks | Any change stops; no stale observation lease. |
| `ready` | With the repository barrier owned, acquire verified narrow App session; exclusively write and flush attempt record | Record/path/flush failure prevents remote write. An existing unresolved barrier blocks any regenerated candidate. |
| `branch-write-attempted` | Exactly one absent-ref push | Any timeout/cancellation/transport ambiguity stops. Do not retry, delete branch or claim absence. |
| `branch-confirmed` | Read back branch; fresh gates; exactly one PR POST | Gate failure leaves branch for human reconciliation. |
| `pr-write-attempted` | Read back successful response and exact PR | Lost/invalid response stops. Do not retry or infer failure from a missing local URL. |
| `published` | Emit verified PR URL, close/revoke credentials, durably archive completed record and release only this successful operation's barrier | No merge, rollout or follow-up write. Any uncertain finalization leaves the barrier for a human. |
| `reconcile-required` | Emit redacted operation id/known public objects/last attempted action | Human inspects actual remote state; source exposes no automatic resume/rollback. |

Use an exclusive directory/record claim in the checked operator-owned state root for the repository barrier; never reclaim an existing barrier based only on age, PID or absent remote branch. Before either remote mutation, record the attempted action and flush the operator-owned record. If recording the second transition fails, do not POST the PR. A normal verified success may archive its completed record and release its own barrier after credential/resource cleanup; a crash or uncertain finalization leaves it for manual reconciliation. This is ordinary checked file/flush recovery bookkeeping on the trusted host, not a universal crash-proof filesystem journal or ext4/hardware durability certificate. State the residual host/storage trust explicitly. Immutable Git objects may have reached GitHub even when the branch push fails; do not describe remote non-mutation as certain.

The current owner may also release its barrier after a proved pre-write failure with complete local cleanup; it knows no remote mutation was attempted. This is not stale-lock reclamation by a later process. After any remote attempt or uncertain ownership/cleanup, only verified full success or explicit human reconciliation can release the barrier.

Remote ref creation is atomic for that ref; public visibility/default-base checks and PR creation are not one GitHub transaction. Recheck before each mutation and after success. A concurrent administrative change can still force manual reconciliation; no transaction-wide lease is claimed. The selected branch's create-only condition prevents overwriting another actor's work.

Revoke the minted installation token when supported and dispose private transport resources after completion/failure. Revocation/cleanup uncertainty is reported separately and prevents further work; it cannot turn an attempted write into a safe retry. Keep public recovery facts even when cleanup fails. Do not automatically remove a remote object or create a second PR to repair uncertainty.

## 8. Public provenance

Publication derives its provenance requirement from the actual approved policy projection, including `provenance.publicManifestRequired`, `publicManifestPath`, `failClosedForRequiredMaterialChanges`, and the supported signed/redacted PRS-PROV-001 contract. There is no `requiresSigned` field. Unknown applicability, unsupported policy semantics, or a missing policy-required signed record blocks publication before either remote write; an unsigned summary remains useful dry-run output but cannot authorize a noncompliant PR.

Where the active approved policy requires private or material-change capture, a native-labelled public manifest is not a substitute. Unavailable, unapproved or unverifiable required capture blocks publication before either remote write. This consumer verifies the applicable approved capture contract and its exact-subject evidence; it never treats a public signature, a caller boolean, synthetic capture, or mere configuration presence as proof that required capture occurred. This clarification grants no private-capture implementation or operational authority and changes neither the existing wire/cryptographic format nor the requirement for genuine GitHub approval when that later gate applies.

Add `signReviewedUpgradeProvenance(reviewed, trustedProvenancePolicy)` as a bounded consumer of the genuine `ReviewedCandidate`. It creates a strict version-2 public manifest with `createPublicProvenance`, uses the existing domain-separated library signing contract through an explicitly authorized provenance signer, and verifies the result with `verifySignedPublicProvenance(envelope, {trustedPublicKeys, expectedSubject: {repository, commitSha}})`. The trusted keyring, signer/principal scope and actual signed subject are independent of App authority and SSH commit signing. Missing or untrusted signer configuration blocks publish. Tests use ephemeral signing keys through this same contract; no production signer is invented or enrolled.

This prepublication record carries only genuine native-review claims, using the existing `execution.workflow` field with exact marker `bootstrap-fleet-native-review-v1` and configured public reviewer identity derived from the owned review completion. The fleet verifier requires that marker and the owned native-lineage association; the marker alone proves nothing. It must never claim those facts are submitted GitHub approval. The existing GitHub-bound provenance CLI requires an already-existing PR and exact-head GitHub review, so it is deliberately not the producer for this prepublication phase. The later PR review/merge consumer continues to require actual native GitHub review lineage. The new native-lineage consumer and its explicit marker require independent source review; no schema field or arbitrary metadata bypass is silently added to the existing strict codec.

The companion public operation manifest binds base/candidate, policy/generator digests, validation profile/image, tests, review result, governance locators and publication intent; the strict provenance envelope retains its existing allowlisted schema. The fleet publication gate consumes the separately reviewed public-provenance record/location contract for the policy's required path (`provenance/runs` in the current standard). A PR-body summary alone is not proof that this location requirement is satisfied. An external record locator is supported only if that approved contract admits it; do not invent an exception or commit an exact-head envelope into the very commit it signs. If the record/location or permitted lineage contract is unavailable, report that precise dependency and keep publish blocked. This is a source integration dependency, not permission to enable private capture or deploy storage.

## 9. Source acceptance tests

Use one end-to-end fabricated-provider test harness around the production parser, state machine, preparation/validation consumers, signer verification, review result owner and publisher. Record ordered calls and capture every outgoing body/argument/stream. Real temporary Git objects and ephemeral SSH signatures preserve object/crypto behavior; fabricated external responses are labelled as such.

Required cases:

1. Default invocation emits human and JSON plans with zero signer/reviewer/token/write calls; unsupported/malformed input is explicit and nonzero.
2. Happy publish path produces exactly one reviewed signed candidate, one absent-ref push and one correct PR; no legacy generic reconcile route runs.
3. Wrong/copied/stale handles, mismatched base/tree/plan/policy/key, hook/check failures, changed source and incomplete cleanup never reach publication.
4. Native exit zero with missing/malformed/truncated/stale report, actionable findings, changed helper/workspace, self-review, or cancellation cannot produce `ReviewedCandidate`. Unknown model family is disclosed, not silently claimed independent or automatically blocked.
5. First representative can be published without releasing its class; pending/failed/wrong-target/wrong-digest/unverified pilot blocks every later member. Exercise pilot publication, exact merge, re-inventory with current pin equal to target, authenticated historical cohort reconciliation and release of the next member. Duplicate numeric identities, incomplete scans, cohort replacement attempts, revoked decisions, exceptions and major notification/ADR cases are exercised.
6. Wrong App/installation, multi-repository scope, broad/wrong permissions, expired token, private/moved repository, insufficient workflow permission and redirected requests fail before mutation. Workflow permission selection covers additions/deletions/renames/modes from the actual owned diff; existing helper profiles retain their prior grants. Token/key material is absent from argv/logs/PR bodies and target/reviewer children.
7. Real disposable local Git transport tests prove exact signed object preservation, a genuine matching NEW-ref result and refusal for existing/racing different-commit and same-commit branches. Explicitly exercise UPTODATE with exit zero and matching readback; it still requires reconciliation. This validates Git semantics without a live GitHub write.
8. Inject faults immediately before/after marker writes, push, branch readback, PR POST, PR readback and credential cleanup. The state machine never retries a write, resumes an ambiguous attempt, deletes a branch, merges or processes another repository.
9. Response loss after successful simulated branch/PR creation yields `reconcile-required` and preserves known public evidence. Restart with a different candidate timestamp/signature/hash, branch or cohort still hits the same repository-wide unresolved barrier. A fully verified successful attempt archives its record and releases only its own barrier; uncertain cleanup never does.
10. Public evidence is credential/path-redacted; required unsigned/missing/wrong-subject/untrusted-key provenance blocks both writes. Native-review lineage cannot satisfy a GitHub-review claim, and an unsupported record location or applicability contract remains blocked. When active policy requires private/material capture, missing/unapproved/unverifiable capture blocks both writes even with an otherwise valid native public envelope; a synthetic record or configured sink is insufficient. PR body follows the repository template and links all #62-required evidence.

Run repo-required lint/test/typecheck/build and final autoreview for each intended PR diff. Maintain actual hosted Docker evidence required by ADR-0013; fabricated provider/native responses do not replace that confinement proof. Native broker/model/API adapters also need their documented qualification before a live run, but source tests require no real App/key/model transmission or fleet mutation.

## 10. Minimal coherent PR scopes

Start after the existing combined preparation/validation component is reviewed and integrated. Measure natural code/config lines; keep each PR within the repository cap. Do not compress code or shift shipped logic into tests to evade it.

1. **Governance producer and runtime request policy.** Concrete current CI/pilot/human-decision observations, trusted policy projection and owned `GovernedCandidate` inputs; deterministic plan behavior and refusal tests. Reconcile reusable CI/approval stage source first. No write route.
2. **Trusted signer and native candidate review.** Exact `CheckedCandidate` workspace adapter, refreshed native profile, strict report completion and independent identity check, cleanup owner and tests. If it exceeds the cap, split at a complete native completion producer followed by its candidate consumer; do not merge a fake success adapter.
3. **One-repository App session and create-only publisher.** Actual broker identity/scope validation, exact Git transport, recovery markers, PR construction/readback and fault tests. API accepts genuine reviewed/governed results and has no public CLI yet. Split credential session from publisher only if necessary at a complete producer boundary.
4. **CLI orchestration and end-to-end acceptance.** Wire the actual prior producers and the approved required-public-provenance consumer into one usable dry-run-default command, human/JSON outputs, runbook and full fabricated-provider acceptance suite. Keep source-complete versus operational evidence distinctions in the issue report. If that provenance consumer/record contract is not ready, it is an explicit source dependency rather than an omitted gate.

No PR is described as closing #62 merely because its internal primitives pass. Assess the final integrated command against issue acceptance and the actual hosted/independent-review evidence. No obligatory real fleet rollout or App installation is added by this design.

## 11. Explicit replacement of draft #231

Draft #231's seven files are absent from main and current candidate work. Its ADR-0024 is labelled Accepted for its bounded accounting/authentication prerequisite, but is unmerged and supplies no enabled runtime path. Its fixed `/etc` approval selection, dual offline approval keys, concrete ext4 profile, Python journal/private ACK, cumulative nonrefundable logical ledger and installed-code measurement graph are not requirements introduced by merged ADR-0016 or by #62 itself.

After independent review, the coordinator may adopt a successor ADR for this source route and supersede the unmerged proposal rather than importing it as main policy. Record the disposition explicitly: **#231 is replaced by one-operation, create-only publication with a checked attempt record and stop-for-human reconciliation; its J0 deployment and journal promises are not implemented by this route.** Do not say its code was merged or equivalent. Close/supersede #231 only after the replacement scope and its retained boundaries are reviewable; root owns that action.

Preserve main's actual non-root fixed isolation, trusted host tools, public identity/ancestry, original-checkout immutability, exact hook/sign/final-check/review order, credential separation, bounded operations, cleanup, current governance and create-only behavior. Removing a draft-specific ledger does not permit unbounded concurrency: this CLI owns one operation and honors every existing per-operation bound. It claims neither process-lifetime heap certification nor transactional rollback/durable storage proof.

## 12. Decisions and remaining evidence

The owner already chose the dedicated single-public-repository App and human reconciliation after uncertain writes, and accepted target-bound pilot rules. Do not ask again for those choices. Routine source architecture, including the explicit supersession of an unused draft implementation, can be coordinator-adopted after independent design review, consistent with ADR-0013/0035/0037 precedent.

Material human decisions are limited to actual changes in governance authority or semantics: a new principal/role allowed to approve exceptions or major deviations; weakening an existing pilot gate; relaxing author/reviewer separation; changing ownership/visibility; or replacing an explicitly owner-imposed requirement that the coordinator can identify in the source record. This packet proposes none of those relaxations. Existing authorized actor choices should be projected and verified; unresolved role semantics must not be guessed.

Physical App ids, key paths, deployed runtime/cgroup details and credentials are not source-design approval questions. Populate and qualify them only for a separately authorized live operation. The policy must also specify the signer identity and approved native reviewer profile before such an operation; tests use fabricated equivalents without pretending they are production enrollment.

The exact remaining issue evidence is behavioral: a default dry run, a governed PR carrying policy/tests/exceptions/provenance, and demonstrated representative/failed-batch enforcement. Integrated tests can prove the latter control behavior without a real rollout; they cannot honestly assert an actual pilot passed. ADR-0013's real hosted Docker suite is an explicit existing runtime requirement. ADR-0037 says its source-only/fixture stage does not close #62; final closure requires an assessment of the assembled integration and evidence, not automatic escalation to an invented requirement to install an App or mutate a fleet.
