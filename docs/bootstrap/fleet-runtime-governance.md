# Public fleet runtime governance source

This component implements ADR-0062's read-only governance producer. It does not
register a command, run target hooks or a reviewer, sign, mint a token, publish,
merge, record a pilot outcome or change repository settings. The future runtime
must combine its owned result with the actual checked candidate, authorized
signer, independent review, required provenance/capture and narrow App publisher.

`captureRuntimePolicy` reads `fleetRuntime` from the genuine captured Bootstrap
generator's `project.bootstrap.yaml` and verifies those exact bytes at Bootstrap's
current public default head. Plain configuration JSON cannot construct its owned
handle. The strict projection selects existing approved numeric actor identities
and roles, allowed public repositories and one public issue containing decisions.
Optional signer, fixed reviewer profile, App and attempt-directory settings are
non-secret references. Missing settings produce specific blockers. The shared
manifest schema and actual CLI projection remain the final runtime scope; do not
install this reserved setting in a live manifest before that integration exists.

`observeUpgradeGovernance` obtains complete current public discovery and genuine
policy observations, then compares them with the authenticated original cohort.
Current versions remain truthful when the representative is already at target.
The ordinary `upgrade-plan` algorithm retains its existing input semantics; this
consumer uses the authenticated original transitions and separately verified
outcomes. Its description still reports pending independent review/publication
and no authority. A copied description cannot replace the owned handle.

Governance comments are read from the fixed configured public issue with complete,
bounded pagination. A record body is exactly `PRS-FLEET-GOVERNANCE-001`, a newline,
and compact canonical JSON (`JSON.stringify` output). Duplicate keys, extra fields,
unknown schemas, malformed authorized records and ambiguous catalogs fail closed.
The writer's native numeric GitHub user ID and login must match the existing
approved actor projection and the record's configured role. This component does
not create, edit or submit any person's decision. Ordinary conversation and
unapproved actors' comments grant no authority.

The version-1 record kinds are:

- `cohort`: complete public inventory identities (including unmanaged entries),
  managed member classes, original source version/digest/head, and exact target
  version/ref/commit/digest. A later cohort explicitly names its predecessor and
  reconciliation. It cannot replace an unfinished representative or target.
- `pilot-outcome`: exact cohort, numeric repository, candidate and merged commit,
  PR number and target digest. A failure permits truthful premerge state and a
  bounded explanation without inventing a merge or success receipt; its actual
  public PR/candidate/base identities are verified before the class stop. A pass
  additionally requires merged SHA, workflow/CI evidence and the actual merged PR with the recorded original
  base and candidate, original immutable manifest/policy transition, truthful
  current target policy and current owned managed-inline extended CI proof.
- `remediation`: references the exact earlier failed outcome and target. It
  permits the representative to retry; it does not pass the pilot or release
  later class members. Revoking a failure alone does not erase the class stop;
  independent classes remain preparable even after a failed pilot merged at the
  target pin. A current-target member in another class is not consumed as passed
  evidence for the selected class; missing success evidence still blocks its own
  class. Failure memory follows the authenticated
  cohort/class and numeric representative identity across successor targets.
- `exception`: binds the exact current exception declaration and expiry.
  Permanent exceptions additionally need an authenticated accepted-ADR record
  matching the declared repository-relative ADR path.
- `major-notice` and `accepted-adr`: bind the exact cohort, selected base and
  target. The ADR must be a current unchanged regular file with an actual plain
  `Status: Accepted` paragraph. Code fences or an arbitrary claimed pass do not
  satisfy it.
- `revoke`: removes a prior decision from active use, only when authored by an
  actor authorized for that decision's original role.

The native CI producer supports the existing generated inline extended workflow
only. It binds the current default head, exact workflow bytes, GitHub Actions App,
run/attempt, job/check IDs, required steps and repeated evidence. Unsupported
workflows and partial pagination never become a pilot pass. CI success alone
is not an outcome or a human decision.

The current cohort's pilot must still be the exact current merged default head.
Completed earlier cohorts use a separate historical proof: native merged PR and
original base/candidate, immutable original policy transition, complete bounded
ancestry to the current head, policy published by the fixed trusted publisher,
exact generated workflow and native CI at the historical merged SHA. Version,
ref, published commit and digest must all match that cohort's target. This lets
C1 completion survive a later C2 pilot merge without weakening C2's current CI.
Unsupported ancestry (including a comparison beyond 250 commits), unknown
workflow/profile or unavailable source remains blocked, never a claimed pass.

Fresh full discovery, source/target policy refs, decision records and controller policy are checked again
before returning. `recheckUpgradeGovernance` repeats the real producers before a
future write; an unchanged timestamp or copied digest is not a freshness lease.
Public GETs are fixed-origin, bounded and anonymous, with no ambient `gh` session
or saved credential provider. A rate limit or missing source blocks the operation.

The signing-request addition exposes immutable public repository/base/tree/source
facts from the owned prepared candidate so the next signer consumer can check
repository authorization before accessing a configured key. It adds no signing
authority; commit bytes remain a separate defensive copy. The regression uses
temporary Git objects and a newly generated disposable test key only.

Tests substitute public providers and fixture-only owned handles for the new
cohort unit cases. The existing raw-policy and candidate suites exercise real
temporary Git and ephemeral SSH signatures with explicitly fabricated host and
Docker adapters. None establishes a deployed App, model execution, actual Docker
confinement, production signer or passed real pilot.

The five-minute governance operation charges verified request/byte totals from every controller-policy capture, discovery and member-policy observation, both native decision catalogs, historical and current pilot CI, native PR checks, ADR reads, and final policy-ref rechecks against one 10,000-request / 256 MiB aggregate. A partially charged local reader contributes only its remaining delta after nested producers return. Each producer retains its own stricter limits and cancellation; the aggregate is checked before starting the next producer. A failed or over-budget observation never creates an owned governance result.
