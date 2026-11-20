import { demand } from "./upgrade-host.js";
import { readRuntimePolicy, type RuntimePolicy } from "./upgrade-runtime-policy.js";
import { describeCheckedCandidate, type CheckedCandidate, type CheckedCandidateFacts } from "./upgrade-validation.js";
import { readAuthorizedSignature } from "./upgrade-signing.js";
import { runOwnedNativeReview, settleNativeReviewCompletion, verifyNativeReviewCompletion, type NativeReviewFacts } from "./upgrade-review-native.js";
import { auditControlledReviewWorkspace, disposeControlledReviewWorkspace, drainReviewWorkspaceCandidate,
  openControlledReviewWorkspace, reviewWorkspaceContext, type ControlledReviewWorkspace } from "./upgrade-review-workspace.js";

declare const reviewedBrand: unique symbol;
export type ReviewedCandidate = { readonly [reviewedBrand]: true };
export interface ReviewedCandidateFacts { readonly candidate: CheckedCandidateFacts; readonly review: NativeReviewFacts;
  readonly signerPrincipal: string; readonly independentExecution: "verified"; readonly publication: "pending"; readonly authority: "none" }
type OwnedReview = { checked: CheckedCandidate; policy: RuntimePolicy; facts: ReviewedCandidateFacts; signal?: AbortSignal };
const reviews = new WeakMap<ReviewedCandidate, OwnedReview>();
const consumed = new WeakSet<CheckedCandidate>();
/** Only actual native completion, unchanged owned workspace and settled cleanup can produce this result. */
export async function reviewCheckedCandidate(checked: CheckedCandidate, policy: RuntimePolicy, options: { signal?: AbortSignal } = {}): Promise<ReviewedCandidate> {
  const signal = options.signal; signal?.throwIfAborted(); demand(!consumed.has(checked));
  const candidate = describeCheckedCandidate(checked); const signature = readAuthorizedSignature(checked, policy);
  const selected = readRuntimePolicy(policy).projection.review;
  if (!selected) throw new Error("Independent fleet native reviewer is not configured."); consumed.add(checked);
  let workspace: ControlledReviewWorkspace | undefined;
  try {
    workspace = await openControlledReviewWorkspace(checked, policy, signal ? { signal } : {});
    const before = await auditControlledReviewWorkspace(workspace); const context = reviewWorkspaceContext(workspace);
    const native = await runOwnedNativeReview({ directory: context.directory, baseCommit: candidate.baseCommit,
      candidateCommit: candidate.candidateCommit, signal: context.signal }, policy);
    const after = await auditControlledReviewWorkspace(workspace); const review = await verifyNativeReviewCompletion(native);
    demand(JSON.stringify(before) === JSON.stringify(after) && review.baseCommit === candidate.baseCommit && review.candidateCommit === candidate.candidateCommit &&
      review.authorSession === selected.authorSession && review.executionSession !== selected.authorSession && review.configuredPrincipal === selected.reviewerPrincipal);
    describeCheckedCandidate(checked); readAuthorizedSignature(checked, policy); signal?.throwIfAborted();
    await disposeControlledReviewWorkspace(workspace); workspace = undefined;
    settleNativeReviewCompletion(native);
    describeCheckedCandidate(checked); readAuthorizedSignature(checked, policy); signal?.throwIfAborted();
    const facts: ReviewedCandidateFacts = Object.freeze({ candidate, review, signerPrincipal: signature.principal,
      independentExecution: "verified", publication: "pending", authority: "none" });
    const handle = Object.freeze({}) as ReviewedCandidate; reviews.set(handle, { checked, policy, facts, ...(signal ? { signal } : {}) }); return handle;
  } finally {
    if (workspace) await disposeControlledReviewWorkspace(workspace);
    await drainReviewWorkspaceCandidate(checked);
  }
}
export function readReviewedCandidate(handle: ReviewedCandidate): Readonly<OwnedReview> {
  const owned = reviews.get(handle); demand(owned); owned.signal?.throwIfAborted();
  describeCheckedCandidate(owned.checked); readAuthorizedSignature(owned.checked, owned.policy); return Object.freeze({ ...owned });
}
