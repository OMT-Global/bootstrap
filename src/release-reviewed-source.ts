import { type ReviewedReleaseManifest, reviewedReleaseSelectors } from "./release-approval.js";
import { capturePublicGenerator, generatorSnapshot } from "./upgrade-generator.js";
import type { VerifiedGitSnapshot } from "./upgrade-git.js";

/**
 * Capture tracked source and raw Git objects matching the reviewed commit/tree.
 * The caller authenticates the review, repository identity and source location;
 * the underlying capture requires its supported Linux trusted-host boundary.
 */
export async function captureReviewedReleaseSource(reviewed: ReviewedReleaseManifest, sourceRoot: string): Promise<VerifiedGitSnapshot> {
  try {
    const selected = reviewedReleaseSelectors(reviewed);
    const capture = await capturePublicGenerator(sourceRoot, selected.targetCommit);
    const snapshot = generatorSnapshot(capture);
    if (snapshot.baseCommit !== selected.targetCommit || snapshot.tree !== selected.targetTree ||
        reviewedReleaseSelectors(reviewed).manifestSha256 !== selected.manifestSha256) throw new Error();
    return snapshot;
  } catch {
    throw new Error("Reviewed release source unavailable.");
  }
}
