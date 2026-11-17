import { type ReviewedReleaseManifest, reviewedReleaseSelectors, verifyReleaseApproval } from "./release-approval.js";
import { type ApprovedReleasePackage, approvedReleasePackageMetadata, prepareApprovedReleasePackage } from "./release-approved-package.js";

type PackageInput = Parameters<typeof prepareApprovedReleasePackage>[0];

/**
 * Bind the fresh, independently derived package observation to the reviewed
 * manifest used for acquisition. This does not itself authenticate the reader,
 * prove the verifier ran, establish artifact provenance, or authorize writes.
 * The caller must protect those boundaries and recheck review before publication.
 */
export function preparePackageForReviewedManifest(review: ReviewedReleaseManifest, input: PackageInput): ApprovedReleasePackage {
  try {
    const selected = reviewedReleaseSelectors(review);
    const current = verifyReleaseApproval(input.observation, input.policy, input.now);
    if (selected.manifestSha256 !== current.manifest_sha256) throw new Error();
    const result = prepareApprovedReleasePackage(input);
    if (approvedReleasePackageMetadata(result).approvalSha256 !== selected.manifestSha256 ||
        reviewedReleaseSelectors(review).manifestSha256 !== selected.manifestSha256) throw new Error();
    return result;
  } catch {
    throw new Error("Reviewed release package unavailable.");
  }
}
