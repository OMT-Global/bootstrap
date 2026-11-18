import { type ReviewedReleaseManifest, reviewedReleaseSelectors } from "./release-approval.js";

/**
 * Derive every immutable preflight verifier selector from one unexpired reviewed
 * manifest. The caller must have authenticated the review observation, execute
 * the verifier in a trusted environment, verify the workflow and target source,
 * and recheck the review and actual package before any publication. This map
 * contains no credentials and does not itself run or authorize the verifier.
 */
export function reviewedPreflightEnvironment(review: ReviewedReleaseManifest): Readonly<{
  GITHUB_REPOSITORY: string;
  GITHUB_REPOSITORY_ID: string;
  PREFLIGHT_RUN_ID: string;
  PREFLIGHT_APPROVED_ATTEMPT: string;
  PREFLIGHT_ARTIFACT_ID: string;
  PREFLIGHT_ARTIFACT_SHA256: string;
  PREFLIGHT_TARGET_SHA: string;
}> {
  const selection = reviewedReleaseSelectors(review);
  return Object.freeze({
    GITHUB_REPOSITORY: selection.repository,
    GITHUB_REPOSITORY_ID: selection.repositoryId,
    PREFLIGHT_RUN_ID: selection.runId,
    PREFLIGHT_APPROVED_ATTEMPT: selection.attempt,
    PREFLIGHT_ARTIFACT_ID: selection.artifactId,
    PREFLIGHT_ARTIFACT_SHA256: selection.archiveSha256,
    PREFLIGHT_TARGET_SHA: selection.targetCommit
  });
}
