import { type ApprovalObservation, type ApprovalPolicy, type ApprovalReviewObservation, type ReviewedReleaseManifest, reviewReleaseManifest, reviewedReleaseSelectors } from "./release-approval.js";
import type { ApprovedReleasePackage } from "./release-approved-package.js";
import { preparePackageForReviewedManifest } from "./release-reviewed-package.js";
import { reviewedPreflightEnvironment } from "./release-reviewed-preflight.js";

type Environment = ReturnType<typeof reviewedPreflightEnvironment>;
type AcquiredPackage = { actual: ApprovalObservation["actual"]; assets: readonly { name: string; bytes: Uint8Array }[] };

/**
 * Source-only composition. Both adapters and their execution environments are
 * trusted: they must authenticate GitHub, establish artifact/source provenance,
 * independently derive actual facts, and prevent selector overrides. This does
 * not establish authority to publish or protect against later review revocation.
 */
export async function prepareReleaseForPublication(input: {
  policy: ApprovalPolicy;
  readApproval: () => Promise<ApprovalReviewObservation>;
  acquire: (environment: Environment, reviewed: ReviewedReleaseManifest) => Promise<AcquiredPackage>;
}): Promise<ApprovedReleasePackage> {
  try {
    input = { ...input };
    const policy = Object.freeze({ ...input.policy });
    const first = structuredClone(await input.readApproval());
    const reviewed = reviewReleaseManifest(first, policy, new Date());
    const environment = reviewedPreflightEnvironment(reviewed);
    const notesAssetName = reviewedReleaseSelectors(reviewed).notesAssetName;
    const acquired = structuredClone(await input.acquire(environment, reviewed));
    const current = structuredClone(await input.readApproval());
    return preparePackageForReviewedManifest(reviewed, {
      observation: { ...current, actual: acquired.actual }, policy, now: new Date(),
      notesAssetName, assets: acquired.assets
    });
  } catch {
    throw new Error("Release preparation unavailable.");
  }
}
