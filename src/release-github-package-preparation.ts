import { createHash } from "node:crypto";
import type { ApprovalObservation, ApprovalPolicy } from "./release-approval.js";
import { reviewReleaseManifest, reviewedReleaseSelectors } from "./release-approval.js";
import { readGitHubExactTag, readGitHubPublicationApproval } from "./github-approval-reader.js";
import { acquireReviewedPreflight } from "./release-artifact-acquisition.js";
import { readReviewedGitHubPreflight } from "./release-reviewed-github-preflight.js";
import { prepareReleaseForPublication } from "./release-prepare-publication.js";
import { captureReviewedReleaseSource } from "./release-reviewed-source.js";
import { verifyBootstrapSourcePublishHook, verifySourceReleasePackage } from "./release-source-package.js";
import type { VerifiedGitSnapshot } from "./upgrade-git.js";
import type { ApprovedReleasePackage } from "./release-approved-package.js";

/**
 * Composition used by a trusted, isolated release runtime. Runtime identity,
 * configured policy/tool pins, authenticated token, target and source checks
 * remain caller requirements. It does not publish or prove exclusive writers.
 */
export async function prepareGitHubReleasePackage(input: {
  policy: ApprovalPolicy;
  approval: Parameters<typeof readGitHubPublicationApproval>[0];
  preflightWorkflowPath: string; preflightWorkflowCommit: string;
  publishScript?: string;
  tag: string; notesAssetName: string; latest: boolean; requireSignedTag: boolean;
  pythonPath: string; pythonSha256: string; ghPath: string; ghSha256: string;
  runtimeDir: string; maxAssetBytes: number; maxArchiveBytes: number; maxExpandedBytes: number; maxMembers: number; sourceSnapshot: VerifiedGitSnapshot;
  assertTarget: (tag: string, commit: string) => Promise<void>;
}): Promise<ApprovedReleasePackage> {
  try {
    input = { ...input, policy: { ...input.policy }, approval: { ...input.approval } };
    if (input.publishScript !== undefined) verifyBootstrapSourcePublishHook(input.sourceSnapshot, input.publishScript);
    return await prepareReleaseForPublication({ policy: input.policy,
      async readApproval() { return await readGitHubPublicationApproval(input.approval); },
      async acquire(_environment, reviewed) {
        const selection = reviewedReleaseSelectors(reviewed);
        if (selection.tag !== input.tag || selection.notesAssetName !== input.notesAssetName || typeof input.latest !== "boolean") throw new Error();
        async function checkTarget(commit: string): Promise<void> {
          await readGitHubExactTag({ repository: input.approval.repository, repositoryId: input.approval.repositoryId,
            tag: input.tag, expectedCommit: commit, requireSigned: input.requireSignedTag, token: input.approval.token,
            ...(input.approval.fetchImpl ? { fetchImpl: input.approval.fetchImpl } : {}) });
          if (await input.assertTarget(input.tag, commit) !== undefined) throw new Error();
        }
        await checkTarget(selection.targetCommit);
        const metadata = await readReviewedGitHubPreflight({ reviewed, repository: input.approval.repository,
          repositoryId: input.approval.repositoryId, expectedWorkflowPath: input.preflightWorkflowPath,
          expectedWorkflowCommit: input.preflightWorkflowCommit, token: input.approval.token,
          ...(input.approval.fetchImpl ? { fetchImpl: input.approval.fetchImpl } : {}) });
        const acquired = await acquireReviewedPreflight({ reviewed, token: input.approval.token, pythonPath: input.pythonPath,
          pythonSha256: input.pythonSha256, ghPath: input.ghPath, ghSha256: input.ghSha256,
          runtimeDir: input.runtimeDir, maxAssetBytes: input.maxAssetBytes, maxArchiveBytes: input.maxArchiveBytes,
          maxExpandedBytes: input.maxExpandedBytes, maxMembers: input.maxMembers });
        await checkTarget(metadata.target_commit);
        if (input.notesAssetName !== "RELEASE_NOTES.md") throw new Error();
        await verifySourceReleasePackage({ snapshot: input.sourceSnapshot, repository: input.approval.repository,
          tag: input.tag, channel: acquired.evidence.channel, commit: metadata.target_commit, tree: metadata.target_tree, assets: acquired.assets });
        await checkTarget(metadata.target_commit);
        const assets = acquired.assets.map((asset) => ({ name: asset.name, size: asset.bytes.byteLength,
          sha256: createHash("sha256").update(asset.bytes).digest("hex") })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
        const actual: ApprovalObservation["actual"] = { schema_version: 2, action: "publish_new_release",
          repository: { id: metadata.repository_id, full_name: input.approval.repository }, tag: input.tag,
          version: acquired.evidence.version, channel: acquired.evidence.channel as ApprovalObservation["actual"]["channel"],
          publication: { notes_asset: input.notesAssetName, latest: input.latest },
          target: { commit: metadata.target_commit, tree: metadata.target_tree },
          preflight: { workflow_path: metadata.workflow_path, workflow_id: metadata.workflow_id, workflow_commit: metadata.workflow_commit,
            run_id: metadata.run_id, attempt: metadata.attempt, artifact_id: metadata.artifact_id, archive_sha256: metadata.archive_sha256,
            requester_id: metadata.requester_id, attempt_actor_id: metadata.attempt_actor_id }, assets };
        return { actual, assets: acquired.assets };
      }
    });
  } catch {
    throw new Error("GitHub release preparation unavailable.");
  }
}

/**
 * Linux-only source-checkout composition. The caller must independently bind
 * the checkout to the intended public repository and provide a trusted runtime;
 * snapshot contents are checked against the reviewed commit and GitHub tree.
 */
export async function prepareGitHubReleasePackageFromCheckout(
  input: Omit<Parameters<typeof prepareGitHubReleasePackage>[0], "sourceSnapshot"> & { sourceRoot: string }
): Promise<ApprovedReleasePackage> {
  try {
    input = { ...input, policy: { ...input.policy }, approval: { ...input.approval } };
    const observation = await readGitHubPublicationApproval(input.approval);
    const reviewed = reviewReleaseManifest(observation, input.policy, new Date());
    const snapshot = await captureReviewedReleaseSource(reviewed, input.sourceRoot);
    const { sourceRoot: _sourceRoot, ...rest } = input;
    return await prepareGitHubReleasePackage({ ...rest, sourceSnapshot: snapshot });
  } catch {
    throw new Error("GitHub release preparation unavailable.");
  }
}
