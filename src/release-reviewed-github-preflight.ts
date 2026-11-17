import { type ReviewedReleaseManifest, reviewedReleaseSelectors } from "./release-approval.js";
import { readGitHubPreflightMetadata } from "./github-approval-reader.js";

type Metadata = Awaited<ReturnType<typeof readGitHubPreflightMetadata>>;

/**
 * Compare reviewed selectors to two authenticated provider reads. The caller
 * owns the trusted policy, token and fetch implementation. This does not prove
 * the reusable workflow, archive bytes, artifact-attempt association, source
 * bytes, token permissions, or publication authority.
 */
export async function readReviewedGitHubPreflight(input: {
  reviewed: ReviewedReleaseManifest; repository: string; repositoryId: string;
  expectedWorkflowPath: string; expectedWorkflowCommit: string; token: string; fetchImpl?: typeof fetch;
}): Promise<Readonly<Metadata>> {
  try {
    input = { ...input };
    const selected = reviewedReleaseSelectors(input.reviewed);
    if (selected.repository !== input.repository || selected.repositoryId !== input.repositoryId ||
        selected.workflowPath !== input.expectedWorkflowPath || selected.workflowCommit !== input.expectedWorkflowCommit) throw new Error();
    const facts = await readGitHubPreflightMetadata({ repository: input.repository, repositoryId: input.repositoryId,
      runId: selected.runId, attempt: selected.attempt, artifactId: selected.artifactId,
      expectedWorkflowPath: input.expectedWorkflowPath, expectedWorkflowCommit: input.expectedWorkflowCommit,
      targetCommit: selected.targetCommit, token: input.token, ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}) });
    if (facts.repository_id !== selected.repositoryId || facts.workflow_id !== selected.workflowId ||
        facts.workflow_path !== selected.workflowPath || facts.workflow_commit !== selected.workflowCommit ||
        facts.run_id !== selected.runId || facts.attempt !== selected.attempt || facts.artifact_id !== selected.artifactId ||
        facts.archive_sha256 !== selected.archiveSha256 || facts.target_commit !== selected.targetCommit ||
        facts.target_tree !== selected.targetTree || facts.requester_id !== selected.requesterId ||
        facts.attempt_actor_id !== selected.attemptActorId ||
        reviewedReleaseSelectors(input.reviewed).manifestSha256 !== selected.manifestSha256) throw new Error();
    return Object.freeze({ ...facts, limitations: Object.freeze({ ...facts.limitations }) });
  } catch {
    throw new Error("Reviewed GitHub preflight unavailable.");
  }
}
