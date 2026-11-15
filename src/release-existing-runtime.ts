import { createPrivateKey, sign } from "node:crypto";
import { realpath } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { withScopedInstallationToken } from "./github-installation-token.js";
import { readGitHubExactTag, readGitHubPublicationApproval } from "./github-approval-reader.js";
import { reviewReleaseManifest, reviewedReleaseSelectors } from "./release-approval.js";
import { type ApprovedReleasePackage, approvedReleasePackageMetadata } from "./release-approved-package.js";
import { prepareGitHubReleasePackageFromCheckout } from "./release-github-package-preparation.js";
import { verifyExistingGitHubRelease } from "./github-existing-release.js";
import { releaseJson, releaseObject } from "./github-release-transport.js";
import { verifyGitHubValidation } from "./release-validation-evidence.js";

/** Refresh approval against the independently acquired package, never expectations
 * derived from the observed release. Trusted callbacks recheck scope and target. */
export async function verifyPreparedGitHubRelease(input: {
  package: ApprovedReleasePackage; policy: Parameters<typeof reviewReleaseManifest>[1];
  approval: Parameters<typeof readGitHubPublicationApproval>[0];
  preflightRunId: string; channel: string; assertScope: () => Promise<void>;
  assertTarget: (tag: string, commit: string) => Promise<void>;
}) {
  input = { ...input, policy: { ...input.policy }, approval: { ...input.approval } };
  const expected = approvedReleasePackageMetadata(input.package);
  const revalidate = async () => {
    if (await input.assertScope() !== undefined) throw new Error();
    const reviewed = reviewReleaseManifest(await readGitHubPublicationApproval(input.approval), input.policy, new Date());
    const selected = reviewedReleaseSelectors(reviewed);
    if (selected.manifestSha256 !== expected.approvalSha256 || selected.runId !== input.preflightRunId || selected.channel !== input.channel ||
        selected.repository !== input.approval.repository || selected.repositoryId !== input.approval.repositoryId) throw new Error();
    if (await input.assertTarget(expected.tag, expected.commit) !== undefined) throw new Error();
    if (await input.assertScope() !== undefined) throw new Error();
  };
  return await verifyExistingGitHubRelease({ package: input.package, token: input.approval.token, revalidate,
    ...(input.approval.fetchImpl ? { fetchImpl: input.approval.fetchImpl } : {}) });
}

const id = z.string().regex(/^[1-9][0-9]{0,15}$/);
const sha = z.string().regex(/^[0-9a-f]{40}$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const workflow = z.object({ id, path: z.string().regex(/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/), commit: sha }).strict();
const configSchema = z.object({
  appId: z.number().int().positive().safe(), installationId: z.number().int().positive().safe(), repositoryId: id,
  runtimeCommit: sha, reviewerId: id, manifestPath: z.string().regex(/^\.github\/release-approvals\/[A-Za-z0-9_-]+\.json$/),
  maxValiditySeconds: z.number().int().min(1).max(86400), publication: workflow,
  preflight: workflow, validation: workflow, latest: z.boolean(),
  pythonPath: z.string().min(1), pythonSha256: digest, ghPath: z.string().min(1), ghSha256: digest,
  maxAssetBytes: z.number().int().positive().safe(), maxArchiveBytes: z.number().int().positive().safe(),
  maxExpandedBytes: z.number().int().positive().safe(), maxMembers: z.number().int().positive().max(10000)
}).strict();

/** Source-only signing entry. The separately provisioned App key and JWT stay in
 * this process; neither is printed or written to disk. */
export function releaseAppJwt(privateKey: string, appId: number, now = Date.now()): string {
  const key = createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 ||
      !Number.isSafeInteger(appId) || appId < 1 || !Number.isFinite(now)) throw new Error("Release App key unavailable.");
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const seconds = Math.floor(now / 1000);
  const content = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ iat: seconds - 60, exp: seconds + 540, iss: String(appId) })}`;
  return `${content}.${sign("RSA-SHA256", Buffer.from(content), key).toString("base64url")}`;
}

/** Guarded Bootstrap workflow consumer. Environment policy, trusted runtime and
 * tool pins require reviewed deployment. The target checkout is read as data. */
export async function runExistingReleaseRuntime(environment: NodeJS.ProcessEnv): Promise<Awaited<ReturnType<typeof verifyExistingGitHubRelease>>> {
  const env = { ...environment };
  try {
    const config = configSchema.parse(JSON.parse(env.RELEASE_RETRY_CONFIG ?? ""));
    if (env.GITHUB_REPOSITORY !== "OMT-Global/bootstrap" || env.GITHUB_REPOSITORY_ID !== config.repositoryId ||
        env.RELEASE_RUNTIME_COMMIT !== config.runtimeCommit || env.GITHUB_SHA !== config.publication.commit ||
        !id.safeParse(env.GITHUB_RUN_ID).success || !id.safeParse(env.GITHUB_RUN_ATTEMPT).success ||
        !id.safeParse(env.PREFLIGHT_RUN_ID).success || !id.safeParse(env.VALIDATION_RUN_ID).success ||
        !id.safeParse(env.APPROVAL_PULL_NUMBER).success || !id.safeParse(env.RELEASE_ISSUE).success ||
        !/^v\d+\.\d+\.\d+(?:-(?:rc|beta)\.\d+)?$/.test(env.TAG ?? "") || !env.RELEASE_APP_PRIVATE_KEY ||
        !env.GITHUB_WORKSPACE || !env.RUNNER_TEMP || env.CREATE_GITHUB_RELEASE !== "true") throw new Error();
    const sourceRoot = await realpath(path.join(env.GITHUB_WORKSPACE, "release-target"));
    if (sourceRoot !== path.join(await realpath(env.GITHUB_WORKSPACE), "release-target")) throw new Error();
    const runtimeDir = await realpath(env.RUNNER_TEMP);
    const key = env.RELEASE_APP_PRIVATE_KEY; delete env.RELEASE_APP_PRIVATE_KEY;
    const appJwt = releaseAppJwt(key, config.appId);
    let result: Awaited<ReturnType<typeof verifyExistingGitHubRelease>> | undefined;
    await withScopedInstallationToken({ appId: config.appId, installationId: config.installationId, repositoryId: Number(config.repositoryId),
      repository: "OMT-Global/bootstrap", appJwt, purpose: "release" }, async (token, _expires, assertScope) => {
      const headers = { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
      async function get(url: string) {
        return releaseObject(await releaseJson(await fetch(url, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(30_000) }), url, 200));
      }
      async function reviewerIdentity() {
        const reviewer = await get("https://api.github.com/users/jmcte");
        if (String(reviewer.id) !== config.reviewerId || String(reviewer.login).toLowerCase() !== "jmcte" || reviewer.type !== "User") throw new Error();
      }
      await reviewerIdentity();
      const policy = { reviewer_id: config.reviewerId, manifest_path: config.manifestPath, max_validity_seconds: config.maxValiditySeconds };
      const approval = { repository: "OMT-Global/bootstrap", repositoryId: config.repositoryId, pullNumber: Number(env.APPROVAL_PULL_NUMBER),
        manifestPath: config.manifestPath, publicationRunId: env.GITHUB_RUN_ID!, publicationAttempt: env.GITHUB_RUN_ATTEMPT!,
        expectedWorkflowId: config.publication.id, expectedWorkflowPath: config.publication.path, expectedWorkflowCommit: config.publication.commit, token };
      const selected = reviewedReleaseSelectors(reviewReleaseManifest(await readGitHubPublicationApproval(approval), policy, new Date()));
      if (selected.workflowId !== config.preflight.id || selected.runId !== env.PREFLIGHT_RUN_ID || selected.channel !== env.CHANNEL) throw new Error();
      const validation = await verifyGitHubValidation({ repository: approval.repository, repositoryId: config.repositoryId,
        runId: env.VALIDATION_RUN_ID!, workflowId: config.validation.id, workflowPath: config.validation.path, workflowCommit: config.validation.commit,
        targetCommit: selected.targetCommit, token, pythonPath: config.pythonPath, pythonSha256: config.pythonSha256,
        ghPath: config.ghPath, ghSha256: config.ghSha256, runtimeDir });
      let targetObject: string | undefined;
      const assertTarget = async (tag: string, commit: string) => {
        await assertScope();
        const observed = await readGitHubExactTag({ repository: approval.repository, repositoryId: approval.repositoryId,
          tag, expectedCommit: commit, requireSigned: true, token });
        if (tag !== env.TAG || (targetObject && observed.objectId !== targetObject)) throw new Error();
        targetObject = observed.objectId;
      };
      const pkg = await prepareGitHubReleasePackageFromCheckout({ policy, approval, sourceRoot,
        preflightWorkflowPath: config.preflight.path, preflightWorkflowCommit: config.preflight.commit,
        tag: env.TAG!, notesAssetName: "RELEASE_NOTES.md", latest: config.latest, requireSignedTag: true,
        pythonPath: config.pythonPath, pythonSha256: config.pythonSha256, ghPath: config.ghPath, ghSha256: config.ghSha256,
        runtimeDir, maxAssetBytes: config.maxAssetBytes, maxArchiveBytes: config.maxArchiveBytes,
        maxExpandedBytes: config.maxExpandedBytes, maxMembers: config.maxMembers, assertTarget });
      result = await verifyPreparedGitHubRelease({ package: pkg, policy, approval, preflightRunId: env.PREFLIGHT_RUN_ID!, channel: env.CHANNEL!,
        assertScope: async () => { await assertScope(); await reviewerIdentity(); await validation(); }, assertTarget });
    });
    if (!result) throw new Error();
    return result;
  } catch { throw new Error("Approved retry failed; no hook, release or alias write was attempted. Reconcile missing or mismatched evidence manually."); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const environment = { ...process.env };
  delete process.env.RELEASE_APP_PRIVATE_KEY;
  runExistingReleaseRuntime(environment).then((result) => process.stdout.write(`${JSON.stringify(result)}\n`), () => {
    process.stderr.write("Approved retry verification failed; publication was not attempted.\n"); process.exitCode = 1;
  });
}
