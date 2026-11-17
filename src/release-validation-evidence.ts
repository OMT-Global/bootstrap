import { acquireValidationEvidence } from "./release-artifact-acquisition.js";
import { nextReleasePage, releaseJson, releaseObject } from "./github-release-transport.js";

/** Binds bounded evidence bytes to a trusted successful workflow and exact target.
 * The returned check repeats authenticated run/artifact identities, never downloads again. */
export async function verifyGitHubValidation(input: {
  repository: string; repositoryId: string; runId: string; workflowId: string; workflowPath: string; workflowCommit: string; targetCommit: string;
  token: string; pythonPath: string; pythonSha256: string; ghPath: string; ghSha256: string; runtimeDir: string; fetchImpl?: typeof fetch;
}): Promise<() => Promise<void>> {
  input = { ...input };
  const fetcher = input.fetchImpl ?? fetch;
  const base = `https://api.github.com/repos/${input.repository}`;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(input.repository) || input.repository.split("/").some((p) => p === "." || p === "..") ||
      ![input.repositoryId, input.runId, input.workflowId].every((n) => /^[1-9][0-9]{0,15}$/.test(n)) ||
      ![input.workflowCommit, input.targetCommit].every((s) => /^[0-9a-f]{40}$/.test(s))) throw new Error("Invalid validation selection.");
  async function get(route: string) {
    const url = `${base}${route}`;
    const response = await fetcher(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(30000),
      headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${input.token}`, "X-GitHub-Api-Version": "2022-11-28" } });
    return { value: await releaseJson(response, url, 200), link: response.headers.get("link"), url };
  }
  function checkRun(raw: unknown, attempt?: number) {
    const run = releaseObject(raw);
    if (String(run.id) !== input.runId || String(run.workflow_id) !== input.workflowId || run.path !== input.workflowPath ||
        run.head_sha !== input.workflowCommit || run.status !== "completed" || run.conclusion !== "success" || run.event !== "workflow_dispatch" ||
        String(releaseObject(run.repository).id) !== input.repositoryId || String(releaseObject(run.head_repository).id) !== input.repositoryId ||
        typeof run.run_attempt !== "number" || !Number.isSafeInteger(run.run_attempt) || run.run_attempt < 1 ||
        (attempt !== undefined && run.run_attempt !== attempt)) throw new Error("Validation run unavailable.");
    return run.run_attempt;
  }
  async function observe() {
    const attempt = checkRun((await get(`/actions/runs/${input.runId}`)).value);
    checkRun((await get(`/actions/runs/${input.runId}/attempts/${attempt}`)).value, attempt);
    const artifacts: Record<string, unknown>[] = []; const ids = new Set<number>(); let total: number | undefined;
    for (let page = 1; ; page++) {
      if (page > 20) throw new Error();
      const response = await get(`/actions/runs/${input.runId}/artifacts?per_page=100&page=${page}`);
      const inventory = releaseObject(response.value);
      if (!Number.isSafeInteger(inventory.total_count) || (inventory.total_count as number) < 0 || (inventory.total_count as number) > 1000 ||
          (total !== undefined && total !== inventory.total_count) || !Array.isArray(inventory.artifacts) || inventory.artifacts.length > 100) throw new Error();
      total = inventory.total_count as number;
      for (const raw of inventory.artifacts) {
        const a = releaseObject(raw);
        if (typeof a.id !== "number" || !Number.isSafeInteger(a.id) || a.id < 1 || ids.has(a.id)) throw new Error();
        ids.add(a.id); artifacts.push(a);
      }
      const next = nextReleasePage(response.link, response.url, page);
      if (next && inventory.artifacts.length === 0) throw new Error();
      if (!next && inventory.artifacts.length < 100) break;
    }
    if (artifacts.length !== total) throw new Error();
    const matches = artifacts.filter((a) => a.name === "release-evidence-validation");
    if (matches.length !== 1) throw new Error();
    const selected = matches[0]!;
    const artifact = releaseObject((await get(`/actions/artifacts/${selected.id}`)).value);
    const context = releaseObject(artifact.workflow_run);
    if (artifact.id !== selected.id || artifact.name !== selected.name || artifact.expired !== false || selected.expired !== false ||
        typeof artifact.digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(artifact.digest) || selected.digest !== artifact.digest ||
        String(context.id) !== input.runId || String(context.repository_id) !== input.repositoryId ||
        String(context.head_repository_id) !== input.repositoryId || context.head_sha !== input.workflowCommit) throw new Error();
    checkRun((await get(`/actions/runs/${input.runId}`)).value, attempt);
    return { attempt: String(attempt), artifactId: String(artifact.id), archiveSha256: artifact.digest.slice(7) };
  }
  const selected = await observe();
  await acquireValidationEvidence({ ...input, ...selected });
  const recheck = async () => { if (JSON.stringify(await observe()) !== JSON.stringify(selected)) throw new Error("Validation evidence changed."); };
  await recheck();
  return recheck;
}
