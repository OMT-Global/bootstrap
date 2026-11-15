import YAML from "yaml";

/**
 * Inactive source prototype. The caller, its app JWT, IDs, clock, consumer and
 * fetch implementation are trusted runtime inputs. Do not call with target
 * repository code or untrusted callbacks. No CLI or workflow invokes this.
 */
export class InstallationTokenError extends Error {
  constructor() { super("Scoped GitHub installation token unavailable."); }
}

type Input = {
  appId: number;
  installationId: number;
  repositoryId: number;
  repository: string;
  appJwt: string;
  purpose: "release" | "fleet-pr";
  fetchImpl?: typeof fetch;
};

function id(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}
function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
  return value as Record<string, unknown>;
}

async function readJson(response: Response, expectedUrl: string, status: number): Promise<Record<string, unknown>> {
  if (response.status !== status || response.redirected || response.url !== expectedUrl || !response.body) throw new Error();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 1024 * 1024) throw new Error();
    chunks.push(chunk);
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  const guard = YAML.parseDocument(text, { uniqueKeys: true, schema: "json" });
  if (guard.errors.length) throw new Error();
  return record(JSON.parse(text) as unknown);
}

/**
 * One scoped token, one trusted consumer, one attempt. A failed or ambiguous
 * POST is never retried here. The issued grant and expiration are retained;
 * the module-provided check observes current access to the selected public
 * repository. It does not prove writer exclusion or immutable permissions.
 * The trusted consumer must call that check at each protected boundary.
 */
export async function withScopedInstallationToken(input: Input, consume: (token: string, expiresAt: Date, assertRepositoryAccess: () => Promise<void>) => Promise<void>): Promise<void> {
  try {
    const { appId, installationId, repositoryId, repository, appJwt, purpose } = input;
    const fetcher = input.fetchImpl ?? fetch;
    if (!id(appId) || !id(installationId) || !id(repositoryId) || typeof repository !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(repository) || [".", ".."].includes(repository.split("/")[1]!) ||
        typeof appJwt !== "string" || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(appJwt) || appJwt.length > 8192 ||
        (purpose !== "release" && purpose !== "fleet-pr") || typeof consume !== "function") throw new Error();
    const headers = { Accept: "application/vnd.github+json", Authorization: `Bearer ${appJwt}`, "X-GitHub-Api-Version": "2022-11-28" };
    const appUrl = "https://api.github.com/app";
    const app = await readJson(await fetcher(appUrl, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(10_000) }), appUrl, 200);
    if (app.id !== appId) throw new Error();
    const permissions: Record<string, string> = { contents: "write" };
    if (purpose === "fleet-pr") permissions.pull_requests = "write";
    else { permissions.actions = "read"; permissions.pull_requests = "read"; }
    const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;
    const response = await fetcher(url, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, redirect: "manual",
      signal: AbortSignal.timeout(10_000), body: JSON.stringify({ repository_ids: [repositoryId], permissions }) });
    const result = await readJson(response, url, 201);
    const granted = record(result.permissions);
    const allowed = new Set([...Object.keys(permissions), "metadata"]);
    if (Object.keys(granted).some((key) => !allowed.has(key)) ||
        Object.entries(permissions).some(([key, value]) => granted[key] !== value) ||
        (granted.metadata !== undefined && granted.metadata !== "read") || result.repository_selection !== "selected" ||
        !Array.isArray(result.repositories) || result.repositories.length !== 1 || record(result.repositories[0]).id !== repositoryId ||
        typeof result.token !== "string" || !/^[\x21-\x7e]{1,4096}$/.test(result.token) ||
        typeof result.expires_at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(result.expires_at)) throw new Error();
    const expires = new Date(result.expires_at);
    const expiresMs = expires.getTime();
    const now = Date.now();
    if (!Number.isFinite(expiresMs) || expires.toISOString().replace(".000Z", "Z") !== result.expires_at ||
        expiresMs - now < 30_000 || expiresMs - now > 3_660_000) throw new Error();
    const token = result.token;
    const repositoryUrl = "https://api.github.com/installation/repositories?per_page=100&page=1";
    const assertRepositoryAccess = async (): Promise<void> => {
      try {
        if (Date.now() >= expiresMs) throw new Error();
        const current = await fetcher(repositoryUrl, { method: "GET", headers: { ...headers, Authorization: `Bearer ${token}` },
          redirect: "manual", signal: AbortSignal.timeout(10_000) });
        if (current.headers.get("link") !== null) throw new Error();
        const inventory = await readJson(current, repositoryUrl, 200);
        if (inventory.total_count !== 1 || !Array.isArray(inventory.repositories) || inventory.repositories.length !== 1) throw new Error();
        const selected = record(inventory.repositories[0]);
        if (selected.id !== repositoryId || selected.full_name !== repository || selected.private !== false || Date.now() >= expiresMs) throw new Error();
      } catch {
        throw new InstallationTokenError();
      }
    };
    await assertRepositoryAccess();
    if (await consume(token, new Date(expiresMs), assertRepositoryAccess) !== undefined) throw new Error();
  } catch {
    throw new InstallationTokenError();
  }
}
