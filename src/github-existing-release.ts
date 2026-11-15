import { type ApprovedReleasePackage, approvedReleasePackageMetadata } from "./release-approved-package.js";
import { nextReleasePage, releaseJson, releaseObject } from "./github-release-transport.js";

/** Authenticated observations of current state, not creation history or an atomic snapshot.
 * The trusted caller supplies the narrowed App token and rechecks its scope, current
 * approval and signed exact target at every gate. No hook or publication writes exist here.
 */
export async function verifyExistingGitHubRelease(input: {
  package: ApprovedReleasePackage; token: string; revalidate: () => Promise<void>; fetchImpl?: typeof fetch;
}): Promise<Readonly<{ kind: "verified-existing"; repository: string; releaseId: string; tag: string; commit: string; approvalSha256: string }>> {
  try {
    const { package: packageFact, token, revalidate } = input;
    const fetcher = input.fetchImpl ?? fetch;
    const expected = approvedReleasePackageMetadata(packageFact);
    if (!/^[\x21-\x7e]{1,4096}$/.test(token) || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(expected.repository) ||
        expected.repository.split("/").some((part) => part === "." || part === "..")) throw new Error();
    const base = `https://api.github.com/repos/${expected.repository}`;
    const headers = { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
    const get = async (url: string) => {
      const response = await fetcher(url, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(30_000) });
      return { value: await releaseJson(response, url, 200), link: response.headers.get("link") };
    };
    const gate = async () => { approvedReleasePackageMetadata(packageFact); if (await revalidate() !== undefined) throw new Error(); approvedReleasePackageMetadata(packageFact); };
    async function list(path: string): Promise<Record<string, unknown>[]> {
      const items: Record<string, unknown>[] = [];
      const ids = new Set<number>();
      for (let page = 1; page <= 20; page++) {
        const url = `${base}${path}?per_page=100&page=${page}`;
        const response = await get(url);
        if (!Array.isArray(response.value) || response.value.length > 100) throw new Error();
        for (const value of response.value) {
          const item = releaseObject(value);
          if (typeof item.id !== "number" || !Number.isSafeInteger(item.id) || item.id < 1 || ids.has(item.id)) throw new Error();
          ids.add(item.id); items.push(item);
          if (items.length > 1000) throw new Error();
        }
        const next = nextReleasePage(response.link, url, page);
        if (next && response.value.length === 0) throw new Error();
        if (!next && response.value.length < 100) return items;
      }
      throw new Error();
    }
    function release(value: unknown, id: number) {
      const r = releaseObject(value);
      if (r.id !== id || r.tag_name !== expected.tag || r.draft !== false || r.body !== expected.notes || r.prerelease !== expected.prerelease) throw new Error();
      return { id, tag: r.tag_name, draft: r.draft, body: r.body, prerelease: r.prerelease };
    }
    async function snapshot() {
      const repo = releaseObject((await get(base)).value);
      if (typeof repo.id !== "number" || !Number.isSafeInteger(repo.id) || String(repo.id) !== expected.repositoryId ||
          typeof repo.full_name !== "string" || repo.full_name.toLowerCase() !== expected.repository.toLowerCase() ||
          repo.private !== false || releaseObject(repo.permissions).push !== true) throw new Error();
      const releases = await list("/releases");
      for (const r of releases) if (typeof r.tag_name !== "string" || r.tag_name.length < 1 || r.tag_name.length > 1024 ||
          r.tag_name.includes("\0") || typeof r.draft !== "boolean") throw new Error();
      const selected = releases.filter((r) => r.tag_name === expected.tag);
      if (selected.length !== 1) throw new Error();
      const id = selected[0]!.id as number;
      const listed = release(selected[0], id);
      const byId = release((await get(`${base}/releases/${id}`)).value, id);
      if (JSON.stringify(listed) !== JSON.stringify(byId)) throw new Error();
      const assets = (await list(`/releases/${id}/assets`)).map((a) => {
        if (typeof a.name !== "string" || typeof a.size !== "number" || !Number.isSafeInteger(a.size) || a.size < 0 ||
            a.state !== "uploaded" || typeof a.digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(a.digest)) throw new Error();
        return { id: a.id, name: a.name, size: a.size, sha256: a.digest.slice(7) };
      }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
      if (assets.length !== expected.assets.length || assets.some((a, i) => a.name !== expected.assets[i]!.name ||
          a.size !== expected.assets[i]!.size || a.sha256 !== expected.assets[i]!.sha256)) throw new Error();
      const latest = releaseObject((await get(`${base}/releases/latest`)).value);
      if (typeof latest.id !== "number" || !Number.isSafeInteger(latest.id) || latest.id < 1 ||
          !releases.some((r) => r.id === latest.id && r.draft === false && r.prerelease === false) ||
          (latest.id === id) !== expected.latest) throw new Error();
      // Re-read by captured ID, never by a possibly recreated tag alone.
      if (JSON.stringify(release((await get(`${base}/releases/${id}`)).value, id)) !== JSON.stringify(byId)) throw new Error();
      return { release: byId, assets, latest: latest.id };
    }
    await gate();
    const first = await snapshot();
    await gate();
    const second = await snapshot();
    await gate();
    if (JSON.stringify(first) !== JSON.stringify(second)) throw new Error();
    return Object.freeze({ kind: "verified-existing", repository: expected.repository, releaseId: String(second.release.id),
      tag: expected.tag, commit: expected.commit, approvalSha256: expected.approvalSha256 });
  } catch {
    throw new Error("Existing release verification unavailable; no publication was attempted.");
  }
}
