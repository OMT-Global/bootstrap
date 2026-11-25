import { type ApprovedReleasePackage, approvedReleasePackageMetadata, copyApprovedReleaseAsset } from "./release-approved-package.js";
import { verifyExistingGitHubRelease } from "./github-existing-release.js";
import { publicationProtection, type PublicationQualification } from "./release-publication-protection.js";
import { nextReleasePage, releaseJson, releaseObject } from "./github-release-transport.js";

/** One attempt, no recovery mutations. The caller supplies a prepared source
 * package and rechecks current approval, validation, scoped token and signed tag.
 * A partial/uncertain write always requires human reconciliation. */
export async function createApprovedSourceRelease(input: {
  package: ApprovedReleasePackage; token: string; qualification: PublicationQualification;
  revalidate: () => Promise<void>; fetchImpl?: typeof fetch;
}) {
  try {
    const { package: packageFact, token, revalidate } = input;
    const fetcher = input.fetchImpl ?? fetch;
    const expected = approvedReleasePackageMetadata(packageFact);
    if (expected.repository !== "OMT-Global/bootstrap" ||
        !/^[\x21-\x7e]{1,4096}$/.test(token)) throw new Error();
    const protection = publicationProtection({ qualification: input.qualification, package: packageFact, token, fetchImpl: fetcher });
    const base = `https://api.github.com/repos/${expected.repository}`;
    const headers = { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
    async function request(url: string, method = "GET", body?: string | Uint8Array, contentType = "application/json") {
      const options = { method, headers: { ...headers, "Content-Type": contentType }, redirect: "manual",
        signal: AbortSignal.timeout(30_000), ...(body === undefined ? {} : { body: typeof body === "string" ? body : Buffer.from(body) }) } as const;
      // No awaited reads or body preparation may occur after this final validity check.
      if (method !== "GET") protection.assertValid();
      const response = await fetcher(url, options);
      return { value: await releaseJson(response, url, method === "POST" ? 201 : 200), link: response.headers.get("link") };
    }
    async function list(suffix: string) {
      const result: Record<string, unknown>[] = []; const ids = new Set<number>();
      for (let page = 1; page <= 20; page++) {
        const url = `${base}${suffix}?per_page=100&page=${page}`; const r = await request(url);
        if (!Array.isArray(r.value) || r.value.length > 100) throw new Error();
        for (const value of r.value) {
          const item = releaseObject(value);
          if (typeof item.id !== "number" || !Number.isSafeInteger(item.id) || item.id < 1 || ids.has(item.id)) throw new Error();
          ids.add(item.id); result.push(item); if (result.length > 1000) throw new Error();
        }
        const next = nextReleasePage(r.link, url, page);
        if (next && !r.value.length) throw new Error();
        if (!next && r.value.length < 100) return result;
      }
      throw new Error();
    }
    async function gate() {
      approvedReleasePackageMetadata(packageFact);
      if (await revalidate() !== undefined) throw new Error();
      const repo = releaseObject((await request(base)).value);
      if (String(repo.id) !== expected.repositoryId || repo.full_name !== expected.repository || repo.private !== false ||
          releaseObject(repo.permissions).push !== true) throw new Error();
      await protection.assertCurrent();
      approvedReleasePackageMetadata(packageFact);
    }
    function release(value: unknown, releaseId: number, draft: boolean) {
      const r = releaseObject(value);
      if (r.id !== releaseId || r.tag_name !== expected.tag || r.name !== expected.tag || r.draft !== draft ||
          r.body !== expected.notes || r.prerelease !== expected.prerelease) throw new Error();
      return r;
    }
    async function inventory() {
      const releases = await list("/releases");
      for (const r of releases) if (typeof r.tag_name !== "string" || !r.tag_name || r.tag_name.includes("\0") ||
          r.tag_name.length > 1024 || typeof r.draft !== "boolean") throw new Error();
      return releases;
    }
    function asset(value: unknown, item: typeof expected.assets[number]) {
      const a = releaseObject(value);
      if (typeof a.id !== "number" || !Number.isSafeInteger(a.id) || a.id < 1 || a.name !== item.name ||
          a.size !== item.size || a.state !== "uploaded" || a.digest !== `sha256:${item.sha256}`) throw new Error();
      return a.id;
    }
    await gate();
    const initial = await inventory();
    if (initial.some((r) => r.tag_name === expected.tag)) throw new Error();
    if (!expected.latest) {
      const latest = releaseObject((await request(`${base}/releases/latest`)).value);
      if (!initial.some((r) => r.id === latest.id && r.draft === false && r.prerelease === false)) throw new Error();
    }
    await gate();
    if ((await inventory()).some((r) => r.tag_name === expected.tag)) throw new Error();
    const created = releaseObject((await request(`${base}/releases`, "POST", JSON.stringify({ tag_name: expected.tag,
      target_commitish: expected.commit, name: expected.tag, body: expected.notes, draft: true, prerelease: expected.prerelease, make_latest: "false" }))).value);
    if (typeof created.id !== "number" || !Number.isSafeInteger(created.id) || created.id < 1) throw new Error();
    const releaseId = created.id; release(created, releaseId, true);
    const upload = `https://uploads.github.com/repos/${expected.repository}/releases/${releaseId}/assets`;
    if (created.upload_url !== `${upload}{?name,label}`) throw new Error();
    const assetIds: number[] = [];
    for (const item of expected.assets) {
      await gate();
      release((await request(`${base}/releases/${releaseId}`)).value, releaseId, true);
      const bytes = copyApprovedReleaseAsset(packageFact, item.name);
      const uploaded = asset((await request(`${upload}?name=${encodeURIComponent(item.name)}`, "POST", bytes, "application/octet-stream")).value, item);
      if (assetIds.includes(uploaded)) throw new Error(); assetIds.push(uploaded);
    }
    await gate();
    const matching = (await inventory()).filter((r) => r.tag_name === expected.tag);
    if (matching.length !== 1) throw new Error(); release(matching[0], releaseId, true);
    release((await request(`${base}/releases/${releaseId}`)).value, releaseId, true);
    const assets = (await list(`/releases/${releaseId}/assets`)).sort((a, b) => String(a.name) < String(b.name) ? -1 : 1);
    if (assets.length !== expected.assets.length || assets.some((a, i) => asset(a, expected.assets[i]!) !== assetIds[i])) throw new Error();
    await gate();
    release((await request(`${base}/releases/${releaseId}`, "PATCH", JSON.stringify({ draft: false, make_latest: String(expected.latest) }))).value, releaseId, false);
    const verified = await verifyExistingGitHubRelease({ package: packageFact, token, revalidate: gate, fetchImpl: fetcher, created: { releaseId, assetIds } });
    return Object.freeze({ ...verified, kind: "verified-created" as const, immutable: true as const });
  } catch {
    throw new Error("Source publication stopped; reconcile any draft, uploaded assets or published release manually. No write is retried or rolled back.");
  }
}
