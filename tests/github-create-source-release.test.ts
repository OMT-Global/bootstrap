import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApprovedSourceRelease } from "../src/github-create-source-release.js";
import { prepareApprovedReleasePackage, approvedReleasePackageMetadata } from "../src/release-approved-package.js";
import { verifyBootstrapSourcePublishHook, verifySourceReleasePackage } from "../src/release-source-package.js";
import { sourcePublicationFixture } from "./helpers/source-publication-fixture.js";
import { publicationQualificationFixture } from "./helpers/publication-qualification-fixture.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => { vi.useRealTimers(); await Promise.all(cleanup.splice(0).map((f) => f())); });
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const canonical = (v: any): any => Array.isArray(v) ? v.map(canonical) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])])) : v;
async function fixture(latest = true) {
  const source = await sourcePublicationFixture(); cleanup.push(source.dispose);
  const files = source.assets(); await verifySourceReleasePackage({ ...source, assets: files });
  verifyBootstrapSourcePublishHook(source.snapshot, "scripts/release/publish.sh");
  const f = packageFixture();
  const manifest = JSON.parse(Buffer.from(f.observation.manifestBytes).toString());
  manifest.repository.full_name = source.repository; manifest.target = { commit: source.commit, tree: source.tree };
  manifest.publication.latest = latest;
  manifest.assets = files.map((a) => ({ name: a.name, size: a.bytes.length, sha256: hash(a.bytes) })).sort((a,b) => a.name < b.name ? -1 : 1);
  f.observation.manifestBytes = Buffer.from(JSON.stringify(canonical(manifest)) + "\n");
  const { approval_id, expires_at, ...actual } = manifest; f.observation.actual = actual;
  f.observation.reviews[0]!.body = `APPROVE-RELEASE-SHA256 ${hash(f.observation.manifestBytes)}`;
  const pkg = prepareApprovedReleasePackage({ ...f, assets: files }); const m = approvedReleasePackageMetadata(pkg);
  const qualification = publicationQualificationFixture(m);
  const calls: { method: string; url: string; body: any }[] = [];
  let release: any; let assets: any[] = []; let mutate: (url: URL, method: string, value: any) => any = (_u,_m,v) => v;
  const provider = vi.fn(async (request: any, init: any) => {
    const url = new URL(String(request)); const method = init.method; calls.push({ method, url: url.pathname + url.search, body: init.body });
    expect(init.headers.Authorization).toBe("Bearer fabricated"); expect(init.redirect).toBe("manual");
    let value: any; let status = method === "POST" ? 201 : 200;
    if (url.pathname.endsWith("/rulesets/42")) value = { ...qualification.record.projection };
    else if (url.pathname.endsWith(`/git/ref/tags/${m.tag}`)) value = { ref: `refs/tags/${m.tag}`, object: { type: "tag", sha: "9".repeat(40) } };
    else if (url.pathname.includes("/git/tags/")) value = { sha: "9".repeat(40), tag: m.tag, object: { type: "commit", sha: m.commit }, verification: { verified: true, reason: "valid", signature: "fabricated", payload: "fabricated" } };
    else if (url.pathname === `/repos/${m.repository}`) value = { id: 100, full_name: m.repository, private: false, permissions: { push: true } };
    else if (url.pathname.endsWith("/releases") && method === "POST") {
      expect(release).toBeUndefined(); const body = JSON.parse(init.body);
      expect(body).toEqual({ tag_name: m.tag, target_commitish: m.commit, name: m.tag, body: m.notes, draft: true, prerelease: m.prerelease, make_latest: "false" });
      release = { ...body, id: 400, immutable: false, upload_url: `https://uploads.github.com/repos/${m.repository}/releases/400/assets{?name,label}` }; value = release;
    } else if (url.pathname.endsWith("/releases")) value = release ? [release] : [];
    else if (url.pathname.endsWith("/assets") && method === "POST") {
      const name = url.searchParams.get("name"); const original = files.find((f) => f.name === name)!;
      expect(Buffer.from(init.body)).toEqual(original.bytes);
      value = { id: 500 + assets.length, name, size: original.bytes.length, state: "uploaded", digest: `sha256:${hash(original.bytes)}` }; assets.push(value);
    } else if (url.pathname.endsWith("/assets")) value = assets;
    else if (url.pathname.endsWith("/latest")) { value = release; if (!release || release.draft) status = 404; }
    else if (url.pathname.endsWith("/releases/400")) {
      if (method === "PATCH") {
        expect(JSON.parse(init.body)).toEqual({ draft: false, make_latest: String(latest) });
        release.draft = false;
        release.immutable = true;
      }
      value = release;
    } else throw new Error("Unexpected request");
    value = mutate(url, method, structuredClone(value));
    if (value instanceof Response) return value;
    const response = new Response(JSON.stringify(value), { status }); Object.defineProperty(response, "url", { value: String(request) }); return response;
  }) as unknown as typeof fetch;
  const revalidate = vi.fn(async () => {});
  const input = { package: pkg, token: "fabricated", qualification: qualification.qualification, revalidate, fetchImpl: provider };
  return { run: () => createApprovedSourceRelease(input), input, calls, revalidate, m, source, qualification, set: (fn: typeof mutate) => { mutate = fn; }, writes: () => calls.filter((c) => c.method !== "GET") };
}

describe("one approved Bootstrap source publication", () => {
  it("publishes real verified four-asset source bytes through one owned draft and captured identities", async () => {
    const f = await fixture();
    expect(await f.run()).toEqual({ kind: "verified-created", immutable: true, repository: f.m.repository, releaseId: "400", tag: f.m.tag,
      commit: f.m.commit, approvalSha256: f.m.approvalSha256 });
    expect(f.writes().map((c) => c.method)).toEqual(["POST", "POST", "POST", "POST", "POST", "PATCH"]);
    expect(f.revalidate.mock.calls.length).toBeGreaterThan(8);
    expect(f.calls.every((c) => (c.method === "GET" || !c.url.includes("/git/")) && c.method !== "DELETE")).toBe(true);
  });
  it("rejects unsupported no-latest state before any write", async () => { const f = await fixture(false); await expect(f.run()).rejects.toThrow("manually"); expect(f.writes()).toHaveLength(0); });
  it.each(["bypass", "disabled", "wrong tag", "missing creation", "wrong repository"])("rejects %s protection evidence before writes", async (kind) => {
    const f = await fixture(); f.set((url,_method,v) => {
      if (url.pathname.includes("/rulesets/")) {
        if (kind === "missing bypass") delete v.bypass_actors;
        if (kind === "bypass") v.bypass_actors = [{ actor_type: "Integration", actor_id: 10 }];
        if (kind === "disabled") v.enforcement = "evaluate";
        if (kind === "wrong tag") v.conditions.ref_name.include = ["refs/tags/v9.9.9"];
        if (kind === "missing creation") v.rules.shift();
        if (kind === "wrong repository") v.source = "Other/repo";
      } return v;
    }); await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(0);
  });
  it("accepts hidden current bypass only with the exact still-current admin qualification", async () => {
    const f = await fixture(); expect((await f.run()).kind).toBe("verified-created");
    expect(f.calls.some((c) => c.url.includes("/rulesets/42"))).toBe(true);
  });
  it.each(["expired", "future", "too long", "wrong app", "wrong installation", "wrong qualifier", "wrong operation", "wrong run", "wrong attempt", "wrong workflow", "wrong approval", "wrong object", "wrong commit", "wrong repo", "qualified bypass"])("rejects %s qualification before publication writes", async (change) => {
    const f = await fixture(); const record: any = f.qualification.record;
    if (change === "expired") record.expires_at = new Date(Date.now()-1000).toISOString();
    if (change === "future") record.qualified_at = new Date(Date.now()+10000).toISOString();
    if (change === "too long") record.expires_at = new Date(Date.now()+3600000).toISOString();
    const fields: any = { "wrong app": "app_id", "wrong installation": "installation_id", "wrong qualifier": "qualified_by", "wrong operation": "action", "wrong run": "publication_run_id", "wrong attempt": "publication_attempt", "wrong workflow": "publication_workflow_commit", "wrong approval": "approval_sha256", "wrong object": "tag_object", "wrong commit": "commit", "wrong repo": "repository_id" };
    const field = fields[change]; if (field) record[field] = typeof record[field] === "number" ? 99 : field.includes("commit") || field === "tag_object" ? "0".repeat(40) : field === "approval_sha256" ? "0".repeat(64) : "999";
    if (change === "qualified bypass") record.bypass_actors = [{ actor_type: "Integration", actor_id: 10 }];
    f.input.qualification.json = JSON.stringify(record); f.input.qualification.sha256 = hash(Buffer.from(f.input.qualification.json));
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(0);
  });
  it("rejects wrong qualification hash and visible provider timestamp drift", async () => {
    const f = await fixture(); f.input.qualification.sha256 = "0".repeat(64); await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(0);
    const g = await fixture(); g.set((u,_m,v) => { if (u.pathname.includes("rulesets")) v.updated_at = new Date().toISOString(); return v; });
    await expect(g.run()).rejects.toThrow(); expect(g.writes()).toHaveLength(0);
  });
  it.each(["draft", "published"])("does not adopt an existing %s", async (state) => {
    const f = await fixture(); f.set((u,m,v) => u.pathname.endsWith("/releases") && m === "GET" ? [{ id: 401, tag_name: f.m.tag, draft: state === "draft" }] : v);
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(0);
  });
  it.each([1,2,3,4,5,6])("stops without retries, rollback or aliases after uncertain write %s", async (ordinal) => {
    const f = await fixture(); f.set((_u,method,v) => { if (method !== "GET" && f.writes().length === ordinal) throw new Error("uncertain"); return v; });
    await expect(f.run()).rejects.toThrow("No write is retried"); expect(f.writes()).toHaveLength(ordinal);
  });
  it.each(["wrong id", "wrong name", "upload origin", "duplicate asset", "starter", "wrong digest", "draft extra", "recreated published asset"])("stops for %s", async (kind) => {
    const f = await fixture(); f.set((u,method,v) => {
      if (method === "POST" && u.pathname.endsWith("/releases")) {
        if (kind === "wrong id") v.id = "400";
        if (kind === "wrong name") v.name = "unapproved";
        if (kind === "upload origin") v.upload_url = "https://other.invalid/assets{?name,label}";
      }
      if (method === "POST" && u.pathname.endsWith("/assets")) {
        if (kind === "duplicate asset") v.id = 500;
        if (kind === "starter") v.state = "starter";
        if (kind === "wrong digest") v.digest = `sha256:${"0".repeat(64)}`;
      }
      if (method === "GET" && u.pathname.endsWith("/assets")) {
        if (kind === "draft extra") v.push({ ...v[0], id: 900, name: "extra" });
        if (kind === "recreated published asset" && f.writes().length === 6) v[0].id = 900;
      } return v;
    }); await expect(f.run()).rejects.toThrow(); expect(f.writes().length).toBeLessThanOrEqual(6);
  });
  it("captures retained options before any await", async () => {
    const f = await fixture(); f.revalidate.mockImplementation(async () => { f.input.token = "substituted"; f.input.qualification.json = "substituted"; f.input.fetchImpl = async () => { throw new Error("substituted provider"); }; });
    expect((await f.run()).kind).toBe("verified-created");
  });
  it.each([1,3,6,8])("stops at revoked current gate %s without subsequent writes", async (boundary) => {
    const f = await fixture(); let writes = -1; f.revalidate.mockImplementation(async () => { if (f.revalidate.mock.calls.length === boundary) { writes = f.writes().length; throw new Error("current authority revoked"); } });
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(writes);
  });
  it.each(["missing", "changed", "not-executable"] as const)("rejects a %s hook in actual verified source without executing it", async (change) => {
    const source = await sourcePublicationFixture(change); cleanup.push(source.dispose);
    await verifySourceReleasePackage({ ...source, assets: source.assets() });
    expect(() => verifyBootstrapSourcePublishHook(source.snapshot, "scripts/release/publish.sh")).toThrow();
  });
  it("blocks a competing draft discovered before publication", async () => {
    const f = await fixture(); f.set((u,m,v) => u.pathname.endsWith("/releases") && m === "GET" && f.writes().length === 5 ? [...v, { ...v[0], id: 401 }] : v);
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(5);
  });
  it("binds the final published release to the actual create ID", async () => {
    const f = await fixture(); f.set((u,m,v) => { if (u.pathname.endsWith("/releases") && m === "GET" && f.writes().length === 6) v[0].id = 401; return v; });
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(6);
  });
  it.each([undefined, false, "true"])("requires immutable publication in the final inventory (%s)", async (immutable) => {
    const f = await fixture();
    f.set((url, method, value) => {
      if (method === "GET" && url.pathname.endsWith("/releases") && f.writes().length === 6) value[0].immutable = immutable;
      return value;
    });
    await expect(f.run()).rejects.toThrow("reconcile");
    expect(f.writes().map((call) => call.method)).toEqual(["POST", "POST", "POST", "POST", "POST", "PATCH"]);
  });
  it("withholds success when a repeated exact-ID read loses the immutable flag", async () => {
    const f = await fixture();
    let publishedReads = 0;
    f.set((url, method, value) => {
      if (method === "GET" && url.pathname.endsWith("/releases/400") && value.draft === false && ++publishedReads === 2) {
        value.immutable = false;
      }
      return value;
    });
    await expect(f.run()).rejects.toThrow("reconcile");
    expect(publishedReads).toBe(2);
    expect(f.writes()).toHaveLength(6);
  });
  it("stops if the package expires after draft creation", async () => {
    const f = await fixture(); vi.useFakeTimers(); f.set((_u,m,v) => { if (m === "POST") vi.setSystemTime(Date.now() + 3600_000); return v; });
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(1);
  });
  it.each([403, 404, 422, 502])("does not retry a rejected/ambiguous provider write (%s)", async (status) => {
    const f = await fixture(); f.set((_u,m,v) => m === "POST" ? new Response("{}", { status }) : v);
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(1);
  });
  it.each(["second inventory", "asset release read"])("blocks the next write when qualification expires in %s", async (where) => {
    const f = await fixture(); vi.useFakeTimers(); let inventories = 0;
    f.set((u,method,v) => {
      if (method === "GET" && u.pathname.endsWith("/releases")) inventories++;
      if ((where === "second inventory" && method === "GET" && u.pathname.endsWith("/releases") && inventories === 2) ||
          (where === "asset release read" && method === "GET" && u.pathname.endsWith("/releases/400") && f.writes().length === 1)) {
        vi.setSystemTime(new Date(f.qualification.record.expires_at));
      } return v;
    });
    await expect(f.run()).rejects.toThrow(); expect(f.writes()).toHaveLength(where === "second inventory" ? 0 : 1);
  });
  it("does not accept forged hook snapshots or alternate selected hooks", async () => {
    const f = await fixture(); expect(() => verifyBootstrapSourcePublishHook({ ...f.source.snapshot }, "scripts/release/publish.sh")).toThrow();
    expect(() => verifyBootstrapSourcePublishHook(f.source.snapshot, "README.md")).toThrow();
  });
});
