import { describe, expect, it, vi } from "vitest";
import { verifyExistingGitHubRelease } from "../src/github-existing-release.js";
import { approvedReleasePackageMetadata, prepareApprovedReleasePackage } from "../src/release-approved-package.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

function fixture() {
  const source = packageFixture();
  const pkg = prepareApprovedReleasePackage(source);
  const m = approvedReleasePackageMetadata(pkg);
  const calls: string[] = [];
  const release = { id: 400, tag_name: m.tag, body: m.notes, draft: false, prerelease: false,
    author: { id: 999 }, created_at: "2020-01-01T00:00:00Z" };
  const assets = m.assets.map((a, i) => ({ id: 500 + i, name: a.name, size: a.size, state: "uploaded", digest: `sha256:${a.sha256}` }));
  let mutate = (_path: string, _value: unknown, _count: number): unknown => undefined;
  const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    expect(init?.method).toBe("GET");
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer fabricated-token");
    const path = String(url).replace("https://api.github.com/repos/Example/repo", "");
    calls.push(path);
    let data: unknown;
    if (path === "") data = { id: 100, full_name: "Example/repo", private: false, permissions: { push: true } };
    else if (path === "/releases?per_page=100&page=1") data = [release];
    else if (path === "/releases/400" || path === "/releases/latest") data = release;
    else if (path === "/releases/400/assets?per_page=100&page=1") data = assets;
    else throw new Error("Unexpected request");
    data = structuredClone(data);
    const replacement = mutate(path, data, calls.filter((p) => p === path).length);
    if (replacement instanceof Response) return replacement;
    const response = new Response(JSON.stringify(replacement ?? data));
    Object.defineProperty(response, "url", { value: String(url) });
    return response;
  }) as unknown as typeof fetch;
  const revalidate = vi.fn(async () => {});
  return { source, pkg, m, calls, revalidate, setMutate(value: typeof mutate) { mutate = value; },
    run: () => verifyExistingGitHubRelease({ package: pkg, token: "fabricated-token", revalidate, fetchImpl }) };
}
describe("authenticated current exact-release retry", () => {
  it("accepts an exact release by another historical publisher with only GET observations", async () => {
    const f = fixture();
    expect(await f.run()).toEqual({ kind: "verified-existing", repository: "Example/repo", releaseId: "400",
      tag: "v1.2.3", commit: "a".repeat(40), approvalSha256: f.m.approvalSha256 });
    expect(f.revalidate).toHaveBeenCalledTimes(3);
    expect(f.calls.filter((p) => p === "/releases/400")).toHaveLength(4);
  });
  it.each([
    ["missing release", (p: string, v: any) => p.startsWith("/releases?") ? [] : v],
    ["draft", (_p: string, v: any) => { if (Array.isArray(v) && v[0]?.tag_name) v[0].draft = true; return v; }],
    ["duplicate tag", (p: string, v: any) => p.startsWith("/releases?") ? [...v, { ...v[0], id: 401 }] : v],
    ["changed notes", (p: string, v: any) => { if (p === "/releases/400") v.body += "changed"; return v; }],
    ["changed prerelease", (p: string, v: any) => { if (p === "/releases/400") v.prerelease = true; return v; }],
    ["renamed tag", (p: string, v: any) => { if (p === "/releases/400") v.tag_name = "v1.2.4"; return v; }],
    ["changed assets", (p: string, v: any) => { if (p.includes("/assets?")) v[0].digest = `sha256:${"0".repeat(64)}`; return v; }],
    ["missing digest", (p: string, v: any) => { if (p.includes("/assets?")) delete v[0].digest; return v; }],
    ["extra assets", (p: string, v: any) => p.includes("/assets?") ? [...v, { ...v[0], id: 800, name: "extra" }] : v],
    ["duplicate asset IDs", (p: string, v: any) => { if (p.includes("/assets?")) v[1].id = v[0].id; return v; }],
    ["wrong latest", (p: string, v: any) => p === "/releases/latest" ? { id: 401 } : v],
    ["wrong repository", (p: string, v: any) => { if (p === "") v.id = 101; return v; }],
    ["no draft visibility", (p: string, v: any) => { if (p === "") v.permissions.push = false; return v; }],
    ["unauthenticated response", () => new Response("denied", { status: 401 })],
    ["ambiguous provider failure", () => { throw new Error("network unavailable"); }],
    ["deleted release", (p: string, v: any) => p === "/releases/400" ? new Response("missing", { status: 404 }) : v],
    ["recreated identity", (p: string, v: any, n: number) => { if (p.startsWith("/releases?") && n === 2) v[0].id = 402; return v; }],
    ["recreated asset", (p: string, v: any, n: number) => { if (p.includes("/assets?") && n === 2) v[0].id = 900; return v; }]
  ] as const)("fails closed for %s without any mutation request", async (_name, mutate) => {
    const f = fixture(); f.setMutate(mutate); await expect(f.run()).rejects.toThrow("no publication was attempted");
  });
  it("revalidates current approval, target and token scope before returning", async () => {
    const f = fixture();
    f.revalidate.mockImplementation(async () => { if (f.revalidate.mock.calls.length === 3) throw new Error("revoked current gate"); });
    await expect(f.run()).rejects.toThrow();
  });
  it("rejects package expiry during observations", async () => {
    const f = fixture(); vi.useFakeTimers();
    try {
      f.setMutate((p, v) => { if (p === "/releases/latest") vi.setSystemTime(new Date(JSON.parse(Buffer.from(f.source.observation.manifestBytes).toString()).expires_at)); return v; });
      await expect(f.run()).rejects.toThrow();
    } finally { vi.useRealTimers(); }
  });
  it("does not treat a truncated full page as complete", async () => {
    const f = fixture();
    f.setMutate((p, v: any) => p.startsWith("/releases?") ? Array.from({ length: 100 }, (_, i) => ({ ...v[0], id: 400 + i, tag_name: i ? `v0.0.${i}` : v[0].tag_name })) : v);
    await expect(f.run()).rejects.toThrow();
    expect(f.calls).toContain("/releases?per_page=100&page=2");
  });
});
