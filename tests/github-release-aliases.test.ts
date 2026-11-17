import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { promoteApprovedReleaseAliases } from "../src/github-release-aliases.js";
import { prepareApprovedReleasePackage, approvedReleasePackageMetadata } from "../src/release-approved-package.js";
import { verifySourceReleasePackage } from "../src/release-source-package.js";
import { sourcePublicationFixture } from "./helpers/source-publication-fixture.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";
const hash = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const canonical = (v: any): any => Array.isArray(v) ? v.map(canonical) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])])) : v;
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { vi.useRealTimers(); await Promise.all(cleanups.splice(0).map((f) => f())); });
async function fixture(channel = "stable") {
  const source = await sourcePublicationFixture(undefined, channel === "stable" ? "v1.2.3" : `v1.2.3-${channel}.1`, channel); cleanups.push(source.dispose); const assets = source.assets();
  await verifySourceReleasePackage({ ...source, assets });
  const f = packageFixture(); const manifest = JSON.parse(Buffer.from(f.observation.manifestBytes).toString());
  manifest.tag=source.tag;manifest.version=source.tag;manifest.channel=channel;manifest.publication.latest=channel==="stable";
  manifest.repository.full_name = source.repository; manifest.target = { commit: source.commit, tree: source.tree };
  manifest.assets = assets.map((a) => ({ name: a.name, size: a.bytes.length, sha256: hash(a.bytes) })).sort((a,b) => a.name < b.name ? -1 : 1);
  f.observation.manifestBytes = Buffer.from(JSON.stringify(canonical(manifest)) + "\n"); const { approval_id, expires_at, ...actual } = manifest;
  f.observation.actual = actual; f.observation.reviews[0]!.body = `APPROVE-RELEASE-SHA256 ${hash(f.observation.manifestBytes)}`;
  const pkg = prepareApprovedReleasePackage({ ...f, assets }); const m = approvedReleasePackageMetadata(pkg); const old = "b".repeat(40);
  const now = Math.floor(Date.now()/1000)*1000;
  const record: any = { schema_version: 1, action: "promote_release_aliases", authorized_by: "111", authorized_at: new Date(now-1000).toISOString(), expires_at: new Date(now+300000).toISOString(),
    repository: m.repository, repository_id: m.repositoryId, app_id: 10, installation_id: 20, tag: m.tag, commit: m.commit, tag_object: "9".repeat(40),
    approval_sha256: m.approvalSha256, release_id: "400", operation_run_id: "130", operation_attempt: "3", operation_workflow_commit: "c".repeat(40),
    updates: [{ name: "refs/tags/v1", beforeOid: old, afterOid: m.commit }, { name: "refs/tags/v1.2", beforeOid: old, afterOid: m.commit }] };
  const refs = new Map<string, any>([[m.tag, { __typename: "Tag", oid: "9".repeat(40), target: { __typename: "Commit", oid: m.commit } }],
    ["v1.2.2", { __typename: "Commit", oid: old }], ["v1", { __typename: "Commit", oid: old }], ["v1.2", { __typename: "Commit", oid: old }]]);
  let release: any = { id: 400, tag_name: m.tag, draft: false, body: m.notes, prerelease: false, name: m.tag };
  const extraReleases: any[] = [];
  const calls: { kind: string; url: string; body: any }[] = [];
  let mutate: (kind: string, url: URL, value: any, body: any) => any = (_k,_u,v) => v;
  const provider = vi.fn(async (request: any, init: any) => {
    const url = new URL(String(request)); const body = init.body ? JSON.parse(init.body) : undefined;
    const kind = url.pathname === "/graphql" ? body.query.startsWith("mutation") ? "mutation" : "query" : "get";
    calls.push({ kind, url: url.pathname + url.search, body });
    expect(init.headers.Authorization).toBe("Bearer fabricated"); expect(init.redirect).toBe("manual");
    let value: any;
    if (kind === "query") {
      expect(body.variables.id).toBe("R_100"); const start = body.variables.cursor ? Number(body.variables.cursor) : 0;
      const all = [...refs].sort(([a],[b]) => a < b ? -1 : 1); const nodes = all.slice(start,start+100).map(([name,target]) => ({ name, prefix: "refs/tags/", target }));
      value = { data: { node: { id: "R_100", nameWithOwner: m.repository, isPrivate: false, refs: { totalCount: all.length, nodes,
        pageInfo: { hasNextPage: start+100<all.length, endCursor: String(start+nodes.length) } } } } };
    } else if (kind === "mutation") {
      const selected = body.variables.input; expect(selected.repositoryId).toBe("R_100");
      // Fabricated provider models documented all-or-none expected-before behavior.
      const conflict = selected.refUpdates.some((u: any) => (refs.get(u.name.slice(10))?.oid ?? "0".repeat(40)) !== u.beforeOid);
      if (conflict) value = { errors: [{ message: "conflict" }] };
      else { for (const u of selected.refUpdates) { expect(u.force).toBe(true); expect(u.afterOid).toBe(m.commit); refs.set(u.name.slice(10), { __typename: "Commit", oid: u.afterOid }); }
        value = { data: { updateRefs: { clientMutationId: selected.clientMutationId } } }; }
    } else if (url.pathname === `/repos/${m.repository}`) value = { id: 100, node_id: "R_100", full_name: m.repository, private: false, permissions: { push: true } };
    else if (url.pathname.endsWith(`/git/ref/tags/${m.tag}`)) value = { ref: `refs/tags/${m.tag}`, object: { type: "tag", sha: "9".repeat(40) } };
    else if (url.pathname.includes("/git/tags/")) value = { sha: "9".repeat(40), tag: m.tag, object: { type: "commit", sha: m.commit }, verification: { verified: true, reason: "valid", signature: "fabricated", payload: "fabricated" } };
    else if (url.pathname.endsWith("/releases")) value = [release, ...extraReleases];
    else if (url.pathname.endsWith("/releases/400") || url.pathname.endsWith("/releases/latest")) value = release;
    else if (url.pathname.endsWith("/releases/400/assets")) value = m.assets.map((a,i) => ({ id: 500+i, name: a.name, size: a.size, state: "uploaded", digest: `sha256:${a.sha256}` }));
    else throw new Error("Unexpected request");
    value = mutate(kind,url,structuredClone(value),body); if (value instanceof Response) return value;
    const response = new Response(JSON.stringify(value), { status: 200 }); Object.defineProperty(response,"url",{ value: String(request) }); return response;
  }) as unknown as typeof fetch;
  const authorization = { json: "", sha256: "", authorizerId: "111", appId: 10, installationId: 20, operationRunId: "130", operationAttempt: "3", operationWorkflowCommit: "c".repeat(40) };
  const refresh = () => { authorization.json = JSON.stringify(record); authorization.sha256 = hash(authorization.json); }; refresh();
  const revalidate = vi.fn(async () => {}); const input = { package: pkg, token: "fabricated", authorization, major: true, minor: true, revalidate, fetchImpl: provider };
  return { input, record, refresh, refs, m, old, calls, extraReleases, revalidate, mutations: () => calls.filter(c=>c.kind==="mutation"),
    set: (fn: typeof mutate) => { mutate=fn; }, run: () => promoteApprovedReleaseAliases(input), changeRelease: (r: any) => { release=r; } };
}

describe("approved atomic compatibility alias promotion", () => {
  it("promotes only two derived aliases in one expected-before transaction after fresh source-package release checks", async () => {
    const f=await fixture(); const result=await f.run(); expect(result).toMatchObject({kind:"promoted-aliases",releaseId:"400",changed:["refs/tags/v1","refs/tags/v1.2"]});
    expect(f.mutations()).toHaveLength(1); expect(f.refs.get("v1").oid).toBe(f.m.commit); expect(f.refs.get(f.m.tag).oid).toBe("9".repeat(40));
    expect(f.calls.every(c=>c.kind!=="mutation"||c.url==="/graphql")).toBe(true);
  });
  it("permits maintenance minor-only promotion without touching a newer major alias", async () => {
    const f=await fixture();const newer="d".repeat(40);f.refs.set("v1.3.0",{__typename:"Commit",oid:newer});f.refs.set("v1",{__typename:"Commit",oid:newer});
    f.record.updates=f.record.updates.filter((u:any)=>u.name==="refs/tags/v1.2");f.refresh();
    expect((await f.run()).changed).toEqual(["refs/tags/v1.2"]);expect(f.refs.get("v1").oid).toBe(newer);
  });
  it.each(["rc","beta"])("rejects an approved %s package without any alias provider mutation",async(channel)=>{const f=await fixture(channel);await expect(f.run()).rejects.toThrow();expect(f.calls).toHaveLength(0);});
  it("keeps the other alias unchanged when expected-before conflicts atomically",async()=>{
    const f=await fixture();let raced=false;f.revalidate.mockImplementation(async()=>{if(!raced&&f.calls.filter(c=>c.kind==="query").length===2){raced=true;f.refs.set("v1",{__typename:"Commit",oid:"d".repeat(40)});}});
    await expect(f.run()).rejects.toThrow();expect(f.mutations()).toHaveLength(1);expect(f.refs.get("v1").oid).toBe("d".repeat(40));expect(f.refs.get("v1.2").oid).toBe(f.old);
  });
  it("does not let a newer prerelease block stable eligibility", async()=>{const f=await fixture();f.refs.set("v1.99.0-rc.1",{__typename:"Commit",oid:"d".repeat(40)});expect((await f.run()).kind).toBe("promoted-aliases");});
  it.each(["v1.2.10","v1.2.90071992547409930000"])("blocks when newer patch %s exists, without numeric precision loss",async(tag)=>{const f=await fixture();f.refs.set(tag,{__typename:"Commit",oid:"d".repeat(40)});await expect(f.run()).rejects.toThrow();expect(f.mutations()).toHaveLength(0);});
  it("rejects an unknown prior baseline after newer historical tags were removed",async()=>{const f=await fixture();f.refs.set("v1",{__typename:"Commit",oid:"d".repeat(40)});f.record.updates[0].beforeOid="d".repeat(40);f.refresh();await expect(f.run()).rejects.toThrow();expect(f.mutations()).toHaveLength(0);});
  it("supports an annotated existing alias while retaining its raw expected-before OID",async()=>{const f=await fixture();f.refs.set("v1",{__typename:"Tag",oid:"e".repeat(40),target:{__typename:"Commit",oid:f.old}});f.record.updates[0].beforeOid="e".repeat(40);f.refresh();expect((await f.run()).kind).toBe("promoted-aliases");expect(f.mutations()[0]!.body.variables.input.refUpdates[0].beforeOid).toBe("e".repeat(40));});
  it("verifies already-correct aliases without a mutation or a promotion claim",async()=>{const f=await fixture();for(const name of ["v1","v1.2"])f.refs.set(name,{__typename:"Commit",oid:f.m.commit});for(const u of f.record.updates)u.beforeOid=f.m.commit;f.refresh();expect((await f.run()).kind).toBe("verified-unchanged-aliases");expect(f.mutations()).toHaveLength(0);});
  it("requires explicitly authorized absence before creating aliases",async()=>{const f=await fixture();f.refs.delete("v1");f.refs.delete("v1.2");for(const u of f.record.updates)u.beforeOid="0".repeat(40);f.refresh();expect((await f.run()).kind).toBe("promoted-aliases");});
  it("reads complete cursor pages and rejects a truncated terminal inventory",async()=>{const f=await fixture();for(let i=0;i<101;i++)f.refs.set(`misc-${i}`,{__typename:"Commit",oid:f.old});expect((await f.run()).kind).toBe("promoted-aliases");expect(f.calls.some(c=>c.kind==="query"&&c.body.variables.cursor==="100")).toBe(true);
    const g=await fixture();g.set((kind,_u,v)=>{if(kind==="query")v.data.node.refs.totalCount++;return v;});await expect(g.run()).rejects.toThrow();expect(g.mutations()).toHaveLength(0);});
  it.each(["duplicate","wrong identity","wrong prefix","unknown baseline type","wrong family"])("blocks %s observations",async(kind)=>{const f=await fixture();
    if(kind==="unknown baseline type")f.refs.set("v1",{__typename:"Blob",oid:f.old});
    if(kind==="wrong family"){f.refs.delete("v1.2.2");f.refs.set("v2.0.0",{__typename:"Commit",oid:f.old});}
    f.set((op,_u,v)=>{if(op==="query"){if(kind==="duplicate")v.data.node.refs.nodes.push(v.data.node.refs.nodes[0]);if(kind==="wrong identity")v.data.node.id="Other";if(kind==="wrong prefix")v.data.node.refs.nodes[0].prefix="refs/heads/";}return v;});await expect(f.run()).rejects.toThrow();expect(f.mutations()).toHaveLength(0);});
  it.each(["expired","wrong run","wrong authorizer","wrong release","exact tag","zero target","extra ref"])("rejects %s authorization",async(kind)=>{const f=await fixture();if(kind==="expired")f.record.expires_at=new Date(Date.now()-10000).toISOString();if(kind==="wrong run")f.record.operation_run_id="999";if(kind==="wrong authorizer")f.record.authorized_by="999";if(kind==="wrong release")f.record.release_id="999";if(kind==="exact tag")f.record.updates[0].name=`refs/tags/${f.m.tag}`;if(kind==="zero target")f.record.updates[0].afterOid="0".repeat(40);if(kind==="extra ref")f.record.updates.push({...f.record.updates[0],name:"refs/tags/v8"});f.refresh();await expect(f.run()).rejects.toThrow();expect(f.mutations()).toHaveLength(0);});
  it("captures retained authority/provider values before awaits",async()=>{const f=await fixture();f.revalidate.mockImplementation(async()=>{f.input.authorization.json="tampered";f.input.fetchImpl=async()=>{throw new Error("tampered");};f.input.major=false;});expect((await f.run()).kind).toBe("promoted-aliases");});
  it("blocks expiry inside the final inventory before the mutation",async()=>{const f=await fixture();vi.useFakeTimers();let queries=0;f.set((kind,_u,v)=>{if(kind==="query"&&++queries===2)vi.setSystemTime(new Date(f.record.expires_at));return v;});await expect(f.run()).rejects.toThrow();expect(f.mutations()).toHaveLength(0);});
  it.each(["network","errors","wrong echo","after mismatch"])("stops once after %s, without rollback or retry",async(kind)=>{const f=await fixture();f.set((op,_u,v)=>{if(op==="mutation"){if(kind==="network")throw new Error("uncertain");if(kind==="errors")return {errors:[{message:"denied"}]};if(kind==="wrong echo")v.data.updateRefs.clientMutationId="wrong";if(kind==="after mismatch")f.refs.set("v1",{__typename:"Commit",oid:f.old});}return v;});await expect(f.run()).rejects.toThrow("No retry");expect(f.mutations()).toHaveLength(1);});
  it("rejects stale release identity and caller-fabricated package diagnostics",async()=>{const f=await fixture();f.changeRelease({id:401,tag_name:f.m.tag,draft:false,prerelease:false,body:f.m.notes});await expect(f.run()).rejects.toThrow();expect(f.mutations()).toHaveLength(0);const g=await fixture();g.input.package={} as any;await expect(g.run()).rejects.toThrow();expect(g.mutations()).toHaveLength(0);});
  it("uses the highest surviving same-commit family baseline without blocking a safe advance", async () => {
    const f = await fixture();
    f.refs.set("v1.2.1", { __typename: "Commit", oid: f.old });
    expect((await f.run()).kind).toBe("promoted-aliases");
    expect(f.mutations()).toHaveLength(1);
  });
  it.each(["missing relevant tag", "duplicate release identity", "release continuation error"])("blocks %s before mutation", async (problem) => {
    const f = await fixture();
    if (problem === "missing relevant tag") f.extraReleases.push({ id: 401, tag_name: "v1.3.0", draft: false, prerelease: false });
    if (problem === "duplicate release identity") f.extraReleases.push({ id: 400, tag_name: "v2.0.0", draft: false, prerelease: false });
    if (problem === "release continuation error") {
      f.set((kind, url, value) => {
        if (kind !== "get" || !url.pathname.endsWith("/releases")) return value;
        if (url.searchParams.get("page") === "2") return new Response("failed", { status: 500 });
        return [...value, ...Array.from({ length: 99 }, (_, i) => ({ id: 600+i, tag_name: `v2.0.${i}`, draft: false, prerelease: false }))];
      });
    }
    await expect(f.run()).rejects.toThrow();
    expect(f.mutations()).toHaveLength(0);
  });
  it("does not make unrelated missing tags or unpublished draft releases a global gate", async () => {
    const f = await fixture();
    f.extraReleases.push({ id: 401, tag_name: "v2.0.0", draft: false, prerelease: false });
    f.extraReleases.push({ id: 402, tag_name: "v1.99.0", draft: true, prerelease: false });
    expect((await f.run()).kind).toBe("promoted-aliases");
  });
  it("establishes terminal completion after a full release page", async () => {
    const f = await fixture();
    f.set((kind, url, value) => {
      if (kind !== "get" || !url.pathname.endsWith("/releases")) return value;
      if (url.searchParams.get("page") === "2") return [];
      return [...value, ...Array.from({ length: 99 }, (_, i) => ({ id: 600+i, tag_name: `v2.0.${i}`, draft: false, prerelease: false }))];
    });
    expect((await f.run()).kind).toBe("promoted-aliases");
    expect(f.calls.some((call) => call.url.endsWith("/releases?per_page=100&page=2"))).toBe(true);
  });

  it.each([240, 241, 246, 1024, 1025])("blocks a newer stable tag of %i characters before alias mutation", async (length) => {
    const f = await fixture();
    f.refs.set(`v1.2.${"9".repeat(length - 5)}`, { __typename: "Commit", oid: "d".repeat(40) });
    await expect(f.run()).rejects.toThrow();
    expect(f.mutations()).toHaveLength(0);
  });
  it.each(["v1.2." + "9".repeat(241) + "-rc.1", "v1.2.0" + "9".repeat(241), "v1.2." + "9".repeat(241) + "x"])("does not treat noncanonical or prerelease numeric text as a stable candidate: %s", async (tag) => {
    const f = await fixture();
    f.refs.set(tag, { __typename: "Commit", oid: "d".repeat(40) });
    expect((await f.run()).kind).toBe("promoted-aliases");
    expect(f.mutations()).toHaveLength(1);
  });

});
