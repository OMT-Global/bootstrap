import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";

import { discoverPublicManifests, PUBLIC_DISCOVERY_LIMITS, readDiscoveredManifest } from "../src/upgrade-discovery.js";

type JsonObject = Record<string, unknown>;
type Reply = { value: unknown; status?: number; headers?: Record<string, string>; url?: string; body?: BodyInit };
const digest = (data: string | Buffer): string => createHash("sha1").update(data).digest("hex");
const manifest = (name = "service", branch = "main"): string => `version: 1\nproject:\n  name: ${name}\n  owner: acme\n  visibility: public\n  defaultBranch: ${branch}\narchetype:\n  kind: generic-empty\n`;
const repo = (name = "service", id = 1): JsonObject => ({
  id, name, full_name: `acme/${name}`, owner: { login: "acme", id: 7, type: "Organization" },
  private: false, visibility: "public", default_branch: "main", fork: false, archived: false, disabled: false
});
const listPath = (page = 1): string => `/orgs/acme/repos?type=public&sort=full_name&direction=asc&per_page=100&page=${page}`;
const link = (page: number, numeric = false): string => `<https://api.github.com/${numeric ? "organizations/7" : "orgs/acme"}/repos?type=public&sort=full_name&direction=asc&per_page=100&page=${page}>; rel="next"`;

class Fixture {
  metadata: JsonObject[] = [repo()];
  texts = new Map<string, string | Buffer>([["service", manifest()]]);
  modes = new Map<string, string>();
  lists = 0;
  calls: { url: string; init: RequestInit }[] = [];
  change?: (path: string, reply: Reply, call: number) => Reply;

  constructor() { vi.stubGlobal("fetch", vi.fn(this.fetch.bind(this))); }

  objectIds(name: string): { head: string; tree: string; blob: string } {
    const body = Buffer.from(this.texts.get(name) ?? manifest(name));
    return { head: digest(`commit:${name}`), tree: digest(`tree:${name}`), blob: createHash("sha1").update(`blob ${body.length}\0`).update(body).digest("hex") };
  }

  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    const url = String(input);
    this.calls.push({ url, init });
    const parsed = new URL(url);
    const path = parsed.pathname + parsed.search;
    const parts = parsed.pathname.split("/");
    const name = parts[3]!;
    const ids = this.objectIds(name);
    const metadata = this.metadata.find((row) => row.name === name);
    let reply: Reply;
    if (parsed.pathname === "/orgs/acme/repos") { this.lists++; reply = { value: this.metadata }; }
    else if (parts[1] === "repos" && parts.length === 4) reply = { value: metadata };
    else if (parts[5] === "ref") reply = { value: { ref: `refs/heads/${decodeURIComponent(parts.slice(7).join("/"))}`, object: { type: "commit", sha: ids.head } } };
    else if (parts[5] === "commits") reply = { value: { sha: ids.head, tree: { sha: ids.tree } } };
    else if (parts[5] === "trees") {
      const body = this.texts.get(name);
      reply = { value: { sha: ids.tree, truncated: false, tree: body === undefined ? [] : [{ path: "project.bootstrap.yaml", type: "blob", mode: this.modes.get(name) ?? "100644", sha: ids.blob, size: Buffer.byteLength(body) }] } };
    } else if (parts[5] === "blobs") {
      const body = Buffer.from(this.texts.get(name)!);
      reply = { value: { sha: ids.blob, size: body.length, encoding: "base64", content: body.toString("base64").replace(/(.{60})/g, "$1\n") } };
    } else throw new Error("Fixture received an unexpected request.");
    reply = this.change?.(path, reply, this.calls.length) ?? reply;
    const response = new Response(reply.body ?? JSON.stringify(reply.value), { status: reply.status ?? 200, headers: { "Content-Type": "application/json", ...reply.headers } });
    Object.defineProperty(response, "url", { value: reply.url ?? url });
    return response;
  }
}

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("anonymous public fleet discovery", () => {
  it("reads the actual fixed ref/commit/tree/blob route and privately binds the complete manifest", async () => {
    const fixture = new Fixture();
    const discovery = await discoverPublicManifests("acme");
    expect(discovery.status).toBe("complete");
    expect(discovery).toMatchObject({ scope: "public-manifest-discovery", verification: { policy: "unverified", drift: "unverified", exceptions: "unverified", pilots: "unverified" } });
    expect(discovery.repositories).toHaveLength(1);
    const found = discovery.repositories[0]!;
    expect(found).toMatchObject({ repository: "acme/service", outcome: "managed", head: fixture.objectIds("service").head, manifest: { oid: fixture.objectIds("service").blob, bytes: Buffer.byteLength(manifest()) } });
    expect(readDiscoveredManifest(discovery, found)).toBe(manifest());
    expect(JSON.stringify(discovery)).not.toContain("archetype:");
    expect(Object.isFrozen(discovery) && Object.isFrozen(discovery.verification) && Object.isFrozen(found) && Object.isFrozen(found.manifest)).toBe(true);
    expect(fixture.calls.map((call) => new URL(call.url).pathname)).toEqual([
      "/orgs/acme/repos", "/repos/acme/service/git/ref/heads/main",
      `/repos/acme/service/git/commits/${fixture.objectIds("service").head}`,
      `/repos/acme/service/git/trees/${fixture.objectIds("service").tree}`,
      `/repos/acme/service/git/blobs/${fixture.objectIds("service").blob}`,
      "/orgs/acme/repos", "/repos/acme/service", "/repos/acme/service/git/ref/heads/main"
    ]);
    for (const call of fixture.calls) {
      expect(new URL(call.url).origin).toBe("https://api.github.com");
      expect(call.init).toMatchObject({ method: "GET", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
      expect(Object.keys(call.init.headers!)).toEqual(["Accept", "X-GitHub-Api-Version", "User-Agent"]);
    }
  });

  it("keeps public organization enumeration anonymous when a trusted broker supplies a read token", async () => {
    const fixture = new Fixture();
    const token = "fabricated-read-capability-0123456789";
    const discovery = await discoverPublicManifests("acme", { publicReadToken: token });
    expect(discovery.status).toBe("complete");
    expect(readDiscoveredManifest(discovery, discovery.repositories[0]!)).toBe(manifest());
    const lists = fixture.calls.filter(({ url }) => new URL(url).pathname === "/orgs/acme/repos");
    const objectReads = fixture.calls.filter(({ url }) => new URL(url).pathname.startsWith("/repos/acme/service"));
    expect(lists).toHaveLength(2);
    expect(objectReads.length).toBeGreaterThan(0);
    for (const { init, url } of lists) {
      expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
      expect(new URL(url).searchParams.get("type")).toBe("public");
    }
    for (const { init, url } of objectReads) {
      expect(new URL(url).origin).toBe("https://api.github.com");
      expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${token}`);
      expect(init).toMatchObject({ method: "GET", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
    }
    expect(JSON.stringify(discovery)).not.toContain(token);
  });

  it("fails incomplete and does not release a manifest or token after an authenticated object-read failure", async () => {
    const fixture = new Fixture();
    const token = "fabricated-read-capability-0123456789";
    fixture.change = (path, reply) => path.includes("/git/trees/") ? { value: { message: token }, status: 403 } : reply;
    const result = await discoverPublicManifests("acme", { publicReadToken: token });
    expect(result).toMatchObject({ status: "incomplete", failure: { code: "http-error", httpStatus: 403 } });
    expect(JSON.stringify(result)).not.toContain(token);
    expect(result.repositories).toEqual([]);
    expect(() => readDiscoveredManifest(result, {} as never)).toThrow("not bound");
  });

  it("does not expose a supplied token when the trusted transport throws", async () => {
    const fixture = new Fixture();
    const token = "fabricated-read-capability-0123456789";
    fixture.change = (path, reply) => {
      if (path.includes("/git/ref/")) throw new Error(`simulated transport error containing ${token}`);
      return reply;
    };
    const result = await discoverPublicManifests("acme", { publicReadToken: token });
    expect(result).toMatchObject({ status: "incomplete", failure: { code: "transport" } });
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("does not turn an installation-scoped 404 into an unmanaged repository", async () => {
    const fixture = new Fixture();
    const token = "fabricated-read-capability-0123456789";
    fixture.change = (path, reply) => path.includes("/git/ref/") ? { value: {}, status: 404 } : reply;
    const result = await discoverPublicManifests("acme", { publicReadToken: token });
    expect(result).toMatchObject({ status: "incomplete", failure: { code: "http-error", httpStatus: 404 } });
    expect(result.repositories).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("keeps a 15-repository public inventory complete when using a fabricated read capability", async () => {
    const fixture = new Fixture();
    fixture.metadata = Array.from({ length: 15 }, (_, i) => repo(`service${i}`, i + 1));
    fixture.texts = new Map(fixture.metadata.map((item): [string, string] => [item.name as string, manifest(item.name as string)]));
    const result = await discoverPublicManifests("acme", { publicReadToken: "fabricated-read-capability-0123456789" });
    expect(result.status).toBe("complete");
    expect(result.repositories).toHaveLength(15);
    expect(result.repositories.every((item) => item.outcome === "managed")).toBe(true);
    expect(result.requests).toBeGreaterThan(60);
    expect(fixture.calls.filter(({ url }) => new URL(url).pathname === "/orgs/acme/repos")).toHaveLength(2);
  });

  it("rejects a redirected object response without requesting the redirect target", async () => {
    const fixture = new Fixture();
    const token = "fabricated-read-capability-0123456789";
    fixture.change = (path, reply) => path.includes("/git/ref/") ? { ...reply, url: "https://elsewhere.invalid/object" } : reply;
    const result = await discoverPublicManifests("acme", { publicReadToken: token });
    expect(result).toMatchObject({ status: "incomplete", failure: { code: "invalid-response" } });
    expect(fixture.calls.every(({ url }) => new URL(url).origin === "https://api.github.com")).toBe(true);
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it.each(["", "short", "fabricated-token-with-newline\ninjected", "x".repeat(4097)])(
    "rejects malformed read capability without transport (%#)", async (token) => {
      const fixture = new Fixture();
      const result = await discoverPublicManifests("acme", { publicReadToken: token });
      expect(result).toMatchObject({ status: "incomplete", failure: { code: "invalid-input" } });
      expect(fixture.calls).toHaveLength(0);
    }
  );

  it("rejects inherited, accessor, unknown and throwing options without reading a token or starting transport", async () => {
    const fixture = new Fixture();
    const getter = vi.fn(() => "fabricated-read-capability-0123456789");
    const accessor = Object.defineProperty({}, "publicReadToken", { enumerable: true, get: getter });
    const inherited = Object.create({ publicReadToken: "fabricated-read-capability-0123456789" });
    const throwing = new Proxy({}, { ownKeys: () => { throw new Error("fixture-private-diagnostic"); } });
    for (const options of [null, [], accessor, inherited, { extra: true }, throwing]) {
      const result = await discoverPublicManifests("acme", options as never);
      expect(result).toMatchObject({ status: "incomplete", failure: { code: "invalid-input" } });
      expect(JSON.stringify(result)).not.toContain("fixture-private-diagnostic");
    }
    expect(getter).not.toHaveBeenCalled();
    expect(fixture.calls).toHaveLength(0);
  });

  it.each([false, true])("completes multi-page enumeration and reconstructs only its fixed org URL, numeric link=%s", async (numeric) => {
    const fixture = new Fixture();
    fixture.metadata.push(repo("other", 2)); fixture.texts.set("other", manifest("other"));
    fixture.change = (path, reply) => {
      if (!path.startsWith("/orgs/")) return reply;
      return path.endsWith("page=1") ? { value: [fixture.metadata[0]], headers: { Link: link(2, numeric) } } : { value: [fixture.metadata[1]] };
    };
    const discovery = await discoverPublicManifests("acme");
    expect(discovery.status).toBe("complete");
    expect(discovery.repositories.map((row) => row.repository)).toEqual(["acme/service", "acme/other"]);
    expect(fixture.calls.filter((call) => new URL(call.url).pathname.includes("/orgs/")).map((call) => new URL(call.url).pathname + new URL(call.url).search)).toEqual([listPath(1), listPath(2), listPath(1), listPath(2)]);
  });

  it("distinguishes proven missing manifests, unsupported types and ordinary archived/forked data", async () => {
    const fixture = new Fixture();
    fixture.metadata = [repo("missing", 1), { ...repo("linked", 2) }, { ...repo("old", 3), fork: true, archived: true }, { ...repo("disabled", 4), disabled: true }];
    fixture.texts.clear(); fixture.texts.set("linked", manifest("linked")); fixture.texts.set("old", manifest("old"));
    fixture.modes.set("linked", "120000");
    const discovery = await discoverPublicManifests("acme");
    expect(discovery.status).toBe("complete");
    expect(discovery.repositories).toMatchObject([
      { repository: "acme/missing", outcome: "unmanaged" },
      { repository: "acme/linked", outcome: "unsupported", reason: "manifest-not-regular" },
      { repository: "acme/old", outcome: "managed", archived: true, fork: true },
      { repository: "acme/disabled", outcome: "unsupported", reason: "repository-disabled" }
    ]);
    expect(fixture.calls.some((call) => call.url.includes("/disabled/git/"))).toBe(false);
    expect(fixture.calls.some((call) => call.url.includes("/linked/git/blobs/"))).toBe(false);
  });

  it("supports executable regular manifest modes without executing or reading declared host paths", async () => {
    const fixture = new Fixture(); fixture.modes.set("service", "100755");
    fixture.texts.set("service", manifest() + "agents:\n  sharedSkills:\n    - ../../not-a-real-host-input\n");
    const readFile = vi.spyOn(fs, "readFile");
    const result = await discoverPublicManifests("acme");
    expect(result.repositories[0]?.outcome).toBe("managed");
    expect(readFile).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain("not-a-real-host-input");
  });

  it("reports bounded normalized class, policy pin and exception count without exposing raw manifest data", async () => {
    const fixture = new Fixture();
    fixture.texts.set("service", manifest() + `repo:\n  class: cli\npolicy:\n  flow:\n    ref: refs/tags/v1.2.3\n    sha256: ${"a".repeat(64)}\n    bundlePath: private-fixture-path.json\n`);
    const result = await discoverPublicManifests("acme");
    expect(result.status).toBe("complete");
    const summary = result.repositories[0]?.manifest?.summary;
    expect(summary).toEqual({ normalizedClass: "cli", flowPolicy: { ref: "refs/tags/v1.2.3", sha256: "a".repeat(64), refStatus: "observed" }, exceptionCount: 0 });
    expect(Object.isFrozen(summary) && Object.isFrozen(summary?.flowPolicy)).toBe(true);
    expect(JSON.stringify(result)).not.toContain("private-fixture-path.json");
  });

  it("does not expose a control-bearing manifest ref in reports", async () => {
    const fixture = new Fixture();
    fixture.texts.set("service", manifest() + `policy:\n  flow:\n    ref: "refs/tags/\\e[31m"\n    sha256: ${"a".repeat(64)}\n    bundlePath: policy.json\n`);
    const result = await discoverPublicManifests("acme");
    expect(result.status).toBe("complete");
    expect(result.repositories[0]?.manifest?.summary?.flowPolicy).toEqual({ ref: null, sha256: "a".repeat(64), refStatus: "unrenderable" });
    expect(JSON.stringify(result)).not.toContain("31m");
  });

  it("refuses copied reports/records and incomplete prefix data as manifest authority", async () => {
    const fixture = new Fixture();
    const discovery = await discoverPublicManifests("acme");
    expect(() => readDiscoveredManifest(JSON.parse(JSON.stringify(discovery)), discovery.repositories[0]!)).toThrow("not bound");
    expect(() => readDiscoveredManifest(discovery, { ...discovery.repositories[0]! })).toThrow("not bound");
    fixture.change = (path, reply) => path === "/repos/acme/service" ? { ...reply, status: 503 } : reply;
    const failed = await discoverPublicManifests("acme");
    expect(failed.status).toBe("incomplete");
    expect(failed.repositories[0]?.outcome).toBe("managed");
    expect(() => readDiscoveredManifest({ ...failed, status: "complete" }, failed.repositories[0]!)).toThrow("not bound");
    expect(() => readDiscoveredManifest(failed, failed.repositories[0]!)).toThrow("not bound");
  });

  it.each(["../other", "a/b", "bad name", "", "-bad", "bad-", "a".repeat(40)])("rejects invalid organization %j without transport", async (organization) => {
    const fixture = new Fixture();
    expect(await discoverPublicManifests(organization)).toMatchObject({ organization: "", status: "incomplete", failure: { code: "invalid-input" } });
    expect(fixture.calls).toHaveLength(0);
  });

  it.each([
    { private: true }, { visibility: "private" }, { full_name: "other/service" }, { id: Number.MAX_SAFE_INTEGER + 1 },
    { owner: { login: "other", type: "Organization", id: 7 } }, { owner: { login: "acme", type: "User", id: 7 } },
    { default_branch: "../other" }, { default_branch: "feature/../other" }, { default_branch: "branch\n" }
  ])("rejects nonpublic or malformed repository identities %j", async (change) => {
    const fixture = new Fixture(); fixture.metadata[0] = { ...fixture.metadata[0], ...change };
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "invalid-response" } });
  });

  it.each([
    link(3), link(2).replace("api.github.com", "elsewhere.invalid"), link(2).replace("type=public", "type=private"),
    link(2).replace("orgs/acme", "orgs/other"), link(2).replace("repos?", "repos?#"), `${link(2)}, ${link(2)}`,
    link(2).replace('rel="next"', 'rel="custom"'), link(2).replace("page=2", "page=02")
  ])("rejects unsafe/incomplete pagination link %j", async (value) => {
    const fixture = new Fixture(); fixture.change = (path, reply) => path.startsWith("/orgs/") ? { ...reply, headers: { Link: value } } : reply;
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "pagination" } });
  });

  it("rejects duplicate identities across pages and an unexplained next page after an empty page", async () => {
    const fixture = new Fixture(); fixture.change = (path, reply) => path.startsWith("/orgs/") && path.endsWith("page=1") ? { ...reply, headers: { Link: link(2) } } : reply;
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "invalid-response" } });
    fixture.metadata = []; fixture.change = (path, reply) => path.startsWith("/orgs/") ? { ...reply, headers: { Link: link(2) } } : reply;
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "pagination" } });
  });

  it.each([404, 409, 503])("keeps an unexpected object HTTP%s incomplete rather than declaring unmanaged", async (status) => {
    const fixture = new Fixture(); fixture.change = (path, reply) => path.includes("/git/trees/") ? { value: { message: "untrusted transport body" }, status } : reply;
    const result = await discoverPublicManifests("acme");
    expect(result).toMatchObject({ status: "incomplete", repositories: [], failure: { code: "http-error", httpStatus: status, repository: "acme/service" } });
    expect(JSON.stringify(result)).not.toContain("untrusted transport body");
  });

  it.each([403, 429])("reports rate limits without retries, status%s", async (status) => {
    const fixture = new Fixture(); fixture.change = () => ({ value: {}, status, headers: { "x-ratelimit-remaining": "0" } });
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "rate-limit", httpStatus: status } });
    expect(fixture.calls).toHaveLength(1);
  });

  it.each([
    (path: string, reply: Reply): Reply => path.includes("/git/ref/") ? { value: { ref: "refs/heads/wrong", object: { type: "commit", sha: "a".repeat(40) } } } : reply,
    (path: string, reply: Reply): Reply => path.includes("/git/commits/") ? { value: { sha: "a".repeat(40), tree: { sha: "b".repeat(40) } } } : reply,
    (path: string, reply: Reply): Reply => path.includes("/git/trees/") ? { value: { ...(reply.value as object), truncated: true } } : reply,
    (path: string, reply: Reply): Reply => path.includes("/git/blobs/") ? { value: { ...(reply.value as object), sha: "b".repeat(40) } } : reply,
    (path: string, reply: Reply): Reply => path.includes("/git/blobs/") ? { value: { ...(reply.value as object), size: 1 } } : reply,
    (path: string, reply: Reply): Reply => path.includes("/git/blobs/") ? { value: { ...(reply.value as object), content: "!!!!" } } : reply,
    (path: string, reply: Reply): Reply => path.includes("/git/blobs/") ? { value: { ...(reply.value as object), content: Buffer.from("different bytes").toString("base64") } } : reply
  ])("rejects malformed or unbound Git object response %#", async (change) => {
    const fixture = new Fixture(); fixture.change = change;
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "invalid-response" } });
  });

  it("only calls absent a manifest after a complete root tree and rejects duplicate root entries", async () => {
    const fixture = new Fixture(); fixture.change = (path, reply) => {
      if (!path.includes("/git/trees/")) return reply;
      const tree = reply.value as { tree: unknown[] };
      return { value: { ...tree, tree: [...tree.tree, ...tree.tree] } };
    };
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "invalid-response" } });
  });

  it.each(["numeric-mode", "empty-path"])("rejects malformed tree representation %s rather than qualifying or skipping it", async (kind) => {
    const fixture = new Fixture();
    fixture.change = (path, reply) => {
      if (!path.includes("/git/trees/")) return reply;
      const tree = reply.value as { tree: JsonObject[] };
      return { value: { ...tree, tree: [{ ...tree.tree[0], ...(kind === "numeric-mode" ? { mode: 100644 } : { path: "" }) }] } };
    };
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "invalid-response" } });
  });

  it.each(["feature/release", "a".repeat(40)])("resolves exact branch names %j through the refs endpoint", async (branch) => {
    const fixture = new Fixture(); fixture.metadata[0] = { ...fixture.metadata[0], default_branch: branch }; fixture.texts.set("service", manifest("service", branch));
    expect((await discoverPublicManifests("acme")).repositories[0]?.outcome).toBe("managed");
    expect(fixture.calls.some((call) => new URL(call.url).pathname === `/repos/acme/service/git/ref/heads/${encodeURIComponent(branch)}`)).toBe(true);
  });

  it.each([
    "not valid yaml: [", manifest().replace("visibility: public", "visibility: private"),
    manifest().replace("name: service", "name: different"), manifest().replace("owner: acme", "owner: other"),
    manifest() + "unrecognized: value\n", manifest() + "alias: &a [*a]\n", manifest() + "constructor: unsafe\n",
    manifest() + `extra: ${"[".repeat(40)}0${"]".repeat(40)}\n`
  ])("records malformed/unsupported canonical manifests without releasing body %#", async (text) => {
    const fixture = new Fixture(); fixture.texts.set("service", text);
    const result = await discoverPublicManifests("acme");
    expect(result).toMatchObject({ status: "complete", repositories: [{ outcome: "unsupported", reason: "invalid-manifest" }] });
    expect(() => readDiscoveredManifest(result, result.repositories[0]!)).toThrow("not bound");
  });

  it("rejects oversized manifest metadata before downloading its blob", async () => {
    const fixture = new Fixture(); fixture.change = (path, reply) => {
      if (!path.includes("/git/trees/")) return reply;
      const tree = reply.value as { tree: JsonObject[] };
      return { value: { ...tree, tree: [{ ...tree.tree[0], size: PUBLIC_DISCOVERY_LIMITS.manifestBytes + 1 }] } };
    };
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "complete", repositories: [{ outcome: "unsupported", reason: "manifest-too-large" }] });
    expect(fixture.calls.some((call) => call.url.includes("/git/blobs/"))).toBe(false);
  });

  it("bounds aggregate consumed bytes across otherwise valid small responses", async () => {
    const fixture = new Fixture();
    fixture.metadata = Array.from({ length: 14 }, (_, index) => repo(`service${index}`, index + 1));
    fixture.texts.clear();
    for (const row of fixture.metadata) fixture.texts.set(String(row.name), manifest(String(row.name)));
    const padding = "x".repeat(1024 * 1024);
    fixture.change = (_path, reply) => Array.isArray(reply.value) ? reply : { ...reply, value: { ...(reply.value as object), padding } };
    const result = await discoverPublicManifests("acme");
    expect(result.status).toBe("incomplete");
    expect(result.failure?.code).toBe("total-byte-limit");
    expect(result.receivedBytes).toBeGreaterThan(PUBLIC_DISCOVERY_LIMITS.totalBytes);
    expect(result.receivedBytes).toBeLessThan(PUBLIC_DISCOVERY_LIMITS.totalBytes + PUBLIC_DISCOVERY_LIMITS.responseBytes);
    expect(() => readDiscoveredManifest(result, result.repositories[0]!)).toThrow("not bound");
  });

  it("rejects oversized root trees rather than proving manifest absence from a prefix", async () => {
    const fixture = new Fixture();
    fixture.change = (path, reply) => !path.includes("/git/trees/") ? reply : {
      value: { ...(reply.value as object), tree: Array.from({ length: PUBLIC_DISCOVERY_LIMITS.treeEntries + 1 }, (_, index) => ({ path: `file${index}` })) }
    };
    expect((await discoverPublicManifests("acme")).failure?.code).toBe("invalid-response");
  });

  it("bounds YAML node conversion before invoking the canonical schema", async () => {
    const fixture = new Fixture();
    fixture.texts.set("service", manifest() + `ci:\n  fastChecks: [${Array.from({ length: PUBLIC_DISCOVERY_LIMITS.manifestNodes + 1 }, () => "a").join(",")} ]\n`);
    const result = await discoverPublicManifests("acme");
    expect(result.status).toBe("complete");
    expect(result.repositories[0]).toMatchObject({ outcome: "unsupported", reason: "invalid-manifest" });
  });

  it.each(["default", "head", "membership"])('fails changed %s observations instead of sealing a completed discovery', async (kind) => {
    const fixture = new Fixture(); let refs = 0;
    fixture.change = (path, reply) => {
      if (kind === "default" && path === "/repos/acme/service") return { value: { ...fixture.metadata[0], default_branch: "different" } };
      if (kind === "head" && path.includes("/git/ref/") && ++refs > 1) return { value: { ref: "refs/heads/main", object: { type: "commit", sha: "a".repeat(40) } } };
      if (kind === "membership" && path.startsWith("/orgs/") && fixture.lists > 1) return { value: [] };
      return reply;
    };
    const result = await discoverPublicManifests("acme");
    expect(result.status).toBe("incomplete");
    expect(result.failure?.code).toBe(kind === "membership" ? "changed-organization" : "changed-repository");
    expect(() => readDiscoveredManifest(result, result.repositories[0]!)).toThrow("not bound");
  });

  it.each([
    { headers: { "Content-Length": String(PUBLIC_DISCOVERY_LIMITS.responseBytes + 1) } },
    { body: "x".repeat(PUBLIC_DISCOVERY_LIMITS.responseBytes + 1) }
  ])("bounds declared and actually consumed HTTP bytes %#", async (change) => {
    const fixture = new Fixture(); fixture.change = () => ({ value: {}, ...change });
    expect(await discoverPublicManifests("acme")).toMatchObject({ status: "incomplete", failure: { code: "response-limit" } });
    expect(fixture.calls).toHaveLength(1);
  });

  it("rejects invalid JSON, changed response origin and unexpected pagination on an object", async () => {
    const fixture = new Fixture(); fixture.change = () => ({ value: {}, body: "{invalid" });
    expect((await discoverPublicManifests("acme")).failure?.code).toBe("invalid-response");
    fixture.change = () => ({ value: [], url: "https://elsewhere.invalid/" });
    expect((await discoverPublicManifests("acme")).failure?.code).toBe("invalid-response");
    fixture.change = (path, reply) => path.includes("/git/ref/") ? { ...reply, headers: { Link: link(2) } } : reply;
    expect((await discoverPublicManifests("acme")).failure?.code).toBe("pagination");
  });

  it("bounds complete pagination and repository counts", async () => {
    const fixture = new Fixture();
    fixture.change = (path, reply) => {
      if (!path.startsWith("/orgs/")) return reply;
      const page = Number(new URL(path, "https://api.github.com").searchParams.get("page"));
      return { value: [repo(`r${page}`, page)], headers: { Link: link(page + 1) } };
    };
    expect((await discoverPublicManifests("acme")).failure?.code).toBe("pagination");
    fixture.change = (path, reply) => {
      if (!path.startsWith("/orgs/")) return reply;
      const page = Number(new URL(path, "https://api.github.com").searchParams.get("page"));
      return { value: Array.from({ length: 100 }, (_, index) => repo(`r${page}-${index}`, (page - 1) * 100 + index + 1)), headers: { Link: link(page + 1) } };
    };
    expect((await discoverPublicManifests("acme")).failure?.code).toBe("repository-limit");
  });

  it("cancels before any request or during an owned pending request without retries", async () => {
    const fixture = new Fixture(); const before = new AbortController(); before.abort();
    expect((await discoverPublicManifests("acme", { signal: before.signal })).failure?.code).toBe("aborted");
    expect(fixture.calls).toHaveLength(0);
    const pending = new AbortController();
    const fake = vi.fn((_input: unknown, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal!.addEventListener("abort", () => reject(new Error("raw private fixture diagnostics")), { once: true });
    }));
    vi.stubGlobal("fetch", fake);
    const operation = discoverPublicManifests("acme", { signal: pending.signal }); pending.abort();
    const result = await operation;
    expect(result.failure?.code).toBe("aborted");
    expect(JSON.stringify(result)).not.toContain("raw private fixture diagnostics");
    expect(fake).toHaveBeenCalledTimes(1);
  });

  it("uses bounded per-request time and a monotonic aggregate deadline", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn((_input: unknown, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal!.addEventListener("abort", () => reject(new Error("timeout fixture")), { once: true });
    })));
    const operation = discoverPublicManifests("acme");
    await vi.advanceTimersByTimeAsync(PUBLIC_DISCOVERY_LIMITS.requestMilliseconds + 1);
    expect((await operation).failure?.code).toBe("deadline");
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
    const clock = vi.spyOn(performance, "now").mockReturnValue(0);
    const fixture = new Fixture(); fixture.change = (_path, reply) => { clock.mockReturnValue(PUBLIC_DISCOVERY_LIMITS.totalMilliseconds + 1); return reply; };
    expect((await discoverPublicManifests("acme")).failure?.code).toBe("deadline");
  });

  it("sanitizes transport failures without retaining raw adapter diagnostics", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("not-a-real-local-auth-value")));
    const result = await discoverPublicManifests("acme");
    expect(result.failure?.code).toBe("transport");
    expect(JSON.stringify(result)).not.toContain("not-a-real-local-auth-value");
  });
});
