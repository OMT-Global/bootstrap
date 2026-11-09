import { execFileSync, type SpawnOptions } from "node:child_process";
import { EventEmitter } from "node:events";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

const faults = vi.hoisted(() => ({ source: "", sha: "", metadata: "", shape: "", depth: "", helperCalls: 0,
  admission: 0, copyCalls: 0, auditCalls: 0, originalRoots: [] as string[], originalOpens: 0, originalStats: 0, dirtyReads: 0, dirtyPath: "", changeHead: false, abortAfterAudit: undefined as undefined | (() => void),
  cleanupCalls: 0, cleanupFailures: 0, holdCleanup: false, resumeCleanup: undefined as undefined | (() => void),
  commands: [] as Array<{ args: string[]; env: NodeJS.ProcessEnv }>, requests: [] as unknown[] }));
vi.mock("../src/upgrade-host.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-host.js")>();
  // Darwin has no prlimit and its Xcode helper ancestry is unsupported by the Linux profile.
  // Those bypasses prove Git semantics only. Linux retains the real profile and kernel limits.
  return { ...actual,
    HOST_LIMITS: { ...actual.HOST_LIMITS, get admission() { return faults.admission || actual.HOST_LIMITS.admission; } },
    trustedExecutable: (file: string) => process.platform === "darwin" && file.endsWith("/git-remote-https") ? Promise.resolve(file) : actual.trustedExecutable(file),
    requireLinuxHost: process.platform === "linux" ? actual.requireLinuxHost : async () => ({ git: "/usr/bin/git", prlimit: "/private/test-only-prlimit" }) };
});
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: (command: string, args: readonly string[], options: SpawnOptions) => {
    if (command !== "/private/test-only-prlimit" && command !== "/usr/bin/prlimit") return actual.spawn(command, args, options);
    const fixed = [...args.slice(args.indexOf("--") + 2)]; faults.commands.push({ args: [...args], env: { ...options.env } });
    if (fixed.includes("fetch")) {
      expect(fixed).toContain("--depth=10000"); expect(fixed).toContain("--keep"); expect(fixed).toContain("https://github.com/example/public.git");
      fixed[fixed.indexOf("https://github.com/example/public.git")] = pathToFileURL(faults.source).href;
      if (faults.depth) fixed[fixed.indexOf("--depth=10000")] = "--depth=" + faults.depth;
      if (faults.shape) {
        const gitdir = String(options.env?.GIT_DIR);
        const marker = faults.shape === "loose" ? path.join(gitdir, "objects", "aa") : path.join(gitdir, "objects", "info");
        execFileSync(process.execPath, ["-e", "const fs=require('fs');fs.mkdirSync(process.argv[1],{recursive:true});fs.writeFileSync(process.argv[1]+'/'+process.argv[2],'test')", marker, faults.shape === "loose" ? "bb" : "alternates"]);
      }
    }
    const git = ["-c", "protocol.file.allow=always", ...fixed];
    return command === "/private/test-only-prlimit" ? actual.spawn("/usr/bin/git", git, options) : actual.spawn(command, [...args.slice(0, args.indexOf("--") + 2), ...git], options);
  } };
});
vi.mock("node:https", async (original) => {
  const actual = await original<typeof import("node:https")>();
  const get = (options: unknown, callback: (response: Readable) => void) => {
    faults.requests.push(options); const request = new EventEmitter() as EventEmitter & { setTimeout: () => void; destroy: () => void };
    request.setTimeout = () => {}; request.destroy = () => {};
    queueMicrotask(() => {
      const endpoint = (options as { path: string }).path;
      const metadata = { full_name: "example/public", private: false, visibility: "public", clone_url: "https://github.com/example/public.git", default_branch: "main", disabled: false, archived: false };
      const body = endpoint.endsWith("/git/ref/heads/main") ? { ref: "refs/heads/main", object: { type: "commit", sha: faults.metadata === "sha" ? "a".repeat(40) : faults.sha } } : { ...metadata, ...(faults.metadata === "private" ? { private: true } : {}), ...(faults.metadata === "name" ? { full_name: "other/repo" } : {}) };
      const response = Readable.from([Buffer.from(JSON.stringify(body))]); Object.assign(response, { statusCode: faults.metadata === "redirect" ? 301 : 200, headers: { "content-type": "application/json; charset=utf-8" } }); callback(response);
    }); return request;
  };
  return { ...actual, default: { ...actual, get } };
});
vi.mock("../src/upgrade-git.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-git.js")>();
  return { ...actual, copySnapshotFiles: (...args: Parameters<typeof actual.copySnapshotFiles>) => { faults.copyCalls++; return actual.copySnapshotFiles(...args); }, openDataRepository: async (...args: Parameters<typeof actual.openDataRepository>) => {
    faults.helperCalls++; const repository = await actual.openDataRepository(...args);
    return { ...repository, dispose: async () => {
      faults.cleanupCalls++; if (faults.cleanupFailures) { faults.cleanupFailures--; throw new Error("private cleanup canary"); }
      if (faults.holdCleanup) await new Promise<void>((resolve) => { faults.resumeCleanup = resolve; });
      await repository.dispose();
    } };
  } };
});
vi.mock("../src/upgrade-checkout.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-checkout.js")>();
  return { ...actual, auditCheckout: async (...args: Parameters<typeof actual.auditCheckout>) => {
    faults.auditCalls++; const result = await actual.auditCheckout(...args);
    if (faults.changeHead) await writeFile(path.join(args[0], ".git/HEAD"), "ref: refs/heads/other\n"); faults.abortAfterAudit?.();
    return result;
  } };
});
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual,
    realpath: actual.realpath,
    lstat: (...args: Parameters<typeof actual.lstat>) => { if (faults.originalRoots.some((root) => String(args[0]).startsWith(root))) faults.originalStats++; return actual.lstat(...args); },
    open: async (...args: Parameters<typeof actual.open>) => {
      const file = String(args[0]); if (faults.originalRoots.some((root) => file.startsWith(root))) faults.originalOpens++;
      const handle = await actual.open(...args);
      if (faults.dirtyPath && file.endsWith(faults.dirtyPath)) { const read = handle.read.bind(handle); handle.read = ((...input: unknown[]) => { faults.dirtyReads++; return Reflect.apply(read, handle, input); }) as typeof handle.read; }
      return handle;
    }
  };
});

import { copySnapshotFiles } from "../src/upgrade-git.js";
import { HOST_LIMITS } from "../src/upgrade-host.js";
import { acquirePublicBase, auditPublicCheckout, copyReservedSnapshotFiles, createBoundedBundle, disposePublicRepository, openReservedDataRepository, reserveUpgradePreparation, transportContext, writeFrozenTree, type PublicRepository } from "../src/upgrade-transport.js";
const repositories: PublicRepository[] = []; const roots: string[] = [];
const fixed = "Governed upgrade host operation is unsupported.";
async function fixture(delta = false) {
  const root = await mkdtemp(path.join(os.tmpdir(), "bootstrap-transport-test-")); roots.push(root); const empty = path.join(root, "empty"); await mkdir(empty);
  const env = { PATH: "/usr/bin:/bin", HOME: empty, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_AUTHOR_NAME: "Synthetic Public", GIT_AUTHOR_EMAIL: "public@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Synthetic Public", GIT_COMMITTER_EMAIL: "public@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=" + empty, "-c", "commit.gpgsign=false", ...args], { cwd: root, env, ...(input === undefined ? {} : { input }), maxBuffer: 64 * 1024 ** 2 });
  git(["init", "-q", "--initial-branch=main", `--template=${empty}`]);
  const sourceFiles = delta ? Array.from({ length: 32 }, (_, i) => ({ path: `public-${i}.txt`, bytes: Buffer.from(`revision ${i}\n` + "public delta fixture\n".repeat(32000)) })) : [{ path: "README.md", bytes: Buffer.from("public fixture\n") }, { path: "script.sh", bytes: Buffer.from("#!/bin/sh\nexit 0\n") }, { path: "utf8/é.txt", bytes: Buffer.from("safe Unicode\n") }];
  for (const file of sourceFiles) {
    const oid = git(["hash-object", "--no-filters", "-w", "--stdin"], file.bytes).toString().trim(); const executable = file.path === "script.sh";
    git(["update-index", "--add", "--cacheinfo", executable ? "100755" : "100644", oid, file.path]);
    await mkdir(path.dirname(path.join(root, file.path)), { recursive: true }); await writeFile(path.join(root, file.path), file.bytes, { mode: executable ? 0o755 : 0o644 });
  }
  const tree = git(["write-tree"]).toString().trim();
  for (let i = 0; i < 3; i++) { const prior = i ? ["-p", faults.sha] : []; faults.sha = git(["commit-tree", tree, ...prior], "Synthetic complete history\n" + i + "\n").toString().trim(); git(["update-ref", "refs/heads/main", faults.sha]); }
  git(["config", "remote.origin.url", "https://github.com/example/public.git"]);
  faults.source = root; return { root, git, files: sourceFiles };
}
async function acquire() { const repo = await acquirePublicBase("example/public", faults.sha); repositories.push(repo); return repo; }
function fillAdmission(context: ReturnType<typeof transportContext>) {
  let bytes = 0; const leases: Array<ReturnType<typeof context.reserve>> = [];
  for (let size = HOST_LIMITS.admission; size >= 1; size = Math.floor(size / 2)) {
    for (;;) { try { leases.push(context.reserve(size)); bytes += size; } catch { break; } }
  }
  return { bytes, leases };
}
afterEach(async () => {
  vi.restoreAllMocks();
  faults.holdCleanup = false; faults.resumeCleanup?.();
  for (const repo of repositories.splice(0)) await disposePublicRepository(repo).catch(() => {});
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  faults.source = ""; faults.sha = ""; faults.metadata = ""; faults.shape = ""; faults.depth = ""; faults.helperCalls = 0; faults.commands.length = 0; faults.requests.length = 0;
  faults.cleanupCalls = 0; faults.cleanupFailures = 0; faults.resumeCleanup = undefined;
  faults.admission = 0; faults.copyCalls = 0; faults.auditCalls = 0; faults.originalRoots.length = 0; faults.originalOpens = 0; faults.originalStats = 0; faults.dirtyReads = 0; faults.dirtyPath = ""; faults.changeHead = false; faults.abortAfterAudit = undefined;
});

describe("private public transport with real Git and simulated Linux launch", () => {
  it("binds complete public history, raw paths/modes and a self-contained base bundle", async () => {
    const original = await fixture(); const before = original.git(["rev-parse", "HEAD"]); const repository = await acquire(); const context = transportContext(repository);
    const packed = await readdir(path.join(context.gitdir, "objects", "pack")); expect(packed.filter((name) => name.endsWith(".pack"))).toHaveLength(1); expect(packed.filter((name) => name.endsWith(".idx"))).toHaveLength(1);
    expect(repository.baseCommit).toBe(faults.sha); expect(copySnapshotFiles(repository.snapshot).find((file) => file.path === "script.sh")?.mode).toBe("100755");
    const bundle = await createBoundedBundle(repository); const imported = path.join(original.root, "import"); await mkdir(imported); const bundlePath = path.join(original.root, "public.bundle"); await writeFile(bundlePath, bundle);
    execFileSync("/usr/bin/git", ["-c", "protocol.file.allow=always", "-c", "init.defaultBranch=fixture", "clone", "-q", "--no-checkout", "--branch", "codex/bootstrap-public-base", bundlePath, imported], { env: { PATH: "/usr/bin:/bin", HOME: original.root, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" } });
    expect(execFileSync("/usr/bin/git", ["-C", imported, "rev-parse", "HEAD"]).toString().trim()).toBe(faults.sha); expect(original.git(["rev-parse", "HEAD"])).toEqual(before);
    expect(faults.requests).toEqual(expect.arrayContaining([expect.objectContaining({ hostname: "api.github.com", agent: false, rejectUnauthorized: true, headers: expect.not.objectContaining({ Authorization: expect.anything() }) })]));
    const directory = context.directory; await disposePublicRepository(repository); await expect(lstat(directory)).rejects.toMatchObject({ code: "ENOENT" });
  });
  it.each(["private", "name", "sha", "redirect"])("rejects %s metadata before any Git launch", async (fault) => {
    await fixture(); faults.metadata = fault; await expect(acquire()).rejects.toThrow(fixed); expect(faults.commands).toHaveLength(0);
  });
  it.each(["NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE", "SSL_CERT_DIR", "OPENSSL_CONF"])("rejects %s override before anonymous identity requests", async (name) => {
    const before = process.env[name]; process.env[name] = name === "NODE_TLS_REJECT_UNAUTHORIZED" ? "0" : "/private/inert-tls-context-canary";
    try { await expect(acquirePublicBase("example/public", "a".repeat(40))).rejects.toThrow(fixed); expect(faults.requests).toHaveLength(0); expect(faults.commands).toHaveLength(0); }
    finally { if (before === undefined) delete process.env[name]; else process.env[name] = before; }
  });
  it.each(["loose", "alternates"])("rejects unexpected %s object storage", async (fault) => {
    await fixture(); faults.shape = fault; await expect(acquire()).rejects.toThrow(fixed); expect(faults.commands.some(({ args }) => args.includes("fsck"))).toBe(false);
  });
  it("rejects an incomplete shallow graph without returning signing/publication authority", async () => {
    await fixture(); faults.depth = "2"; await expect(acquire()).rejects.toThrow(fixed); expect(faults.commands.some(({ args }) => args.includes("commit-tree"))).toBe(false);
  });
  it("does not inherit credentials, agent, tracing, proxy or injected Git environment", async () => {
    await fixture(); const transportCanary = "inert-test-token-canary";
    const canaries = { SSH_AUTH_SOCK: "/private/test-agent-canary", GH_TOKEN: transportCanary, GIT_TRACE: "/private/test-trace-canary", GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "credential.helper", GIT_CONFIG_VALUE_0: "inert-test-helper", HTTPS_PROXY: "http://canary.invalid" };
    const old = Object.fromEntries(Object.keys(canaries).map((name) => [name, process.env[name]])); Object.assign(process.env, canaries);
    try { await acquire(); for (const { env } of faults.commands) for (const name of Object.keys(canaries)) expect(env).not.toHaveProperty(name); }
    finally { for (const [name, value] of Object.entries(old)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; } }
  });
  it("constructs frozen blobs/tree without filters and independently binds additions, modes and deletions", async () => {
    await fixture(); const repository = await acquire(); const files = [{ path: "new/hello.txt", mode: "100644" as const, bytes: Buffer.from("new public file\n") }, { path: "tool", mode: "100755" as const, bytes: Buffer.from("public executable\n") }];
    reserveUpgradePreparation(repository, files); const written = await writeFrozenTree(repository, files);
    expect(copySnapshotFiles(written.snapshot)).toEqual(files); const context = transportContext(repository);
    const tree = execFileSync("/usr/bin/git", ["--git-dir", context.gitdir, "ls-tree", "-r", written.tree]).toString(); expect(tree).toContain("100755 blob"); expect(tree).not.toContain("README.md");
    expect(faults.commands.filter(({ args }) => args.includes("hash-object")).every(({ args }) => args.includes("--no-filters"))).toBe(true);
  });
  it("reserves expanded helper representations before a delta-rich source can write them", async () => {
    const data = await fixture(true); const repository = await acquire(); const context = transportContext(repository); const packed = (await readdir(path.join(context.gitdir, "objects", "pack"))).find((name) => name.endsWith(".pack"))!;
    const packedBytes = (await lstat(path.join(context.gitdir, "objects", "pack", packed))).size; const sourceBytes = data.files.reduce((total, file) => total + file.bytes.length, 0); expect(sourceBytes).toBeGreaterThan(packedBytes * 50);
    fillAdmission(context);
    await expect(openReservedDataRepository(repository)).rejects.toThrow(fixed); expect(faults.helperCalls).toBe(0);
    const before = await readdir(context.gitdir); await expect(writeFrozenTree(repository, copySnapshotFiles(repository.snapshot))).rejects.toThrow(fixed); expect(await readdir(context.gitdir)).toEqual(before);
  });
  it("holds base helper storage until verified disposal and rejects forged capabilities", async () => {
    await fixture(); const repository = await acquire(); const helper = await openReservedDataRepository(repository); expect(faults.helperCalls).toBe(1); expect(await readFile(path.join(helper.root, "README.md"), "utf8")).toBe("public fixture\n");
    await helper.dispose(); await expect(lstat(helper.root)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(createBoundedBundle({ ...repository })).rejects.toThrow(fixed); await expect(createBoundedBundle(repository, "a".repeat(40))).rejects.toThrow(fixed);
  });
  it("serializes concurrent helper cleanup and releases its admission charge exactly once", async () => {
    await fixture(); const repository = await acquire(); const context = transportContext(repository); const reserve = context.reserve; const charged: number[] = [];
    context.reserve = (bytes) => { charged.push(bytes); return reserve(bytes); };
    const helper = await openReservedDataRepository(repository); context.reserve = reserve; const bytes = charged[0]!;
    fillAdmission(context); faults.holdCleanup = true;
    const first = helper.dispose(); const second = helper.dispose();
    await vi.waitFor(() => expect(faults.cleanupCalls).toBe(1)); expect(faults.resumeCleanup).toBeTypeOf("function"); faults.resumeCleanup!();
    await Promise.all([first, second]); expect(faults.cleanupCalls).toBe(1);
    expect(() => reserve(bytes + 1)).toThrow(fixed); reserve(bytes); expect(() => reserve(1)).toThrow(fixed);
    await helper.dispose(); expect(faults.cleanupCalls).toBe(1); await expect(lstat(helper.root)).rejects.toMatchObject({ code: "ENOENT" });
  });
  it("retains a failed cleanup charge and admits it only after a successful retry", async () => {
    await fixture(); const repository = await acquire(); const context = transportContext(repository); const reserve = context.reserve; const charged: number[] = [];
    context.reserve = (bytes) => { charged.push(bytes); return reserve(bytes); };
    const helper = await openReservedDataRepository(repository); context.reserve = reserve; const bytes = charged[0]!;
    fillAdmission(context); faults.cleanupFailures = 1;
    await expect(helper.dispose()).rejects.toThrow(fixed); expect(() => reserve(1)).toThrow(fixed); expect(await readFile(path.join(helper.root, "README.md"), "utf8")).toBe("public fixture\n");
    await helper.dispose(); expect(faults.cleanupCalls).toBe(2); reserve(bytes); expect(() => reserve(1)).toThrow(fixed);
  });
  it("charges blob stream/concat/private copies before the crossing decompression call", async () => {
    const data = await fixture(true); faults.admission = 1240 * 1024 ** 2;
    await expect(acquire()).rejects.toThrow(fixed);
    const sizes = faults.commands.filter(({ args }) => args.includes("cat-file") && args.includes("-s"));
    const contents = faults.commands.filter(({ args }) => args.includes("cat-file") && args.includes("blob"));
    expect(contents.length).toBeGreaterThan(0); expect(contents.length).toBeLessThan(data.files.length);
    expect(contents.map(({ args }) => args.at(-1))).not.toContain(sizes.at(-1)!.args.at(-1)); expect(faults.helperCalls).toBe(0);
  });
  it("sizes helpers from cached facts and reserves explicit copied inventories before making them", async () => {
    await fixture(); const repository = await acquire(); faults.copyCalls = 0;
    const helper = await openReservedDataRepository(repository); expect(faults.copyCalls).toBe(0); await helper.dispose();
    expect(copyReservedSnapshotFiles(repository)).toHaveLength(3); expect(faults.copyCalls).toBe(1);
    fillAdmission(transportContext(repository)); expect(() => copyReservedSnapshotFiles(repository)).toThrow(fixed); expect(faults.copyCalls).toBe(1);
  });
  it("refuses original audit admission before every original read/stat and helper call", async () => {
    const data = await fixture(); const repository = await acquire(); fillAdmission(transportContext(repository)); faults.originalRoots.push(data.root);
    await expect(auditPublicCheckout(repository, data.root)).rejects.toThrow(fixed);
    expect(faults.originalOpens).toBe(0); expect(faults.originalStats).toBe(0); expect(faults.auditCalls).toBe(0); expect(faults.helperCalls).toBe(0);
  });
  it("audits only the exact original default symbolic branch and preserves its bytes", async () => {
    const data = await fixture(); const repository = await acquire(); const names = [".git/HEAD", ".git/index", ".git/config", "README.md", "script.sh", "utf8/é.txt"];
    const before = await Promise.all(names.map((name) => readFile(path.join(data.root, name))));
    expect((await auditPublicCheckout(repository, data.root)).baseCommit).toBe(repository.baseCommit);
    expect(await Promise.all(names.map((name) => readFile(path.join(data.root, name))))).toEqual(before); expect(faults.auditCalls).toBe(1);
  });
  it("keeps audit copy/read buffer charges after its temporary helper has closed", async () => {
    const data = await fixture(); const repository = await acquire(); const context = transportContext(repository);
    const initial = fillAdmission(context); await Promise.all(initial.leases.map((lease) => lease.releaseAfterCleanup(async () => {})));
    const reserve = context.reserve; const charges: number[] = []; context.reserve = (bytes) => { const lease = reserve(bytes); charges.push(bytes); return lease; };
    await auditPublicCheckout(repository, data.root); context.reserve = reserve;
    const remaining = fillAdmission(context); expect(initial.bytes - remaining.bytes).toBe(charges[0]); expect(faults.auditCalls).toBe(1);
  });
  it.each(["detached", "other"])("rejects %s HEAD at the same commit before helper materialization", async (kind) => {
    const data = await fixture(); const repository = await acquire();
    if (kind === "other") data.git(["update-ref", "refs/heads/other", faults.sha]);
    await writeFile(path.join(data.root, ".git/HEAD"), kind === "detached" ? faults.sha + "\n" : "ref: refs/heads/other\n");
    await expect(auditPublicCheckout(repository, data.root)).rejects.toThrow(fixed); expect(faults.auditCalls).toBe(0);
  });
  it("rejects an external HEAD change after an otherwise valid original audit", async () => {
    const data = await fixture(); const repository = await acquire(); faults.changeHead = true;
    await expect(auditPublicCheckout(repository, data.root)).rejects.toThrow(fixed); expect(faults.auditCalls).toBe(1);
  });
  it("does not return successful audit evidence after late cancellation during finalization", async () => {
    const data = await fixture(); const cancellation = new AbortController(); const repository = await acquirePublicBase("example/public", faults.sha, { signal: cancellation.signal }); repositories.push(repository);
    faults.abortAfterAudit = () => cancellation.abort(new Error("private late cancellation"));
    await expect(auditPublicCheckout(repository, data.root)).rejects.toThrow(fixed); expect(faults.auditCalls).toBe(1);
  });
  it("fstat-rejects oversized dirty originals before allocating or reading their bytes", async () => {
    const data = await fixture(); const repository = await acquire(); const dirty = Buffer.alloc(1024 ** 2, 120); await writeFile(path.join(data.root, "README.md"), dirty);
    faults.dirtyPath = path.join(path.basename(data.root), "README.md"); const allocations = vi.spyOn(Buffer, "alloc");
    await expect(auditPublicCheckout(repository, data.root)).rejects.toThrow(fixed);
    expect(faults.dirtyReads).toBe(0); expect(allocations.mock.calls.some(([size]) => size === dirty.length + 1)).toBe(false);
    expect(await readFile(path.join(data.root, "README.md"))).toEqual(dirty);
  });
  it("refuses candidate copy/object admission before copying bytes or writing any Git object", async () => {
    await fixture(); const repository = await acquire(); fillAdmission(transportContext(repository)); const payload = Buffer.from("known public target\n");
    const copies = vi.spyOn(Buffer, "from"); const before = faults.commands.length;
    await expect(writeFrozenTree(repository, [{ path: "target.txt", mode: "100644", bytes: payload }])).rejects.toThrow(fixed);
    expect(copies.mock.calls.some(([value]) => value === payload)).toBe(false); expect(faults.commands).toHaveLength(before);
  });
});
