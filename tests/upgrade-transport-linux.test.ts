import { execFileSync, type ChildProcess, type SpawnOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { createReadStream, existsSync, lstatSync, readdirSync } from "node:fs";
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const fixtureState = vi.hoisted(() => ({ source: "", sha: "", prlimit: "", git: "", fetchUrl: "",
  commands: [] as Array<{ command: string; original: string[]; launched: string[]; cwd: string; child: ChildProcess;
    closed: boolean; packFiles: Array<{ name: string; bytes: number; regular: boolean }>; looseDirectories: string[];
    objectPayloadBytes: number; invalidObjectShape: boolean }>,
  requests: [] as unknown[], unexpectedLaunches: [] as Array<{ command: string; args: string[] }>
}));

// Only the literal fetch destination changes. The real trusted Git/prlimit,
// detached process group, fixed resource flags, UID/proc checks and environment
// are untouched. Destinations are a disposable file source or a controlled
// loopback dumb-HTTP fixture. No external network/auth or production override.
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: (command: string, args: readonly string[], options: SpawnOptions) => {
    if (command !== fixtureState.prlimit) {
      fixtureState.unexpectedLaunches.push({ command, args: [...args] });
      throw new Error("Resource fixture refuses an unexpected unrestricted launch.");
    }
    const launched = [...args]; const separator = launched.indexOf("--");
    if (launched.includes("fetch")) {
      const url = launched.indexOf("https://github.com/example/public.git");
      if (url < 0) throw new Error("Resource fixture refuses an unrecognized fetch destination.");
      if (fixtureState.fetchUrl && !/^http:\/\/127\.0\.0\.1:\d+\/public\.git$/.test(fixtureState.fetchUrl))
        throw new Error("Resource fixture refuses a non-loopback HTTP destination.");
      launched[url] = fixtureState.fetchUrl || pathToFileURL(fixtureState.source).href;
      launched.splice(separator + 2, 0, "-c", fixtureState.fetchUrl ? "protocol.http.allow=always" : "protocol.file.allow=always");
    }
    const child = actual.spawn(command, launched, options);
    const record = { command, original: [...args], launched, cwd: String(options.cwd), child, closed: false,
      packFiles: [] as Array<{ name: string; bytes: number; regular: boolean }>, looseDirectories: [] as string[],
      objectPayloadBytes: 0, invalidObjectShape: false };
    fixtureState.commands.push(record);
    child.once("close", () => {
      record.closed = true;
      if (!args.includes("fetch")) return;
      // Observe only the owned disposable gitdir, synchronously before the
      // production close handler can start deleting its failed acquisition.
      const objects = path.join(String(options.env?.GIT_DIR), "objects");
      if (!existsSync(objects)) return;
      let entries = 0;
      const inspect = (directory: string) => {
        for (const name of readdirSync(directory)) {
          if (++entries > 1000) { record.invalidObjectShape = true; return; }
          const file = path.join(directory, name); const stat = lstatSync(file);
          if (stat.isDirectory()) inspect(file);
          else if (stat.isFile() && stat.nlink === 1) record.objectPayloadBytes += stat.size;
          else record.invalidObjectShape = true;
        }
      };
      inspect(objects);
      record.looseDirectories = readdirSync(objects).filter((name) => /^[a-f0-9]{2}$/.test(name));
      const packs = path.join(objects, "pack");
      if (existsSync(packs)) record.packFiles = readdirSync(packs).map((name) => {
        const stat = lstatSync(path.join(packs, name)); return { name, bytes: stat.size, regular: stat.isFile() && stat.nlink === 1 };
      });
    });
    return child;
  } };
});

// Synthetic anonymous REST identity only. It supplies no proof of kernel limits.
vi.mock("node:https", async (original) => {
  const actual = await original<typeof import("node:https")>();
  const get = (options: unknown, callback: (response: Readable) => void) => {
    fixtureState.requests.push(options);
    const request = new EventEmitter() as EventEmitter & { setTimeout: () => void; destroy: () => void };
    request.setTimeout = () => {}; request.destroy = () => {};
    queueMicrotask(() => {
      const endpoint = (options as { path: string }).path;
      const body = endpoint.endsWith("/git/ref/heads/main") ? { ref: "refs/heads/main", object: { type: "commit", sha: fixtureState.sha } } :
        { full_name: "example/public", private: false, visibility: "public", clone_url: "https://github.com/example/public.git", default_branch: "main", disabled: false, archived: false };
      const response = Readable.from([Buffer.from(JSON.stringify(body))]);
      Object.assign(response, { statusCode: 200, headers: { "content-type": "application/json; charset=utf-8" } }); callback(response);
    });
    return request;
  };
  return { ...actual, get, default: { ...actual, get } };
});

import { HOST_LIMITS, neutralEnvironment, requireLinuxHost, trustedExecutable } from "../src/upgrade-host.js";
import { acquirePublicBase, disposePublicRepository, transportContext, type PublicRepository } from "../src/upgrade-transport.js";

const required = process.env.BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS === "1";
const linux = process.platform === "linux";
const fixed = "Governed upgrade host operation is unsupported.";
const roots: string[] = []; const capabilities: PublicRepository[] = [];
const pending: Array<{ controller: AbortController; settled: Promise<unknown> }> = [];
const servers: Array<{ server: Server; sockets: Set<Socket> }> = [];
let python: string;

async function preflight() {
  expect(process.platform, "Mandatory Git resource proof requires Linux; Darwin simulations cannot satisfy it.").toBe("linux");
  const tools = await requireLinuxHost(); fixtureState.prlimit = tools.prlimit; fixtureState.git = tools.git;
  python = await trustedExecutable("/usr/bin/python3");
}
it.skipIf(!required)("requires an actual eligible nonroot Linux x64 host and trusted Git/prlimit/Python for transport resource proof", preflight);

afterEach(async () => {
  for (const operation of pending) operation.controller.abort();
  await Promise.all(pending.splice(0).map((operation) => operation.settled));
  for (const capability of capabilities.splice(0)) await disposePublicRepository(capability).catch(() => {});
  // Stop only still-running process groups created by this file if an assertion
  // interrupts a test before the production cancellation path completes.
  const closing = fixtureState.commands.filter((record) => !record.closed).map(({ child }) => new Promise<void>((resolve) => child.once("close", () => resolve())));
  for (const record of fixtureState.commands) if (!record.closed && record.child.pid) { try { process.kill(-record.child.pid, "SIGKILL"); } catch {} }
  await Promise.all(closing);
  for (const { server, sockets } of servers.splice(0)) {
    const closed = server.listening ? new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())) : Promise.resolve();
    for (const socket of sockets) socket.destroy();
    await closed; server.removeAllListeners();
  }
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  fixtureState.source = ""; fixtureState.sha = ""; fixtureState.fetchUrl = ""; fixtureState.commands.length = 0; fixtureState.requests.length = 0; fixtureState.unexpectedLaunches.length = 0;
});

// This writer streams an ordinary valid SHA-1 loose blob; memory stays bounded
// to 1 MiB input chunks. It never creates a multi-GiB uncompressed working file.
const objectWriter = `import hashlib, json, os, sys, zlib
gitdir, size, kind = sys.argv[1], int(sys.argv[2]), sys.argv[3]
header = ('blob %d\\0' % size).encode('ascii')
digest = hashlib.sha1(header)
compressor = zlib.compressobj()
temporary = os.path.join(gitdir, 'objects', 'fixture-object')
chunk = b'\\0' * (1024 * 1024)
with open(temporary, 'xb') as output:
    output.write(compressor.compress(header))
    remaining = size
    while remaining:
        count = min(remaining, len(chunk))
        data = os.urandom(count) if kind == 'random' else chunk[:count]
        digest.update(data)
        output.write(compressor.compress(data))
        remaining -= count
    output.write(compressor.flush())
oid = digest.hexdigest()
directory = os.path.join(gitdir, 'objects', oid[:2])
os.makedirs(directory, exist_ok=True)
target = os.path.join(directory, oid[2:])
os.rename(temporary, target)
print(json.dumps({'oid': oid, 'logical': size, 'stored': os.stat(target).st_size, 'path': target}))
`;

async function fileManifest(root: string): Promise<Record<string, { size: number; digest: string }>> {
  const result: Record<string, { size: number; digest: string }> = {};
  async function visit(directory: string) {
    for (const name of await readdir(directory)) {
      const file = path.join(directory, name); const stat = await lstat(file);
      if (stat.isDirectory()) await visit(file);
      else {
        expect(stat.isFile()).toBe(true); const digest = createHash("sha256");
        for await (const chunk of createReadStream(file)) digest.update(chunk);
        result[path.relative(root, file)] = { size: stat.size, digest: digest.digest("hex") };
      }
    }
  }
  await visit(root); return result;
}
async function fixture(size: number, kind: "zero" | "random", packed: boolean) {
  const root = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-transport-linux-")); roots.push(root);
  const source = path.join(root, "source"); const empty = path.join(root, "empty"); await mkdir(source); await mkdir(empty);
  const env = { ...neutralEnvironment(empty, root), GIT_AUTHOR_NAME: "Synthetic Public", GIT_AUTHOR_EMAIL: "public@example.invalid",
    GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Synthetic Public", GIT_COMMITTER_EMAIL: "public@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync(fixtureState.git,
    ["-c", "core.hooksPath=" + empty, "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", "-c", "pack.threads=1", ...args],
    { cwd: source, env, ...(input === undefined ? {} : { input }), maxBuffer: HOST_LIMITS.output, timeout: 120_000 });
  git(["init", "-q", "--object-format=sha1", "--initial-branch=main", `--template=${empty}`]);
  const writer = path.join(root, "object-writer.py"); await writeFile(writer, objectWriter, { mode: 0o600 });
  // Known synthetic preparation is intentionally outside production acquisition;
  // no untrusted source, operator repository, authentication or checkout is read.
  const blob = JSON.parse(execFileSync(python, ["-I", "-S", writer, path.join(source, ".git"), String(size), kind],
    { cwd: root, env: neutralEnvironment(empty, root), maxBuffer: HOST_LIMITS.output, timeout: 120_000 }).toString()) as
    { oid: string; logical: number; stored: number; path: string };
  expect(blob.logical).toBe(size); expect(blob.oid).toMatch(/^[a-f0-9]{40}$/);
  expect(Number(git(["cat-file", "-s", blob.oid]).toString())).toBe(size);
  // --missing avoids decompressing the deliberately enormous valid blob during
  // fixture construction. The writer above creates its ordinary object bytes.
  const tree = git(["mktree", "--missing"], `100644 blob ${blob.oid}\tpayload.bin\n`).toString().trim();
  const sha = git(["commit-tree", tree], "Synthetic bounded transport resource fixture\n").toString().trim();
  git(["update-ref", "refs/heads/main", sha]); await writeFile(path.join(source, "original-canary"), "disposable source must remain unchanged\n");
  if (packed) git(["-c", "pack.window=0", "repack", "-ad"]);
  fixtureState.source = source; fixtureState.sha = sha;
  return { root, source, blob, sha, git, before: await fileManifest(source) };
}
async function acquire() {
  const controller = new AbortController(); const operation = acquirePublicBase("example/public", fixtureState.sha, { signal: controller.signal });
  pending.push({ controller, settled: operation.catch(() => {}) });
  const capability = await operation; capabilities.push(capability); return capability;
}
async function dumbHttp(source: Awaited<ReturnType<typeof fixture>>) {
  const responses = new Map<string, { type: string; bytes: Buffer }>();
  const refs = { type: "text/plain; charset=utf-8", bytes: Buffer.from(`${source.sha}\trefs/heads/main\n`) };
  responses.set("/public.git/info/refs?service=git-upload-pack", refs); responses.set("/public.git/info/refs", refs);
  responses.set("/public.git/HEAD", { type: "text/plain; charset=utf-8", bytes: Buffer.from("ref: refs/heads/main\n") });
  responses.set("/public.git/objects/info/packs", { type: "text/plain; charset=utf-8", bytes: Buffer.from("\n") });
  for (const file of Object.keys(source.before).filter((name) => /^\.git\/objects\/[a-f0-9]{2}\/[a-f0-9]{38}$/.test(name)))
    responses.set("/public.git/" + file.slice(".git/".length), { type: "application/octet-stream", bytes: await readFile(path.join(source.source, file)) });
  const requests: Array<{ method: string; path: string; hasAuthorization: boolean }> = [];
  const sockets = new Set<Socket>();
  const server = createServer((request, response) => {
    const route = request.url ?? "";
    requests.push({ method: request.method ?? "", path: route, hasAuthorization: request.headers.authorization !== undefined });
    // The complete route table holds frozen public fixture bytes. No URL ever
    // becomes a filesystem path, and no redirect/auth/challenge route exists.
    const body = request.method === "GET" ? responses.get(route) : undefined;
    response.writeHead(body ? 200 : 404, { "Content-Type": body?.type ?? "text/plain", "Connection": "close" });
    response.end(body?.bytes ?? Buffer.from("Unknown public fixture route\n"));
  });
  server.maxConnections = 4; server.maxHeadersCount = 16; server.requestTimeout = 5000; server.headersTimeout = 1000;
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  servers.push({ server, sockets });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); expect(address && typeof address !== "string").toBeTruthy();
  if (!address || typeof address === "string") throw new Error("Missing fixture loopback port.");
  fixtureState.fetchUrl = `http://127.0.0.1:${address.port}/public.git`;
  return requests;
}
function assertLimitedLaunches() {
  expect(fixtureState.unexpectedLaunches, "No unrestricted command or fallback may bypass real prlimit.").toEqual([]);
  expect(fixtureState.commands.length).toBeGreaterThan(0);
  for (const record of fixtureState.commands) {
    expect(record.closed).toBe(true); expect(record.command).toBe(fixtureState.prlimit);
    expect(record.original.slice(0, 8)).toEqual(["--fsize=67108864:67108864", "--cpu=60:60", "--as=1073741824:1073741824",
      "--nofile=64:64", "--nproc=128:128", "--core=0:0", "--", fixtureState.git]);
    expect(record.launched.slice(0, 8)).toEqual(record.original.slice(0, 8));
  }
  expect(fixtureState.requests).toHaveLength(2);
  for (const request of fixtureState.requests) expect(request).toMatchObject({ hostname: "api.github.com", agent: false,
    headers: expect.not.objectContaining({ Authorization: expect.anything() }) });
}
function phaseObservations() {
  return fixtureState.commands.map(({ original, child }) => ({
    phase: ["--exec-path", "init", "fetch", "rev-parse", "fsck", "ls-tree", "cat-file"].find((phase) => original.includes(phase)),
    ...(original.includes("cat-file") ? { operation: original.includes("-s") ? "size" : original.at(-2) } : {}),
    exit: child.exitCode, signal: child.signalCode
  }));
}
async function assertNoAuthorityAndPreserved(source: Awaited<ReturnType<typeof fixture>>) {
  expect(capabilities).toHaveLength(0); assertLimitedLaunches();
  const fetches = fixtureState.commands.filter(({ original }) => original.includes("fetch"));
  expect(fetches, "Exactly one bounded fetch; no unrestricted or fallback retry.").toHaveLength(1);
  const fetch = fetches[0]!;
  expect(fetch.original).toEqual(expect.arrayContaining(["--keep", "--depth=10000", "--no-tags", "--no-recurse-submodules",
    "--no-auto-maintenance", "--no-write-commit-graph", "--no-write-fetch-head", "https://github.com/example/public.git"]));
  expect(fetch.launched).toContain(fixtureState.fetchUrl || pathToFileURL(source.source).href);
  expect(fetch.launched).toContain(fixtureState.fetchUrl ? "protocol.http.allow=always" : "protocol.file.allow=always");
  expect(fetch.invalidObjectShape).toBe(false);
  expect(fetch.looseDirectories).toEqual([]);
  expect(fetch.packFiles.filter(({ name }) => name.endsWith(".pack") || name.startsWith("tmp_pack_")).length).toBeLessThanOrEqual(1);
  expect(fetch.packFiles.filter(({ name }) => name.endsWith(".idx") || name.startsWith("tmp_idx_")).length).toBeLessThanOrEqual(1);
  expect(fetch.packFiles.filter(({ name }) => name.endsWith(".keep")).length).toBeLessThanOrEqual(1);
  for (const file of fetch.packFiles) {
    expect(file.regular).toBe(true); expect(file.bytes).toBeLessThanOrEqual(67108864);
    expect(file.name).toMatch(/^(?:tmp_(?:pack|idx)_[A-Za-z0-9]+|pack-[a-f0-9]{40}\.(?:pack|idx|keep))$/);
    if (file.name.endsWith(".keep")) expect(file.bytes).toBeLessThanOrEqual(4096);
  }
  for (const directory of new Set(fixtureState.commands.map(({ cwd }) => cwd)))
    await expect(lstat(directory)).rejects.toMatchObject({ code: "ENOENT" });
  expect(source.git(["rev-parse", "HEAD"]).toString().trim()).toBe(source.sha);
  expect(await fileManifest(source.source)).toEqual(source.before);
  expect(await readFile(path.join(source.source, "original-canary"), "utf8")).toBe("disposable source must remain unchanged\n");
}

// Explicit skip on Darwin; mandatory preflight above still fails closed there.
// Run only on a dedicated nonroot Linux x64 host with:
// BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS=1 npm test -- tests/upgrade-transport-linux.test.ts
describe.skipIf(!required || !linux)("actual Git transport resource failures under Linux prlimit (explicit opt-in)", () => {
  beforeAll(preflight);

  it("accepts a small ordinary source through the same literal-URL adapter and real limited pipeline", async () => {
    const source = await fixture(4096, "zero", false); const capability = await acquire();
    expect(capability.baseCommit).toBe(source.sha); const context = transportContext(capability);
    const packed = await readdir(path.join(context.gitdir, "objects", "pack"));
    expect(packed.filter((name) => /^pack-[a-f0-9]{40}\.pack$/.test(name))).toHaveLength(1);
    expect(packed.filter((name) => /^pack-[a-f0-9]{40}\.idx$/.test(name))).toHaveLength(1);
    assertLimitedLaunches(); await disposePublicRepository(capability);
    await expect(lstat(context.directory)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await fileManifest(source.source)).toEqual(source.before);
  }, 30_000);

  it("rejects dumb HTTP at positive depth before requesting objects or writing any object payload", async () => {
    const source = await fixture(4096, "zero", false); const requests = await dumbHttp(source);
    await expect(acquire()).rejects.toThrow(new Error(fixed)); await assertNoAuthorityAndPreserved(source);
    const fetch = fixtureState.commands.find(({ original }) => original.includes("fetch"))!;
    expect(fetch.original).toContain("--depth=10000"); expect(fetch.child.exitCode).not.toBe(0);
    expect(requests).toContainEqual({ method: "GET", path: "/public.git/info/refs?service=git-upload-pack", hasAuthorization: false });
    expect(requests.every(({ method, path: route, hasAuthorization }) => method === "GET" && !hasAuthorization &&
      ["/public.git/info/refs?service=git-upload-pack", "/public.git/info/refs", "/public.git/HEAD"].includes(route))).toBe(true);
    expect(requests.filter(({ path: route }) => route.startsWith("/public.git/objects/"))).toEqual([]);
    expect(fetch.objectPayloadBytes).toBe(0); expect(fetch.packFiles).toEqual([]); expect(fetch.looseDirectories).toEqual([]);
    console.info("Synthetic dumb-HTTP depth refusal:", JSON.stringify({ requests, phases: phaseObservations(), objectPayloadBytes: fetch.objectPayloadBytes }));
  }, 30_000);

  it("rejects an incompressible source pack over 64 MiB without authority, retry, lingering owned processes or source changes", async () => {
    const source = await fixture(72 * 1024 ** 2, "random", true);
    const packs = Object.entries(source.before).filter(([name]) => /^\.git\/objects\/pack\/pack-[a-f0-9]{40}\.pack$/.test(name));
    expect(packs).toHaveLength(1); expect(packs[0]![1].size).toBeGreaterThan(67108864);
    await expect(acquire()).rejects.toThrow(new Error(fixed)); await assertNoAuthorityAndPreserved(source);
    const fetch = fixtureState.commands.find(({ original }) => original.includes("fetch"))!;
    expect(fetch.child.exitCode !== 0 || fetch.child.signalCode !== null, "The actual oversized fetch must fail, rather than succeeding and relying on an after-the-fact audit.").toBe(true);
    console.info("Synthetic oversized-pack refusal:", JSON.stringify(phaseObservations()));
  }, 240_000);

  it("refuses a valid 2 GiB logical blob stored in a few MiB without authority or source mutation", async () => {
    const source = await fixture(2 * 1024 ** 3, "zero", false);
    expect(source.blob.logical).toBeGreaterThan(1073741824); expect(source.blob.stored).toBeLessThan(4 * 1024 ** 2);
    await expect(acquire()).rejects.toThrow(new Error(fixed)); await assertNoAuthorityAndPreserved(source);
    // Git versions may stream huge ordinary blobs. Refusal can occur in a
    // bounded Git command or at the explicit logical source ceiling; no specific
    // allocator behavior or AS failure is inferred merely from the blob size.
    const failed = fixtureState.commands.some(({ child }) => child.exitCode !== 0 || child.signalCode !== null);
    if (!failed) {
      const last = fixtureState.commands.at(-1)!;
      expect(last.original.slice(-3)).toEqual(["cat-file", "-s", source.blob.oid]);
      expect(last.child.exitCode).toBe(0);
    }
    console.info("Synthetic 2-GiB-blob refusal:", JSON.stringify({ mechanism: failed ? "bounded Git failure" : "512-MiB logical source ceiling", phases: phaseObservations() }));
  }, 240_000);
});
