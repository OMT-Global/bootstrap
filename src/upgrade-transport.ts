import { createHash } from "node:crypto";
import https from "node:https";
import { lstat, mkdir, mkdtemp, opendir, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ISOLATION_LIMITS, type IsolatedSourceFile } from "./isolation/node-profile.js";
import { copySnapshotFiles, decodeGitPath, openDataRepository, verifyGitSnapshot, type DataRepository, type VerifiedGitSnapshot } from "./upgrade-git.js";
import { auditCheckout, type CheckoutAudit } from "./upgrade-checkout.js";
import { HOST_LIMITS, PRLIMIT_ARGS, boundedCommand, decode, demand, hostFailure, neutralEnvironment, readRegular, requireLinuxHost, trustedExecutable } from "./upgrade-host.js";

const sha1 = (kind: string, bytes: Uint8Array) => createHash("sha1").update(`${kind} ${bytes.byteLength}\0`).update(bytes).digest("hex");
const baseRef = "refs/heads/codex/bootstrap-public-base";
export interface PublicRepository { readonly repository: string; readonly defaultBranch: string; readonly baseCommit: string; readonly snapshot: VerifiedGitSnapshot }
interface Lease { readonly bytes: number; releaseAfterCleanup(cleanup: () => Promise<void>): Promise<void> }
export interface TransportContext {
  directory: string; root: string; gitdir: string; empty: string; git: string; prlimit: string; execPath: string;
  env: NodeJS.ProcessEnv; signal: AbortSignal; candidate?: string; preparedTree?: string; signedBranch?: string; signedPlanSha256?: string; pending: Set<Promise<unknown>>; reserve(bytes: number): Lease;
}
interface InventoryFacts { total: number; objects: number; files: number; entries: number; paths: number; index: number }
interface State extends TransportContext { helpers: Set<DataRepository>; cancellation: AbortController; disposed: boolean; reservations: number; facts?: Readonly<InventoryFacts> }
const states = new WeakMap<PublicRepository, State>();
// This accessor is for trusted sibling fixed-operation modules only, never a caller command surface.
export function transportContext(repository: PublicRepository): TransportContext { const state = states.get(repository); demand(state && !state.disposed && !state.signal.aborted); return state; }
export function gitArguments(context: Pick<TransportContext, "empty">, args: readonly string[]): string[] {
  return ["protocol.allow=never", "protocol.https.allow=always", "protocol.version=0", "http.sslVerify=true", "http.followRedirects=false", "http.maxRequests=1", "http.proxy=", "http.extraHeader=", "http.cookieFile=", "credential.helper=", "credential.useHttpPath=true",
    "core.hooksPath=" + context.empty, "core.fsmonitor=false", "core.attributesFile=/dev/null", "core.excludesFile=/dev/null", "core.autocrlf=false", "core.ignoreCase=false", "core.logAllRefUpdates=false", "core.pager=cat", "gc.auto=0", "maintenance.auto=false", "fetch.writeCommitGraph=false", "fetch.parallel=1", "fetch.unpackLimit=1", "transfer.unpackLimit=1", "pack.threads=1", "index.threads=1", "pack.writeReverseIndex=false", "fetch.fsckObjects=true", "transfer.fsckObjects=true"]
    .flatMap((value) => ["-c", value]).concat(args);
}
async function git(context: TransportContext, args: readonly string[], input?: Uint8Array, output = HOST_LIMITS.output): Promise<Buffer> {
  const pending = boundedCommand(context.prlimit, [...PRLIMIT_ARGS, context.git, ...gitArguments(context, args)], { cwd: context.directory, env: context.env, signal: context.signal, output, combinedOutput: output === HOST_LIMITS.output ? HOST_LIMITS.output : output + HOST_LIMITS.output, ...(input ? { input } : {}) });
  context.pending.add(pending); try { return await pending; } finally { context.pending.delete(pending); }
}
function branch(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value) && !value.includes("..") && !value.includes("//") && value.split("/").every((part) => !part.endsWith(".") && !part.endsWith(".lock"));
}
async function publicJson(endpoint: string, signal: AbortSignal): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const request = https.get({ hostname: "api.github.com", port: 443, path: endpoint, method: "GET", agent: false, rejectUnauthorized: true, signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
      headers: { Accept: "application/vnd.github+json", "User-Agent": "bootstrap-public-upgrade", "X-GitHub-Api-Version": "2026-03-10" } }, (response) => {
      if (response.statusCode !== 200 || !/^application\/json(?:;|$)/i.test(String(response.headers["content-type"]))) { response.destroy(); reject(hostFailure()); return; }
      let size = 0; const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => { size += chunk.length; if (size > HOST_LIMITS.output) { response.destroy(); reject(hostFailure()); } else chunks.push(chunk); });
      response.once("error", () => reject(hostFailure()));
      response.once("end", () => { try { resolve(JSON.parse(decode(Buffer.concat(chunks)))); } catch { reject(hostFailure()); } });
    });
    request.setTimeout(30_000, () => request.destroy(hostFailure())); request.once("error", () => reject(hostFailure()));
  });
}
function record(value: unknown): Record<string, unknown> { demand(value && typeof value === "object" && !Array.isArray(value)); return value as Record<string, unknown>; }
async function verifyPublic(repository: string, baseCommit: string, signal: AbortSignal): Promise<string> {
  demand(/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(repository) && /^[a-f0-9]{40}$/.test(baseCommit));
  const metadata = record(await publicJson(`/repos/${repository}`, signal));
  demand(metadata.full_name === repository && metadata.private === false && metadata.visibility === "public" && metadata.clone_url === `https://github.com/${repository}.git` && metadata.disabled === false && metadata.archived === false && typeof metadata.default_branch === "string" && branch(metadata.default_branch));
  const ref = record(await publicJson(`/repos/${repository}/git/ref/heads/${encodeURIComponent(metadata.default_branch)}`, signal));
  const object = record(ref.object); demand(ref.ref === `refs/heads/${metadata.default_branch}` && object.type === "commit" && object.sha === baseCommit);
  return metadata.default_branch;
}
async function auditPack(context: TransportContext): Promise<void> {
  let count = 0; let metadata = 0; const packs: string[] = []; const indexes: string[] = []; let keeps = 0;
  const directories = new Set(["", "objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/heads/codex", "refs/tags"]);
  const files = new Set(["HEAD", "config", "refs/heads/codex/bootstrap-public-base"]);
  const walk = async (relative: string): Promise<void> => {
    for await (const entry of await opendir(path.join(context.gitdir, relative))) {
      const name = entry.name;
      demand(++count <= 64 && /^[A-Za-z0-9._-]+$/.test(name)); const item = relative ? `${relative}/${name}` : name; const file = path.join(context.gitdir, item);
      const stat = await lstat(file);
      if (stat.isDirectory()) { demand(directories.has(item)); await walk(item); continue; }
      demand(stat.isFile() && stat.nlink === 1 && !(stat.mode & 0o111));
      const pack = /^objects\/pack\/pack-([a-f0-9]{40})\.(pack|idx|keep)$/.exec(item);
      if (pack) {
        demand(stat.size <= (pack[2] === "keep" ? 4096 : HOST_LIMITS.bytes));
        if (pack[2] === "pack") packs.push(pack[1]!); else if (pack[2] === "idx") indexes.push(pack[1]!); else keeps++;
      } else { demand(files.has(item)); metadata += stat.size; demand(metadata <= HOST_LIMITS.output); }
      await readRegular(file, pack && pack[2] !== "keep" ? HOST_LIMITS.bytes : HOST_LIMITS.output);
    }
  };
  await walk(""); demand(packs.length === 1 && indexes.length === 1 && packs[0] === indexes[0] && keeps <= 1);
  demand(decode(await git(context, ["rev-parse", "--verify", baseRef])).trim() !== "");
  await git(context, ["fsck", "--strict", "--no-reflogs"]);
}
async function snapshot(context: TransportContext, baseCommit: string): Promise<{ verified: VerifiedGitSnapshot; facts: InventoryFacts; inspection: number }> {
  const commitBytes = await git(context, ["cat-file", "commit", baseCommit]);
  const listing = await git(context, ["ls-tree", "-r", "-z", "--full-tree", baseCommit], undefined, HOST_LIMITS.bytes);
  demand(listing.length > 0 && listing.at(-1) === 0); const files: IsolatedSourceFile[] = []; let total = 0;
  for (const line of listing.subarray(0, -1).toString("binary").split("\0")) {
    demand(files.length < ISOLATION_LIMITS.files); const raw = Buffer.from(line, "binary"); const separator = raw.indexOf(9);
    const header = /^(100644|100755) blob ([a-f0-9]{40})$/.exec(raw.subarray(0, separator).toString("ascii")); demand(separator > 0 && header);
    const name = decodeGitPath(raw.subarray(separator + 1)); const sizeText = decode(await git(context, ["cat-file", "-s", header[2]!]));
    demand(/^(?:0|[1-9][0-9]*)\n$/.test(sizeText)); const size = Number(sizeText); demand(Number.isSafeInteger(size)); total += size; demand(total <= ISOLATION_LIMITS.sourceBytes);
    // Chunks, concat output and the helper's retained private copy can coexist.
    context.reserve(3 * size + 4096);
    const bytes = await git(context, ["cat-file", "blob", header[2]!], undefined, size); demand(bytes.length === size);
    files.push({ path: name, mode: header[1] as "100644" | "100755", bytes });
  }
  const facts = inventory(files, commitBytes.length); const verified = verifyGitSnapshot({ baseCommit, commitBytes, files });
  return { verified, facts, inspection: 16 * listing.length + 8 * commitBytes.length + 4096 * facts.entries };
}
function inventory(files: readonly IsolatedSourceFile[], commitBytes = ISOLATION_LIMITS.manifestBytes): InventoryFacts {
  demand(files.length > 0 && files.length <= ISOLATION_LIMITS.files); let total = 0; let objects = 2 * commitBytes + 4096; let paths = 0; let index = 0; const names = new Set<string>(); const trees = new Map<string, Map<string, number>>([["", new Map()]]);
  for (const file of files) {
    demand(file.bytes instanceof Uint8Array && ["100644", "100755"].includes(file.mode)); const name = decodeGitPath(Buffer.from(file.path)); demand(!names.has(name) && !["node_modules", "dist"].includes(name.split("/")[0]!)); names.add(name);
    total += file.bytes.byteLength; objects += 2 * file.bytes.byteLength + 4096; paths += Buffer.byteLength(name); index += 49 + Buffer.byteLength(name);
    const parts = name.split("/");
    for (let end = 0; end < parts.length; end++) {
      const parent = parts.slice(0, end).join("/"); if (!trees.has(parent)) trees.set(parent, new Map());
      trees.get(parent)!.set(parts[end]!, Buffer.byteLength(parts[end]!) + (end === parts.length - 1 ? 28 : 27));
    }
  }
  demand(total <= ISOLATION_LIMITS.sourceBytes && names.size + trees.size - 1 <= ISOLATION_LIMITS.entries);
  for (const tree of trees.keys()) demand(!names.has(tree));
  for (const entries of trees.values()) objects += 2 * [...entries.values()].reduce((sum, value) => sum + value, 0) + 4096;
  return { total, objects, files: files.length, entries: names.size + trees.size - 1, paths, index };
}
const helperFraming = (facts: InventoryFacts) => 4 * ISOLATION_LIMITS.lockBytes + 8 * HOST_LIMITS.output + 8 * facts.index + 8 * facts.paths + 4096 * facts.entries;
const helperBudget = (facts: InventoryFacts) => facts.total + facts.objects + helperFraming(facts);
function cachedFacts(repository: PublicRepository): Readonly<InventoryFacts> { const facts = states.get(repository)?.facts; demand(facts); return facts; }
export async function acquirePublicBase(repository: string, baseCommit: string, options: { signal?: AbortSignal } = {}): Promise<PublicRepository> {
  let directory: string | undefined;
  try {
    demand(["NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE", "SSL_CERT_DIR", "OPENSSL_CONF"].every((name) => !process.env[name]));
    const tools = await requireLinuxHost(); const cancellation = new AbortController(); const signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(ISOLATION_LIMITS.phaseMs), ...(options.signal ? [options.signal] : [])]);
    const defaultBranch = await verifyPublic(repository, baseCommit, signal);
    directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-upgrade-host-")); const root = path.join(directory, "source"); const empty = path.join(directory, "empty");
    await mkdir(root); await mkdir(empty); const env = neutralEnvironment(empty, directory);
    const execPath = decode(await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, tools.git, "--exec-path"], { cwd: directory, env, signal })).trim();
    demand(path.isAbsolute(execPath)); await trustedExecutable(path.join(execPath, "git-remote-https"));
    const state: State = { ...tools, execPath, root, empty, directory, gitdir: path.join(root, ".git"), env, signal, cancellation, disposed: false, reservations: 0, helpers: new Set(), pending: new Set(),
      reserve(bytes: number): Lease {
        demand(!state.disposed && !signal.aborted && Number.isSafeInteger(bytes) && bytes >= 0 && state.reservations + bytes <= HOST_LIMITS.admission); state.reservations += bytes;
        let released = false; let releasing: Promise<void> | undefined;
        return Object.freeze({ bytes, releaseAfterCleanup(cleanup: () => Promise<void>): Promise<void> {
          if (released) return Promise.resolve(); if (releasing) return releasing;
          releasing = (async () => { await cleanup(); state.reservations -= bytes; released = true; })().catch((error) => { releasing = undefined; throw error; });
          return releasing;
        } });
      } };
    state.reserve(129 * 1024 ** 2); Object.assign(env, { GIT_DIR: state.gitdir, GIT_WORK_TREE: root, GIT_EXEC_PATH: execPath });
    await git(state, ["init", "--quiet", "--object-format=sha1", "--initial-branch=codex/bootstrap-preparation", `--template=${empty}`]);
    await git(state, ["fetch", "--keep", "--depth=10000", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance", "--no-write-commit-graph", "--no-write-fetch-head", `https://github.com/${repository}.git`, `${baseCommit}:${baseRef}`]);
    const envelope = 16 * HOST_LIMITS.bytes + 8 * HOST_LIMITS.output + 4096 * ISOLATION_LIMITS.entries; state.reserve(envelope);
    await auditPack(state); demand(decode(await git(state, ["rev-parse", "--verify", baseRef])).trim() === baseCommit);
    const frozen = await snapshot(state, baseCommit); demand(frozen.inspection <= envelope);
    // Only never-used upper capacity retires; all observed framing and >=3*n blob charges remain held.
    state.reservations -= envelope - frozen.inspection; state.facts = Object.freeze(frozen.facts);
    const result = Object.freeze({ repository, defaultBranch, baseCommit, snapshot: frozen.verified }); states.set(result, state); return result;
  } catch { if (directory) try { await rm(directory, { recursive: true, force: true }); } catch { /* Failure includes uncertain cleanup; never return authority. */ } throw hostFailure(); }
}
export async function openReservedDataRepository(repository: PublicRepository): Promise<DataRepository> {
  const state = transportContext(repository); const lease = state.reserve(helperBudget(cachedFacts(repository)));
  let result: DataRepository;
  try { result = await openDataRepository(repository.snapshot, { signal: state.signal }); }
  catch { /* A failed helper cleanup may retain bytes; retain its reservation. */ throw hostFailure(); }
  const wrapped = Object.freeze({ ...result, dispose: async () => {
    try { await lease.releaseAfterCleanup(async () => { await result.dispose(); states.get(repository)!.helpers.delete(wrapped); }); } catch { throw hostFailure(); }
  } });
  states.get(repository)!.helpers.add(wrapped); return wrapped;
}
export function copyReservedSnapshotFiles(repository: PublicRepository): IsolatedSourceFile[] {
  const state = transportContext(repository); const facts = cachedFacts(repository); state.reserve(facts.total + 4096 * facts.entries);
  return copySnapshotFiles(repository.snapshot);
}
export async function auditPublicCheckout(repository: PublicRepository, root: string): Promise<CheckoutAudit> {
  const state = transportContext(repository); const facts = cachedFacts(repository);
  // Per-file fstat<=verified blob size in the unchanged audit rejects dirty oversized reads before allocation.
  state.reserve(helperBudget(facts) + 3 * facts.total + facts.files + 8 * (ISOLATION_LIMITS.entries * 4096) + 8 * ISOLATION_LIMITS.outputBytes + 4 * ISOLATION_LIMITS.lockBytes + 8 * HOST_LIMITS.output);
  try {
    demand((await lstat(root)).isDirectory()); root = await realpath(root); demand((await lstat(path.join(root, ".git"))).isDirectory());
    const headPath = path.join(root, ".git/HEAD"); const head = await readRegular(headPath, 4096); const expected = `ref: refs/heads/${repository.defaultBranch}`;
    demand(decode(head) === expected || decode(head) === expected + "\n");
    const result = await auditCheckout(root, repository.snapshot, `https://github.com/${repository.repository}.git`, { signal: state.signal });
    demand((await readRegular(headPath, 4096)).equals(head) && transportContext(repository) === state); return result;
  } catch { throw hostFailure(); }
}
export function reserveUpgradePreparation(repository: PublicRepository, files: readonly IsolatedSourceFile[]): Readonly<{ bytes: number }> {
  const state = transportContext(repository); const size = inventory(files);
  // Renderer final + replacement bytes, separate target loose objects, index/locks and temporary framing.
  return Object.freeze({ bytes: state.reserve(2 * size.total + size.objects + helperFraming(size)).bytes });
}
export async function writeFrozenTree(repository: PublicRepository, files: readonly IsolatedSourceFile[]): Promise<{ tree: string; snapshot: VerifiedGitSnapshot }> {
  const state = transportContext(repository); demand(!state.preparedTree && !state.candidate);
  const size = inventory(files); state.reserve(2 * size.total + size.objects + helperFraming(size));
  const frozen = files.map((file) => ({ ...file, bytes: Buffer.from(file.bytes) }));
  const entries: Buffer[] = [];
  for (const file of frozen) {
    const oid = sha1("blob", file.bytes); demand(decode(await git(state, ["hash-object", "--no-filters", "-w", "--stdin"], file.bytes)).trim() === oid);
    entries.push(Buffer.from(`${file.mode} ${oid}\t${file.path}\0`));
  }
  await git(state, ["read-tree", "--empty"]); await git(state, ["update-index", "-z", "--index-info"], Buffer.concat(entries)); const tree = decode(await git(state, ["write-tree"])).trim();
  demand(/^[a-f0-9]{40}$/.test(tree)); const commitBytes = Buffer.from(`tree ${tree}\nparent ${repository.baseCommit}\nauthor Public Tree <tree@example.invalid> 0 +0000\ncommitter Public Tree <tree@example.invalid> 0 +0000\n\nPublic consistency proof\n`);
  const verified = verifyGitSnapshot({ baseCommit: sha1("commit", commitBytes), commitBytes, files: frozen }); states.get(repository)!.preparedTree = verified.tree;
  return Object.freeze({ tree: verified.tree, snapshot: verified });
}
export async function createBoundedBundle(repository: PublicRepository, candidate?: string): Promise<Buffer> {
  const state = transportContext(repository); demand(candidate === undefined || /^[a-f0-9]{40}$/.test(candidate) && candidate === state.candidate);
  // Retained bytes and one host transfer copy may coexist before backend storage takes ownership.
  state.reserve(2 * HOST_LIMITS.bytes); const refs = [baseRef];
  if (candidate) { const ref = "refs/heads/codex/bootstrap-signed-candidate"; await git(state, ["update-ref", ref, candidate, "0000000000000000000000000000000000000000"]); refs.push(ref); }
  return git(state, ["bundle", "create", "--version=2", "-", ...refs], undefined, HOST_LIMITS.bytes);
}
export async function disposePublicRepository(repository: PublicRepository): Promise<void> {
  const state = states.get(repository); demand(state); state.disposed = true; state.cancellation.abort();
  try {
    await Promise.allSettled(state.pending);
    for (const helper of state.helpers) { await helper.dispose(); state.helpers.delete(helper); }
    await rm(state.directory, { recursive: true, force: true });
  } catch { throw hostFailure(); }
}
