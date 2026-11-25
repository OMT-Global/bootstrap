import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, opendir, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ISOLATION_LIMITS, type IsolatedSourceFile } from "./isolation/node-profile.js";
import { copySnapshotFiles, decodeGitPath, verifyGitSnapshot, type VerifiedGitSnapshot } from "./upgrade-git.js";
import { boundedGitCommand, decode, demand, gitArguments, HOST_LIMITS, neutralEnvironment, PRLIMIT_ARGS, readRegular, requireLinuxHost, trustedExecutable } from "./upgrade-host.js";
import { readOwnedPolicyObservation, type PolicyObservation } from "./upgrade-policy.js";
import { copyPreparedUpgradeSource, describePreparedUpgrade, prepareObservedUpgrade, type PreparedUpgrade } from "./upgrade-preparation.js";
import { publicHead, publicRepository, PublicObservationRead } from "./upgrade-public-read.js";

declare const historyBrand: unique symbol;
export type PreparedHistory = { readonly [historyBrand]: true };
interface PublicBase {
  repository: string; id: number; head: string; defaultBranch?: string;
}
interface PublicGit {
  base: PublicBase; directory: string; gitdir: string; empty: string; git: string; prlimit: string;
  env: NodeJS.ProcessEnv; signal: AbortSignal; cancellation: AbortController; pending: Set<Promise<Buffer>>;
  lifetime: AbortSignal; closed: boolean;
}
interface State extends PublicGit {
  candidate: PreparedUpgrade; bundle: Buffer; candidateCommit?: string; disposal?: Promise<void>;
}
const histories = new WeakMap<PreparedHistory, State>();
const baseRef = "refs/heads/codex/bootstrap-public-base";
const candidateRef = "refs/heads/codex/bootstrap-signed-candidate";
const blobBatchBytes = 16 * 1024 ** 2;
const failure = () => new Error("Prepared public history unavailable.");
const oid = (kind: string, bytes: Uint8Array) => createHash("sha1").update(`${kind} ${bytes.byteLength}\0`).update(bytes).digest("hex");
function state(handle: PreparedHistory, candidate: PreparedUpgrade): State {
  const value = histories.get(handle); demand(value && !value.closed && value.candidate === candidate);
  value.signal.throwIfAborted(); describePreparedUpgrade(candidate); return value;
}
async function git(value: PublicGit, args: string[], input?: Uint8Array, output = HOST_LIMITS.output): Promise<Buffer> {
  const operation = boundedGitCommand(value.prlimit, [...PRLIMIT_ARGS, value.git, ...gitArguments(value, args)],
    { cwd: value.directory, env: value.env, signal: value.signal, output, combinedOutput: output + HOST_LIMITS.output, ...(input ? { input } : {}) });
  value.pending.add(operation); try { return await operation; } finally { value.pending.delete(operation); }
}
async function refresh(value: PublicGit): Promise<void> {
  const read = new PublicObservationRead(value.signal, value.base.repository);
  try {
    const identity = await publicRepository(read, value.base);
    demand(await publicHead(read, identity.repository, identity.defaultBranch) === value.base.head);
    value.base.defaultBranch = identity.defaultBranch; read.check();
  } finally { await read.close(); }
}
async function auditPack(value: PublicGit): Promise<void> {
  const directories = new Set(["", "objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/heads/codex", "refs/tags"]);
  const metadata = new Set(["HEAD", "config", baseRef]); const packs: string[] = []; const indexes: string[] = [];
  let count = 0; let metadataBytes = 0; let keeps = 0;
  const walk = async (prefix: string): Promise<void> => {
    for await (const entry of await opendir(path.join(value.gitdir, prefix))) {
      value.signal.throwIfAborted(); demand(++count <= 64 && /^[A-Za-z0-9._-]+$/.test(entry.name));
      const name = prefix ? `${prefix}/${entry.name}` : entry.name; const file = path.join(value.gitdir, name); const stat = await lstat(file);
      if (stat.isDirectory()) { demand(directories.has(name)); await walk(name); continue; }
      demand(stat.isFile() && stat.nlink === 1 && !(stat.mode & 0o111));
      const pack = /^objects\/pack\/pack-([a-f0-9]{40})\.(pack|idx|keep)$/.exec(name);
      if (pack) {
        demand(stat.size <= (pack[2] === "keep" ? 4096 : ISOLATION_LIMITS.bundleBytes));
        if (pack[2] === "pack") packs.push(pack[1]!); else if (pack[2] === "idx") indexes.push(pack[1]!); else keeps++;
      } else { demand(metadata.has(name)); metadataBytes += stat.size; demand(metadataBytes <= HOST_LIMITS.output); }
      await readRegular(file, pack && pack[2] !== "keep" ? ISOLATION_LIMITS.bundleBytes : HOST_LIMITS.output);
    }
  };
  // In particular, shallow boundaries, alternates, replacement refs and grafts
  // are never admitted. A depth-limited acquisition must still be complete.
  await walk(""); demand(packs.length === 1 && indexes.length === 1 && packs[0] === indexes[0] && keeps <= 1);
  await git(value, ["fsck", "--strict", "--no-reflogs"]);
}
async function cleanup(value: PublicGit): Promise<void> {
  value.closed = true; value.cancellation.abort(); await Promise.allSettled([...value.pending]);
  await rm(value.directory, { recursive: true, force: true });
}
async function openPublicGit(base: PublicBase, parent: AbortSignal | undefined, timeout: number, candidate?: PreparedUpgrade): Promise<PublicGit> {
  let value: PublicGit | undefined; let directory: string | undefined;
  try {
    demand(parent === undefined || parent instanceof AbortSignal);
    const cancellation = new AbortController();
    const lifetime = AbortSignal.any([AbortSignal.timeout(timeout), ...(parent ? [parent] : [])]);
    const signal = AbortSignal.any([cancellation.signal, lifetime]); signal.throwIfAborted();
    const tools = await requireLinuxHost();
    signal.throwIfAborted(); directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-history-"));
    const empty = path.join(directory, "empty"); const gitdir = path.join(directory, "git"); await mkdir(empty);
    const env = neutralEnvironment(empty, directory);
    const execPath = decode(await boundedGitCommand(tools.prlimit, [...PRLIMIT_ARGS, tools.git, "--exec-path"], { cwd: directory, env, signal })).trim();
    demand(path.isAbsolute(execPath)); await trustedExecutable(path.join(execPath, "git-remote-https"));
    value = { ...tools, directory, gitdir, empty, env: { ...env, GIT_DIR: gitdir, GIT_WORK_TREE: directory, GIT_EXEC_PATH: execPath }, signal,
      base: { ...base }, lifetime, cancellation, pending: new Set(), closed: false };
    if (candidate) describePreparedUpgrade(candidate);
    await refresh(value);
    await git(value, ["init", "--quiet", "--object-format=sha1", "--initial-branch=codex/bootstrap-history", `--template=${empty}`]);
    await git(value, ["fetch", "--keep", "--depth=10000", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance", "--no-write-commit-graph", "--no-write-fetch-head",
      `https://github.com/${base.repository}.git`, `${base.head}:${baseRef}`]);
    await auditPack(value); demand(decode(await git(value, ["rev-parse", "--verify", baseRef])).trim() === base.head);
    return value;
  } catch {
    if (value) await cleanup(value).catch(() => undefined); else if (directory) await rm(directory, { recursive: true, force: true }).catch(() => undefined);
    throw failure();
  }
}

interface BlobRow { path: string; mode: IsolatedSourceFile["mode"]; oid: string; size: number }
async function snapshotFiles(value: PublicGit): Promise<IsolatedSourceFile[]> {
  const output = await git(value, ["ls-tree", "-r", "-l", "-z", "--full-tree", value.base.head], undefined, HOST_LIMITS.bytes);
  const rows: BlobRow[] = []; let total = 0;
  for (let offset = 0; offset < output.length;) {
    const end = output.indexOf(0, offset); demand(end > offset && rows.length < ISOLATION_LIMITS.files);
    const row = output.subarray(offset, end);
    const tab = row.indexOf(9); demand(tab > 0 && tab <= 80);
    const fields = /^(100644|100755) blob ([a-f0-9]{40}) +(0|[1-9][0-9]{0,9})$/.exec(decode(row.subarray(0, tab)));
    demand(fields && fields[0].length === tab);
    const size = Number(fields[3]); total += size; demand(total <= ISOLATION_LIMITS.sourceBytes);
    rows.push({ path: decodeGitPath(row.subarray(tab + 1)), mode: fields[1] === "100755" ? "100755" : "100644", oid: fields[2]!, size });
    offset = end + 1;
  }
  demand(rows.length > 0);
  const files: IsolatedSourceFile[] = [];
  // Keep the usual batch small. A single larger blob remains within the
  // already-checked total source budget.
  for (let index = 0; index < rows.length;) {
    const batch: Array<{ row: BlobRow; header: Buffer }> = []; let limit = 0;
    while (index < rows.length) {
      const row = rows[index]!;
      const header = Buffer.from(`${row.oid} blob ${row.size}\n`);
      const bytes = header.length + row.size + 1;
      if (batch.length && limit + bytes > blobBatchBytes) break;
      batch.push({ row, header }); limit += bytes; index++;
    }
    const raw = await git(value, ["cat-file", "--batch"], Buffer.from(batch.map(({ row }) => row.oid + "\n").join("")), limit);
    demand(raw.length === limit); let offset = 0;
    for (const { row, header } of batch) {
      demand(raw.subarray(offset, offset + header.length).equals(header)); offset += header.length;
      const bytes = raw.subarray(offset, offset + row.size); offset += row.size;
      demand(raw[offset++] === 10 && oid("blob", bytes) === row.oid);
      files.push({ path: row.path, mode: row.mode, bytes });
    }
  }
  return files;
}

/** Fetch the exact current public base for a genuine policy observation. */
export async function acquireObservedUpgradeSnapshot(observation: PolicyObservation, options: { signal?: AbortSignal } = {}): Promise<VerifiedGitSnapshot> {
  let value: PublicGit | undefined;
  try {
    const { repository } = readOwnedPolicyObservation(observation);
    value = await openPublicGit(repository, options.signal, ISOLATION_LIMITS.phaseMs);
    const commitBytes = await git(value, ["cat-file", "commit", repository.head], undefined, ISOLATION_LIMITS.manifestBytes);
    const files = await snapshotFiles(value);
    const snapshot = verifyGitSnapshot({ baseCommit: repository.head, commitBytes, files });
    demand(snapshot.tree === repository.tree);
    await refresh(value);
    await cleanup(value);
    value.lifetime.throwIfAborted();
    return snapshot;
  } catch {
    if (value) await cleanup(value).catch(() => undefined);
    throw failure();
  }
}

/** Compose fixed remote acquisition with the existing read-only checkout audit. */
export async function preparePublicUpgrade(input: Omit<Parameters<typeof prepareObservedUpgrade>[0], "source">): Promise<PreparedUpgrade> {
  const { observation, generator, originalRoot, signal } = input;
  const cancellation = signal === undefined ? {} : { signal };
  const source = await acquireObservedUpgradeSnapshot(observation, cancellation);
  return await prepareObservedUpgrade({ observation, generator, originalRoot, source, ...cancellation });
}

/** Fixed anonymous acquisition only; no input bundles or operator Git configuration. */
export async function acquirePreparedHistory(candidate: PreparedUpgrade, options: { signal?: AbortSignal } = {}): Promise<PreparedHistory> {
  let value: State | undefined;
  try {
    const facts = describePreparedUpgrade(candidate); const { base } = copyPreparedUpgradeSource(candidate);
    value = Object.assign(await openPublicGit({ repository: facts.repository, id: facts.repositoryId, head: facts.baseCommit },
      options.signal, ISOLATION_LIMITS.operationMs, candidate), { candidate, bundle: Buffer.alloc(0) });
    const raw = await git(value, ["cat-file", "commit", facts.baseCommit]); demand(oid("commit", raw) === base.baseCommit && decode(raw).startsWith(`tree ${base.tree}\n`));
    const expected = copySnapshotFiles(base); const rows: Buffer[] = [];
    for (const file of expected) rows.push(Buffer.from(`${file.mode} blob ${oid("blob", file.bytes)}\t${file.path}\0`));
    const listing = await git(value, ["ls-tree", "-r", "-z", "--full-tree", facts.baseCommit], undefined, HOST_LIMITS.bytes);
    // Git orders directories specially; compare exact raw records by path bytes.
    const ordered = (bytes: Buffer) => bytes.subarray(0, -1).toString("binary").split("\0").sort().join("\0");
    demand(listing.length > 0 && listing.at(-1) === 0 && ordered(listing) === ordered(Buffer.concat(rows)));
    value.bundle = await git(value, ["bundle", "create", "--version=2", "-", baseRef], undefined, ISOLATION_LIMITS.bundleBytes);
    demand(value.bundle.length > 0); describePreparedUpgrade(candidate); await refresh(value); value.signal.throwIfAborted(); describePreparedUpgrade(candidate);
    const handle = Object.freeze({}) as PreparedHistory; histories.set(handle, value); return handle;
  } catch {
    if (value) await cleanup(value).catch(() => undefined);
    throw failure();
  }
}
export function copyPreparedHistoryBundle(handle: PreparedHistory, candidate: PreparedUpgrade): Buffer {
  try { return Buffer.from(state(handle, candidate).bundle); } catch { throw failure(); }
}
/** Trusted sibling operation: stores raw signed bytes after independent signature verification. */
export async function bundleSignedCandidate(handle: PreparedHistory, candidate: PreparedUpgrade, raw: Uint8Array): Promise<{ commit: string; bundle: Buffer }> {
  try {
    const value = state(handle, candidate); const facts = describePreparedUpgrade(candidate); demand(!value.candidateCommit);
    demand(raw instanceof Uint8Array && raw.byteLength > 0 && raw.byteLength <= ISOLATION_LIMITS.manifestBytes);
    const bytes = Buffer.from(raw); demand(decode(bytes).startsWith(`tree ${facts.tree}\nparent ${facts.baseCommit}\n`));
    const index: Buffer[] = [];
    for (const file of copyPreparedUpgradeSource(candidate).files) {
      const hash = oid("blob", file.bytes); demand(decode(await git(value, ["hash-object", "--no-filters", "-w", "--stdin"], file.bytes)).trim() === hash);
      index.push(Buffer.from(`${file.mode} ${hash}\t${file.path}\0`));
    }
    await git(value, ["read-tree", "--empty"]); await git(value, ["update-index", "-z", "--index-info"], Buffer.concat(index));
    demand(decode(await git(value, ["write-tree"])).trim() === facts.tree);
    const commit = oid("commit", bytes); demand(decode(await git(value, ["hash-object", "-t", "commit", "-w", "--stdin"], bytes)).trim() === commit);
    await git(value, ["update-ref", candidateRef, commit, "0".repeat(40)]); value.candidateCommit = commit;
    const bundle = await git(value, ["bundle", "create", "--version=2", "-", baseRef, candidateRef], undefined, ISOLATION_LIMITS.bundleBytes);
    state(handle, candidate); await refresh(value); state(handle, candidate); return { commit, bundle };
  } catch { throw failure(); }
}
export async function discardPreparedHistory(handle: PreparedHistory): Promise<void> {
  const value = histories.get(handle); if (!value) throw failure();
  value.disposal ??= cleanup(value).then(() => { histories.delete(handle); }).catch(() => { delete value.disposal; throw failure(); });
  await value.disposal;
}
