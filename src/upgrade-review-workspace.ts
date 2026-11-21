import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, opendir, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { ISOLATION_LIMITS } from "./isolation/node-profile.js";
import { decodeGitPath, verifyGitSnapshot } from "./upgrade-git.js";
import { HOST_LIMITS, PRLIMIT_ARGS, boundedGitCommand, decode, demand, gitArguments, hostFailure, readRegular,
  neutralEnvironment, requireLinuxHost, trustedExecutable } from "./upgrade-host.js";
import { copyCheckedCandidateBundle, describeCheckedCandidate, type CheckedCandidate } from "./upgrade-validation.js";
import { readAuthorizedSignature } from "./upgrade-signing.js";
import type { RuntimePolicy } from "./upgrade-runtime-policy.js";

declare const workspaceBrand: unique symbol;
export type ControlledReviewWorkspace = { readonly [workspaceBrand]: true };
export interface ReviewWorkspaceAuditFacts {
  readonly baseCommit: string;
  readonly candidateCommit: string;
  readonly tree: string;
  readonly sourceSha256: string;
  readonly rawCommitSha256: string;
  readonly objects: number;
  readonly objectBytes: number;
  readonly historyCommits: number;
  readonly files: number;
}
export interface ReviewWorkspaceContext {
  readonly directory: string;
  readonly root: string;
  readonly gitdir: string;
  readonly empty: string;
  readonly runtime: string;
  readonly home: string;
  readonly temporary: string;
  readonly output: string;
  readonly jsonOutput: string;
  readonly humanOutput: string;
  readonly baseCommit: string;
  readonly candidateCommit: string;
  readonly branch: string;
  readonly signal: AbortSignal;
}
interface State {
  candidate: CheckedCandidate;
  policy: RuntimePolicy;
  context: Readonly<ReviewWorkspaceContext>;
  git: string;
  prlimit: string;
  env: NodeJS.ProcessEnv;
  cancellation: AbortController;
  pending: Set<Promise<Buffer>>;
  closed: boolean;
  cleanup?: Promise<void>;
  facts?: Readonly<ReviewWorkspaceAuditFacts>;
  configSha256?: string;
}
const states = new WeakMap<ControlledReviewWorkspace, State>();
const owned = new WeakMap<CheckedCandidate, ControlledReviewWorkspace>();
const consumed = new WeakSet<CheckedCandidate>();
const baseRef = "refs/heads/codex/bootstrap-public-base";
const signedRef = "refs/heads/codex/bootstrap-signed-candidate";
const zero = "0".repeat(40);
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const oid = (kind: string, bytes: Uint8Array) => createHash("sha1").update(`${kind} ${bytes.byteLength}\0`).update(bytes).digest("hex");
const objectLimit = 20_000;
const inventoryLimit = 2 * HOST_LIMITS.output;

// A cleanup failure is a live source observation, never an importable receipt.
export class ReviewWorkspaceCleanupError extends Error {
  constructor() { super("Controlled review workspace cleanup is unconfirmed."); }
}
function stateFor(handle: ControlledReviewWorkspace): State {
  const state = states.get(handle);
  demand(state && !state.closed && !state.context.signal.aborted);
  describeCheckedCandidate(state.candidate);
  readAuthorizedSignature(state.candidate, state.policy);
  return state;
}
// Source-internal fixed consumer seam; not exported by the package or CLI.
export function reviewWorkspaceContext(handle: ControlledReviewWorkspace): Readonly<ReviewWorkspaceContext> {
  return stateFor(handle).context;
}
async function git(state: State, args: readonly string[], input?: Uint8Array, output = HOST_LIMITS.output): Promise<Buffer> {
  demand(!state.closed && !state.context.signal.aborted);
  describeCheckedCandidate(state.candidate);
  readAuthorizedSignature(state.candidate, state.policy);
  if (state.configSha256) demand(sha256(await readRegular(path.join(state.context.gitdir, "config"), 65536)) === state.configSha256);
  const pending = boundedGitCommand(state.prlimit, [...PRLIMIT_ARGS, state.git, ...gitArguments(state.context, args)], {
    cwd: state.context.directory, env: state.env, signal: state.context.signal, output,
    combinedOutput: output + HOST_LIMITS.output, ...(input ? { input } : {})
  });
  state.pending.add(pending);
  try {
    const result = await pending;
    describeCheckedCandidate(state.candidate);
    readAuthorizedSignature(state.candidate, state.policy);
    return result;
  } finally { state.pending.delete(pending); }
}
function bundleHeader(bytes: Buffer, base: string, candidate: string): void {
  const end = bytes.indexOf(Buffer.from("\n\n"));
  demand(end > 0 && end <= 4096);
  const lines = decode(bytes.subarray(0, end)).split("\n");
  demand(lines.length === 3 && lines[0] === "# v2 git bundle" &&
    new Set(lines.slice(1)).size === 2 &&
    lines.includes(`${base} ${baseRef}`) && lines.includes(`${candidate} ${signedRef}`));
  demand(bytes.subarray(end + 2, end + 6).equals(Buffer.from("PACK")));
}
async function objects(state: State, candidate: string): Promise<{ count: number; bytes: number; commits: number }> {
  const listing = decode(await git(state, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], undefined, inventoryLimit));
  demand(listing.endsWith("\n"));
  const ids = new Set<string>();
  let bytes = 0;
  let commits = 0;
  for (const line of listing.slice(0, -1).split("\n")) {
    const match = /^([a-f0-9]{40}) (blob|tree|commit) (0|[1-9][0-9]*)$/.exec(line);
    demand(match && !ids.has(match[1]!) && ids.size < objectLimit);
    const size = Number(match[3]);
    demand(Number.isSafeInteger(size));
    bytes += size;
    demand(bytes <= ISOLATION_LIMITS.sourceBytes);
    if (match[2] === "commit") { demand(size <= HOST_LIMITS.output); commits++; }
    ids.add(match[1]!);
  }
  const reachable = decode(await git(state, ["rev-list", "--objects", "--no-object-names", candidate], undefined, inventoryLimit));
  demand(reachable.endsWith("\n"));
  const seen = new Set<string>();
  for (const id of reachable.slice(0, -1).split("\n")) {
    demand(/^[a-f0-9]{40}$/.test(id) && ids.has(id) && !seen.has(id));
    seen.add(id);
  }
  demand(seen.size === ids.size && commits >= 2);
  await git(state, ["fsck", "--strict", "--full", "--no-reflogs"]);
  return { count: ids.size, bytes, commits };
}
async function storage(state: State): Promise<void> {
  const allowed = new Set(["", "objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/heads/codex", "refs/tags"]);
  const metadata = new Set(["HEAD", "config", "index", "refs/heads/codex/bootstrap-public-base", `refs/heads/${state.context.branch}`]);
  let entries = 0;
  let size = 0;
  const walk = async (prefix: string): Promise<void> => {
    for await (const entry of await opendir(path.join(state.context.gitdir, prefix))) {
      describeCheckedCandidate(state.candidate);
      readAuthorizedSignature(state.candidate, state.policy);
      demand(++entries <= objectLimit + ISOLATION_LIMITS.entries);
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      const stat = await lstat(path.join(state.context.gitdir, name));
      if (stat.isDirectory()) {
        demand(allowed.has(name) || /^objects\/[a-f0-9]{2}$/.test(name) || name.startsWith("refs/heads/") && state.context.branch.startsWith(name.slice(11) + "/"));
        await walk(name);
      } else {
        demand(stat.isFile() && stat.nlink === 1 && !(stat.mode & 0o111));
        demand(metadata.has(name) || /^objects\/pack\/pack-[a-f0-9]{40}\.(pack|idx)$/.test(name) || /^objects\/[a-f0-9]{2}\/[a-f0-9]{38}$/.test(name));
        demand(stat.size <= (name.startsWith("objects/") ? HOST_LIMITS.bytes : ISOLATION_LIMITS.lockBytes));
        size += stat.size;
        demand(size <= ISOLATION_LIMITS.sourceBytes + 2 * HOST_LIMITS.bytes);
      }
    }
  };
  await walk("");
}
export async function openControlledReviewWorkspace(candidate: CheckedCandidate, policy: RuntimePolicy, options: { signal?: AbortSignal } = {}): Promise<ControlledReviewWorkspace> {
  const parent = options.signal; demand(!consumed.has(candidate)); consumed.add(candidate);
  const completed = describeCheckedCandidate(candidate); const authorization = readAuthorizedSignature(candidate, policy);
  const signedBundle = copyCheckedCandidateBundle(candidate); const publicKey = authorization.publicKey;
  const facts = { ...completed, tree: completed.preparedTree };
  const tools = await requireLinuxHost();
  describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); parent?.throwIfAborted();
  const ssh = await trustedExecutable("/usr/bin/ssh-keygen");
  demand(sha256(Buffer.from(publicKey)) === facts.publicKeySha256 && /^codex\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(facts.branch) &&
    !facts.branch.includes("..") && !facts.branch.includes("//") && facts.branch.split("/").every((part) => !part.endsWith(".") && !part.endsWith(".lock")));
  bundleHeader(signedBundle, facts.baseCommit, facts.candidateCommit);
  const directory = await mkdtemp(path.join(await realpath("/tmp"), "bootstrap-review-workspace-"));
  const root = path.join(directory, "source"), empty = path.join(directory, "empty");
  const runtime = path.join(directory, "runtime"), output = path.join(directory, "output");
  const cancellation = new AbortController();
  const context = Object.freeze({ directory, root, empty, runtime, output, gitdir: path.join(root, ".git"),
    home: path.join(runtime, "home"), temporary: path.join(runtime, "tmp"),
    jsonOutput: path.join(output, "review.json"), humanOutput: path.join(output, "review.txt"),
    baseCommit: facts.baseCommit, candidateCommit: facts.candidateCommit, branch: facts.branch,
    signal: AbortSignal.any([AbortSignal.timeout(1_800_000), cancellation.signal, ...(parent ? [parent] : [])]) });
  const env = { ...neutralEnvironment(empty, directory), GIT_DIR: context.gitdir, GIT_WORK_TREE: root, GIT_EXEC_PATH: empty };
  const state: State = { candidate, policy, context, ...tools, env, cancellation, pending: new Set(), closed: false };
  const handle = Object.freeze({}) as ControlledReviewWorkspace;
  states.set(handle, state);
  owned.set(candidate, handle);
  try {
    describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
    for (const name of [root, empty, runtime, output, context.home, context.temporary]) {
      await mkdir(name, { mode: 0o700 });
      describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
    }
    await git(state, ["init", "--quiet", "--object-format=sha1", "--initial-branch=codex/bootstrap-review-initial", `--template=${empty}`]);
    state.configSha256 = sha256(await readRegular(path.join(context.gitdir, "config"), 65536));
    const bundle = path.join(directory, "public.signed.bundle");
    await writeFile(bundle, signedBundle, { flag: "wx", mode: 0o600 });
    describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
    await git(state, ["bundle", "verify", bundle]);
    const refs = decode(await git(state, ["bundle", "unbundle", bundle])).trim().split("\n").sort();
    demand(JSON.stringify(refs) === JSON.stringify([`${facts.baseCommit} ${baseRef}`, `${facts.candidateCommit} ${signedRef}`].sort()));
    await rm(bundle);
    describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
    const raw = await git(state, ["cat-file", "commit", facts.candidateCommit]);
    demand(oid("commit", raw) === facts.candidateCommit && decode(raw).startsWith(`tree ${facts.tree}\nparent ${facts.baseCommit}\n`));
    const listing = await git(state, ["ls-tree", "-r", "-z", "--full-tree", facts.candidateCommit], undefined, inventoryLimit);
    demand(listing.length > 0 && listing.at(-1) === 0);
    const files: Array<{ path: string; mode: "100644" | "100755"; bytes: Buffer }> = [];
    let totalBytes = 0;
    for (const row of decode(listing.subarray(0, -1)).split("\0")) {
      const tab = row.indexOf("\t"); const header = /^(100644|100755) blob ([a-f0-9]{40})$/.exec(row.slice(0, tab));
      demand(tab > 0 && header && files.length < ISOLATION_LIMITS.entries);
      const name = decodeGitPath(Buffer.from(row.slice(tab + 1))); const bytes = await git(state, ["cat-file", "blob", header[2]!], undefined, HOST_LIMITS.bytes);
      totalBytes += bytes.length; demand(totalBytes <= ISOLATION_LIMITS.sourceBytes && oid("blob", bytes) === header[2]);
      files.push({ path: name, mode: header[1] as "100644" | "100755", bytes });
    }
    const snapshot = verifyGitSnapshot({ baseCommit: facts.candidateCommit, commitBytes: raw, files });
    demand(snapshot.tree === facts.tree && snapshot.sourceSha256 === facts.sourceSha256);
    demand(decode(await git(state, ["rev-list", "--parents", "-n", "1", facts.candidateCommit])).trim() === `${facts.candidateCommit} ${facts.baseCommit}`);
    const entries: Buffer[] = [];
    const made = new Set<string>();
    for (const file of files) {
      describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
      const name = decodeGitPath(Buffer.from(file.path));
      const parts = name.split("/");
      for (let index = 1; index < parts.length; index++) {
        const parent = parts.slice(0, index).join("/");
        if (!made.has(parent)) {
          await mkdir(path.join(root, parent), { mode: 0o700 });
          describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
          made.add(parent);
        }
      }
      await writeFile(path.join(root, name), file.bytes, { flag: "wx", mode: file.mode === "100755" ? 0o755 : 0o644 });
      describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
      const blob = oid("blob", file.bytes);
      demand(decode(await git(state, ["hash-object", "--no-filters", "-w", "--stdin"], file.bytes)).trim() === blob);
      entries.push(Buffer.from(`${file.mode} ${blob}\t${name}\0`));
    }
    await git(state, ["read-tree", "--empty"]);
    await git(state, ["update-index", "-z", "--index-info"], Buffer.concat(entries));
    demand(decode(await git(state, ["write-tree"])).trim() === facts.tree);
    await git(state, ["update-ref", baseRef, facts.baseCommit, zero]);
    await git(state, ["update-ref", `refs/heads/${facts.branch}`, facts.candidateCommit, zero]);
    await git(state, ["symbolic-ref", "HEAD", `refs/heads/${facts.branch}`]);
    const allowed = path.join(directory, "public.allowed-signers");
    await writeFile(allowed, `bootstrap-review namespaces="git" ${publicKey}`, { flag: "wx", mode: 0o600 });
    describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
    await git(state, ["-c", "gpg.format=ssh", "-c", `gpg.ssh.program=${ssh}`, "-c", `gpg.ssh.allowedSignersFile=${allowed}`, "verify-commit", facts.candidateCommit]);
    await rm(allowed);
    describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
    const inventory = await objects(state, facts.candidateCommit);
    await storage(state);
    state.facts = Object.freeze({ baseCommit: facts.baseCommit, candidateCommit: facts.candidateCommit, tree: facts.tree,
      sourceSha256: facts.sourceSha256, rawCommitSha256: sha256(raw),
      objects: inventory.count, objectBytes: inventory.bytes, historyCommits: inventory.commits, files: files.length });
    describeCheckedCandidate(candidate); readAuthorizedSignature(candidate, policy); context.signal.throwIfAborted();
    return handle;
  } catch {
    await disposeControlledReviewWorkspace(handle);
    throw hostFailure();
  }
}
export async function auditControlledReviewWorkspace(handle: ControlledReviewWorkspace): Promise<Readonly<ReviewWorkspaceAuditFacts>> {
  const state = stateFor(handle);
  demand(state.facts);
  demand(decode(await git(state, ["rev-parse", "--verify", "HEAD"])).trim() === state.facts.candidateCommit);
  demand(decode(await git(state, ["write-tree"])).trim() === state.facts.tree);
  demand((await git(state, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching"])).length === 0);
  demand(sha256(await git(state, ["cat-file", "commit", state.facts.candidateCommit])) === state.facts.rawCommitSha256);
  await storage(state);
  return state.facts;
}
export async function disposeControlledReviewWorkspace(handle: ControlledReviewWorkspace): Promise<void> {
  const state = states.get(handle);
  demand(state);
  if (state.cleanup) return state.cleanup;
  state.closed = true;
  state.cancellation.abort();
  const cleanup = (async () => {
    await Promise.allSettled([...state.pending]);
    await rm(state.context.directory, { recursive: true, force: true });
    try { await lstat(state.context.directory); throw new ReviewWorkspaceCleanupError(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new ReviewWorkspaceCleanupError(); }
    owned.delete(state.candidate);
  })();
  state.cleanup = cleanup;
  try { await cleanup; }
  catch { delete state.cleanup; throw new ReviewWorkspaceCleanupError(); }
}

// Cleanup remains reachable after cancellation or a failed constructor.
export async function drainReviewWorkspaceCandidate(candidate: CheckedCandidate): Promise<void> {
  const handle = owned.get(candidate);
  if (handle) await disposeControlledReviewWorkspace(handle);
}
