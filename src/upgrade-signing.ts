import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, opendir, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ISOLATION_LIMITS, type IsolatedSourceFile, type PlannedGitIdentity } from "./isolation/node-profile.js";
import { decodeGitPath, verifyGitSnapshot } from "./upgrade-git.js";
import { PRLIMIT_ARGS, boundedCommand, decode, demand, hostFailure, neutralEnvironment, readRegular, requireLinuxHost, trustedExecutable } from "./upgrade-host.js";
import { gitArguments, transportContext, type PublicRepository } from "./upgrade-transport.js";

export interface PublicSigningIdentity { readonly name: string; readonly email: string }
export interface SigningCapability { readonly identity: PublicSigningIdentity }
export interface FrozenCommitPlan {
  readonly author: Readonly<PlannedGitIdentity>; readonly committer: Readonly<PlannedGitIdentity>; readonly baseCommit: string;
  readonly branch: string; readonly commitMessage: string; readonly hook: "none" | ".githooks/pre-commit"; readonly commitPlanSha256: string;
}
interface Signer { identity: PublicSigningIdentity; key: Buffer; socket: string; ssh: string }
const signers = new WeakMap<SigningCapability, Signer>(); const identities = new WeakSet<PublicSigningIdentity>(); const plans = new WeakMap<FrozenCommitPlan, PublicSigningIdentity>();
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const oid = (kind: string, bytes: Uint8Array) => createHash("sha1").update(`${kind} ${bytes.byteLength}\0`).update(bytes).digest("hex");
const sha = (value: string) => /^[a-f0-9]{40}$/.test(value);
const branch = (value: string) => Buffer.byteLength(value) <= 4096 && /^codex\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value) && !value.includes("..") && !value.includes("//") && value.split("/").every((part) => !part.startsWith(".") && !part.endsWith(".") && !part.endsWith(".lock"));
async function absent(file: string): Promise<void> { try { await lstat(file); throw hostFailure(); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw hostFailure(); } }
async function optional(file: string, limit: number): Promise<Buffer | undefined> { try { return await readRegular(file, limit, true); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw hostFailure(); } }
function publicIdentity(name: string | undefined, email: string | undefined): PublicSigningIdentity {
  demand(name && email && name.trim() === name && email.trim() === email && Buffer.byteLength(name) <= 256 && Buffer.byteLength(email) <= 254 &&
    !/[\x00-\x1f\x7f-\x9f<>]/.test(name) && !/[\s\x00-\x1f\x7f-\x9f<>]/.test(email));
  const result = Object.freeze({ name, email }); identities.add(result); return result;
}
async function layout(root: string): Promise<{ gitdir: string; common: string }> {
  demand(path.isAbsolute(root) && await realpath(root) === path.resolve(root) && (await lstat(root)).isDirectory());
  const dot = path.join(root, ".git"); const stat = await lstat(dot); let gitdir = dot; let common = dot;
  if (!stat.isDirectory()) {
    const match = /^gitdir: ([^\r\n\0]+)\n?$/.exec(decode(await readRegular(dot, 4096, true))); demand(match && path.isAbsolute(match[1]!)); gitdir = path.resolve(match[1]!);
    demand(decode(await readRegular(path.join(gitdir, "commondir"), 4096, true)) === "../..\n"); common = path.resolve(gitdir, "../..");
    demand(gitdir === path.join(common, "worktrees", path.basename(gitdir)) && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(path.basename(gitdir)) &&
      decode(await readRegular(path.join(gitdir, "gitdir"), 4096, true)) === dot + "\n"); await absent(path.join(gitdir, "config"));
  } else await absent(path.join(dot, "commondir"));
  for (const file of [path.join(common, "config.worktree"), path.join(gitdir, "config.worktree"), path.join(common, "objects/info/alternates"), path.join(common, "objects/info/http-alternates"), path.join(common, "info/grafts"), path.join(common, "shallow"), path.join(common, "refs/replace")]) await absent(file);
  let count = 0; for await (const entry of await opendir(gitdir)) demand(++count <= ISOLATION_LIMITS.entries && !entry.name.startsWith("sharedindex.")); return { gitdir, common };
}

export async function captureGeneratorSigning(generatorRoot: string, expectedCommit: string, options: { signal?: AbortSignal } = {}): Promise<{ identity: PublicSigningIdentity; capability: SigningCapability }> {
  let directory: string | undefined;
  try {
    demand(sha(expectedCommit) && !Object.keys(process.env).some((name) => name.startsWith("GIT_") || name === "EMAIL"));
    const home = os.userInfo().homedir; demand(!process.env.HOME || path.resolve(process.env.HOME) === home);
    demand(!process.env.XDG_CONFIG_HOME || path.resolve(process.env.XDG_CONFIG_HOME) === path.join(home, ".config"));
    const tools = await requireLinuxHost(); const ssh = await trustedExecutable("/usr/bin/ssh-keygen"); const metadata = await layout(generatorRoot);
    directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-generator-signing-")); const empty = path.join(directory, "empty"); const source = path.join(directory, "source");
    await mkdir(empty); await mkdir(source); const gitdir = path.join(directory, "git"); const env = { ...neutralEnvironment(empty, directory), GIT_DIR: gitdir, GIT_WORK_TREE: source, GIT_EXEC_PATH: empty, GIT_OPTIONAL_LOCKS: "0" };
    const run = (args: readonly string[], input?: Uint8Array, extra: NodeJS.ProcessEnv = {}, allowedExit = [0]) => boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, tools.git, ...gitArguments({ empty }, args)], {
      cwd: directory!, env: { ...env, ...extra }, output: ISOLATION_LIMITS.lockBytes, allowedExit, ...(input ? { input } : {}), ...(options.signal ? { signal: options.signal } : {}) });
    await run(["init", "--quiet", "--object-format=sha1", "--initial-branch=codex/generator-audit", `--template=${empty}`]);
    const captured = new Map<string, Buffer>(); const missing: string[] = []; const read = async (file: string, limit: number) => { const bytes = await readRegular(file, limit, true); captured.set(file, bytes); return bytes; };
    const entries: Array<[string, string]> = [];
    for (const file of [path.join(home, ".config/git/config"), path.join(home, ".gitconfig"), path.join(metadata.common, "config")]) {
      const bytes = file === path.join(metadata.common, "config") ? await read(file, ISOLATION_LIMITS.manifestBytes) : await optional(file, ISOLATION_LIMITS.manifestBytes);
      if (!bytes) { missing.push(file); continue; } captured.set(file, bytes); const output = decode(await run(["config", "--file", "-", "--no-includes", "--null", "--list"], bytes)); demand(!output || output.endsWith("\0"));
      for (const record of output ? output.slice(0, -1).split("\0") : []) { const end = record.indexOf("\n"); demand(end > 0); entries.push([record.slice(0, end), record.slice(end + 1)]); }
    }
    const config = new Map(entries);
    for (const [key] of entries) demand(!key.startsWith("include.") && !key.startsWith("includeif.") && !key.startsWith("extensions.") && !["core.worktree", "core.splitindex", "core.sparsecheckout", "core.sparsecheckoutcone", "author.name", "author.email", "committer.name", "committer.email"].includes(key));
    demand((!config.has("core.bare") || config.get("core.bare") === "false") && (!config.has("core.repositoryformatversion") || config.get("core.repositoryformatversion") === "0") && !entries.some(([key]) => /^remote\..+\.(?:promisor|partialclonefilter)$/.test(key)));
    demand(config.get("gpg.format") === "ssh" && !entries.some(([key, value]) => value && ["gpg.ssh.program", "gpg.ssh.defaultkeycommand", "gpg.ssh.allowedsignersfile", "gpg.ssh.revocationfile", "gpg.mintrustlevel"].includes(key)));
    const identity = publicIdentity(config.get("user.name"), config.get("user.email")); const keyValue = config.get("user.signingkey");
    demand(keyValue && keyValue.endsWith(".pub") && !/[\r\n\0]/.test(keyValue)); const keyPath = keyValue.startsWith("~/") ? path.join(home, keyValue.slice(2)) : keyValue;
    demand(path.isAbsolute(keyPath)); const keyBytes = await readRegular(keyPath, 16_384, true); demand((await lstat(keyPath)).uid === process.getuid?.());
    const keyMatch = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\r\n\0]*)?\n?$/.exec(decode(keyBytes)); demand(keyMatch);
    const wire = Buffer.from(keyMatch[1]!, "base64"); demand(wire.length === 51 && wire.toString("base64") === keyMatch[1] && wire.readUInt32BE(0) === 11 && wire.subarray(4, 15).toString("ascii") === "ssh-ed25519" && wire.readUInt32BE(15) === 32);
    const head = decode(await read(path.join(metadata.gitdir, "HEAD"), 4096)); let current = /^[a-f0-9]{40}\n?$/.test(head) ? head.trimEnd() : "";
    if (!current) {
      const ref = /^ref: (refs\/heads\/[A-Za-z0-9][A-Za-z0-9._/-]*)\n?$/.exec(head); demand(ref && !ref[1]!.includes("..") && !ref[1]!.includes("//") && ref[1]!.split("/").every((part) => !part.endsWith(".lock") && !part.endsWith(".")));
      const loosePath = path.join(metadata.common, ref[1]!); const loose = await optional(loosePath, 4096);
      if (loose) { captured.set(loosePath, loose); const value = decode(loose); demand(/^[a-f0-9]{40}\n?$/.test(value)); current = value.trimEnd(); }
      else { missing.push(loosePath); const packed = decode(await read(path.join(metadata.common, "packed-refs"), ISOLATION_LIMITS.manifestBytes)); const found: string[] = [];
        for (const line of packed.split("\n")) { if (!line || line.startsWith("#") || /^\^[a-f0-9]{40}$/.test(line)) continue; demand(/^[a-f0-9]{40} refs\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(line)); if (line.slice(41) === ref[1]) found.push(line.slice(0, 40)); }
        demand(found.length === 1); current = found[0]!; }
    }
    demand(current === expectedCommit); let objectEntries = 0;
    const inspectObjects = async (relative: string): Promise<void> => {
      demand(relative.split("/").length <= ISOLATION_LIMITS.pathDepth); const location = path.join(metadata.common, "objects", relative); const directoryStat = await lstat(location); demand(directoryStat.isDirectory() && !(directoryStat.mode & 0o022) && (directoryStat.uid === 0 || directoryStat.uid === process.getuid?.()));
      for await (const entry of await opendir(location)) { const name = entry.name;
        options.signal?.throwIfAborted(); demand(++objectEntries <= ISOLATION_LIMITS.entries && /^[A-Za-z0-9._-]+$/.test(name) && !name.endsWith(".promisor")); const file = path.join(location, name); const stat = await lstat(file);
        if (stat.isDirectory()) await inspectObjects(relative ? relative + "/" + name : name); else demand(stat.isFile() && stat.nlink === 1 && stat.size <= 64 * 1024 ** 2 && !(stat.mode & 0o022) && (stat.uid === 0 || stat.uid === process.getuid?.()));
      }
    };
    await inspectObjects(""); const commitBytes = await run(["cat-file", "commit", expectedCommit], undefined, { GIT_OBJECT_DIRECTORY: path.join(metadata.common, "objects") });
    const index = await read(path.join(metadata.gitdir, "index"), ISOLATION_LIMITS.lockBytes);
    demand(index.length >= 32 && index.subarray(0, 4).toString() === "DIRC" && [2, 3, 4].includes(index.readUInt32BE(4)) && index.readUInt32BE(8) <= ISOLATION_LIMITS.files && createHash("sha1").update(index.subarray(0, -20)).digest().equals(index.subarray(-20)));
    const indexCopy = path.join(directory, "index"); await writeFile(indexCopy, index, { flag: "wx", mode: 0o600 });
    const listing = await run(["ls-files", "--stage", "--sparse", "-z"], undefined, { GIT_INDEX_FILE: indexCopy }); demand(listing.length > 0 && listing.at(-1) === 0);
    const files: IsolatedSourceFile[] = []; let bytes = 0;
    for (const record of listing.subarray(0, -1).toString("binary").split("\0")) {
      options.signal?.throwIfAborted(); demand(files.length < ISOLATION_LIMITS.files); const raw = Buffer.from(record, "binary"); const separator = raw.indexOf(9); const header = /^(100644|100755) ([a-f0-9]{40}) 0$/.exec(raw.subarray(0, separator).toString("ascii")); demand(separator > 0 && header);
      const name = decodeGitPath(raw.subarray(separator + 1)); const file = path.join(generatorRoot, name); const stat = await lstat(file); demand(stat.isFile() && stat.size <= ISOLATION_LIMITS.sourceBytes - bytes); const content = await read(file, stat.size); bytes += content.length;
      demand(oid("blob", content) === header[2] && ((await lstat(file)).mode & 0o100 ? "100755" : "100644") === header[1]); files.push({ path: name, mode: header[1] as "100644" | "100755", bytes: content });
      if (path.basename(name) === ".gitignore") { await mkdir(path.dirname(path.join(source, name)), { recursive: true }); await writeFile(path.join(source, name), content, { flag: "wx", mode: 0o600 }); }
    }
    verifyGitSnapshot({ baseCommit: expectedCommit, commitBytes, files }); const tracked = new Set(files.map((file) => file.path)); let walked = 0;
    const walk = async (prefix: string): Promise<void> => {
      const names: string[] = []; const directory = await opendir(path.join(generatorRoot, prefix), { encoding: "buffer" as BufferEncoding });
      for await (const entry of directory) { options.signal?.throwIfAborted(); const raw: unknown = entry.name; demand(Buffer.isBuffer(raw)); if (!prefix && raw.equals(Buffer.from(".git"))) continue; demand(++walked <= ISOLATION_LIMITS.entries); const name = decodeGitPath(raw); demand(!name.includes("/")); names.push(decodeGitPath(Buffer.from(prefix ? prefix + "/" + name : name))); }
      const unknown = names.filter((name) => !tracked.has(name)); const ignoredOutput = unknown.length ? await run(["check-ignore", "--no-index", "-z", "--stdin"], Buffer.from(unknown.join("\0") + "\0"), {}, [0, 1]) : Buffer.alloc(0);
      demand(!ignoredOutput.length || ignoredOutput.at(-1) === 0); const ignored = new Set(ignoredOutput.length ? ignoredOutput.subarray(0, -1).toString("binary").split("\0").map((name) => decodeGitPath(Buffer.from(name, "binary"))) : []);
      for (const name of unknown) { if (ignored.has(name)) continue; demand((await lstat(path.join(generatorRoot, name))).isDirectory()); await walk(name); }
    };
    await walk(""); for (const [file, before] of captured) demand((await readRegular(file, before.length, true)).equals(before)); for (const file of missing) await absent(file);
    for (const file of files) { const stat = await lstat(path.join(generatorRoot, file.path)); demand(stat.isFile() && (stat.mode & 0o100 ? "100755" : "100644") === file.mode); }
    const finalLayout = await layout(generatorRoot); demand(finalLayout.gitdir === metadata.gitdir && finalLayout.common === metadata.common);
    const socket = process.env.SSH_AUTH_SOCK; demand(socket && path.isAbsolute(socket)); const agent = await lstat(socket); demand(agent.isSocket() && agent.uid === process.getuid?.());
    options.signal?.throwIfAborted(); const capability = Object.freeze({ identity }); signers.set(capability, { identity, key: Buffer.from(`ssh-ed25519 ${keyMatch[1]}\n`), socket, ssh }); return { identity, capability };
  } catch { throw hostFailure(); }
  finally { if (directory) try { await rm(directory, { recursive: true, force: true }); } catch { throw hostFailure(); } }
}

export function freezeCommitPlan(identity: PublicSigningIdentity, base: string, selectedBranch: string, message: string, hook: "none" | ".githooks/pre-commit"): FrozenCommitPlan {
  try {
    demand(identities.has(identity) && sha(base) && branch(selectedBranch) && ["none", ".githooks/pre-commit"].includes(hook) && message.length > 0 && Buffer.byteLength(message) <= 16_384 && !/[\r\0]/.test(message) && Buffer.from(message).toString() === message);
    const dco = `Signed-off-by: ${identity.name} <${identity.email}>`; demand(!message.split("\n").some((line) => /^Signed-off-by:/i.test(line) && line !== dco));
    const commitMessage = message.replace(/\n+$/, "") + (message.split("\n").includes(dco) ? "\n" : `\n\n${dco}\n`);
    const epoch = Math.floor(Date.now() / 1000); demand(Buffer.byteLength(commitMessage) <= 16_384 && Number.isSafeInteger(epoch) && epoch >= 0 && epoch <= 99_999_999_999); const author = Object.freeze({ ...identity, date: `${epoch} +0000` });
    const frozen = { author, committer: author, baseCommit: base, branch: selectedBranch, commitMessage, hook }; const plan = Object.freeze({ ...frozen, commitPlanSha256: sha256(Buffer.from(JSON.stringify(frozen))) }); plans.set(plan, identity); return plan;
  } catch { throw hostFailure(); }
}

export async function signAndVerify(repository: PublicRepository, tree: string, plan: FrozenCommitPlan, capability: SigningCapability): Promise<string> {
  let directory: string | undefined; let lease: ReturnType<ReturnType<typeof transportContext>["reserve"]> | undefined;
  try {
    const context = transportContext(repository); const signer = signers.get(capability); demand(signer && plans.get(plan) === signer.identity && sha(tree) && context.preparedTree === tree && plan.baseCommit === repository.baseCommit && !context.candidate);
    lease = context.reserve(8 * 1024 ** 2); directory = await mkdtemp(path.join(context.directory, "signing-")); const key = path.join(directory, "selected.pub"); const allowed = path.join(directory, "allowed"); const signature = path.join(directory, "signature");
    await writeFile(key, signer.key, { flag: "wx", mode: 0o600 }); await writeFile(allowed, Buffer.concat([Buffer.from('bootstrap-upgrade namespaces="git" '), signer.key]), { flag: "wx", mode: 0o600 });
    const run = async (executable: string, args: readonly string[], input?: Uint8Array, signing = false): Promise<Buffer> => {
      const pending = boundedCommand(context.prlimit, [...PRLIMIT_ARGS, executable, ...args], { cwd: context.directory, env: { ...context.env, ...(signing ? { SSH_AUTH_SOCK: signer.socket,
        GIT_AUTHOR_NAME: plan.author.name, GIT_AUTHOR_EMAIL: plan.author.email, GIT_AUTHOR_DATE: "@" + plan.author.date,
        GIT_COMMITTER_NAME: plan.committer.name, GIT_COMMITTER_EMAIL: plan.committer.email, GIT_COMMITTER_DATE: "@" + plan.committer.date } : {}) }, signal: context.signal, ...(input ? { input } : {}) });
      context.pending.add(pending); try { return await pending; } finally { context.pending.delete(pending); }
    };
    const candidate = decode(await run(context.git, [...gitArguments(context, ["-c", "gpg.format=ssh", "-c", `gpg.ssh.program=${signer.ssh}`, "-c", `user.signingkey=${key}`, "commit-tree", "-S", tree, "-p", plan.baseCommit]),], Buffer.from(plan.commitMessage), true)).trim(); demand(sha(candidate));
    const raw = await run(context.git, gitArguments(context, ["cat-file", "commit", candidate])); demand(oid("commit", raw) === candidate);
    const text = decode(raw); const boundary = text.indexOf("\n\n"); demand(boundary > 0 && !text.includes("\0")); const lines = text.slice(0, boundary).split("\n");
    const prefix = [`tree ${tree}`, `parent ${plan.baseCommit}`, `author ${plan.author.name} <${plan.author.email}> ${plan.author.date}`, `committer ${plan.committer.name} <${plan.committer.email}> ${plan.committer.date}`];
    demand(prefix.every((line, index) => lines[index] === line) && lines[4] === "gpgsig -----BEGIN SSH SIGNATURE-----" && lines.at(-1) === " -----END SSH SIGNATURE-----" && lines.slice(5, -1).every((line) => /^ [A-Za-z0-9+/=]+$/.test(line)) && text.slice(boundary + 2) === plan.commitMessage);
    await writeFile(signature, lines.slice(4).map((line, index) => index ? line.slice(1) : line.slice(7)).join("\n") + "\n", { flag: "wx", mode: 0o600 });
    const unsigned = Buffer.from(prefix.join("\n") + "\n\n" + plan.commitMessage); await run(signer.ssh, ["-Y", "verify", "-f", allowed, "-I", "bootstrap-upgrade", "-n", "git", "-s", signature], unsigned);
    demand((await readRegular(key, signer.key.length)).equals(signer.key)); await lease.releaseAfterCleanup(() => rm(directory!, { recursive: true, force: true })); directory = undefined; lease = undefined;
    demand(transportContext(repository) === context && !context.signal.aborted); context.signedBranch = plan.branch; context.signedPlanSha256 = plan.commitPlanSha256; context.candidate = candidate; return candidate;
  } catch { throw hostFailure(); }
  finally { if (directory) { if (lease) await lease.releaseAfterCleanup(() => rm(directory!, { recursive: true, force: true })).catch(() => { throw hostFailure(); }); else await rm(directory, { recursive: true, force: true }).catch(() => { throw hostFailure(); }); } }
}
