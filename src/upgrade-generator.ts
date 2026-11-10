import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, opendir, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ISOLATION_LIMITS, type IsolatedSourceFile } from "./isolation/node-profile.js";
import { decodeGitPath, verifyGitSnapshot, type VerifiedGitSnapshot } from "./upgrade-git.js";
import {
  PRLIMIT_ARGS, boundedGitCommand, decode, demand, gitArguments, hostFailure,
  neutralEnvironment, readRegular, requireLinuxHost
} from "./upgrade-host.js";

export interface PublicGeneratorCapture {
  readonly sourceCommit: string;
  readonly tree: string;
  readonly sourceSha256: string;
}
const captures = new WeakMap<PublicGeneratorCapture, VerifiedGitSnapshot>();
// A real producer result, never an imported JSON statement or permission to sign.
export function generatorSnapshot(capture: PublicGeneratorCapture): VerifiedGitSnapshot {
  const snapshot = captures.get(capture);
  demand(snapshot);
  return snapshot;
}
const oid = (kind: string, bytes: Uint8Array) =>
  createHash("sha1").update(`${kind} ${bytes.byteLength}\0`).update(bytes).digest("hex");
async function absent(file: string): Promise<void> {
  try { await lstat(file); throw hostFailure(); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw hostFailure(); }
}
async function optional(file: string, limit: number): Promise<Buffer | undefined> {
  try { return await readRegular(file, limit, true); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw hostFailure(); }
}
async function layout(root: string): Promise<{ gitdir: string; common: string }> {
  demand(path.isAbsolute(root) && await realpath(root) === path.resolve(root) && (await lstat(root)).isDirectory());
  const dot = path.join(root, ".git");
  const stat = await lstat(dot);
  let gitdir = dot;
  let common = dot;
  if (!stat.isDirectory()) {
    const match = /^gitdir: ([^\r\n\0]+)\n?$/.exec(decode(await readRegular(dot, 4096, true)));
    demand(match && path.isAbsolute(match[1]!));
    gitdir = path.resolve(match[1]!);
    demand(decode(await readRegular(path.join(gitdir, "commondir"), 4096, true)) === "../..\n");
    common = path.resolve(gitdir, "../..");
    demand(gitdir === path.join(common, "worktrees", path.basename(gitdir)) &&
      /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(path.basename(gitdir)) &&
      decode(await readRegular(path.join(gitdir, "gitdir"), 4096, true)) === dot + "\n");
    await absent(path.join(gitdir, "config"));
  } else await absent(path.join(dot, "commondir"));
  for (const file of [
    path.join(common, "config.worktree"), path.join(gitdir, "config.worktree"),
    path.join(common, "objects/info/alternates"), path.join(common, "objects/info/http-alternates"),
    path.join(common, "info/grafts"), path.join(common, "shallow"), path.join(common, "refs/replace")
  ]) await absent(file);
  let count = 0;
  for await (const entry of await opendir(gitdir))
    demand(++count <= ISOLATION_LIMITS.entries && !entry.name.startsWith("sharedindex."));
  return { gitdir, common };
}

// This audits tracked source and lock bytes. Ignored builds/dependencies remain a trusted-installation assumption.
export async function capturePublicGenerator(
  generatorRoot: string, expectedCommit: string, options: { signal?: AbortSignal } = {}
): Promise<PublicGeneratorCapture> {
  const signal = AbortSignal.any([
    AbortSignal.timeout(ISOLATION_LIMITS.phaseMs), ...(options.signal ? [options.signal] : [])
  ]);
  let directory: string | undefined;
  let snapshot: VerifiedGitSnapshot | undefined;
  try {
    signal.throwIfAborted();
    demand(/^[a-f0-9]{40}$/.test(expectedCommit) &&
      !Object.keys(process.env).some((name) => name.startsWith("GIT_") || name === "EMAIL"));
    const home = os.userInfo().homedir;
    demand(!process.env.HOME || path.resolve(process.env.HOME) === home);
    demand(!process.env.XDG_CONFIG_HOME || path.resolve(process.env.XDG_CONFIG_HOME) === path.join(home, ".config"));
    const tools = await requireLinuxHost();
    const metadata = await layout(generatorRoot);
    directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-generator-audit-"));
    const empty = path.join(directory, "empty");
    const source = path.join(directory, "source");
    await mkdir(empty);
    await mkdir(source);
    const env = {
      ...neutralEnvironment(empty, directory), GIT_DIR: path.join(directory, "git"),
      GIT_WORK_TREE: source, GIT_EXEC_PATH: empty, GIT_OPTIONAL_LOCKS: "0"
    };
    const run = (args: readonly string[], input?: Uint8Array, extra: NodeJS.ProcessEnv = {}, allowedExit = [0]) =>
      boundedGitCommand(tools.prlimit, [...PRLIMIT_ARGS, tools.git, ...gitArguments({ empty }, args)], {
        cwd: directory!, env: { ...env, ...extra }, output: ISOLATION_LIMITS.lockBytes,
        combinedOutput: ISOLATION_LIMITS.lockBytes + 1024 ** 2, allowedExit, signal,
        ...(input ? { input } : {})
      });
    await run(["init", "--quiet", "--object-format=sha1", "--initial-branch=codex/generator-audit", `--template=${empty}`]);
    const captured = new Map<string, Buffer>();
    const missing: string[] = [];
    const read = async (file: string, limit: number) => {
      signal.throwIfAborted();
      const bytes = await readRegular(file, limit, true);
      captured.set(file, bytes);
      return bytes;
    };
    const entries: Array<[string, string]> = [];
    for (const file of [path.join(home, ".config/git/config"), path.join(home, ".gitconfig"), path.join(metadata.common, "config")]) {
      const bytes = file === path.join(metadata.common, "config") ?
        await read(file, ISOLATION_LIMITS.manifestBytes) : await optional(file, ISOLATION_LIMITS.manifestBytes);
      if (!bytes) { missing.push(file); continue; }
      captured.set(file, bytes);
      const output = decode(await run(["config", "--file", "-", "--no-includes", "--null", "--list"], bytes));
      demand(!output || output.endsWith("\0"));
      for (const record of output ? output.slice(0, -1).split("\0") : []) {
        const end = record.indexOf("\n");
        demand(end > 0);
        entries.push([record.slice(0, end), record.slice(end + 1)]);
      }
    }
    const config = new Map(entries);
    for (const [key] of entries) demand(!key.startsWith("include.") && !key.startsWith("includeif.") &&
      !key.startsWith("extensions.") && ![
        "core.worktree", "core.splitindex", "core.sparsecheckout", "core.sparsecheckoutcone",
        "author.name", "author.email", "committer.name", "committer.email"
      ].includes(key));
    demand((!config.has("core.bare") || config.get("core.bare") === "false") &&
      (!config.has("core.repositoryformatversion") || config.get("core.repositoryformatversion") === "0") &&
      !entries.some(([key]) => /^remote\..+\.(?:promisor|partialclonefilter)$/.test(key)));
    const head = decode(await read(path.join(metadata.gitdir, "HEAD"), 4096));
    let current = /^[a-f0-9]{40}\n?$/.test(head) ? head.trimEnd() : "";
    if (!current) {
      const ref = /^ref: (refs\/heads\/[A-Za-z0-9][A-Za-z0-9._/-]*)\n?$/.exec(head);
      demand(ref && !ref[1]!.includes("..") && !ref[1]!.includes("//") &&
        ref[1]!.split("/").every((part) => !part.endsWith(".lock") && !part.endsWith(".")));
      const loosePath = path.join(metadata.common, ref[1]!);
      const loose = await optional(loosePath, 4096);
      if (loose) {
        captured.set(loosePath, loose);
        const value = decode(loose);
        demand(/^[a-f0-9]{40}\n?$/.test(value));
        current = value.trimEnd();
      } else {
        missing.push(loosePath);
        const packed = decode(await read(path.join(metadata.common, "packed-refs"), ISOLATION_LIMITS.manifestBytes));
        const found: string[] = [];
        for (const line of packed.split("\n")) {
          if (!line || line.startsWith("#") || /^\^[a-f0-9]{40}$/.test(line)) continue;
          demand(/^[a-f0-9]{40} refs\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(line));
          if (line.slice(41) === ref[1]) found.push(line.slice(0, 40));
        }
        demand(found.length === 1);
        current = found[0]!;
      }
    }
    demand(current === expectedCommit);
    let objectEntries = 0;
    const inspectObjects = async (relative: string): Promise<void> => {
      demand(relative.split("/").length <= ISOLATION_LIMITS.pathDepth);
      const location = path.join(metadata.common, "objects", relative);
      const directoryStat = await lstat(location);
      demand(directoryStat.isDirectory() && !(directoryStat.mode & 0o022) &&
        (directoryStat.uid === 0 || directoryStat.uid === process.getuid?.()));
      for await (const entry of await opendir(location)) {
        signal.throwIfAborted();
        const name = entry.name;
        demand(++objectEntries <= ISOLATION_LIMITS.entries && /^[A-Za-z0-9._-]+$/.test(name) && !name.endsWith(".promisor"));
        const file = path.join(location, name);
        const stat = await lstat(file);
        if (stat.isDirectory()) await inspectObjects(relative ? relative + "/" + name : name);
        else demand(stat.isFile() && stat.nlink === 1 && stat.size <= 64 * 1024 ** 2 &&
          !(stat.mode & 0o022) && (stat.uid === 0 || stat.uid === process.getuid?.()));
      }
    };
    await inspectObjects("");
    const commitBytes = await run(["cat-file", "commit", expectedCommit], undefined, {
      GIT_OBJECT_DIRECTORY: path.join(metadata.common, "objects")
    });
    const index = await read(path.join(metadata.gitdir, "index"), ISOLATION_LIMITS.lockBytes);
    demand(index.length >= 32 && index.subarray(0, 4).toString() === "DIRC" &&
      [2, 3, 4].includes(index.readUInt32BE(4)) && index.readUInt32BE(8) <= ISOLATION_LIMITS.files &&
      createHash("sha1").update(index.subarray(0, -20)).digest().equals(index.subarray(-20)));
    const indexCopy = path.join(directory, "index");
    await writeFile(indexCopy, index, { flag: "wx", mode: 0o600 });
    const listing = await run(["ls-files", "--stage", "--sparse", "-z"], undefined, { GIT_INDEX_FILE: indexCopy });
    demand(listing.length > 0 && listing.at(-1) === 0);
    const files: IsolatedSourceFile[] = [];
    let bytes = 0;
    for (const record of listing.subarray(0, -1).toString("binary").split("\0")) {
      signal.throwIfAborted();
      demand(files.length < ISOLATION_LIMITS.files);
      const raw = Buffer.from(record, "binary");
      const separator = raw.indexOf(9);
      const header = /^(100644|100755) ([a-f0-9]{40}) 0$/.exec(raw.subarray(0, separator).toString("ascii"));
      demand(separator > 0 && header);
      const name = decodeGitPath(raw.subarray(separator + 1));
      const file = path.join(generatorRoot, name);
      const stat = await lstat(file);
      demand(stat.isFile() && stat.size <= ISOLATION_LIMITS.sourceBytes - bytes);
      const content = await read(file, stat.size);
      bytes += content.length;
      demand(oid("blob", content) === header[2] &&
        ((await lstat(file)).mode & 0o100 ? "100755" : "100644") === header[1]);
      files.push({ path: name, mode: header[1] as "100644" | "100755", bytes: content });
      if (path.basename(name) === ".gitignore") {
        await mkdir(path.dirname(path.join(source, name)), { recursive: true });
        await writeFile(path.join(source, name), content, { flag: "wx", mode: 0o600 });
      }
    }
    // The aggregate source bound was checked before every read and before the snapshot's owned copy.
    snapshot = verifyGitSnapshot({ baseCommit: expectedCommit, commitBytes, files });
    const tracked = new Set(files.map((file) => file.path));
    let walked = 0;
    const walk = async (prefix: string): Promise<void> => {
      const names: string[] = [];
      const entries = await opendir(path.join(generatorRoot, prefix), { encoding: "buffer" as BufferEncoding });
      for await (const entry of entries) {
        signal.throwIfAborted();
        const raw: unknown = entry.name;
        demand(Buffer.isBuffer(raw));
        if (!prefix && raw.equals(Buffer.from(".git"))) continue;
        demand(++walked <= ISOLATION_LIMITS.entries);
        const name = decodeGitPath(raw);
        demand(!name.includes("/"));
        names.push(decodeGitPath(Buffer.from(prefix ? prefix + "/" + name : name)));
      }
      const unknown = names.filter((name) => !tracked.has(name));
      const ignoredOutput = unknown.length ? await run(["check-ignore", "--no-index", "-z", "--stdin"],
        Buffer.from(unknown.join("\0") + "\0"), {}, [0, 1]) : Buffer.alloc(0);
      demand(!ignoredOutput.length || ignoredOutput.at(-1) === 0);
      const ignored = new Set(ignoredOutput.length ? ignoredOutput.subarray(0, -1).toString("binary")
        .split("\0").map((name) => decodeGitPath(Buffer.from(name, "binary"))) : []);
      for (const name of unknown) {
        if (ignored.has(name)) continue;
        demand((await lstat(path.join(generatorRoot, name))).isDirectory());
        await walk(name);
      }
    };
    await walk("");
    for (const [file, before] of captured) demand((await readRegular(file, before.length, true)).equals(before));
    for (const file of missing) await absent(file);
    for (const file of files) {
      const stat = await lstat(path.join(generatorRoot, file.path));
      demand(stat.isFile() && (stat.mode & 0o100 ? "100755" : "100644") === file.mode);
    }
    const finalLayout = await layout(generatorRoot);
    demand(finalLayout.gitdir === metadata.gitdir && finalLayout.common === metadata.common);
    signal.throwIfAborted();
  } catch { throw hostFailure(); }
  finally {
    if (directory) try { await rm(directory, { recursive: true, force: true }); }
    catch { throw hostFailure(); }
  }
  if (signal.aborted) throw hostFailure();
  demand(snapshot);
  const capture = Object.freeze({
    sourceCommit: snapshot.baseCommit, tree: snapshot.tree, sourceSha256: snapshot.sourceSha256
  });
  captures.set(capture, snapshot);
  return capture;
}
