import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import type { CommandOptions } from "../src/upgrade-host.js";

const scaffold = vi.hoisted(() => ({
  home: "", calls: [] as Array<{ args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv }>,
  reads: [] as string[], directories: [] as string[], cleanupFails: false,
  ignoreQueries: [] as Array<{ input: string[]; output: string[] }>,
  sourceLimit: undefined as number | undefined, fileLimit: undefined as number | undefined,
  afterCommand: undefined as undefined | ((args: readonly string[]) => Promise<void>)
}));
vi.mock("node:os", async (original) => {
  const actual = await original<typeof import("node:os")>();
  return { ...actual, default: { ...actual, userInfo: () => ({ ...actual.userInfo(), homedir: scaffold.home }) } };
});
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual,
    mkdtemp: async (prefix: string) => {
      const result = await actual.mkdtemp(prefix);
      if (prefix.includes("bootstrap-generator-audit-")) scaffold.directories.push(result);
      return result;
    },
    rm: async (file: string, options: Parameters<typeof actual.rm>[1]) => {
      await actual.rm(file, options);
      if (scaffold.cleanupFails && scaffold.directories.includes(file)) throw new Error("fixture cleanup failed");
    }
  };
});
vi.mock("../src/isolation/node-profile.js", async (original) => {
  const actual = await original<typeof import("../src/isolation/node-profile.js")>();
  return { ...actual, ISOLATION_LIMITS: { ...actual.ISOLATION_LIMITS,
    get sourceBytes() { return scaffold.sourceLimit ?? actual.ISOLATION_LIMITS.sourceBytes; },
    get files() { return scaffold.fileLimit ?? actual.ISOLATION_LIMITS.files; }
  } };
});
// Real filesystem and Git semantics; only Linux eligibility/prlimit are simulated on Darwin.
vi.mock("../src/upgrade-host.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-host.js")>();
  return { ...actual, PRLIMIT_ARGS: [], requireLinuxHost: async () => ({ git: "/usr/bin/git", prlimit: "/usr/bin/env" }),
    readRegular: (...args: Parameters<typeof actual.readRegular>) => {
      scaffold.reads.push(args[0]); return actual.readRegular(...args);
    },
    boundedGitCommand: async (executable: string, args: readonly string[], options: CommandOptions) => {
      scaffold.calls.push({ args, cwd: options.cwd, env: options.env });
      const result = await actual.boundedGitCommand(executable, args, options);
      if (args.includes("check-ignore")) {
        const paths = (bytes: Uint8Array) => {
          if (bytes.byteLength > 4096) throw new Error("Fixture ignore query exceeds its byte bound.");
          if (!bytes.byteLength) return [];
          const names = Buffer.from(bytes).toString("utf8").split("\0");
          if (names.pop() !== "" || names.length > 16) throw new Error("Fixture ignore query exceeds its path bound.");
          return names;
        };
        scaffold.ignoreQueries.push({ input: paths(options.input ?? Buffer.alloc(0)), output: paths(result) });
      }
      await scaffold.afterCommand?.(args);
      return result;
    }
  };
});

import { capturePublicGenerator, generatorSnapshot } from "../src/upgrade-generator.js";
import { copySnapshotFiles } from "../src/upgrade-git.js";
import { neutralEnvironment, readRegular } from "../src/upgrade-host.js";

const roots: string[] = [];
const blocked = "Governed upgrade host operation is unsupported.";
function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: Uint8Array | string): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
    "-c", "commit.gpgsign=false", ...args], { cwd: root, env, input, maxBuffer: 2 * 1024 ** 2 });
}
async function fixtureDirectory(): Promise<string> {
  for (const parent of [path.join(process.cwd(), "node_modules"), os.tmpdir()]) {
    let directory: string | undefined;
    try {
      directory = await mkdtemp(path.join(await realpath(parent), ".bootstrap-generator-test-"));
      const probe = path.join(directory, "probe"); await writeFile(probe, "fixture");
      await readRegular(probe, 7, true); await rm(probe); roots.push(directory); return directory;
    } catch { if (directory) await rm(directory, { recursive: true, force: true }); }
  }
  throw new Error("Generator fixture requires private writable ancestry.");
}
async function fixture(linked = false, nested = false) {
  const directory = await fixtureDirectory();
  const home = path.join(directory, "home");
  const canonical = path.join(directory, "generator");
  const empty = path.join(directory, "empty");
  await Promise.all([home, canonical, empty].map((file) => mkdir(file)));
  scaffold.home = home;
  for (const name of Object.keys(process.env))
    if (name.startsWith("GIT_") || name === "EMAIL" || name === "XDG_CONFIG_HOME") vi.stubEnv(name, undefined);
  vi.stubEnv("HOME", home); vi.stubEnv("SSH_AUTH_SOCK", undefined);
  const env = { ...neutralEnvironment(home, directory),
    GIT_AUTHOR_NAME: "Fixture Operator", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000",
    GIT_COMMITTER_NAME: "Fixture Operator", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000"
  };
  git(canonical, env, ["init", "--quiet", "--initial-branch=codex/fixture", `--template=${empty}`]);
  const files = [
    { path: "README.txt", bytes: Buffer.from("pinned generator source\n") },
    { path: "package-lock.json", bytes: Buffer.from('{"lockfileVersion":3}\n') },
    { path: ".gitignore", bytes: Buffer.from("ignored/\ndist/\nnode_modules/\n") },
    { path: ".gitattributes", bytes: Buffer.from("*.txt filter=canary\n") },
    ...(nested ? [{ path: "src/entry.txt", bytes: Buffer.from("nested pinned source\n") }] : [])
  ];
  const index: Buffer[] = [];
  for (const file of files) {
    await mkdir(path.dirname(path.join(canonical, file.path)), { recursive: true });
    await writeFile(path.join(canonical, file.path), file.bytes);
    const oid = git(canonical, env, ["hash-object", "--no-filters", "-w", "--stdin"], file.bytes).toString().trim();
    index.push(Buffer.from(`100644 ${oid}\t${file.path}\0`));
  }
  git(canonical, env, ["update-index", "-z", "--index-info"], Buffer.concat(index));
  const tree = git(canonical, env, ["write-tree"]).toString().trim();
  const base = git(canonical, env, ["commit-tree", tree], "fabricated generator\n").toString().trim();
  git(canonical, env, ["update-ref", "refs/heads/codex/fixture", base]);
  let root = canonical;
  if (linked) {
    root = path.join(directory, "linked");
    git(canonical, env, ["worktree", "add", "--quiet", "--detach", root, base]);
  }
  const ignored = path.join(root, ...(nested ? ["src", "ignored"] : ["ignored"]));
  await mkdir(ignored);
  await writeFile(path.join(ignored, "operator-data"), "ignored fabricated bytes\n");
  const config = (key: string, value: string) => git(canonical, env, ["config", "--local", key, value]);
  return { directory, home, canonical, root, env, base, tree, config, files };
}
afterEach(async () => {
  scaffold.afterCommand = undefined; scaffold.cleanupFails = false;
  scaffold.sourceLimit = undefined; scaffold.fileLimit = undefined;
  vi.unstubAllEnvs();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  for (const directory of scaffold.directories.splice(0)) await rm(directory, { recursive: true, force: true });
  scaffold.calls.length = 0; scaffold.reads.length = 0; scaffold.ignoreQueries.length = 0;
});

describe("agent-free public generator source capture (real Git; simulated Linux eligibility)", () => {
  it.each([false, true])("audits ordinary/linked=%s without any signer identity, key or socket", async (linked) => {
    const data = await fixture(linked);
    const indexPath = linked ? path.join(data.canonical, ".git/worktrees/linked/index") : path.join(data.root, ".git/index");
    const before = await readFile(indexPath);
    const result = await capturePublicGenerator(data.root, data.base);
    expect(result).toEqual({ sourceCommit: data.base, tree: data.tree, sourceSha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.keys(result).sort()).toEqual(["sourceCommit", "sourceSha256", "tree"]);
    expect(JSON.stringify(result)).not.toContain(data.directory);
    expect(copySnapshotFiles(generatorSnapshot(result)).map((file) => file.path).sort()).toEqual(data.files.map((file) => file.path).sort());
    expect(() => generatorSnapshot({ ...result })).toThrow(blocked);
    expect(() => generatorSnapshot(JSON.parse(JSON.stringify(result)))).toThrow(blocked);
    expect(await readFile(indexPath)).toEqual(before);
    expect(scaffold.calls.every((call) => call.cwd !== data.root && !call.env.SSH_AUTH_SOCK)).toBe(true);
    expect(scaffold.calls.some((call) => call.args.some((arg) => /ssh-keygen|commit-tree|signingkey/.test(arg)))).toBe(false);
    for (const directory of scaffold.directories) await expect(lstat(directory)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does not execute original hooks, filters, fsmonitor or ignored build content", async () => {
    const data = await fixture(); const canary = path.join(data.directory, "executed");
    const program = path.join(data.directory, "canary.sh"); await writeFile(program, `#!/bin/sh\ntouch '${canary}'\n`, { mode: 0o755 });
    data.config("filter.canary.clean", program); data.config("core.fsmonitor", program); data.config("core.hooksPath", data.directory);
    await writeFile(path.join(data.directory, "pre-commit"), await readFile(program), { mode: 0o755 });
    await mkdir(path.join(data.root, "dist")); await writeFile(path.join(data.root, "dist", "entry.js"), "ignored fixture build\n");
    await capturePublicGenerator(data.root, data.base);
    await expect(readFile(canary)).rejects.toMatchObject({ code: "ENOENT" });
    expect(scaffold.reads.some((file) => file.includes("/ignored/") || file.includes("/dist/"))).toBe(false);
  });

  it.each(["raw", "staged", "assume-unchanged", "skip-worktree", "mode", "untracked", "head", "lock"])("rejects %s source drift", async (kind) => {
    const data = await fixture(); const file = path.join(data.root, "README.txt");
    if (kind === "mode") await chmod(file, 0o755);
    else if (kind === "untracked") await writeFile(path.join(data.root, "extra"), "untracked\n");
    else if (kind === "head") await writeFile(path.join(data.root, ".git/HEAD"), "0".repeat(40) + "\n");
    else if (kind === "lock") await writeFile(path.join(data.root, "package-lock.json"), "changed\n");
    else {
      if (["assume-unchanged", "skip-worktree"].includes(kind)) git(data.root, data.env, ["update-index", "--" + kind, "README.txt"]);
      await writeFile(file, "changed source\n");
      if (kind === "staged") {
        const oid = git(data.root, data.env, ["hash-object", "--no-filters", "-w", "--stdin"], "changed source\n").toString().trim();
        git(data.root, data.env, ["update-index", "--cacheinfo", `100644,${oid},README.txt`]);
      }
    }
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
  });

  it.each(["include.path", "includeIf.gitdir:/.path", "extensions.worktreeConfig", "core.worktree", "core.splitIndex", "author.name"])("rejects configured %s before source promotion", async (key) => {
    const data = await fixture(); data.config(key, "fixture");
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
  });

  it.each(["GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_AUTHOR_NAME", "EMAIL", "XDG_CONFIG_HOME"])("rejects ambient %s overrides", async (key) => {
    const data = await fixture(); vi.stubEnv(key, "fixture");
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
  });

  it.each(["mode", "source", "config", "abort"])("rejects late %s after the last Git child closes", async (kind) => {
    const data = await fixture(); const controller = new AbortController();
    scaffold.afterCommand = async (args) => {
      if (!args.includes("check-ignore")) return;
      if (kind === "mode") await chmod(path.join(data.root, "README.txt"), 0o755);
      else if (kind === "source") await writeFile(path.join(data.root, "README.txt"), "late change\n");
      else if (kind === "config") await writeFile(path.join(data.root, ".git/config"), "[core]\n bare = true\n");
      else controller.abort();
    };
    await expect(capturePublicGenerator(data.root, data.base, { signal: controller.signal })).rejects.toThrow(blocked);
  });

  it.each([
    { label: "root nonignored", nested: false, ignored: false },
    { label: "nested nonignored", nested: true, ignored: false },
    { label: "root ignored child", nested: false, ignored: true },
    { label: "nested ignored child", nested: true, ignored: true }
  ])("checks late inventory $label after the last real check-ignore child", async ({ nested, ignored }) => {
    const data = await fixture(false, nested);
    const ignoredDirectory = nested ? "src/ignored/" : "ignored/";
    const oldQuery = ignoredDirectory + "operator-data";
    const destination = path.join(data.root, ...(nested ? ["src"] : []), ...(ignored ? ["ignored"] : []), "late-added");
    const bytes = Buffer.from("late fabricated generator bytes\n");
    let mutations = 0;
    let mutationQuery: { input: string[]; output: string[] } | undefined;
    scaffold.afterCommand = async (args) => {
      if (!args.includes("check-ignore")) return;
      const query = scaffold.ignoreQueries.at(-1)!;
      if (!query.input.includes(ignoredDirectory) && !query.input.includes(oldQuery)) return;
      expect(mutations).toBe(0);
      const selected = query.input.includes(ignoredDirectory) ? ignoredDirectory : oldQuery;
      expect(query.output).toEqual([selected]);
      mutationQuery = query;
      await writeFile(destination, bytes);
      mutations++;
    };
    let result: Awaited<ReturnType<typeof capturePublicGenerator>> | undefined;
    let failure: unknown;
    try { result = await capturePublicGenerator(data.root, data.base); } catch (error) { failure = error; }
    expect(mutations).toBe(1);
    expect(mutationQuery).toBeDefined();
    expect(scaffold.ignoreQueries.at(-1)).toBe(mutationQuery);
    expect(await readFile(destination)).toEqual(bytes);
    expect(scaffold.reads.some((file) => file.includes("/ignored/") || file === destination)).toBe(false);
    if (ignored) {
      expect(failure).toBeUndefined();
      expect(result).toEqual({ sourceCommit: data.base, tree: data.tree, sourceSha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
      expect(copySnapshotFiles(generatorSnapshot(result!))).toEqual(data.files.map((file) => ({
        ...file, mode: "100644"
      })).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))));
    } else {
      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error).message).toBe(blocked);
    }
  });

  it("rejects a loose ref appearing after packed-ref capture", async () => {
    const data = await fixture(); git(data.root, data.env, ["pack-refs", "--all", "--prune"]);
    scaffold.afterCommand = async (args) => {
      if (args.includes("check-ignore")) await writeFile(path.join(data.root, ".git/refs/heads/codex/fixture"), data.base + "\n");
    };
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
  });

  it("checks total source/index bounds before reading tracked payloads", async () => {
    const data = await fixture(); scaffold.sourceLimit = 1;
    scaffold.reads.length = 0;
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
    expect(scaffold.reads.some((name) => data.files.some((file) => name === path.join(data.root, file.path)))).toBe(false);
    scaffold.sourceLimit = undefined; scaffold.fileLimit = 3; scaffold.calls.length = 0;
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
    expect(scaffold.calls.some((call) => call.args.includes("ls-files"))).toBe(false);
  });

  it("rejects invalid checksum, linked metadata and alternate object layouts", async () => {
    const data = await fixture(); const index = path.join(data.root, ".git/index"); const before = await readFile(index);
    const broken = Buffer.from(before); broken[broken.length - 1] = broken.at(-1)! ^ 1; await writeFile(index, broken);
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked); await writeFile(index, before);
    await writeFile(path.join(data.root, ".git/objects/info/alternates"), "/not-selected\n");
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
    await rm(path.join(data.root, ".git/objects/info/alternates"));
    const linked = await fixture(true); const dot = await readFile(path.join(linked.root, ".git"), "utf8");
    const gitdir = dot.slice("gitdir: ".length).trim(); await writeFile(path.join(gitdir, "gitdir"), "/wrong-backlink\n");
    await expect(capturePublicGenerator(linked.root, linked.base)).rejects.toThrow(blocked);
  });

  it("rejects symlinked source and source object hardlinks", async () => {
    const data = await fixture(); const file = path.join(data.root, "README.txt"); await rm(file);
    await symlink(path.join(data.root, "package-lock.json"), file);
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
    await rm(file); await writeFile(file, data.files[0]!.bytes);
    const bytes = data.files[0]!.bytes;
    const blob = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    await link(path.join(data.root, ".git/objects", blob.slice(0, 2), blob.slice(2)), path.join(data.directory, "object-copy"));
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
  });

  it("never returns a completion when owned cleanup fails or cancellation precedes work", async () => {
    const data = await fixture(); scaffold.cleanupFails = true;
    await expect(capturePublicGenerator(data.root, data.base)).rejects.toThrow(blocked);
    scaffold.cleanupFails = false; scaffold.calls.length = 0;
    const controller = new AbortController(); controller.abort();
    await expect(capturePublicGenerator(data.root, data.base, { signal: controller.signal })).rejects.toThrow(blocked);
    expect(scaffold.calls).toHaveLength(0);
  });
});
