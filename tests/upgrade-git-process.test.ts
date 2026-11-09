import { execFileSync, type ChildProcess, type SpawnOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { auditCheckout } from "../src/upgrade-checkout.js";
import { openDataRepository, verifyGitSnapshot, type DataRepository } from "../src/upgrade-git.js";

const faults = vi.hoisted(() => ({
  zeroFlag: "" as "" | "O_NOFOLLOW" | "O_NONBLOCK",
  spawnFault: "" as "" | "throw" | "null-status",
  blockConfig: false,
  blocked: [] as ChildProcess[],
  closed: [] as ChildProcess[],
  cwd: [] as string[],
  cleanupDirectory: "",
  captureCleanupDirectory: false,
  cleanupAttempts: 0,
  cleanupFailures: 0
}));

// Private fault scaffolding: commands and bytes still go to real Git unless the
// named transport fault is injected. This is not Git semantics or confinement proof.
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: (command: string, args: readonly string[] = [], options: SpawnOptions = {}) => {
    faults.cwd.push(String(options.cwd));
    if (faults.captureCleanupDirectory && !faults.cleanupDirectory) faults.cleanupDirectory = String(options.cwd);
    if (faults.spawnFault === "throw") throw new Error("private spawn failure detail");
    const child = actual.spawn(command, args, options);
    child.once("close", () => { faults.closed.push(child); });
    if (faults.spawnFault === "null-status") {
      const once = child.once.bind(child);
      child.once = ((event: string | symbol, listener: (...args: unknown[]) => void) =>
        once(event, event === "close" ? () => listener(null, null) : listener)) as typeof child.once;
    }
    if (faults.blockConfig && args.includes("config") && args.includes("--file") && args.includes("-")) {
      faults.blocked.push(child);
      // Keep real `git config --file -` waiting on its pipe until the supervisor
      // cancels, times out, or observes an actual termination signal.
      child.stdin!.end = (() => child.stdin!) as typeof child.stdin.end;
    }
    return child;
  } };
});

vi.mock("node:fs", async (original) => {
  const actual = await original<typeof import("node:fs")>();
  return { ...actual, constants: { ...actual.constants,
    get O_NOFOLLOW() { return faults.zeroFlag === "O_NOFOLLOW" ? 0 : actual.constants.O_NOFOLLOW; },
    get O_NONBLOCK() { return faults.zeroFlag === "O_NONBLOCK" ? 0 : actual.constants.O_NONBLOCK; }
  } };
});

vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, rm: (...args: Parameters<typeof actual.rm>) => {
    if (String(args[0]) === faults.cleanupDirectory && args[1]?.recursive) {
      faults.cleanupAttempts++;
      if (faults.cleanupFailures) {
        faults.cleanupFailures--;
        return Promise.reject(Object.assign(new Error("private cleanup failure detail"), { code: "EACCES" }));
      }
    }
    return actual.rm(...args);
  } };
});

const directories: string[] = [];
const repositories: DataRepository[] = [];
const fixed = "Governed upgrade Git data is unsupported.";
const config = Buffer.from("[canary]\n value = public fixture\n");

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "bootstrap-git-process-test-")); directories.push(root);
  const empty = path.join(root, "empty-template"); await mkdir(empty);
  const env = { PATH: "/usr/bin:/bin:/usr/local/bin", HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_AUTHOR_NAME: "Public Fixture",
    GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Public Fixture",
    GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null",
    "-c", "commit.gpgsign=false", "-c", "core.fsmonitor=false", ...args], { cwd: root, env,
    ...(input === undefined ? {} : { input }), maxBuffer: 16 * 1024 ** 2 });
  git(["init", "-q", "--initial-branch=main", `--template=${empty}`]);
  git(["config", "remote.origin.url", "https://github.com/example/public.git"]);
  const bytes = Buffer.from("public fixture\n");
  const blob = git(["hash-object", "-w", "--no-filters", "--stdin"], bytes).toString().trim();
  git(["update-index", "-z", "--index-info"], Buffer.from(`100644 ${blob}\tREADME.md\0`));
  const tree = git(["write-tree"]).toString().trim();
  const baseCommit = git(["commit-tree", tree], "test: synthetic public process fixture\n").toString().trim();
  git(["update-ref", "refs/heads/main", baseCommit]);
  const commitBytes = git(["cat-file", "commit", baseCommit]);
  const snapshot = verifyGitSnapshot({ baseCommit, commitBytes, files: [{ path: "README.md", mode: "100644", bytes }] });
  // Materialize only the ordinary original checkout for the flags gate case.
  const { writeFile } = await import("node:fs/promises"); await writeFile(path.join(root, "README.md"), bytes);
  return { root, git, snapshot };
}

async function repositoryFor(snapshot: ReturnType<typeof verifyGitSnapshot>, signal?: AbortSignal) {
  const repository = await openDataRepository(snapshot, signal ? { signal } : {});
  repositories.push(repository); return repository;
}

async function blockedChild(): Promise<ChildProcess> {
  await vi.waitFor(() => { expect(faults.blocked).toHaveLength(1); }, { timeout: 2000, interval: 10 });
  return faults.blocked[0]!;
}

async function originalInventory(root: string, prefix = ""): Promise<unknown[]> {
  const result: unknown[] = [];
  for (const name of (await readdir(path.join(root, prefix))).sort()) {
    const relative = prefix ? prefix + "/" + name : name; const entry = path.join(root, relative); const stat = await lstat(entry);
    if (stat.isDirectory()) result.push([relative, "directory", stat.mode], ...await originalInventory(root, relative));
    else {
      expect(stat.isFile()).toBe(true);
      result.push([relative, "file", stat.mode, createHash("sha256").update(await readFile(entry)).digest("hex")]);
    }
  }
  return result;
}

afterEach(async () => {
  vi.useRealTimers(); faults.zeroFlag = ""; faults.spawnFault = ""; faults.blockConfig = false;
  const cleanupDirectory = faults.cleanupDirectory;
  faults.cleanupDirectory = ""; faults.captureCleanupDirectory = false; faults.cleanupFailures = 0; faults.cleanupAttempts = 0;
  for (const child of faults.blocked) {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
  for (const repository of repositories.splice(0)) {
    await repository.dispose().catch(() => {});
    // Reap only known disposable fixture paths even when testing a broken cleanup.
    await rm(path.dirname(repository.root), { recursive: true, force: true });
  }
  if (cleanupDirectory && faults.cwd.includes(cleanupDirectory)) await rm(cleanupDirectory, { recursive: true, force: true });
  faults.blocked.length = 0; faults.closed.length = 0; faults.cwd.length = 0;
  await Promise.all(directories.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("private Git process faults (not semantic or confinement evidence)", () => {
  it("rejects zero no-follow or nonblocking flags without modifying original metadata", async () => {
    const data = await fixture();
    const before = await readFile(path.join(data.root, ".git/index"));
    for (const flag of ["O_NOFOLLOW", "O_NONBLOCK"] as const) {
      faults.zeroFlag = flag;
      await expect(auditCheckout(data.root, data.snapshot, "https://github.com/example/public.git"))
        .rejects.toThrow("Checkout is not eligible for a governed upgrade.");
    }
    expect(await readFile(path.join(data.root, ".git/index"))).toEqual(before);
  });

  it("cancels a real Git process blocked on stdin and waits for its close before rejecting", async () => {
    const data = await fixture(); const controller = new AbortController();
    const repository = await repositoryFor(data.snapshot, controller.signal); faults.blockConfig = true;
    const pending = repository.configEntries(config).catch((error: unknown) => error);
    const child = await blockedChild(); controller.abort(new Error("private cancellation reason"));
    expect((await pending as Error).message).toBe(fixed);
    expect(faults.closed).toContain(child);
    expect(child.signalCode).toBe("SIGKILL");
    await repository.dispose(); await expect(lstat(repository.root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("enforces the command deadline on blocked real Git and still cleans the repository", async () => {
    const data = await fixture(); const repository = await repositoryFor(data.snapshot);
    faults.blockConfig = true; vi.useFakeTimers();
    const pending = repository.configEntries(config).catch((error: unknown) => error);
    const child = await blockedChild();
    await vi.advanceTimersByTimeAsync(30_001); vi.useRealTimers();
    expect((await pending as Error).message).toBe(fixed);
    expect(faults.closed).toContain(child); expect(child.signalCode).toBe("SIGKILL");
    await repository.dispose(); await expect(lstat(repository.root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["throw", "null-status"] as const)("rejects the controlled %s transport fault and removes incomplete staging", async (mode) => {
    const data = await fixture(); faults.spawnFault = mode;
    const error = await openDataRepository(data.snapshot).then(() => undefined, (value: unknown) => value);
    expect((error as Error).message).toBe(fixed);
    expect(faults.cwd).toHaveLength(1);
    await expect(lstat(faults.cwd[0]!)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects actual signal termination instead of treating null exit status as success", async () => {
    const data = await fixture(); const repository = await repositoryFor(data.snapshot); faults.blockConfig = true;
    const pending = repository.configEntries(config).catch((error: unknown) => error);
    const child = await blockedChild(); child.kill("SIGTERM");
    expect((await pending as Error).message).toBe(fixed);
    expect(faults.closed).toContain(child); expect(child.exitCode).toBeNull(); expect(child.signalCode).toBe("SIGTERM");
  });

  it.each([1, 3])("audit cleanup owner bounds a %i-failure cleanup and preserves the original checkout", async (failures) => {
    const data = await fixture(); const before = await originalInventory(data.root);
    faults.captureCleanupDirectory = true; faults.cleanupFailures = failures;
    const error = await auditCheckout(data.root, data.snapshot, "https://github.com/example/public.git").then(() => undefined, (value: unknown) => value);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("Checkout is not eligible for a governed upgrade.");
    expect((error as Error).message).not.toContain(faults.cleanupDirectory);
    expect(faults.cleanupAttempts).toBe(2);
    if (failures === 1) await expect(lstat(faults.cleanupDirectory)).rejects.toMatchObject({ code: "ENOENT" });
    else { expect((await lstat(faults.cleanupDirectory)).isDirectory()).toBe(true); expect(faults.cleanupFailures).toBe(1); }
    expect(await originalInventory(data.root)).toEqual(before);
  });

  it.each([1, 3])("initialization cleanup owner bounds a %i-failure cleanup and preserves the primary sanitized error", async (failures) => {
    const data = await fixture(); const before = await originalInventory(data.root);
    faults.captureCleanupDirectory = true; faults.cleanupFailures = failures; faults.spawnFault = "throw";
    const error = await openDataRepository(data.snapshot).then(() => undefined, (value: unknown) => value);
    expect(error).toBeInstanceOf(Error); expect((error as Error).message).toBe(fixed);
    expect((error as Error).message).not.toContain("private");
    expect((error as Error).message).not.toContain(faults.cleanupDirectory);
    expect(faults.cleanupAttempts).toBe(2);
    if (failures === 1) await expect(lstat(faults.cleanupDirectory)).rejects.toMatchObject({ code: "ENOENT" });
    else { expect((await lstat(faults.cleanupDirectory)).isDirectory()).toBe(true); expect(faults.cleanupFailures).toBe(1); }
    expect(await originalInventory(data.root)).toEqual(before);
  });

  it("retries a failed cleanup rather than reporting false success on a second dispose", async () => {
    const data = await fixture(); const repository = await repositoryFor(data.snapshot);
    faults.cleanupDirectory = path.dirname(repository.root); faults.cleanupFailures = 1;
    await expect(repository.dispose()).rejects.toThrow(fixed);
    expect((await lstat(repository.root)).isDirectory()).toBe(true);
    await repository.dispose(); await expect(lstat(repository.root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("bounds real Git index output and removes its temporary index after overflow", async () => {
    const data = await fixture(); const repository = await repositoryFor(data.snapshot);
    data.git(["read-tree", "--empty"]);
    const emptyBlob = data.git(["hash-object", "--no-filters", "-w", "--stdin"], "").toString().trim();
    const prefix = Array.from({ length: 4 }, (_, index) => String(index).repeat(175)).join("/");
    const records = Array.from({ length: 10_000 }, (_, index) =>
      `100644 ${emptyBlob}\t${prefix}/file-${String(index).padStart(5, "0")}-${"x".repeat(170)}\0`).join("");
    expect(Buffer.byteLength(records)).toBeGreaterThan(8 * 1024 ** 2);
    data.git(["update-index", "-z", "--index-info"], records);
    const bytes = await readFile(path.join(data.root, ".git/index"));
    expect(bytes.length).toBeLessThan(16 * 1024 ** 2);
    const directory = path.dirname(repository.root); const before = (await readdir(directory)).sort();
    const digest = createHash("sha256").update(bytes).digest("hex");
    await expect(repository.readIndex(bytes)).rejects.toThrow(fixed);
    expect((await readdir(directory)).sort()).toEqual(before);
    expect(createHash("sha256").update(await readFile(path.join(data.root, ".git/index"))).digest("hex")).toBe(digest);
  }, 15_000);
});
