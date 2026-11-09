import { execFileSync, type SpawnOptions } from "node:child_process";
import { EventEmitter } from "node:events";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

// Test-only source-bound witness; it observes the actual guard without changing host policy.
const { hostDiagnostic, makeHostDiagnostic } = await vi.hoisted(async () => {
  const { AsyncLocalStorage } = await import("node:async_hooks");
  const makeHostDiagnostic = (
    process: { platform: string; env: NodeJS.ProcessEnv; getuid?: () => number } = globalThis.process,
    console: { info: (line: string) => void } = globalThis.console
  ) => {
    type Phase = "entry" | "proc-read" | "proc-open" | "proc-next" | "proc-entry" | "proc-owner" | "proc-status" | "trusted-tool";
    type Entry = { ownerSeen: boolean; sameUid: boolean; enoent: boolean; returned: boolean; closed: boolean; utf8: boolean | null; count: number | null };
    type Capture = { phase: Phase; entries: number; sameUid: number; skipped: number; accepted: number; total: number; known: boolean; complete: boolean; traversing: boolean; pending?: Entry };
    const contexts = new AsyncLocalStorage<Capture>(); let emitted = false;
    const runId = process.env.GITHUB_RUN_ID ?? ""; const runAttempt = process.env.GITHUB_RUN_ATTEMPT ?? "";
    const enabled = process.platform === "linux" && process.env.GITHUB_ACTIONS === "true" && process.env.RELEASE_PROFILE === "full"
      && process.env.GITHUB_REPOSITORY === "OMT-Global/bootstrap" && process.env.GITHUB_EVENT_NAME === "workflow_dispatch"
      && /^[1-9][0-9]{0,19}$/.exec(runId)?.[0] === runId && /^[1-9][0-9]{0,5}$/.exec(runAttempt)?.[0] === runAttempt;
    const observe = (capture: Capture, action: () => void) => { try { action(); } catch { capture.complete = false; } };
    const failed = (capture: Capture, error: unknown) => observe(capture, () => {
      if ((error as NodeJS.ErrnoException | null)?.code === "ENOENT" && capture.pending) capture.pending.enoent = true;
    });
    const acceptPrevious = (capture: Capture) => {
      const entry = capture.pending; delete capture.pending;
      if (!entry) return;
      if (entry.enoent) { capture.skipped = Math.min(100_000, capture.skipped + 1); return; }
      if (!entry.sameUid) return;
      if (!entry.returned || !entry.closed || entry.utf8 !== true || entry.count === null) { capture.known = false; return; }
      capture.accepted = Math.min(100_000, capture.accepted + 1); capture.total += entry.count;
      // The next iterator request witnesses acceptance; a contradictory projection is unknown.
      if (!(capture.total < 120)) capture.known = false;
    };
    const emit = (capture: Capture) => {
      if (emitted) return; emitted = true;
      try {
        const entry = capture.pending;
        const ready = capture.complete && capture.known && capture.phase === "proc-status" && !!entry?.sameUid && !entry.enoent && entry.returned && entry.closed && entry.utf8 === true;
        const candidate = ready && entry && entry.count !== null ? capture.total + entry.count : null;
        const predicate = candidate === null ? null : candidate < 120;
        const record = { schema: 1, boundary: "actual-requireLinuxHost-rejection", phase: capture.phase,
          procEntriesDelivered: capture.entries, sameUidEntriesObserved: capture.sameUid, enoentEntriesSkipped: capture.skipped,
          threadReadsAcceptedBeforeTerminal: capture.accepted, acceptedThreadTotal: capture.complete && capture.known ? capture.total : null,
          terminalReadReturnWitness: !!entry?.returned, terminalReadCloseSucceeded: !!entry?.closed,
          terminalUtf8Valid: entry?.utf8 ?? null, terminalThreadsLineMatched: entry?.returned && entry.utf8 === true ? entry.count !== null : null,
          terminalThreadTotalCapped: candidate === null ? null : Math.min(1_000_000, candidate), terminalThreadTotalWasCapped: candidate !== null && candidate > 1_000_000,
          sameUidThreadTotalBelow120: predicate, failedPredicate: ready && entry?.count === null ? "threads-line" : predicate === false ? "thread-total-below-120" : "unknown",
          diagnosticComplete: capture.complete };
        const line = "BOOTSTRAP_HOST_GUARD_DIAGNOSTIC " + JSON.stringify(record);
        if (Buffer.byteLength(line + "\n", "utf8") <= 2048) console.info(line);
      } catch { /* A diagnostic failure must not mask the actual rejection. */ }
    };
    return {
      async call<T>(operation: () => Promise<T>): Promise<T> {
        if (!enabled) return operation();
        const capture: Capture = { phase: "entry", entries: 0, sameUid: 0, skipped: 0, accepted: 0, total: 0, known: true, complete: true, traversing: false };
        let started = false;
        try { return await contexts.run(capture, async () => {
          started = true;
          try { return await operation(); } catch (error) { emit(capture); throw error; }
        }); } catch (error) { if (!started) return operation(); throw error; }
      },
      realpath(file: unknown) { const capture = contexts.getStore(); if (capture && (file === "/usr/bin/git" || file === "/usr/bin/prlimit")) observe(capture, () => { capture.phase = "trusted-tool"; }); },
      async lstat<T extends { uid: number | bigint }>(operation: () => Promise<T>, file: unknown): Promise<T> {
        const capture = contexts.getStore();
        if (capture) observe(capture, () => { if (!capture.traversing && capture.phase !== "trusted-tool") capture.phase = "proc-read"; else if (capture.pending && !capture.pending.ownerSeen) capture.phase = "proc-owner"; });
        try {
          const result = await operation();
          if (capture) observe(capture, () => {
            const entry = capture.pending;
            if (capture.traversing && entry && !entry.ownerSeen && typeof file === "string" && /^\/proc\/[0-9]+$/.test(file)) {
              entry.ownerSeen = true; entry.sameUid = result.uid === process.getuid?.();
              if (entry.sameUid) capture.sameUid = Math.min(100_000, capture.sameUid + 1);
            }
          });
          return result;
        } catch (error) { if (capture) failed(capture, error); throw error; }
      },
      async directory<T extends import("node:fs").Dir>(operation: () => Promise<T>, file: unknown): Promise<T> {
        const capture = contexts.getStore();
        if (!capture || file !== "/proc") return operation();
        observe(capture, () => { capture.phase = "proc-open"; });
        const directory = await operation();
        observe(capture, () => {
          const original = directory[Symbol.asyncIterator].bind(directory);
          const descriptor = Object.getOwnPropertyDescriptor(directory, Symbol.asyncIterator);
          const restore = () => observe(capture, () => { if (descriptor) Object.defineProperty(directory, Symbol.asyncIterator, descriptor); else if (!Reflect.deleteProperty(directory, Symbol.asyncIterator)) capture.complete = false; });
          Object.defineProperty(directory, Symbol.asyncIterator, { configurable: true, value: () => {
            const iterator = original(); capture.traversing = true;
            return {
              [Symbol.asyncIterator]() { return this; },
              async next(...args: Parameters<typeof iterator.next>) {
                observe(capture, () => { acceptPrevious(capture); capture.phase = "proc-next"; });
                const step = await iterator.next(...args);
                observe(capture, () => {
                  if (step.done) { capture.traversing = false; restore(); return; }
                  capture.phase = "proc-entry"; capture.entries = Math.min(100_001, capture.entries + 1);
                  if (/^[0-9]+$/.test(step.value.name)) capture.pending = { ownerSeen: false, sameUid: false, enoent: false, returned: false, closed: false, utf8: null, count: null };
                });
                return step;
              },
              async return(...args: Parameters<NonNullable<typeof iterator.return>>) {
                restore(); return iterator.return ? iterator.return(...args) : { done: true as const, value: undefined };
              },
              async throw(...args: Parameters<NonNullable<typeof iterator.throw>>) {
                restore(); if (iterator.throw) return iterator.throw(...args); throw args[0];
              }
            };
          } });
        });
        return directory;
      },
      opened(file: string, error?: unknown) {
        const capture = contexts.getStore();
        if (capture) observe(capture, () => { if (capture.traversing && /^\/proc\/[0-9]+\/status$/.test(file)) capture.phase = "proc-status"; else if (!capture.traversing) capture.phase = "proc-read"; });
        if (capture && error !== undefined) failed(capture, error);
      },
      handle(handle: import("node:fs/promises").FileHandle, file: string) {
        const capture = contexts.getStore(); const entry = capture?.pending;
        if (!capture || !entry?.sameUid || !capture.traversing || !/^\/proc\/[0-9]+\/status$/.test(file)) return;
        observe(capture, () => {
          const read = handle.read; const stat = handle.stat; const close = handle.close;
          const originals = ["read", "stat", "close"].map((name) => [name, Object.getOwnPropertyDescriptor(handle, name)] as const);
          let buffer: Buffer | undefined; let subarray: typeof Buffer.prototype.subarray | undefined; let busy = 0; let stats = 0; let delivered = 0;
          const restore = () => {
            observe(capture, () => {
              if (buffer && subarray) {
                if (Object.getOwnPropertyDescriptor(buffer, "subarray")?.value === subarray) { if (!Reflect.deleteProperty(buffer, "subarray")) capture.complete = false; }
                else capture.complete = false;
              }
            });
            for (const [name, descriptor] of originals) observe(capture, () => { if (descriptor) Object.defineProperty(handle, name, descriptor); else if (!Reflect.deleteProperty(handle, name)) capture.complete = false; });
          };
          let installed = false;
          try {
          handle.stat = (async (...args: Parameters<typeof stat>) => {
            busy++; try { const result = await Reflect.apply(stat, handle, args); stats++; return result; }
            catch (error) { failed(capture, error); throw error; } finally { busy--; }
          }) as typeof stat;
          handle.read = (async (...args: unknown[]) => {
            observe(capture, () => {
              const candidate = args[0];
              if (!buffer && Buffer.isBuffer(candidate)) {
                if (Object.hasOwn(candidate, "subarray")) { capture.complete = false; return; }
                buffer = candidate; const original = candidate.subarray;
                subarray = function (this: Buffer, start?: number, end?: number) {
                  const result = Reflect.apply(original, this, [start, end]) as Buffer;
                  observe(capture, () => {
                    if (this !== buffer || busy !== 0 || stats !== 2 || start !== 0 || end !== delivered || entry.returned) return;
                    entry.returned = true;
                    let text: string;
                    try { text = new TextDecoder("utf-8", { fatal: true }).decode(result); }
                    catch { entry.utf8 = false; return; }
                    entry.utf8 = true;
                    const match = /^Threads:\s+(\d+)$/m.exec(text); entry.count = match ? Number(match[1]) : null;
                  });
                  return result;
                };
                Object.defineProperty(candidate, "subarray", { configurable: true, writable: true, value: subarray });
              } else if (buffer && candidate !== buffer) capture.complete = false;
            });
            busy++;
            try {
              const result = await Reflect.apply(read, handle, args);
              observe(capture, () => { if (!Number.isInteger(result.bytesRead) || result.bytesRead < 0 || delivered + result.bytesRead > 65537) capture.complete = false; else delivered += result.bytesRead; });
              return result;
            } catch (error) { failed(capture, error); throw error; } finally { busy--; }
          }) as typeof read;
          handle.close = async () => {
            restore();
            try { await Reflect.apply(close, handle, []); observe(capture, () => { entry.closed = true; }); }
            catch (error) { failed(capture, error); throw error; }
          };
          installed = true;
          } finally { if (!installed) restore(); }
        });
      }
    };
  };
  return { makeHostDiagnostic, hostDiagnostic: makeHostDiagnostic() };
});

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
    requireLinuxHost: process.platform === "linux" ? () => hostDiagnostic.call(() => actual.requireLinuxHost()) : async () => ({ git: "/usr/bin/git", prlimit: "/private/test-only-prlimit" }) };
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
    realpath: (...args: Parameters<typeof actual.realpath>) => { hostDiagnostic.realpath(args[0]); return actual.realpath(...args); },
    opendir: (...args: Parameters<typeof actual.opendir>) => hostDiagnostic.directory(() => actual.opendir(...args), args[0]),
    lstat: (...args: Parameters<typeof actual.lstat>) => { if (faults.originalRoots.some((root) => String(args[0]).startsWith(root))) faults.originalStats++; return hostDiagnostic.lstat(() => actual.lstat(...args), args[0]); },
    open: async (...args: Parameters<typeof actual.open>) => {
      const file = String(args[0]); if (faults.originalRoots.some((root) => file.startsWith(root))) faults.originalOpens++;
      hostDiagnostic.opened(file);
      let handle: Awaited<ReturnType<typeof actual.open>>;
      try { handle = await actual.open(...args); } catch (error) { hostDiagnostic.opened(file, error); throw error; }
      if (faults.dirtyPath && file.endsWith(faults.dirtyPath)) { const read = handle.read.bind(handle); handle.read = ((...input: unknown[]) => { faults.dirtyReads++; return Reflect.apply(read, handle, input); }) as typeof handle.read; }
      hostDiagnostic.handle(handle, file);
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

// Synthetic instances use fabricated inputs and never reset the live observer.
describe("host diagnostic collector synthetic", () => {
  type Observer = ReturnType<typeof makeHostDiagnostic>;
  const prefix = "BOOTSTRAP_HOST_GUARD_DIAGNOSTIC ";
  const keys = ["schema", "boundary", "phase", "procEntriesDelivered", "sameUidEntriesObserved", "enoentEntriesSkipped", "threadReadsAcceptedBeforeTerminal", "acceptedThreadTotal", "terminalReadReturnWitness", "terminalReadCloseSucceeded", "terminalUtf8Valid", "terminalThreadsLineMatched", "terminalThreadTotalCapped", "terminalThreadTotalWasCapped", "sameUidThreadTotalBelow120", "failedPredicate", "diagnosticComplete"];
  const gate = { GITHUB_ACTIONS: "true", RELEASE_PROFILE: "full", GITHUB_REPOSITORY: "OMT-Global/bootstrap", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "1", GITHUB_RUN_ATTEMPT: "1" };
  function fresh(env: NodeJS.ProcessEnv = {}, platform = "linux", sink?: (line: string) => void, getuid = () => 1001) {
    const lines: string[] = [];
    const fakeProcess = { platform, env: { ...gate, ...env }, getuid };
    const observer = makeHostDiagnostic(fakeProcess, { info: (line) => { lines.push(line); sink?.(line); } });
    return { observer, lines, fakeProcess };
  }
  function record(lines: string[]) {
    expect(lines).toHaveLength(1); expect(lines[0]!.startsWith(prefix)).toBe(true);
    expect(Buffer.byteLength(lines[0]! + "\n", "utf8")).toBeLessThanOrEqual(2048);
    const result = JSON.parse(lines[0]!.slice(prefix.length)) as Record<string, unknown>;
    expect(Object.keys(result)).toEqual(keys); return result;
  }
  function deferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((done) => { resolve = done; });
    return { promise, resolve };
  }
  function directory(names = ["3141592653", "3141592654"]) {
    let index = 0;
    const steps = names.map((name) => ({ done: false as const, value: { name } }));
    const done = { done: true as const, value: undefined };
    const calls: unknown[][] = [];
    const originalIterator = {
      async next(...args: unknown[]) { calls.push(["next", this, ...args]); return steps[index++] ?? done; },
      async return(...args: unknown[]) { calls.push(["return", this, ...args]); return done; },
      async throw(...args: unknown[]) { calls.push(["throw", this, ...args]); throw args[0]; }
    };
    const object = { [Symbol.asyncIterator]() { return originalIterator; } };
    const descriptor = Object.getOwnPropertyDescriptor(object, Symbol.asyncIterator);
    return { object: object as unknown as import("node:fs").Dir, originalIterator, descriptor, calls, steps, done };
  }
  async function begin(observer: Observer, names?: string[]) {
    const fixture = directory(names); let calls = 0;
    const returned = await observer.directory(async () => { calls++; return fixture.object; }, "/proc");
    expect(returned).toBe(fixture.object); expect(calls).toBe(1);
    const iterator = returned[Symbol.asyncIterator]();
    expect(await iterator.next()).toBe(fixture.steps[0]);
    return { ...fixture, iterator };
  }
  async function owner(observer: Observer, ...uidInput: unknown[]) {
    const uid = uidInput.length ? uidInput[0] : 1001;
    const stat = { uid } as { uid: number | bigint }; let calls = 0;
    expect(await observer.lstat(async () => { calls++; return stat; }, "/proc/3141592653")).toBe(stat);
    expect(calls).toBe(1); observer.opened("/proc/3141592653/status");
  }
  function handle(bytes: Buffer = Buffer.from("Threads:\t120\n"), closeError?: unknown) {
    let reads = 0; let stats = 0; let closes = 0;
    const calls: unknown[][] = []; const readResults: Array<{ bytesRead: number; buffer: Buffer }> = [];
    const statResult = Object.freeze({ fixture: "stat-result" });
    const object = {
      async read(buffer: Buffer, offset: number, length: number, position: number) {
        calls.push(["read", this, buffer, offset, length, position]);
        const size = reads++ === 0 ? bytes.length : 0;
        if (size) bytes.copy(buffer, offset);
        const result = { bytesRead: size, buffer }; readResults.push(result); return result;
      },
      async stat(...args: unknown[]) { calls.push(["stat", this, ...args]); stats++; return statResult; },
      async close() { calls.push(["close", this]); closes++; if (closeError !== undefined) throw closeError; }
    };
    const originals = { read: object.read, stat: object.stat, close: object.close };
    return { object: object as unknown as import("node:fs/promises").FileHandle, originals, calls, readResults, statResult,
      counts: () => ({ reads, stats, closes }), bytes };
  }
  async function status(fixture: ReturnType<typeof handle>, witness = true, buffer: Buffer = Buffer.alloc(65537)) {
    expect(await fixture.object.stat()).toBe(fixture.statResult);
    const first = await fixture.object.read(buffer, 0, 65537, 0); expect(first).toBe(fixture.readResults[0]);
    const eof = await fixture.object.read(buffer, fixture.bytes.length, 65537 - fixture.bytes.length, fixture.bytes.length); expect(eof).toBe(fixture.readResults[1]);
    expect(await fixture.object.stat()).toBe(fixture.statResult);
    const view = witness ? buffer.subarray(0, fixture.bytes.length) : undefined;
    await fixture.object.close(); return { buffer, view };
  }
  async function terminal(bytes: Buffer, options: { witness?: boolean; closeError?: unknown } = {}) {
    const fixture = fresh(); const rejection = new Error("synthetic terminal PRIVATE_ERROR_CANARY");
    let file!: ReturnType<typeof handle>;
    await expect(fixture.observer.call(async () => {
      const traversal = await begin(fixture.observer); await owner(fixture.observer);
      file = handle(bytes, options.closeError); fixture.observer.handle(file.object, "/proc/3141592653/status");
      await status(file, options.witness ?? true); await traversal.iterator.return?.(); throw rejection;
    })).rejects.toBe(options.closeError ?? rejection);
    return { ...fixture, file, observed: record(fixture.lines) };
  }

  it("preserves resolved authority identity, rejects by identity and delegates once", async () => {
    const { observer, lines } = fresh(); const authority = Object.freeze({ git: "synthetic", prlimit: "synthetic" }); let calls = 0;
    expect(await observer.call(async () => { calls++; return authority; })).toBe(authority); expect(calls).toBe(1); expect(lines).toHaveLength(0);
    const error = new Error("PRIVATE_ERROR_CANARY");
    await expect(observer.call(async () => { calls++; throw error; })).rejects.toBe(error); expect(calls).toBe(2);
    expect(record(lines)).toMatchObject({ phase: "entry", failedPredicate: "unknown", diagnosticComplete: true });
    expect(lines[0]).not.toContain("PRIVATE_ERROR_CANARY");
  });
  it.each([[119, true, "unknown"], [120, false, "thread-total-below-120"], [121, false, "thread-total-below-120"]] as const)("observes terminal %i without implementing a guard", async (count, below, failure) => {
    const { observed } = await terminal(Buffer.from(`Threads:\t${count}\n`));
    expect(observed).toMatchObject({ acceptedThreadTotal: 0, terminalReadReturnWitness: true, terminalReadCloseSucceeded: true,
      terminalUtf8Valid: true, terminalThreadsLineMatched: true, terminalThreadTotalCapped: count,
      sameUidThreadTotalBelow120: below, failedPredicate: failure, diagnosticComplete: true });
  });
  it("commits prior119 only at next and diagnoses a separately scripted terminal1", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => {
      const traversal = await begin(observer); await owner(observer);
      const prior = handle(Buffer.from("Threads:\t119\n")); observer.handle(prior.object, "/proc/3141592653/status"); await status(prior);
      expect(await traversal.iterator.next()).toBe(traversal.steps[1]); await owner(observer);
      const last = handle(Buffer.from("Threads:\t1\n")); observer.handle(last.object, "/proc/3141592653/status"); await status(last);
      await traversal.iterator.return?.(); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ threadReadsAcceptedBeforeTerminal: 1, acceptedThreadTotal: 119, terminalThreadTotalCapped: 120, sameUidThreadTotalBelow120: false, failedPredicate: "thread-total-below-120" });
  });
  it("keeps accepted119 and preserves trusted-tool stage across ancestry lstats", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => {
      const traversal = await begin(observer, ["3141592653"]); await owner(observer);
      const file = handle(Buffer.from("Threads:\t119\n")); observer.handle(file.object, "/proc/3141592653/status"); await status(file);
      expect(await traversal.iterator.next()).toBe(traversal.done);
      observer.realpath("/usr/bin/git"); await observer.lstat(async () => ({ uid: 0 }), "/usr/bin/git");
      await observer.lstat(async () => { throw error; }, "/usr/bin");
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ phase: "trusted-tool", acceptedThreadTotal: 119, failedPredicate: "unknown", sameUidThreadTotalBelow120: null });
  });
  it("reports missing Threads but keeps invalid UTF8 unknown", async () => {
    const missing = await terminal(Buffer.from("Name:\tPRIVATE_STATUS_CANARY\n"));
    expect(missing.observed).toMatchObject({ terminalUtf8Valid: true, terminalThreadsLineMatched: false, terminalThreadTotalCapped: null, failedPredicate: "threads-line" });
    expect(missing.lines[0]).not.toContain("PRIVATE_STATUS_CANARY");
    const invalid = await terminal(Buffer.from([0xff]));
    expect(invalid.observed).toMatchObject({ terminalUtf8Valid: false, terminalThreadsLineMatched: null, terminalThreadTotalCapped: null, failedPredicate: "unknown" });
  });
  it("cannot infer a threshold from bytes and close without the return expression", async () => {
    const { observed } = await terminal(Buffer.from("Threads:\t120\n"), { witness: false });
    expect(observed).toMatchObject({ terminalReadReturnWitness: false, terminalReadCloseSucceeded: true, terminalThreadTotalCapped: null, failedPredicate: "unknown" });
  });
  it("excludes a returned120 when original close rejects ENOENT and the trace advances", async () => {
    const { observer, lines } = fresh(); const missing = Object.assign(new Error("synthetic missing"), { code: "ENOENT" }); const error = new Error("synthetic tools");
    await expect(observer.call(async () => {
      const traversal = await begin(observer, ["3141592653"]); await owner(observer);
      const file = handle(Buffer.from("Threads:\t120\n"), missing); observer.handle(file.object, "/proc/3141592653/status");
      await expect(status(file)).rejects.toBe(missing); expect(await traversal.iterator.next()).toBe(traversal.done);
      observer.realpath("/usr/bin/git"); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ enoentEntriesSkipped: 1, acceptedThreadTotal: 0, threadReadsAcceptedBeforeTerminal: 0, failedPredicate: "unknown" });
  });
  it("does not mask nonENOENT close errors or create a terminal predicate", async () => {
    const error = Object.assign(new Error("synthetic close"), { code: "EIO" });
    const { observed, file } = await terminal(Buffer.from("Threads:\t120\n"), { closeError: error });
    expect(file.counts().closes).toBe(1); expect(observed).toMatchObject({ terminalReadReturnWitness: true, terminalReadCloseSucceeded: false, failedPredicate: "unknown" });
  });
  it("delegates the same Buffer view and restores only the private buffer descriptor", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic"); let delegated!: Buffer; let actual!: Buffer | undefined;
    const buffer = Buffer.alloc(65537); const globalSubarray = Buffer.prototype.subarray;
    const inherited = Object.create(Object.getPrototypeOf(buffer), { subarray: { configurable: true, value: function (this: Buffer, start?: number, end?: number) { delegated = Reflect.apply(globalSubarray, this, [start, end]); return delegated; } } });
    Object.setPrototypeOf(buffer, inherited);
    await expect(observer.call(async () => {
      const traversal = await begin(observer); await owner(observer); const file = handle(); observer.handle(file.object, "/proc/3141592653/status");
      actual = (await status(file, true, buffer)).view;
      expect(file.object.read).toBe(file.originals.read); expect(file.object.stat).toBe(file.originals.stat); expect(file.object.close).toBe(file.originals.close);
      await traversal.iterator.return?.(); expect(Object.getOwnPropertyDescriptor(traversal.object, Symbol.asyncIterator)).toEqual(traversal.descriptor); throw error;
    })).rejects.toBe(error);
    expect(actual).toBe(delegated); expect(Object.hasOwn(buffer, "subarray")).toBe(false); expect(Object.getPrototypeOf(buffer)).toBe(inherited); expect(Buffer.prototype.subarray).toBe(globalSubarray);
    expect(record(lines).terminalReadReturnWitness).toBe(true);
  });
  it.each(["stat", "read", "close"] as const)("rolls back partial installation when %s is nonwritable", async (locked) => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => {
      await begin(observer); await owner(observer); const file = handle();
      Object.defineProperty(file.object, locked, { writable: false, configurable: false });
      const before = Object.fromEntries(["stat", "read", "close"].map((key) => [key, Object.getOwnPropertyDescriptor(file.object, key)]));
      expect(() => observer.handle(file.object, "/proc/3141592653/status")).not.toThrow();
      for (const key of ["stat", "read", "close"]) expect(Object.getOwnPropertyDescriptor(file.object, key)).toEqual(before[key]);
      await file.object.close(); expect(file.counts().closes).toBe(1); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ diagnosticComplete: false, acceptedThreadTotal: null, failedPredicate: "unknown" });
  });
  it.each(["stat", "read", "close"] as const)("continues restoring other targets when restoring %s throws", async (blocked) => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => {
      await begin(observer); await owner(observer); const file = handle(); let armed = false;
      const proxied = new Proxy(file.object, { defineProperty(target, key, descriptor) {
        if (armed && key === blocked && descriptor.value === file.originals[blocked]) throw new Error("synthetic descriptor refusal");
        return Reflect.defineProperty(target, key, descriptor);
      } });
      observer.handle(proxied, "/proc/3141592653/status"); armed = true;
      await status({ ...file, object: proxied });
      for (const key of ["stat", "read", "close"] as const) if (key !== blocked) expect(proxied[key]).toBe(file.originals[key]);
      expect(file.counts().closes).toBe(1); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ diagnosticComplete: false, acceptedThreadTotal: null, terminalThreadTotalCapped: null, failedPredicate: "unknown" });
  });
  it("restores handle targets and calls original close even if buffer cleanup fails", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => {
      await begin(observer); await owner(observer); const file = handle(); observer.handle(file.object, "/proc/3141592653/status");
      const buffer = Buffer.alloc(65537); await file.object.stat(); await file.object.read(buffer, 0, 65537, 0); await file.object.stat(); buffer.subarray(0, file.bytes.length);
      Object.defineProperty(buffer, "subarray", { configurable: false }); await file.object.close();
      for (const key of ["stat", "read", "close"] as const) expect(file.object[key]).toBe(file.originals[key]);
      expect(file.counts().closes).toBe(1); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ diagnosticComplete: false, failedPredicate: "unknown" });
  });
  it.each([[1001, 1], [1002, 0], [1001n, 0], ["1001", 0], [NaN, 0], [Infinity, 0], [undefined, 0]] as const)("uses strict numeric UID comparison for %s", async (uid, expected) => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => { await begin(observer); await owner(observer, uid); throw error; })).rejects.toBe(error);
    expect(record(lines).sameUidEntriesObserved).toBe(expected);
  });
  it("never coerces a UID object or counts parent lstats twice", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic"); let coercions = 0;
    await expect(observer.call(async () => {
      await begin(observer); await owner(observer, { valueOf() { coercions++; return 1001; } });
      await observer.lstat(async () => ({ uid: 1001 }), "/proc/3141592653"); throw error;
    })).rejects.toBe(error);
    expect(coercions).toBe(0); expect(record(lines).sameUidEntriesObserved).toBe(0);
  });
  it("retains A-owned handle observations when B invokes its wrapped methods", async () => {
    const { observer, lines } = fresh(); const ready = deferred<ReturnType<typeof handle>>(); const worked = deferred<void>(); const releaseB = deferred<void>();
    const errorA = new Error("synthetic A"); const errorB = new Error("synthetic B");
    const a = observer.call(async () => {
      await begin(observer); await owner(observer); const file = handle(); observer.handle(file.object, "/proc/3141592653/status"); ready.resolve(file);
      await worked.promise; throw errorA;
    });
    const b = observer.call(async () => { const fileA = await ready.promise; await status(fileA); worked.resolve(); await releaseB.promise; throw errorB; });
    await expect(a).rejects.toBe(errorA); releaseB.resolve(); await expect(b).rejects.toBe(errorB);
    expect(record(lines)).toMatchObject({ procEntriesDelivered: 1, sameUidEntriesObserved: 1, terminalReadReturnWitness: true, terminalThreadTotalCapped: 120, failedPredicate: "thread-total-below-120" });
  });
  it("makes one attempt per instance even if console throws, without resetting the live observer", async () => {
    const { observer, lines } = fresh({}, "linux", () => { throw new Error("synthetic sink"); }); const error = new Error("synthetic original");
    await expect(observer.call(async () => { throw error; })).rejects.toBe(error);
    await expect(observer.call(async () => { throw error; })).rejects.toBe(error); expect(lines).toHaveLength(1);
    const independent = fresh(); await expect(independent.observer.call(async () => { throw error; })).rejects.toBe(error); expect(independent.lines).toHaveLength(1);
  });
  it.each([
    ["GITHUB_ACTIONS", undefined], ["GITHUB_ACTIONS", "TRUE"], ["GITHUB_ACTIONS", "1"],
    ["RELEASE_PROFILE", undefined], ["RELEASE_PROFILE", "standard"], ["RELEASE_PROFILE", "Full"],
    ["GITHUB_REPOSITORY", undefined], ["GITHUB_REPOSITORY", "omt-global/bootstrap"],
    ["GITHUB_EVENT_NAME", undefined], ["GITHUB_EVENT_NAME", "push"],
    ["GITHUB_RUN_ID", undefined], ["GITHUB_RUN_ID", "0"], ["GITHUB_RUN_ID", "01"], ["GITHUB_RUN_ID", " 1"], ["GITHUB_RUN_ID", "1.0"], ["GITHUB_RUN_ID", "9".repeat(21)],
    ["GITHUB_RUN_ATTEMPT", undefined], ["GITHUB_RUN_ATTEMPT", "0"], ["GITHUB_RUN_ATTEMPT", "01"], ["GITHUB_RUN_ATTEMPT", "+1"], ["GITHUB_RUN_ATTEMPT", "9".repeat(7)],
    ["GITHUB_RUN_ID", "1\n"], ["GITHUB_RUN_ID", "1\r\n"], ["GITHUB_RUN_ID", "1\r"], ["GITHUB_RUN_ID", "1\u2028"], ["GITHUB_RUN_ID", "1\u2029"],
    ["GITHUB_RUN_ATTEMPT", "1\n"], ["GITHUB_RUN_ATTEMPT", "1\r\n"], ["GITHUB_RUN_ATTEMPT", "1\r"], ["GITHUB_RUN_ATTEMPT", "1\u2028"], ["GITHUB_RUN_ATTEMPT", "1\u2029"]
  ] as const)("keeps gate off for %s=%s while preserving exact delegation", async (name, value) => {
    const { observer, lines } = fresh({ [name]: value }); const error = new Error("synthetic"); let calls = 0;
    await expect(observer.call(async () => { calls++; throw error; })).rejects.toBe(error); expect(calls).toBe(1); expect(lines).toHaveLength(0);
  });
  it.each(["darwin", "win32"])("keeps %s gate off", async (platform) => {
    const { observer, lines } = fresh({}, platform); const error = new Error("synthetic");
    await expect(observer.call(async () => { throw error; })).rejects.toBe(error); expect(lines).toHaveLength(0);
  });
  it.each([undefined, "0", "1", "PRIVATE_ENV_CANARY"])("does not gate on the host-broker flag %s", async (flag) => {
    const { observer, lines } = fresh({ BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS: flag, GITHUB_RUN_ID: "9".repeat(20), GITHUB_RUN_ATTEMPT: "9".repeat(6) }); const error = new Error("PRIVATE_ERROR_CANARY");
    await expect(observer.call(async () => { throw error; })).rejects.toBe(error); record(lines); expect(lines[0]).not.toContain("PRIVATE_ENV_CANARY"); expect(lines[0]).not.toContain("PRIVATE_ERROR_CANARY");
  });
  it("captures the gate when a fresh instance is constructed", async () => {
    const { observer, lines, fakeProcess } = fresh({ RELEASE_PROFILE: "standard" }); fakeProcess.env.RELEASE_PROFILE = "full";
    const error = new Error("synthetic"); await expect(observer.call(async () => { throw error; })).rejects.toBe(error); expect(lines).toHaveLength(0);
  });
  it("caps projected overflow while retaining fixed public schema and no private status text", async () => {
    const { observed, lines } = await terminal(Buffer.from("Private:\tPRIVATE_STATUS_CANARY\nThreads:\t" + "9".repeat(4096) + "\n"));
    expect(observed).toMatchObject({ terminalThreadTotalCapped: 1000000, terminalThreadTotalWasCapped: true, sameUidThreadTotalBelow120: false, failedPredicate: "thread-total-below-120" });
    for (const value of Object.values(observed)) if (typeof value === "number") expect(Number.isFinite(value)).toBe(true);
    expect(lines[0]).not.toContain("PRIVATE_STATUS_CANARY"); expect(lines[0]).not.toContain("3141592653"); expect(Buffer.byteLength(lines[0]! + "\n", "utf8")).toBeLessThanOrEqual(585);
  });
  it.each(["owner", "open", "read", "stat"] as const)("excludes ENOENT at %s before a later rejection", async (stage) => {
    const { observer, lines } = fresh(); const missing = Object.assign(new Error("synthetic vanished"), { code: "ENOENT" }); const error = new Error("synthetic later");
    await expect(observer.call(async () => {
      const traversal = await begin(observer, ["3141592653"]);
      if (stage === "owner") await expect(observer.lstat(async () => { throw missing; }, "/proc/3141592653")).rejects.toBe(missing);
      else {
        await owner(observer);
        if (stage === "open") observer.opened("/proc/3141592653/status", missing);
        else {
          const file = handle();
          if (stage === "read") file.object.read = (async () => { throw missing; }) as typeof file.object.read;
          else file.object.stat = (async () => { throw missing; }) as typeof file.object.stat;
          observer.handle(file.object, "/proc/3141592653/status"); await expect(status(file)).rejects.toBe(missing); await file.object.close();
        }
      }
      expect(await traversal.iterator.next()).toBe(traversal.done); observer.realpath("/usr/bin/git"); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ enoentEntriesSkipped: 1, threadReadsAcceptedBeforeTerminal: 0, acceptedThreadTotal: 0, failedPredicate: "unknown" });
  });
  it("does not infer from a terminal count when an earlier accepted total is unknown", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => {
      const traversal = await begin(observer); await owner(observer);
      const prior = handle(Buffer.from("Threads:\t1\n")); observer.handle(prior.object, "/proc/3141592653/status"); await status(prior, false);
      expect(await traversal.iterator.next()).toBe(traversal.steps[1]); await owner(observer);
      const last = handle(); observer.handle(last.object, "/proc/3141592653/status"); await status(last); await traversal.iterator.return?.(); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ acceptedThreadTotal: null, terminalReadReturnWitness: true, terminalThreadTotalCapped: null, failedPredicate: "unknown" });
  });
  it("does not witness a return while a read is pending even with two stats", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic"); const pending = deferred<{ bytesRead: number; buffer: Buffer }>();
    await expect(observer.call(async () => {
      await begin(observer); await owner(observer); const file = handle(); const buffer = Buffer.alloc(65537);
      file.object.read = (() => pending.promise) as typeof file.object.read; observer.handle(file.object, "/proc/3141592653/status");
      await file.object.stat(); await file.object.stat(); const reading = file.object.read(buffer, 0, buffer.length, 0);
      buffer.subarray(0, 0); const returned = { bytesRead: 0, buffer }; pending.resolve(returned); expect(await reading).toBe(returned);
      await file.object.close(); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ terminalReadReturnWitness: false, failedPredicate: "unknown" });
  });
  it("does not witness a different subarray range", async () => {
    const { observer, lines } = fresh(); const error = new Error("synthetic");
    await expect(observer.call(async () => {
      await begin(observer); await owner(observer); const file = handle(); observer.handle(file.object, "/proc/3141592653/status"); const buffer = Buffer.alloc(65537);
      await file.object.stat(); await file.object.read(buffer, 0, buffer.length, 0); await file.object.stat(); buffer.subarray(1, file.bytes.length);
      await file.object.close(); throw error;
    })).rejects.toBe(error);
    expect(record(lines)).toMatchObject({ terminalReadReturnWitness: false, failedPredicate: "unknown" });
  });
});
