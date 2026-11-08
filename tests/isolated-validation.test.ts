import { mkdtemp, mkdir, readFile, writeFile, chmod, rm, access } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { validateIsolatedNode } from "../src/isolation/node-validation.js";
import { CONTAINER_SETUP } from "../src/isolation/setup.js";
import { Script } from "node:vm";
import { ISOLATION_LIMITS, type NodeValidationInput } from "../src/isolation/node-profile.js";

const transport = vi.hoisted(() => ({ executable: "", unavailable: true, uid: 0, mode: 0o100755, badAncestor: false }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const fixed = (value: unknown) => value === "/usr/bin/docker" || value === "/usr/local/bin/docker";
  return { ...actual,
    access: async (value: Parameters<typeof actual.access>[0], mode?: number) => {
      if (fixed(value)) { if (transport.unavailable) throw Object.assign(new Error("Missing fixture tool"), { code: "ENOENT" }); return; }
      return actual.access(value, mode);
    },
    realpath: async (value: Parameters<typeof actual.realpath>[0], options?: Parameters<typeof actual.realpath>[1]) => fixed(value) ? value : actual.realpath(value, options),
    stat: async (value: Parameters<typeof actual.stat>[0]) => {
      if (fixed(value)) return { uid: transport.uid, mode: transport.mode, isFile: () => true, isDirectory: () => false };
      if (transport.badAncestor && ["/usr/bin", "/usr/local/bin"].includes(String(value))) return { uid: 0, mode: 0o40777, isDirectory: () => true };
      return actual.stat(value);
    }
  };
});
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: (executable: string, args: readonly string[], options: import("node:child_process").SpawnOptions) =>
    actual.spawn(["/usr/bin/docker", "/usr/local/bin/docker"].includes(executable) && transport.executable ? transport.executable : executable, args, options) };
});
const directories: string[] = [];
const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
const architecture = Object.getOwnPropertyDescriptor(process, "arch")!;
const originalPath = process.env.PATH;
function fixture(hook = false, phase: "prepared-hook" | "final-check" = "final-check"): NodeValidationInput {
  const file = (name: string, text: string, executable = false) => ({ path: name, bytes: Buffer.from(text), mode: executable ? "100755" as const : "100644" as const });
  return { ...(phase === "final-check" ? { phase, candidateCommit: "c".repeat(40) } : { phase }), profile: "node-npm-linux-v1", baseBundle: Buffer.from("synthetic bundle, validated by real Docker tests"), baseCommit: "a".repeat(40),
    author: { name: "Synthetic Author", email: "author@example.invalid", date: "1767225600 +0000" },
    committer: { name: "Synthetic Committer", email: "committer@example.invalid", date: "1767225601 +0000" },
    branch: "codex/isolated-test", commitMessage: "test: isolated validation\n\nSigned-off-by: Synthetic Tester <fixture@example.invalid>\n",
    hook: hook ? ".githooks/pre-commit" : "none", files: [file("package.json", '{"name":"fixture","version":"1.0.0"}'),
      file("package-lock.json", '{"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"}}}'),
      file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nexit 0\n", true), ...(hook ? [file(".githooks/pre-commit", "#!/bin/bash\nexit 0\n", true)] : [])] };
}
interface FakeOptions { failAt?: string; exitCode?: number; hangAt?: string; cleanupFailure?: boolean; excessiveOutput?: boolean; platform?: string; invalidEvidence?: boolean; untrustedUid?: number; untrustedMode?: number; untrustedAncestor?: boolean }
async function fakeDocker(options: FakeOptions = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-docker-control-")); directories.push(directory);
  const log = path.join(directory, "calls.jsonl"); const config = path.join(directory, "options.json");
  await writeFile(config, JSON.stringify(options)); await mkdir(path.join(directory, "bin"));
  const executable = path.join(directory, "bin/docker");
  await writeFile(executable, `#!${process.execPath}\nconst fs=require('node:fs');
const cfg=JSON.parse(fs.readFileSync(${JSON.stringify(config)},'utf8'));
const args=process.argv.slice(6), command=args[0], name=args.includes('--name')?args[args.indexOf('--name')+1]:args.at(-1);
fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({args,environment:process.env,cwd:process.cwd()})+'\\n');
const phase=String(name).split('-').at(-1);
if(cfg.cleanupFailure && ((command==='rm')||(command==='volume'&&args[1]==='rm'))) process.exit(28);
if(cfg.failAt===command || cfg.failAt===command+':'+phase) process.exit(23);
if(cfg.hangAt===command+':'+phase) setInterval(()=>{},1000);
else if(command==='version' || command==='image') console.log(cfg.platform||'linux/amd64');
else if(command==='start' && phase==='prepare') console.log(JSON.stringify(cfg.invalidEvidence?{}:{tree:'b'.repeat(40),tools:{bash:'GNU bash',git:'git',python:'Python 3',node:'v24.0.0',npm:'11'}}));
else if(command==='start' && cfg.excessiveOutput) process.stdout.write('x'.repeat(9*1024*1024));
else if(command==='inspect') console.log(JSON.stringify({Running:false,ExitCode:phase==='check'?(cfg.exitCode||0):0,OOMKilled:false,Error:''}));
else if(command==='cp') { const transfer=args[1].slice(0,-2); fs.writeFileSync(${JSON.stringify(path.join(directory, "transferred.json"))},fs.readFileSync(transfer+'/manifest.json')); }
else if(command==='create'||command==='volume') console.log(name);
`);
  await chmod(executable, 0o755);
  transport.executable = executable; transport.unavailable = false; transport.uid = options.untrustedUid ?? 0; transport.mode = options.untrustedMode ?? 0o100755; transport.badAncestor = options.untrustedAncestor ?? false;
  process.env.PATH = `${path.dirname(executable)}${path.delimiter}${originalPath}`;
  Object.defineProperty(process, "platform", { value: "linux" }); Object.defineProperty(process, "arch", { value: "x64" });
  return { directory, calls: async () => (await readFile(log, "utf8").catch((error: NodeJS.ErrnoException) => { if (error.code === "ENOENT") return ""; throw error; })).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) };
}
afterEach(async () => {
  Object.defineProperty(process, "platform", platform); Object.defineProperty(process, "arch", architecture);
  if (originalPath === undefined) delete process.env.PATH; else process.env.PATH = originalPath;
  delete process.env.BOOTSTRAP_SYNTHETIC_OPERATOR_CANARY;
  transport.executable = ""; transport.unavailable = true; transport.uid = 0; transport.mode = 0o100755; transport.badAncestor = false;
  vi.useRealTimers(); vi.restoreAllMocks();
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("isolated Docker supervisor lifecycle (controlled CLI, not confinement proof)", () => {
  it("constructs a fixed confined profile and separately validates a declared hook", async () => {
    const fake = await fakeDocker(); process.env.BOOTSTRAP_SYNTHETIC_OPERATOR_CANARY = "fixture-only";
    const replay = await validateIsolatedNode(fixture(true, "prepared-hook"));
    expect(replay.phase).toBe("prepared-hook");
    const report = await validateIsolatedNode(fixture(true));
    expect(report.phase).toBe("final-check");
    expect(report.phase === "final-check" && report.candidateCommit).toBe("c".repeat(40));
    expect(report.preparedTree).toBe("b".repeat(40)); expect(report.tools.node).toBe("v24.0.0");
    const calls = await fake.calls(); const creates = calls.filter(({ args }) => args[0] === "create");
    expect(creates).toHaveLength(4);
    for (const { args, environment } of creates) {
      for (const values of [["--network", "none"], ["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"], ["--user", "1000:1000"], ["--memory", "4g"], ["--pids-limit", "256"]]) {
        expect(args.slice(args.indexOf(values[0]), args.indexOf(values[0]) + 2)).toEqual(values);
      }
      expect(args).toContain("--read-only"); expect(args).toContain("--no-healthcheck");
      expect(args.filter((value: string) => value.startsWith("type="))).not.toContainEqual(expect.stringContaining("type=bind"));
      expect(environment.BOOTSTRAP_SYNTHETIC_OPERATOR_CANARY).toBeUndefined(); expect(Object.keys(environment).filter((key) => !(platform.value === "darwin" && key === "__CF_USER_TEXT_ENCODING")).sort()).toEqual(["HOME", "PATH"]);
    }
    for (const { args } of creates.filter(({ args }) => args.at(-1) !== "prepare")) {
      const source = args.find((value: string) => value.startsWith("type=volume") && value.includes("dst=/repo"));
      const cache = args.find((value: string) => value.startsWith("type=volume") && value.includes("dst=/pristine-cache"));
      expect(source).toContain(",readonly"); expect(cache).toContain(",readonly");
    }
    expect(creates.map(({ args }) => args.at(-1))).toEqual(["prepare", "hook", "prepare", "check"]);
    expect(calls.filter(({ args }) => args[0] === "rm")).toHaveLength(4);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(6);
    await expect(access(calls[0]!.cwd)).rejects.toThrow();
  });
  it("freezes caller bytes before asynchronous Docker work", async () => {
    const fake = await fakeDocker(); const input = fixture(); const original = Buffer.from(input.files[0]!.bytes);
    const operation = validateIsolatedNode(input); input.files[0]!.bytes.fill(0);
    const report = await operation;
    const transferred = JSON.parse(await readFile(path.join(fake.directory, "transferred.json"), "utf8"));
    const { createHash } = await import("node:crypto");
    expect(transferred.files.find((file: { path: string }) => file.path === "package.json").sha256).toBe(createHash("sha256").update(original).digest("hex"));
    expect(report.phase).toBe("final-check");
    expect("hookOutput" in report).toBe(false);
  });
  it("rejects a failed container even if docker start itself exits successfully", async () => {
    const fake = await fakeDocker({ exitCode: 17 });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("isolated process did not complete successfully");
    const calls = await fake.calls(); expect(calls.some(({ args }) => args[0] === "inspect")).toBe(true);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
  });
  it.each(["create:prepare", "create:check", "start:prepare", "start:check", "start:hook"])("cleans partial Docker state after %s fails", async (failAt) => {
    const fake = await fakeDocker({ failAt });
    await expect(validateIsolatedNode(fixture(true, failAt.endsWith(":hook") ? "prepared-hook" : "final-check"))).rejects.toThrow();
    const calls = await fake.calls();
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
    const created = calls.filter(({ args }) => args[0] === "create").map(({ args }) => args[args.indexOf("--name") + 1]);
    const removed = calls.filter(({ args }) => args[0] === "rm").map(({ args }) => args.at(-1));
    expect(removed).toEqual(expect.arrayContaining(created));
  });
  it("does not reuse a validation container or its mutable cache for hook replay", async () => {
    const fake = await fakeDocker();
    await validateIsolatedNode(fixture(true, "prepared-hook"));
    await validateIsolatedNode(fixture(true));
    const calls = await fake.calls();
    const check = calls.find(({ args }) => args[0] === "create" && args.at(-1) === "check").args;
    const hook = calls.find(({ args }) => args[0] === "create" && args.at(-1) === "hook").args;
    expect(check[check.indexOf("--name") + 1]).not.toBe(hook[hook.indexOf("--name") + 1]);
    expect(calls.findIndex(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-hook"))).toBeLessThan(calls.findIndex(({ args }) => args[0] === "create" && args.at(-1) === "check"));
    expect(check).toContainEqual(expect.stringContaining("/npm-cache:rw,nosuid,nodev,size="));
    expect(hook).toContainEqual(expect.stringContaining("/npm-cache:rw,nosuid,nodev,size="));
  });
  it("kills the active client and removes the actual named resource on cancellation", async () => {
    const fake = await fakeDocker({ hangAt: "start:check" }); const controller = new AbortController();
    const operation = validateIsolatedNode(fixture(), { signal: controller.signal });
    for (let attempt = 0; attempt < 200; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      if ((await fake.calls()).some(({ args }) => args[0] === "start" && args.at(-1).endsWith("-check"))) break;
    }
    controller.abort(); await expect(operation).rejects.toThrow("cancelled");
    const calls = await fake.calls();
    expect(calls.some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-check"))).toBe(true);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
  });
  it("enforces its own phase deadline and still removes the named container", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const fake = await fakeDocker({ hangAt: "start:check" }); const controller = new AbortController();
    const operation = validateIsolatedNode(fixture(), { signal: controller.signal }).then(() => ({ passed: true, error: undefined }), (error: unknown) => ({ passed: false, error }));
    try {
      let attached = false; const until = Date.now() + 5000;
      while (Date.now() < until) {
        await new Promise<void>((resolve) => setImmediate(resolve));
        attached = (await fake.calls()).some(({ args }) => args[0] === "start" && args.at(-1).endsWith("-check"));
        if (attached) break;
      }
      expect(attached).toBe(true);
      await vi.advanceTimersByTimeAsync(ISOLATION_LIMITS.phaseMs);
      const outcome = await operation;
      expect(outcome.passed).toBe(false); expect(outcome.error).toBeInstanceOf(Error);
      expect((outcome.error as Error).message).toContain("timed out");
      expect((await fake.calls()).some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-check"))).toBe(true);
    } finally { controller.abort(); vi.useRealTimers(); await operation; }
  }, 15_000);
  it("keeps the original failure when Docker cleanup also fails", async () => {
    await fakeDocker({ failAt: "start:check", cleanupFailure: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow(/Isolated phase.*Cleanup failed/);
  });
  it("enforces the retained-output bound and still cleans up", async () => {
    const fake = await fakeDocker({ excessiveOutput: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("output exceeded");
    expect((await fake.calls()).some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-check"))).toBe(true);
  });
  it("rejects invalid setup evidence and incompatible Docker platforms", async () => {
    await fakeDocker({ platform: "linux/arm64" });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("supported platform");
    await fakeDocker({ invalidEvidence: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow();
  });
  it("blocks unsupported supervisors, absent Docker, and already-cancelled requests", async () => {
    Object.defineProperty(process, "platform", { value: "darwin" });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("Linux/amd64");
    Object.defineProperty(process, "platform", { value: "linux" }); Object.defineProperty(process, "arch", { value: "x64" }); process.env.PATH = ".";
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("trusted Docker CLI is unavailable");
    const controller = new AbortController(); controller.abort();
    await expect(validateIsolatedNode(fixture(), { signal: controller.signal })).rejects.toHaveProperty("name", "AbortError");
  });
  it("does not execute a repository-controlled Docker shadow from PATH", async () => {
    const fake = await fakeDocker(); transport.unavailable = true;
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("trusted Docker CLI is unavailable");
    expect(await fake.calls()).toEqual([]);
  });
  it.each([{ untrustedUid: 1000 }, { untrustedMode: 0o100775 }, { untrustedAncestor: true }])("blocks a non-root or writable tool chain before execution: %j", async (options) => {
    const fake = await fakeDocker(options);
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("trusted Docker CLI is unavailable");
    expect(await fake.calls()).toEqual([]);
  });
  it("parses the fixed helper without executing repository code on the host", () => expect(() => new Script(CONTAINER_SETUP)).not.toThrow());
});
