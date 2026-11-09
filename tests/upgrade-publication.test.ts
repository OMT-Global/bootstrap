import { execFileSync, type SpawnOptions } from "node:child_process";
import { readFileSync } from "node:fs";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const faults = vi.hoisted(() => ({
  contexts: new Map<object, unknown>(), provider: "", providerFiles: "", providerAncestors: [] as string[], providerReads: 0,
  directory: "", remote: "", scenario: "", api: "", branch: "codex/publication-fixture", base: "", candidate: "",
  commands: [] as Array<{ executable: string; args: string[]; environment: NodeJS.ProcessEnv }>,
  cleanupFailures: 0, race: "" as "" | "base" | "candidate", cancelAfterPush: undefined as AbortController | undefined,
  helper: "", missingTools: false, providerWritable: false, actualToolMetadata: false, actualLimits: false
}));

// Only fixture provider metadata, command transport and the private capability
// seam are replaced. Actual boundedCommand and Git ref protection execute.
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual,
    realpath: (file: Parameters<typeof actual.realpath>[0]) => {
      if (!faults.actualToolMetadata && ["/usr/bin/gh", "/usr/local/bin/gh", "/usr/bin/node"].includes(String(file))) {
        return faults.missingTools ? Promise.reject(new Error("fixture missing fixed tool")) : Promise.resolve(String(file));
      }
      return actual.realpath(file);
    },
    lstat: async (file: Parameters<typeof actual.lstat>[0], options?: Parameters<typeof actual.lstat>[1]) => {
      if (!faults.actualToolMetadata && ["/usr/bin/gh", "/usr/local/bin/gh", "/usr/bin/node"].includes(String(file))) {
        return { uid: 0, mode: 0o100755, isFile: () => true, isDirectory: () => false };
      }
      if (!faults.actualToolMetadata && faults.providerAncestors.includes(String(file))) return { uid: 0, mode: faults.providerWritable ? 0o40777 : 0o40755, isDirectory: () => true };
      return actual.lstat(file, options);
    },
    open: (file: Parameters<typeof actual.open>[0], ...args: Parameters<typeof actual.open> extends [unknown, ...infer T] ? T : never) => {
      if (String(file).startsWith(faults.provider + "/")) { faults.providerReads++; return actual.open(path.join(faults.providerFiles, path.basename(String(file))), ...args); }
      return actual.open(file, ...args);
    },
    rm: (file: Parameters<typeof actual.rm>[0], options?: Parameters<typeof actual.rm>[1]) => {
      if (faults.cleanupFailures && String(file).startsWith(path.join(faults.directory, "publication-"))) {
        faults.cleanupFailures--; return Promise.reject(new Error("private cleanup fixture detail"));
      }
      return actual.rm(file, options);
    }
  };
});
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: (executable: string, args: readonly string[], options: SpawnOptions) => {
    if (faults.actualLimits && executable === "/usr/bin/prlimit") return actual.spawn(executable, args, options);
    if (executable !== "/publication-fixture/prlimit") throw new Error("unexpected fixture command");
    const command = args[7]!; const fixed = args.slice(8); const environment = { ...options.env };
    faults.commands.push({ executable: command, args: [...fixed], environment });
    if (command === "/usr/bin/git") {
      const setting = fixed.find((arg) => arg.startsWith("credential.https://github.com/example/public.git.helper="))!;
      const file = / '([^']+)'$/.exec(setting)![1]!; faults.helper = readFileSync(file, "utf8");
      if (faults.race === "base") execFileSync("/usr/bin/git", ["--git-dir", faults.remote, "update-ref", `refs/heads/${faults.branch}`, faults.base], { env: { PATH: "/usr/bin:/bin" } });
      if (faults.race === "candidate") execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "push", "--quiet", faults.remote, `${faults.candidate}:refs/heads/${faults.branch}`], { env: environment });
      const mapped = fixed.map((arg) => arg === "https://github.com/example/public.git" ? faults.remote : arg);
      const child = actual.spawn(command, ["-c", "protocol.file.allow=always", ...mapped], options);
      child.once("close", (code) => { if (code === 0) faults.cancelAfterPush?.abort(); }); return child;
    }
    if (command !== "/usr/bin/gh" || fixed[0] !== "api") throw new Error("unexpected fixture provider operation");
    return actual.spawn(process.execPath, [faults.api, ...fixed], { ...options, env: { ...environment, PUBLICATION_FIXTURE_SCENARIO: faults.scenario } });
  } };
});
vi.mock("../src/upgrade-transport.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-transport.js")>();
  return { ...actual, transportContext: (repository: object) => {
    const context = faults.contexts.get(repository); if (!context) throw new Error("Governed upgrade host operation is unsupported."); return context;
  } };
});

import { boundedCommand, neutralEnvironment, PRLIMIT_ARGS, requireLinuxHost, trustedExecutable } from "../src/upgrade-host.js";
import { finishRecovery, publishCandidate } from "../src/upgrade-publication.js";
import type { PublicRepository, TransportContext } from "../src/upgrade-transport.js";

const directories: string[] = [];
const providerCanary = "fixture-provider-canary";
const contextCanary = "context-token-canary";
const replyMarker = "synthetic-only";
const requiredLinux = process.env.BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS === "1";
const overrides = ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "GH_PATH"];
beforeEach(() => { for (const key of overrides) vi.stubEnv(key, ""); });
afterEach(async () => {
  vi.unstubAllEnvs(); faults.cleanupFailures = 0; faults.race = ""; faults.missingTools = false; faults.providerWritable = false;
  faults.actualToolMetadata = false; faults.actualLimits = false; faults.providerReads = 0;
  faults.cancelAfterPush = undefined; faults.contexts.clear(); faults.commands.length = 0; faults.helper = "";
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});
async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-publication-test-")); directories.push(directory); faults.directory = directory;
  const root = path.join(directory, "source"); const empty = path.join(directory, "empty"); const providerFiles = path.join(directory, "provider");
  await mkdir(root); await mkdir(empty); await mkdir(providerFiles); const remote = path.join(directory, "remote.git");
  const bareEnv = neutralEnvironment(empty, directory);
  execFileSync("/usr/bin/git", ["init", "--bare", "--quiet", `--template=${empty}`, remote], { env: bareEnv });
  const execPath = execFileSync("/usr/bin/git", ["--exec-path"], { env: bareEnv }).toString().trim();
  const environment = { ...bareEnv, GIT_DIR: path.join(root, ".git"), GIT_WORK_TREE: root, GIT_EXEC_PATH: execPath,
    GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000",
    GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: string) => execFileSync("/usr/bin/git", ["-c", "commit.gpgsign=false", "-c", `core.hooksPath=${empty}`, ...args], { cwd: directory, env: environment, ...(input !== undefined ? { input } : {}) }).toString().trim();
  git(["init", "--quiet", "--initial-branch=codex/base", `--template=${empty}`]); const tree = git(["mktree"], "");
  const baseCommit = git(["commit-tree", tree], "fixture base\n"); const candidate = git(["commit-tree", tree, "-p", baseCommit], "fixture candidate\n");
  git(["push", "--quiet", remote, `${baseCommit}:refs/heads/trunk`]); faults.remote = remote; faults.base = baseCommit; faults.candidate = candidate;
  const cancellation = new AbortController(); let reserved = 0;
  const context: TransportContext = { directory, root, gitdir: environment.GIT_DIR, empty, execPath, git: "/usr/bin/git", prlimit: "/publication-fixture/prlimit", env: environment, signal: cancellation.signal, candidate, signedBranch: faults.branch, signedPlanSha256: "a".repeat(64), pending: new Set(),
    reserve(bytes) { reserved += bytes; let released = false; return { bytes, async releaseAfterCleanup(cleanup) { expect(released).toBe(false); await cleanup(); released = true; reserved -= bytes; } }; } };
  const repository = Object.freeze({ repository: "example/public", defaultBranch: "trunk", baseCommit, snapshot: undefined }) as unknown as PublicRepository;
  faults.contexts.set(repository, context); faults.providerFiles = providerFiles; faults.provider = path.join(os.userInfo().homedir, ".config/gh");
  faults.providerAncestors.length = 0;
  for (let parent = faults.provider; parent !== path.dirname(parent); parent = path.dirname(parent)) faults.providerAncestors.push(parent);
  await writeFile(path.join(providerFiles, "config.yml"), "git_protocol: https\nprompt: disabled\n", { mode: 0o600 });
  await writeFile(path.join(providerFiles, "hosts.yml"), `github.com:\n  user: public-fixture\n  oauth_token: ${providerCanary}\n  git_protocol: https\n`, { mode: 0o600 });
  const pr = { number: 7, html_url: "https://github.com/example/public/pull/7", state: "open", draft: true,
    base: { ref: "trunk", sha: baseCommit, repo: { full_name: "example/public" } },
    head: { ref: faults.branch, sha: candidate, repo: { full_name: "example/public" } } };
  const scenario = { remote: { ref: `refs/heads/${faults.branch}`, object: { type: "commit", sha: candidate } }, create: structuredClone(pr), readback: structuredClone(pr), fail: "" };
  faults.scenario = path.join(directory, "scenario.json"); faults.api = path.join(directory, "api.cjs");
  await writeFile(faults.api, `const fs = require("node:fs"); const state = JSON.parse(fs.readFileSync(process.env.PUBLICATION_FIXTURE_SCENARIO));
const args = process.argv.slice(2); const endpoint = args.find(value => value.startsWith("/repos/"));
const stage = endpoint.includes("/git/ref/") ? "remote" : endpoint.endsWith("/7") ? "readback" : "create";
let body = ""; process.stdin.on("data", part => body += part); process.stdin.on("end", () => {
fs.appendFileSync(process.env.PUBLICATION_FIXTURE_SCENARIO + ".requests", JSON.stringify({args,body}) + "\\n");
if (state.fail === stage) process.exit(9); process.stdout.write(JSON.stringify(state[stage])); });\n`);
  const save = () => writeFile(faults.scenario, JSON.stringify(scenario)); await save();
  const publish = () => publishCandidate(repository, candidate, faults.branch, "Fixture upgrade", "Generated template fixture\n");
  const remoteHead = () => execFileSync("/usr/bin/git", ["--git-dir", remote, "rev-parse", `refs/heads/${faults.branch}`], { env: bareEnv }).toString().trim();
  return { directory, providerFiles, repository, context, candidate, baseCommit, scenario, save, publish, remoteHead, cancellation, reserved: () => reserved };
}

describe("private create-only publication broker (synthetic provider only)", () => {
  it("publishes one explicit candidate and verifies the captured default base, draft and structured readback", async () => {
    const data = await fixture(); const result = await data.publish();
    expect(result).toMatchObject({ ok: true, phase: "complete", push: "confirmed", candidate: data.candidate, pullRequestUrl: "https://github.com/example/public/pull/7" });
    expect(result).not.toHaveProperty("cleanupFailed");
    expect(Object.isFrozen(result)).toBe(true); expect(data.remoteHead()).toBe(data.candidate); expect(data.reserved()).toBe(0); expect(data.context.pending.size).toBe(0);
    expect(faults.providerReads).toBe(2);
    expect((await readdir(data.directory)).some((name) => name.startsWith("publication-"))).toBe(false);
    const push = faults.commands[0]!; expect(push.args).toContain("--atomic"); expect(push.args).toContain(`--force-with-lease=refs/heads/${faults.branch}:`);
    expect(push.args.slice(-2)).toEqual(["https://github.com/example/public.git", `${data.candidate}:refs/heads/${faults.branch}`]);
    expect(push.args).toContain("credential.helper="); expect(push.args).toContain("credential.https://github.com/example/public.git.useHttpPath=true");
    expect(faults.commands.some((command) => command.args.includes("ls-remote"))).toBe(false);
    const requests = (await readFile(faults.scenario + ".requests", "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    expect(JSON.parse(requests[1].body)).toEqual({ head: faults.branch, base: "trunk", title: "Fixture upgrade", body: "Generated template fixture\n", draft: true, maintainer_can_modify: false });
    for (const request of requests) expect(request.args.slice(0, 3)).toEqual(["api", "--hostname", "github.com"]);
    await expect(data.publish()).rejects.toThrow("Governed upgrade host operation is unsupported.");
  });
  it("rejects unbranded or unsigned candidates before provider access", async () => {
    const data = await fixture();
    await expect(publishCandidate({ ...data.repository }, data.candidate, faults.branch, "Fixture", "body")).rejects.toThrow("unsupported");
    await expect(publishCandidate(data.repository, data.baseCommit, faults.branch, "Fixture", "body")).rejects.toThrow("unsupported");
    expect(faults.commands).toHaveLength(0);
  });
  it("rejects publication on a branch different from the retained signed plan before provider access", async () => {
    const data = await fixture();
    await expect(publishCandidate(data.repository, data.candidate, "codex/different-from-signed-plan", "Fixture", "body")).rejects.toThrow("unsupported");
    expect(faults.providerReads).toBe(0); expect(faults.commands).toHaveLength(0);
  });
  it.each(["missing-branch", "missing-hash", "malformed-hash"])("rejects %s signing bindings before provider access", async (fault) => {
    const data = await fixture();
    if (fault === "missing-branch") delete data.context.signedBranch;
    if (fault === "missing-hash") delete data.context.signedPlanSha256;
    if (fault === "malformed-hash") data.context.signedPlanSha256 = "not-a-frozen-plan-hash";
    await expect(data.publish()).rejects.toThrow("unsupported");
    expect(faults.providerReads).toBe(0); expect(faults.commands).toHaveLength(0);
  });
  it.each(["codex/trailing/", "codex/.hidden", "codex/two..dots", "codex/branch.lock", "main"])("rejects unsupported publication branch %s", async (branch) => {
    const data = await fixture(); await expect(publishCandidate(data.repository, data.candidate, branch, "Fixture", "body")).rejects.toThrow("unsupported");
    expect(faults.commands).toHaveLength(0);
  });
  it("preserves a concurrently created branch using the real empty expected-old lease", async () => {
    const data = await fixture(); faults.race = "base"; const result = await data.publish();
    expect(result).toMatchObject({ ok: false, phase: "push", push: "uncertain", candidate: data.candidate });
    expect(data.remoteHead()).toBe(data.baseCommit); expect(faults.commands).toHaveLength(1);
  });
  it("rejects an existing branch at the exact same candidate without opening another PR", async () => {
    const data = await fixture(); faults.race = "candidate";
    expect(await data.publish()).toMatchObject({ ok: false, phase: "push", push: "uncertain" });
    expect(data.remoteHead()).toBe(data.candidate); expect(faults.commands).toHaveLength(1);
  });
  it("retains a confirmed pushed candidate when draft creation fails", async () => {
    const data = await fixture(); data.scenario.fail = "create"; await data.save();
    expect(await data.publish()).toMatchObject({ ok: false, phase: "create", push: "confirmed", ref: `refs/heads/${faults.branch}` });
    expect(data.remoteHead()).toBe(data.candidate);
  });
  it("reports a cancelled push as uncertain even when the real remote accepted the ref", async () => {
    const data = await fixture(); faults.cancelAfterPush = data.cancellation;
    expect(await data.publish()).toMatchObject({ ok: false, phase: "push", push: "uncertain" }); expect(data.remoteHead()).toBe(data.candidate);
    expect(data.context.pending.size).toBe(0); expect(data.reserved()).toBe(0);
  });
  it("never calls PR creation after a wrong remote head confirmation", async () => {
    const data = await fixture(); data.scenario.remote.object.sha = data.baseCommit; await data.save();
    expect(await data.publish()).toMatchObject({ ok: false, phase: "confirm", push: "uncertain" }); expect(faults.commands).toHaveLength(2);
  });
  it.each(["head-sha", "head-repo", "head-branch", "base-ref", "base-sha", "base-repo"])("rejects a create response with mismatched %s", async (fault) => {
    const data = await fixture(); const response = data.scenario.create;
    if (fault === "head-sha") response.head.sha = data.baseCommit;
    if (fault === "head-repo") response.head.repo.full_name = "different/repository";
    if (fault === "head-branch") response.head.ref = "codex/different";
    if (fault === "base-ref") response.base.ref = "main";
    if (fault === "base-sha") response.base.sha = data.candidate;
    if (fault === "base-repo") response.base.repo.full_name = "different/repository";
    await data.save(); const result = await data.publish();
    expect(result).toMatchObject({ ok: false, phase: "create", push: "confirmed", candidate: data.candidate, ref: `refs/heads/${faults.branch}` });
    expect(result).not.toHaveProperty("pullRequestUrl"); expect(result).not.toHaveProperty("cleanupFailed");
    expect(faults.commands).toHaveLength(3);
  });
  it("retains the known same-repository URL after a readback mismatch", async () => {
    const data = await fixture(); data.scenario.readback.head.sha = data.baseCommit; await data.save();
    expect(await data.publish()).toMatchObject({ ok: false, phase: "readback", push: "confirmed", pullRequestUrl: "https://github.com/example/public/pull/7" });
  });
  it("rejects an inconsistent PR number on structured readback", async () => {
    const data = await fixture(); data.scenario.readback.number = 8; await data.save();
    expect(await data.publish()).toMatchObject({ ok: false, phase: "readback", push: "confirmed", pullRequestUrl: "https://github.com/example/public/pull/7" });
  });
  it("does not return an unverified cross-repository URL", async () => {
    const data = await fixture(); data.scenario.create.html_url = "https://github.com/different/repository/pull/7"; await data.save();
    const result = await data.publish(); expect(result).toMatchObject({ ok: false, phase: "create", push: "confirmed" }); expect(result).not.toHaveProperty("pullRequestUrl");
  });
  it("retains the known PR URL and reservation after cleanup failure, then retries cleanup alone", async () => {
    const data = await fixture(); faults.cleanupFailures = 2;
    expect(await data.publish()).toMatchObject({ ok: false, phase: "cleanup", push: "confirmed", pullRequestUrl: "https://github.com/example/public/pull/7", cleanupFailed: true });
    expect(data.reserved()).toBeGreaterThan(0); const commands = faults.commands.length;
    await expect(finishRecovery(data.repository)).rejects.toThrow("Governed upgrade host operation is unsupported."); expect(data.reserved()).toBeGreaterThan(0);
    await finishRecovery(data.repository); expect(data.reserved()).toBe(0); expect(faults.commands).toHaveLength(commands);
  });
  it.each(["push", "create"] as const)("preserves the primary %s failure and candidate when cleanup also fails", async (primary) => {
    const data = await fixture(); faults.cleanupFailures = 1;
    if (primary === "push") faults.race = "base";
    else { data.scenario.fail = "create"; await data.save(); }
    const result = await data.publish();
    expect(result).toMatchObject({ ok: false, phase: primary, cleanupFailed: true, candidate: data.candidate,
      ref: `refs/heads/${faults.branch}`, push: primary === "push" ? "uncertain" : "confirmed", recoveryDirectory: data.directory });
    expect(result).not.toHaveProperty("pullRequestUrl"); expect(data.remoteHead()).toBe(primary === "push" ? data.baseCommit : data.candidate);
    expect(data.reserved()).toBeGreaterThan(0); const commands = faults.commands.length;
    await finishRecovery(data.repository); expect(data.reserved()).toBe(0); expect(faults.commands).toHaveLength(commands);
  });
  it.each(["api_host: attacker.invalid\n", "http_unix_socket: /fixture/socket\n", "aliases:\n  api: '!touch /fixture/marker'\n", "pager: canary\n", "git_protocol: &alias https\nprompt: *alias\n"])("blocks unsupported saved provider configuration", async (config) => {
    const data = await fixture(); await writeFile(path.join(data.providerFiles, "config.yml"), config);
    expect(await data.publish()).toMatchObject({ ok: false, phase: "provider", push: "not-attempted" }); expect(faults.commands).toHaveLength(0);
  });
  const unsupportedProviderFields = [
    ["refresh_token", "fixture-refresh"],
    ["oauth_token_expires_at", "fixture-expiry"],
    ["api_host", "attacker.invalid"]
  ].map(([key, value]) => `${key}: ${value}`);
  it.each(unsupportedProviderFields)("blocks refresh or endpoint fields in provider credentials", async (field) => {
    const data = await fixture(); await writeFile(path.join(data.providerFiles, "hosts.yml"), `github.com:\n  user: public-fixture\n  oauth_token: ${providerCanary}\n  ${field}\n`);
    expect(await data.publish()).toMatchObject({ ok: false, phase: "provider", push: "not-attempted" }); expect(faults.commands).toHaveLength(0);
  });
  it("blocks keyring-only, writable, missing fixed tools and ambient credential overrides", async () => {
    for (const mode of ["keyring", "writable", "tools", "override"] as const) {
      const data = await fixture();
      if (mode === "keyring") await writeFile(path.join(data.providerFiles, "hosts.yml"), "github.com:\n  user: public-fixture\n");
      faults.providerWritable = mode === "writable"; faults.missingTools = mode === "tools"; if (mode === "override") vi.stubEnv("GH_TOKEN", "ambient-token-canary");
      expect(await data.publish()).toMatchObject({ ok: false, phase: "provider", push: "not-attempted" }); expect(faults.commands).toHaveLength(0);
    }
  });
  it("keeps provider credentials, sockets, target config and command canaries out of subprocess inheritance", async () => {
    const data = await fixture(); vi.stubEnv("SSH_AUTH_SOCK", "/ambient-socket-canary"); vi.stubEnv("GH_DEBUG", "api"); vi.stubEnv("HTTPS_PROXY", "proxy-canary");
    const contextEnvironmentFixture = { SSH_AUTH_SOCK: "/context-socket-canary", GH_TOKEN: contextCanary, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.sshCommand", GIT_CONFIG_VALUE_0: "target-command-canary" };
    Object.assign(data.context.env, contextEnvironmentFixture);
    expect(await data.publish()).toMatchObject({ ok: true });
    for (const command of faults.commands) {
      expect(command.environment.GH_CONFIG_DIR).toBe(faults.provider);
      expect(JSON.stringify(command.environment)).not.toMatch(/canary|GH_DEBUG|SSH_AUTH_SOCK|HTTPS_PROXY|GIT_CONFIG_COUNT/);
    }
    expect(faults.helper).not.toContain("fixture-provider-canary"); expect(faults.helper).not.toMatch(/socket-canary|token-canary/);
  });
  it("executes the fixed credential wrapper and rejects malformed or out-of-scope requests before any provider invocation", async () => {
    const data = await fixture(); await data.publish(); const wrapper = path.join(data.directory, "captured-helper.cjs"); await writeFile(wrapper, faults.helper);
    const marker = path.join(data.directory, "provider-called"); const preload = path.join(data.directory, "provider-preload.cjs");
    await writeFile(preload, `require("node:child_process").spawnSync = (exe, args, options) => { require("node:fs").writeFileSync(${JSON.stringify(marker)}, JSON.stringify({exe,args,env:options.env,input:options.input.toString()})); return { status: 0, signal: null, stdout: Buffer.from("protocol=https\\nhost=github.com\\nusername=public-fixture\\npassword=${replyMarker}\\n"), stderr: Buffer.alloc(0) }; };`);
    const request = "protocol=https\nhost=github.com\npath=example/public.git\n\n";
    const capabilities = "capability[]=authtype\ncapability[]=state\n";
    const invalid = [request.replace("https", "http"), request.replace("github.com", "attacker.invalid"), request.replace("public.git", "other.git"), request.replace("path=example/public.git\n", ""), request.replace("\n\n", "\nhost=github.com\n\n"), request.replace("\n\n", "\nusername=unknown\n\n"), "x".repeat(8193),
      "capability[]=unknown\n" + request, "capability[]=state\n" + capabilities + request, request.replace("\n\n", "\ncapability[]=state\n\n"),
      request + "trailing-data\n", request.replaceAll("\n", "\r\n"), Buffer.concat([Buffer.from(request), Buffer.from([0xff])]), "wwwauth[]=Basic\n" + request];
    for (const input of invalid) {
      try { execFileSync(process.execPath, ["--require", preload, wrapper, "get"], { input, stdio: ["pipe", "pipe", "pipe"] }); throw new Error("wrapper accepted bad request"); }
      catch (error) { expect((error as { status: number }).status).toBe(1); expect(String((error as { stdout: Buffer }).stdout)).toBe(""); }
      await expect(lstat(marker)).rejects.toMatchObject({ code: "ENOENT" });
    }
    for (const operation of ["store", "erase", "unknown"]) expect(() => execFileSync(process.execPath, ["--require", preload, wrapper, operation], { input: request, stdio: ["pipe", "pipe", "pipe"] })).toThrow();
    await expect(lstat(marker)).rejects.toMatchObject({ code: "ENOENT" });
    expect(execFileSync(process.execPath, ["--require", preload, wrapper, "get"], { input: request }).toString()).toContain("synthetic-only");
    expect(JSON.parse(await readFile(marker, "utf8"))).toMatchObject({ exe: "/usr/bin/gh", args: ["auth", "git-credential", "get"] });
    expect(execFileSync(process.execPath, ["--require", preload, wrapper, "get"], { input: capabilities + request.slice(0, -1) }).toString()).toContain("synthetic-only");
    expect(JSON.parse(await readFile(marker, "utf8")).input).toBe(request.slice(0, -1));
    // Git sends EOF after one trailing LF to its helper, even though its own
    // credential stdin accepts a blank-line terminator. Only synthetic bytes
    // are returned by the preloaded provider; stdout is captured, never logged.
    const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
    const plumbing = execFileSync("/usr/bin/git", ["-c", "credential.helper=", "-c", `credential.helper=!${shellQuote(process.execPath)} --require ${shellQuote(preload)} ${shellQuote(wrapper)}`,
      "-c", "credential.useHttpPath=true", "credential", "fill"], { cwd: data.directory, env: neutralEnvironment(data.directory, data.directory), input: capabilities + request });
    expect(plumbing.toString()).toContain(`password=${replyMarker}`);
    expect(JSON.parse(await readFile(marker, "utf8")).input).toBe(request.slice(0, -1));
    const plain = `protocol=https\nhost=github.com\nusername=public-fixture\npassword=${replyMarker}\n`;
    for (const output of [plain.replace("github.com", "attacker.invalid"), plain.replace("synthetic-only", "bad token"), plain.replace("synthetic-only", "bad\u0001token"), plain + "state[]=unsupported\n", plain.replace(`password=${replyMarker}`, "authtype=Basic")]) {
      await writeFile(preload, `require("node:child_process").spawnSync = () => ({ status: 0, signal: null, stdout: Buffer.from(${JSON.stringify(output)}), stderr: Buffer.alloc(0) });`);
      try { execFileSync(process.execPath, ["--require", preload, wrapper, "get"], { input: request, stdio: ["pipe", "pipe", "pipe"] }); throw new Error("wrapper accepted unsafe output"); }
      catch (error) { expect((error as { status: number }).status).toBe(1); expect(String((error as { stdout: Buffer }).stdout)).toBe(""); }
    }
  }, 15_000);
});

it.skipIf(!requiredLinux)("requires actual Linux system Node credential-wrapper startup proof when host broker proof is mandatory", async () => {
  expect(process.platform, "Mandatory wrapper startup proof requires Linux; synthetic Darwin tests cannot satisfy it.").toBe("linux");
  faults.actualToolMetadata = true; await requireLinuxHost(); expect(await trustedExecutable("/usr/bin/node")).toBe("/usr/bin/node");
});
it.skipIf(!requiredLinux || process.platform !== "linux")("runs the generated credential wrapper with actual system Node under unchanged Linux prlimit ceilings", async () => {
  const data = await fixture(); expect(await data.publish()).toMatchObject({ ok: true });
  const wrapper = path.join(data.directory, "linux-wrapper.cjs"); const preload = path.join(data.directory, "linux-provider.cjs"); const marker = path.join(data.directory, "linux-provider-called.json");
  // This changes only the fixture's saved provider location. The production
  // wrapper code executes unchanged, and the provider process is never started.
  await writeFile(wrapper, faults.helper.replaceAll(JSON.stringify(faults.provider), JSON.stringify(data.providerFiles)));
  await writeFile(preload, `require("node:child_process").spawnSync = (exe,args,options) => { require("node:fs").writeFileSync(${JSON.stringify(marker)}, JSON.stringify({exe,args,env:options.env,input:options.input.toString()})); return {status:0,signal:null,stdout:Buffer.from("protocol=https\\nhost=github.com\\nusername=public-fixture\\npassword=${replyMarker}\\n"),stderr:Buffer.alloc(0)}; };`);
  faults.actualToolMetadata = true; const tools = await requireLinuxHost(); const node = await trustedExecutable("/usr/bin/node"); expect(node).toBe("/usr/bin/node"); faults.actualLimits = true;
  const input = Buffer.from("capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=github.com\npath=example/public.git\n");
  const output = await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, node, "--require", preload, wrapper, "get"], { cwd: data.directory, env: neutralEnvironment(data.directory, data.directory), input });
  expect(output.toString()).toBe(`protocol=https\nhost=github.com\nusername=public-fixture\npassword=${replyMarker}\n`);
  const called = JSON.parse(await readFile(marker, "utf8")); expect(called).toMatchObject({ exe: "/usr/bin/gh", args: ["auth", "git-credential", "get"], env: { GH_CONFIG_DIR: data.providerFiles } });
  expect(JSON.stringify(called.env)).not.toMatch(/SSH_AUTH_SOCK|GH_TOKEN|GITHUB_TOKEN|DEBUG|PROXY/);
}, 120_000);
