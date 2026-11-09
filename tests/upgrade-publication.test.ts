import { execFileSync, type SpawnOptions } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const faults = vi.hoisted(() => ({
  contexts: new Map<object, unknown>(), provider: "", providerFiles: "", providerAncestors: [] as string[], providerReads: 0,
  directory: "", remote: "", scenario: "", api: "", branch: "codex/publication-fixture", base: "", candidate: "",
  commands: [] as Array<{ executable: string; args: string[]; environment: NodeJS.ProcessEnv }>,
  cleanupFailures: 0, race: "" as "" | "base" | "candidate", cancelAfterPush: undefined as AbortController | undefined,
  helper: "", missingTools: false, missingPython: false, pythonWritable: false, pythonCanonical: "/usr/bin/python3", toolPaths: [] as string[],
  providerWritable: false, actualToolMetadata: false, actualPythonMetadata: false, actualLimits: false
}));

// Only fixture provider metadata, command transport and the private capability
// seam are replaced. Actual boundedCommand and Git ref protection execute.
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual,
    realpath: (file: Parameters<typeof actual.realpath>[0]) => {
      if (!faults.actualToolMetadata && ["/usr/bin/gh", "/usr/local/bin/gh", "/usr/bin/python3"].includes(String(file))) {
        faults.toolPaths.push(String(file));
        if (String(file) === "/usr/bin/python3" && faults.actualPythonMetadata) return actual.realpath(file);
        if (faults.missingTools || String(file) === "/usr/bin/python3" && faults.missingPython) return Promise.reject(new Error("fixture missing fixed tool"));
        return Promise.resolve(String(file) === "/usr/bin/python3" ? faults.pythonCanonical : String(file));
      }
      return actual.realpath(file);
    },
    lstat: async (file: Parameters<typeof actual.lstat>[0], options?: Parameters<typeof actual.lstat>[1]) => {
      if (!faults.actualToolMetadata && ["/usr/bin/gh", "/usr/local/bin/gh", ...(faults.actualPythonMetadata ? [] : ["/usr/bin/python3", faults.pythonCanonical])].includes(String(file))) {
        return { uid: 0, mode: String(file) === faults.pythonCanonical && faults.pythonWritable ? 0o100777 : 0o100755, isFile: () => true, isDirectory: () => false };
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
      const quoted = setting.slice(setting.indexOf(" -I -S ") + " -I -S ".length);
      const file = quoted.slice(1, -1).replaceAll("'\\''", "'"); faults.helper = readFileSync(file, "utf8");
      expect(path.basename(file)).toMatch(/^(credential|captured-credential)\.py$/); expect(lstatSync(file).mode & 0o777).toBe(0o600);
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
beforeEach(() => { for (const key of overrides) vi.stubEnv(key, ""); vi.stubEnv("HOME", os.userInfo().homedir); });
afterEach(async () => {
  vi.unstubAllEnvs(); faults.cleanupFailures = 0; faults.race = ""; faults.missingTools = false; faults.providerWritable = false;
  faults.actualToolMetadata = false; faults.actualPythonMetadata = false; faults.actualLimits = false; faults.providerReads = 0;
  faults.missingPython = false; faults.pythonWritable = false; faults.pythonCanonical = "/usr/bin/python3"; faults.toolPaths.length = 0;
  faults.cancelAfterPush = undefined; faults.contexts.clear(); faults.commands.length = 0; faults.helper = "";
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});
async function fixture(prefix = "bootstrap-publication-test-") {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix)); directories.push(directory); faults.directory = directory;
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
  it("rejects a provider home inconsistent with the resolved account before reading files or running commands", async () => {
    const data = await fixture(); vi.stubEnv("HOME", path.join(data.directory, "different-home"));
    expect(await data.publish()).toMatchObject({ ok: false, phase: "provider", push: "not-attempted" });
    expect(faults.providerReads).toBe(0); expect(faults.commands).toHaveLength(0);
  });
});

const requestFields = ["protocol=https", "host=github.com", "path=example/public.git"];
const canonicalRequest = Buffer.from(requestFields.join("\n") + "\n");
const serializeCredentialFields = (fields: readonly (readonly [string, string])[]) =>
  fields.map(([field, value]) => `${field}=${value}`).join("\n");
const credentialReply = (marker = replyMarker, username = "public-fixture") => Buffer.from(serializeCredentialFields([
  ["protocol", "https"], ["host", "github.com"], ["username", username], ["password", marker]
]) + "\n");
const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
interface WrapperConfiguration { gh: string; expected: string[]; env: Record<string, string>; cwd: string }
interface ProviderScenario { stdout?: Buffer; stderr?: Buffer; status?: number; signal?: string; fragmented?: boolean; mode?: "sleep" | "descendant" | "orphan-pipe" | "stop-wrapper"; escapeDelay?: number; outerArgv?: string[]; prefixBeforeWait?: boolean }
function readWrapperConfiguration(source: string) {
  const line = source.split("\n").find((entry) => entry.startsWith("CONFIG = json.loads("));
  expect(line).toBeDefined();
  const encoded = line!.slice("CONFIG = json.loads(".length, -1);
  return { line: line!, config: JSON.parse(JSON.parse(encoded)) as WrapperConfiguration };
}
async function syntheticWrapper(prefix = "bootstrap-publication-test-") {
  const data = await fixture(prefix); expect(await data.publish()).toMatchObject({ ok: true });
  const source = faults.helper; const { line, config } = readWrapperConfiguration(source);
  expect(config).toMatchObject({ gh: "/usr/bin/gh", expected: requestFields, env: { GH_CONFIG_DIR: faults.provider } });
  expect(path.dirname(config.cwd)).toBe(data.directory); expect(path.basename(config.cwd)).toMatch(/^publication-/);
  // Publication cleaned its private directory. Recreate that exact owned cwd;
  // its serialized location and every byte of runtime code stay unchanged.
  await mkdir(config.cwd, { mode: 0o700 });
  const actualFs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  const python = await actualFs.realpath("/usr/bin/python3");
  const provider = path.join(data.directory, "synthetic-provider.py"); const wrapper = path.join(data.directory, "captured-credential.py");
  const scenarioFile = path.join(data.directory, "credential-scenario.json"); const called = path.join(data.directory, "provider-called.json");
  const ready = path.join(data.directory, "descendant-ready.json"); const escaped = path.join(data.directory, "descendant-escaped");
  await writeFile(provider, `#!${python} -I
import json, os, signal, subprocess, sys, time
with open(${JSON.stringify(scenarioFile)}, "r", encoding="utf-8") as stream:
    scenario = json.load(stream)
payload = sys.stdin.buffer.read(8193)
record = {"args": sys.argv[1:], "cwd": os.getcwd(), "env": dict(os.environ), "input": payload.decode("utf-8"), "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp()}
if sys.platform == "linux":
    import resource
    record["limits"] = {name: list(resource.getrlimit(getattr(resource, name))) for name in ("RLIMIT_FSIZE", "RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_NOFILE", "RLIMIT_NPROC", "RLIMIT_CORE")}
    with open("/proc/%d/limits" % os.getppid(), "r", encoding="ascii") as stream:
        record["parentLimits"] = stream.read(16385)
    def identity(pid):
        with open("/proc/%d/stat" % pid, "r", encoding="ascii") as stream:
            fields = stream.read(4096).split(") ", 1)[1].split()
        with open("/proc/%d/cmdline" % pid, "rb") as stream:
            argv = stream.read(16385).split(b"\\0")[:-1]
        return {"pid": pid, "start": fields[19], "pgid": int(fields[2]), "uid": os.stat("/proc/%d" % pid).st_uid, "argv": [value.decode("utf-8") for value in argv]}
    record["parent"] = identity(os.getppid())
    record["self"] = identity(os.getpid())
    record["leader"] = identity(os.getpgrp())
    record["parentGroup"] = record["parent"]["pgid"]
with open(${JSON.stringify(called)}, "w", encoding="utf-8") as stream:
    json.dump(record, stream)
mode = scenario.get("mode")
if scenario.get("prefixBeforeWait"):
    os.write(1, bytes.fromhex(scenario["stdout"]))
if mode in ("descendant", "orphan-pipe", "stop-wrapper"):
    child_code = "import json,os,sys,time;identity={'pid':os.getpid(),'pgid':os.getpgrp()};identity.update({'start':open('/proc/%d/stat'%os.getpid()).read(4096).split(') ',1)[1].split()[19]} if sys.platform=='linux' else {});open(sys.argv[1],'w').write(json.dumps(identity));time.sleep(float(sys.argv[3]));open(sys.argv[2],'w').write('synthetic-descendant-survived');time.sleep(120)"
    subprocess.Popen([sys.executable, "-I", "-S", "-c", child_code, ${JSON.stringify(ready)}, ${JSON.stringify(escaped)}, str(scenario.get("escapeDelay", 35))], stdin=subprocess.DEVNULL)
    if mode == "orphan-pipe":
        sys.exit(0)
    if mode == "stop-wrapper":
        parent = os.getppid()
        expected = [${JSON.stringify(python)}, "-I", "-S", ${JSON.stringify(wrapper)}, "get"]
        own = record.get("parent", {})
        leader = record.get("leader", {})
        supervisor_group = os.getpgid(${process.pid})
        if (parent <= 1 or parent == ${process.pid} or own.get("argv") != expected or
                own.get("uid") != os.getuid() or own.get("pgid") != os.getpgrp() or
                os.getpgrp() <= 1 or os.getpgrp() == supervisor_group or
                leader.get("uid") != os.getuid() or leader.get("argv") != scenario.get("outerArgv") or
                identity(parent) != own):
            sys.exit(7)
        record["stopIdentityVerified"] = True
        with open(${JSON.stringify(called)}, "w", encoding="utf-8") as stream:
            json.dump(record, stream)
        os.kill(parent, signal.SIGSTOP)
if mode in ("sleep", "descendant", "stop-wrapper"):
    time.sleep(120)
if scenario.get("signal"):
    os.kill(os.getpid(), getattr(signal, scenario["signal"]))
for descriptor, name in ((1, "stdout"), (2, "stderr")):
    body = bytes.fromhex(scenario.get(name, ""))
    step = 7 if scenario.get("fragmented") else 4096
    for offset in range(0, len(body), step):
        os.write(descriptor, body[offset:offset + step])
        if scenario.get("fragmented"):
            time.sleep(0.001)
sys.exit(scenario.get("status", 0))
`, { mode: 0o700 });
  const changed: WrapperConfiguration = { ...config, gh: provider, env: { ...config.env, GH_CONFIG_DIR: data.providerFiles } };
  const changedLine = "CONFIG = json.loads(" + JSON.stringify(JSON.stringify(changed)) + ")";
  const restored = { ...changed, gh: config.gh, env: { ...changed.env, GH_CONFIG_DIR: config.env.GH_CONFIG_DIR! } };
  expect("CONFIG = json.loads(" + JSON.stringify(JSON.stringify(restored)) + ")").toBe(line);
  const wrapperSource = source.replace(line, changedLine); expect(wrapperSource.replace(changedLine, line)).toBe(source);
  expect(wrapperSource.split("\n").filter((entry, index) => entry !== source.split("\n")[index])).toEqual([changedLine]);
  await writeFile(wrapper, wrapperSource, { mode: 0o600 }); const runtimeCwd = await actualFs.realpath(config.cwd);
  const save = async ({ stdout = credentialReply(), stderr = Buffer.alloc(0), ...scenario }: ProviderScenario = {}) => {
    await rm(called, { force: true }); await rm(ready, { force: true }); await rm(escaped, { force: true });
    await writeFile(scenarioFile, JSON.stringify({ ...scenario, stdout: stdout.toString("hex"), stderr: stderr.toString("hex") }));
  };
  await save();
  return { ...data, python, wrapper, source, wrapperSource, config: changed, runtimeCwd, called, ready, escaped, save };
}
async function executeWrapper(data: Awaited<ReturnType<typeof syntheticWrapper>>, input: Buffer = canonicalRequest, args = ["get"], fragments?: Buffer[], env?: NodeJS.ProcessEnv) {
  const actual = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  return new Promise<{ status: number | null; signal: string | null; stdout: Buffer; stderr: Buffer }>((resolve, reject) => {
    const child = actual.spawn(data.python, ["-I", "-S", data.wrapper, ...args], { cwd: data.directory, env: env ?? neutralEnvironment(data.directory, data.directory), detached: true, stdio: ["pipe", "pipe", "pipe"] });
    const output: Buffer[] = []; const errors: Buffer[] = []; let closed = false;
    const kill = () => { if (child.pid) try { process.kill(-child.pid, "SIGKILL"); } catch { /* Owned group already gone. */ } };
    const timer = setTimeout(() => { kill(); reject(new Error("synthetic wrapper exceeded its 12s test safety bound")); }, 12_000);
    child.stdout.on("data", (part: Buffer) => output.push(part)); child.stderr.on("data", (part: Buffer) => errors.push(part)); child.stdin.on("error", () => {});
    child.once("error", (error) => { clearTimeout(timer); kill(); reject(error); });
    child.once("close", (status, signal) => { closed = true; clearTimeout(timer); kill(); resolve({ status, signal, stdout: Buffer.concat(output), stderr: Buffer.concat(errors) }); });
    if (!fragments) child.stdin.end(input);
    else void (async () => { for (const part of fragments) { if (closed) return; child.stdin.write(part); await new Promise((done) => setTimeout(done, 2)); } child.stdin.end(); })();
  });
}
function protocolVectors() {
  const vectors: Array<{ name: string; input: Buffer; args: string[]; output: Buffer; accepted: boolean; called: boolean; fragments?: Buffer[] }> = [];
  const input = (name: string, value: string | Buffer, accepted = false, args = ["get"], fragments?: Buffer[]) => vectors.push({ name, input: Buffer.from(value), args, output: credentialReply(), accepted, called: accepted, ...(fragments ? { fragments } : {}) });
  const output = (name: string, value: string | Buffer, accepted = false) => vectors.push({ name, input: canonicalRequest, args: ["get"], output: Buffer.from(value), accepted, called: true });
  input("one LF", canonicalRequest, true); input("two LF", Buffer.concat([canonicalRequest, Buffer.from("\n")]), true);
  for (const order of [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]) input(`field order ${order}`, order.map((index) => requestFields[index]).join("\n") + "\n", true);
  for (const capabilities of [["authtype"], ["state"], ["authtype", "state"], ["state", "authtype"]]) input(`capabilities ${capabilities}`, capabilities.map((name) => `capability[]=${name}\n`).join("") + canonicalRequest, true);
  const bom = Buffer.from([0xef, 0xbb, 0xbf]); input("one BOM", Buffer.concat([bom, canonicalRequest]), true); input("two BOM", Buffer.concat([bom, bom, canonicalRequest]));
  const invalidRequests = ["", "\n", requestFields.join("\n"), "\n" + canonicalRequest, canonicalRequest + "\n\n", canonicalRequest.toString().replaceAll("\n", "\r\n"), canonicalRequest + "state=fixture\n", `protocol=https\nprotocol=https\n${requestFields[2]}\n`, requestFields.slice(0, 2).join("\n") + "\n", canonicalRequest.toString().replace("https", "http"), canonicalRequest.toString().replace("github.com", "attacker.invalid"), canonicalRequest.toString().replace("public.git", "other.git"), " " + canonicalRequest, canonicalRequest + "\0\n", "capability[]=unknown\n" + canonicalRequest, "capability[]=state\ncapability[]=state\n" + canonicalRequest, canonicalRequest + "capability[]=state\n", requestFields[0] + "\ncapability[]=state\n" + requestFields.slice(1).join("\n") + "\n", "capability[]=\n" + canonicalRequest, "wwwauth[]=Basic\n" + canonicalRequest, "protocol=https\n\ufeffhost=github.com\npath=example/public.git\n"];
  invalidRequests.forEach((value, index) => input(`malformed request ${index}`, value));
  const invalidUtf8 = [[0xc0, 0xaf], [0xe2, 0x28, 0xa1], [0xed, 0xa0, 0x80], [0xf0, 0x9f, 0x92], [0xf4, 0x90, 0x80, 0x80]];
  const malformedResponseFields = [
    ["protocol", "https"], ["host", "github.com"], ["username", "public-fixture"], ["password", ""]
  ] as const;
  invalidUtf8.forEach((value, index) => { input(`request strict UTF8 ${index}`, Buffer.concat([Buffer.from(value), canonicalRequest])); output(`response strict UTF8 ${index}`, Buffer.concat([Buffer.from(serializeCredentialFields(malformedResponseFields)), Buffer.from(value), Buffer.from("\n")])); });
  input("8192 malformed bytes", Buffer.alloc(8192, 0x61)); input("8193 overflow bytes", Buffer.alloc(8193, 0x61));
  input("fragmented request", canonicalRequest, true, ["get"], [...canonicalRequest].map((byte) => Buffer.from([byte])));
  input("fragmented BOM", Buffer.concat([bom, canonicalRequest]), true, ["get"], [bom.subarray(0, 1), bom.subarray(1, 2), bom.subarray(2), canonicalRequest]);
  input("fragmented overflow", Buffer.alloc(8193, 0x61), false, ["get"], [Buffer.alloc(8192, 0x61), Buffer.from("a")]);
  for (const args of [[], ["store"], ["erase"], ["GET"], ["unknown"], ["get", "extra"], ["get", ""], ["get", "get"]]) input(`operation ${JSON.stringify(args)}`, canonicalRequest, false, args);
  const plain = credentialReply().toString(); output("response canonical", plain, true); output("response one BOM preserves bytes", Buffer.concat([bom, credentialReply()]), true); output("response two BOM", Buffer.concat([bom, bom, credentialReply()]));
  ["", plain.slice(0, -1), plain + "\n", plain.replaceAll("\n", "\r\n"), plain.replace("https", "http"), plain.replace("github.com", "attacker.invalid"), `host=github.com\nprotocol=https\nusername=public-fixture\npassword=${replyMarker}\n`, plain + "state=fixture\n", plain + "authtype=Basic\n", plain.replace("username=public-fixture\n", ""), plain + "junk", credentialReply("a\nb"), credentialReply("a\rb")].forEach((value, index) => output(`malformed response ${index}`, value));
  for (const [name, accepted] of [["a", true], ["1-user", true], ["a".repeat(39), true], ["a".repeat(40), false], ["-user", false], ["fixture_user", false], ["café", false], ["", false], ["fixture user", false], ["fixture\n", false], ["fixture\u2028", false], ["fixture\u2029", false]] as const) output(`username ${JSON.stringify(name)}`, credentialReply(replyMarker, name), accepted);
  for (const code of [...Array.from({ length: 33 }, (_, index) => index), 0x7f, 0xa0, 0x1680, ...Array.from({ length: 11 }, (_, index) => 0x2000 + index), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]) output(`excluded code point ${code}`, credentialReply("a" + String.fromCodePoint(code) + "b"));
  for (const code of [0x80, 0x85, 0x9f, 0x180e, 0x200b, 0x2060, 0xfffd]) output(`accepted code point ${code}`, credentialReply("a" + String.fromCodePoint(code) + "b"), true);
  for (const [name, value, accepted] of [["empty", "", false], ["ASCII4096", "x".repeat(4096), true], ["ASCII4097", "x".repeat(4097), false], ["astral4096", "😀".repeat(2048), true], ["astral4098", "😀".repeat(2049), false], ["mixed4096", "😀".repeat(2047) + "xy", true], ["mixed4097", "😀".repeat(2047) + "xyz", false], ["BMP4096", "一".repeat(4096), true]] as const) output(`UTF16 ${name}`, credentialReply(value), accepted);
  output("16384 malformed output bytes", Buffer.alloc(16384, 0x61)); output("16385 output overflow", Buffer.alloc(16385, 0x61));
  return vectors;
}

describe("isolated Python credential wrapper (real subprocess; synthetic provider only)", () => {
  it("selects only fixed Python, accepts its trusted canonical result and emits quoted -I -S private helpers", async () => {
    faults.pythonCanonical = "/usr/bin/python3.123"; const data = await fixture(); expect(await data.publish()).toMatchObject({ ok: true });
    const push = faults.commands.find((command) => command.executable === "/usr/bin/git")!;
    const setting = push.args.find((value) => value.startsWith("credential.https://github.com/example/public.git.helper="))!;
    expect(setting).toMatch(/^credential\.https:\/\/github\.com\/example\/public\.git\.helper=!'\/usr\/bin\/python3\.123' -I -S '.*\/credential\.py'$/s);
    expect(faults.toolPaths).toContain("/usr/bin/python3"); expect(faults.toolPaths).not.toContain("/usr/bin/node");
    expect(faults.helper).not.toContain(providerCanary); expect(faults.helper).not.toContain(contextCanary);
    faults.pythonCanonical = "/usr/bin/python3";
  });
  it.each(["absent", "untrusted"])("blocks %s selected Python before push without trying another interpreter", async (mode) => {
    const data = await fixture(); faults.missingPython = mode === "absent"; faults.pythonWritable = mode === "untrusted";
    expect(await data.publish()).toMatchObject({ ok: false, phase: "provider", push: "not-attempted" }); expect(faults.commands).toHaveLength(0);
    expect(faults.toolPaths.filter((file) => file.includes("python") || file.includes("node"))).toEqual(["/usr/bin/python3"]);
  });
  it("preserves the complete byte, Unicode, capability, argv and UTF16 admission contract", async () => {
    const data = await syntheticWrapper();
    for (const vector of protocolVectors()) {
      await data.save({ stdout: vector.output }); const result = await executeWrapper(data, vector.input, vector.args, vector.fragments);
      expect(result.status, vector.name).toBe(vector.accepted ? 0 : 1); expect(result.signal, vector.name).toBeNull(); expect(result.stderr, vector.name).toEqual(Buffer.alloc(0));
      expect(result.stdout, vector.name).toEqual(vector.accepted ? vector.output : Buffer.alloc(0));
      if (!vector.called) await expect(lstat(data.called), vector.name).rejects.toMatchObject({ code: "ENOENT" });
      else {
        const called = JSON.parse(await readFile(data.called, "utf8"));
        expect(called, vector.name).toMatchObject({ args: ["auth", "git-credential", "get"], cwd: data.runtimeCwd, env: data.config.env, input: canonicalRequest.toString() });
      }
    }
  }, 90_000);
  it("bounds real provider streams and rejects errors without releasing any credential bytes", async () => {
    const data = await syntheticWrapper();
    for (const scenario of [{ status: 9 }, { signal: "SIGTERM" }, { stderr: Buffer.from("x") }, { stderr: Buffer.alloc(16384 - credentialReply().length, 0x61) }, { stdout: credentialReply(), stderr: Buffer.alloc(16385, 0x61) }, { stdout: Buffer.concat([credentialReply(), Buffer.alloc(16385, 0x61)]), fragmented: true }, { stdout: credentialReply("a\u2028b"), fragmented: true }]) {
      await data.save(scenario); const result = await executeWrapper(data);
      expect(result.status).toBe(1); expect(result.stdout).toEqual(Buffer.alloc(0)); expect(result.stderr).toEqual(Buffer.alloc(0));
    }
    await data.save({ fragmented: true }); expect((await executeWrapper(data)).stdout).toEqual(credentialReply());
    await rm(data.config.gh); const result = await executeWrapper(data); expect(result.status).toBe(1); expect(result.stdout.length + result.stderr.length).toBe(0);
  }, 20_000);
  it("keeps real Git credential-fill plumbing, exact public literals and Python isolation intact", async () => {
    const data = await syntheticWrapper("bootstrap-pub-'quote\\slash\nUnicode-雪-");
    const injection = path.join(data.directory, "python-injection-executed");
    const canary = `open(${JSON.stringify(injection)}, "w").write("synthetic-import-canary")\nraise RuntimeError("synthetic import canary")\n`;
    for (const directory of [data.directory, data.config.cwd]) for (const name of ["json.py", "subprocess.py", "sitecustomize.py", "usercustomize.py"]) await writeFile(path.join(directory, name), canary);
    const outerEnv = { ...neutralEnvironment(data.directory, data.directory), PYTHONPATH: data.directory, PYTHONHOME: path.join(data.directory, "missing-python-home"), PYTHONSTARTUP: path.join(data.directory, "sitecustomize.py"), PYTHONINSPECT: "1", PYTHONUSERBASE: data.directory };
    const direct = await executeWrapper(data, canonicalRequest, ["get"], undefined, outerEnv); expect(direct.status).toBe(0); expect(direct.stdout).toEqual(credentialReply());
    await expect(lstat(injection)).rejects.toMatchObject({ code: "ENOENT" });
    const helper = `!${shellQuote(data.python)} -I -S ${shellQuote(data.wrapper)}`;
    const result = execFileSync("/usr/bin/git", ["-c", "credential.helper=", "-c", `credential.helper=${helper}`, "-c", "credential.useHttpPath=true", "credential", "fill"], { cwd: data.directory, env: outerEnv, input: "capability[]=state\ncapability[]=authtype\n" + canonicalRequest + "\n", stdio: ["pipe", "pipe", "pipe"] });
    const expectedPasswordField = ["password", replyMarker] as const;
    expect(result.toString()).toContain(serializeCredentialFields([expectedPasswordField])); const called = JSON.parse(await readFile(data.called, "utf8"));
    expect(called.input).toBe(canonicalRequest.toString()); expect(called.cwd).toBe(data.runtimeCwd);
    const observed = { ...called.env };
    // Darwin's developer-tool shim adds only these observed public keys when
    // Git invokes the synthetic provider's interpreter. Linux stays exact.
    if (process.platform === "darwin") for (const name of ["CPATH", "LIBRARY_PATH", "MANPATH", "SDKROOT", "__CF_USER_TEXT_ENCODING"]) delete observed[name];
    expect(observed).toEqual(data.config.env);
    expect(Object.keys(called.env).some((name) => /PYTHON|TOKEN|PROXY|DEBUG|SSH_AUTH_SOCK/.test(name))).toBe(false);
    await expect(lstat(injection)).rejects.toMatchObject({ code: "ENOENT" });
  }, 15_000);
});

function credentialGitArguments(data: Awaited<ReturnType<typeof syntheticWrapper>>) {
  return ["-c", "credential.helper=", "-c", `credential.https://github.com/example/public.git.helper=!${shellQuote(data.python)} -I -S ${shellQuote(data.wrapper)}`,
    "-c", "credential.https://github.com/example/public.git.useHttpPath=true", "credential", "fill"];
}
it("cancels the complete real Git/Python/Popen composition with fabricated descendants (ordinary host; simulated ceilings)", async () => {
  const data = await syntheticWrapper(); await data.save({ mode: "descendant", escapeDelay: 0.8, prefixBeforeWait: true }); const cancellation = new AbortController();
  const pending = boundedCommand("/publication-fixture/prlimit", [...PRLIMIT_ARGS, "/usr/bin/git", ...credentialGitArguments(data)], { cwd: data.directory, env: neutralEnvironment(data.directory, data.directory), input: canonicalRequest, signal: cancellation.signal });
  const rejected = expect(pending).rejects.toThrow("unsupported");
  try { await vi.waitFor(async () => expect(JSON.parse(await readFile(data.ready, "utf8")).pid).toBeGreaterThan(1), { timeout: 3000, interval: 10 }); }
  finally { cancellation.abort(); await pending.catch(() => {}); }
  await rejected; const called = JSON.parse(await readFile(data.called, "utf8")); const descendant = JSON.parse(await readFile(data.ready, "utf8"));
  expect(descendant.pgid).toBe(called.pgid); expect(called.pgid).not.toBe(process.pid);
  await new Promise((done) => setTimeout(done, 900)); await expect(lstat(data.escaped)).rejects.toMatchObject({ code: "ENOENT" });
}, 10_000);
async function linuxWrapper() {
  expect(process.platform, "Mandatory Python proof requires genuine Linux; ordinary tests cannot satisfy it.").toBe("linux");
  faults.actualPythonMetadata = true; const data = await syntheticWrapper(); faults.actualToolMetadata = true;
  const tools = await requireLinuxHost(); const python = await trustedExecutable("/usr/bin/python3"); expect(python).toBe(data.python);
  const push = faults.commands.find((command) => command.executable === "/usr/bin/git")!;
  expect(push.args).toContain(`credential.https://github.com/example/public.git.helper=!${shellQuote(python)} -I -S ${shellQuote(data.config.cwd + "/credential.py")}`);
  faults.actualLimits = true;
  const run = (input = canonicalRequest, signal?: AbortSignal) => boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, python, "-I", "-S", data.wrapper, "get"], { cwd: data.directory, env: neutralEnvironment(data.directory, data.directory), input, ...(signal ? { signal } : {}) });
  const outerArgv = [tools.git, ...credentialGitArguments(data)];
  const runGit = (signal?: AbortSignal) => boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, ...outerArgv], { cwd: data.directory, env: neutralEnvironment(data.directory, data.directory), input: canonicalRequest, ...(signal ? { signal } : {}) });
  return { ...data, run, runGit, outerArgv };
}
async function ownedProcessStopped(identity: { pid: number; start: string }) {
  try { const stat = (await readFile(`/proc/${identity.pid}/stat`, "utf8")).split(") ")[1]!.split(" "); return stat[0] === "Z" || stat[19] !== identity.start; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return true; throw error; }
}
async function assertOwnedGroupClean(data: Awaited<ReturnType<typeof linuxWrapper>>) {
  const provider = JSON.parse(await readFile(data.called, "utf8")); const descendant = JSON.parse(await readFile(data.ready, "utf8"));
  expect(descendant.pgid).toBe(provider.pgid); expect(provider.parentGroup).toBe(provider.pgid); expect(provider.pgid).not.toBe(process.pid);
  await vi.waitFor(async () => { expect(await ownedProcessStopped(provider.self)).toBe(true); expect(await ownedProcessStopped(provider.parent)).toBe(true); expect(await ownedProcessStopped(provider.leader)).toBe(true); expect(await ownedProcessStopped(descendant)).toBe(true); }, { timeout: 3000, interval: 20 });
  await expect(lstat(data.escaped)).rejects.toMatchObject({ code: "ENOENT" });
}
it.skipIf(!requiredLinux)("requires actual selected canonical Python startup when host broker proof is mandatory", async () => {
  expect(process.platform, "Mandatory wrapper startup proof requires Linux.").toBe("linux"); faults.actualToolMetadata = true; await requireLinuxHost();
  expect(path.isAbsolute(await trustedExecutable("/usr/bin/python3"))).toBe(true);
});
it.skipIf(!requiredLinux || process.platform !== "linux")("runs actual isolated Python parser and Popen under all unchanged Linux ceilings", async () => {
  const data = await linuxWrapper(); expect(await data.run(Buffer.from("capability[]=authtype\ncapability[]=state\n" + canonicalRequest))).toEqual(credentialReply());
  const called = JSON.parse(await readFile(data.called, "utf8")); expect(called).toMatchObject({ args: ["auth", "git-credential", "get"], cwd: data.runtimeCwd, env: data.config.env, input: canonicalRequest.toString() });
  const limits = { RLIMIT_FSIZE: 67108864, RLIMIT_CPU: 60, RLIMIT_AS: 1073741824, RLIMIT_NOFILE: 64, RLIMIT_NPROC: 128, RLIMIT_CORE: 0 };
  for (const [name, value] of Object.entries(limits)) expect(called.limits[name], name).toEqual([value, value]);
  for (const [name, value] of [["Max file size", 67108864], ["Max cpu time", 60], ["Max address space", 1073741824], ["Max open files", 64], ["Max processes", 128], ["Max core file size", 0]]) expect(called.parentLimits).toMatch(new RegExp(`^${name}\\s+${value}\\s+${value}(?:\\s|$)`, "m"));
  expect(called.parentGroup).toBe(called.pgid);
  await data.save(); await expect(data.run(Buffer.from(canonicalRequest.toString().replace("https", "http")))).rejects.toThrow("unsupported");
  await expect(lstat(data.called)).rejects.toMatchObject({ code: "ENOENT" });
}, 15_000);
it.skipIf(!requiredLinux || process.platform !== "linux")("enforces the real 30s provider budget and cleans inherited descendant pipes", async () => {
  const data = await linuxWrapper();
  for (const mode of ["descendant", "orphan-pipe"] as const) {
    await data.save({ mode, escapeDelay: 35, prefixBeforeWait: true }); const started = performance.now(); const safety = new AbortController();
    const timer = setTimeout(() => safety.abort(), 41_000);
    try { await expect(data.runGit(safety.signal)).rejects.toThrow("unsupported"); }
    finally { clearTimeout(timer); safety.abort(); }
    expect(performance.now() - started).toBeGreaterThanOrEqual(29_000); expect(performance.now() - started).toBeLessThan(40_000);
    await assertOwnedGroupClean(data);
  }
}, 85_000);
it.skipIf(!requiredLinux || process.platform !== "linux")("aborts the real wrapper/provider group and leaves no live fabricated descendants", async () => {
  const data = await linuxWrapper(); await data.save({ mode: "descendant", escapeDelay: 0.8, prefixBeforeWait: true }); const cancellation = new AbortController(); const pending = data.runGit(cancellation.signal);
  const rejected = expect(pending).rejects.toThrow("unsupported");
  try { await vi.waitFor(async () => expect(JSON.parse(await readFile(data.ready, "utf8")).pid).toBeGreaterThan(1), { timeout: 3000, interval: 10 }); }
  finally { cancellation.abort(); await pending.catch(() => {}); }
  await rejected; await assertOwnedGroupClean(data); await new Promise((done) => setTimeout(done, 900)); await expect(lstat(data.escaped)).rejects.toMatchObject({ code: "ENOENT" });
}, 10_000);
it.skipIf(!requiredLinux || process.platform !== "linux")("enforces the real 90s outer deadline over Git/helper/Python/Popen when only the owned wrapper is stopped", async () => {
  const data = await linuxWrapper(); await data.save({ mode: "stop-wrapper", escapeDelay: 95, outerArgv: data.outerArgv });
  const started = performance.now(); const cancellation = new AbortController(); const pending = data.runGit(cancellation.signal); const rejected = expect(pending).rejects.toThrow("unsupported");
  try {
    await vi.waitFor(async () => expect(JSON.parse(await readFile(data.called, "utf8")).stopIdentityVerified).toBe(true), { timeout: 3000, interval: 10 });
    await rejected; expect(performance.now() - started).toBeGreaterThanOrEqual(89_000); expect(performance.now() - started).toBeLessThan(100_000);
  } finally { cancellation.abort(); await pending.catch(() => {}); }
  await assertOwnedGroupClean(data);
}, 110_000);
