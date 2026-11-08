import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import type { CommandOptions } from "../src/upgrade-host.js";
import type { PublicRepository, TransportContext } from "../src/upgrade-transport.js";

// Real Git/SSH semantics with fabricated data only. These mocks do not prove Linux kernel enforcement.
const scaffold = vi.hoisted(() => ({ home: "", contexts: new WeakMap<object, TransportContext>(), calls: [] as Array<{ args: readonly string[]; socket: boolean }>,
  afterSign: undefined as undefined | ((candidate: string, options: CommandOptions) => Buffer), afterCommand: undefined as undefined | ((args: readonly string[]) => Promise<void>), failVerify: false, mutateKey: false, reads: 0 }));
vi.mock("node:os", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:os")>();
  return { ...original, default: { ...original, userInfo: () => ({ ...original.userInfo(), homedir: scaffold.home }) } };
});
vi.mock("../src/upgrade-host.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/upgrade-host.js")>();
  return { ...original, PRLIMIT_ARGS: [], requireLinuxHost: async () => ({ git: "/usr/bin/git", prlimit: "/usr/bin/env" }),
    readRegular: (...args: Parameters<typeof original.readRegular>) => { scaffold.reads++; return original.readRegular(...args); },
    boundedCommand: async (executable: string, args: readonly string[], options: CommandOptions) => {
      scaffold.calls.push({ args, socket: !!options.env.SSH_AUTH_SOCK });
      if (scaffold.failVerify && args.includes("verify")) throw original.hostFailure();
      const result = await original.boundedCommand(executable, args, options);
      await scaffold.afterCommand?.(args);
      if (args.includes("commit-tree") && scaffold.afterSign) return scaffold.afterSign(result.toString().trim(), options);
      if (args.includes("verify") && scaffold.mutateKey) {
        const allowed = args[args.indexOf("-f") + 1]!; await writeFile(path.join(path.dirname(allowed), "selected.pub"), "changed public key\n");
      }
      return result;
    } };
});
vi.mock("../src/upgrade-transport.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/upgrade-transport.js")>();
  return { ...original, transportContext: (repository: object) => { const result = scaffold.contexts.get(repository); original.transportContext; if (!result || result.signal.aborted) throw new Error("synthetic repository disposed"); return result; } };
});

import { captureGeneratorSigning, freezeCommitPlan, signAndVerify } from "../src/upgrade-signing.js";
import { neutralEnvironment } from "../src/upgrade-host.js";
import { verifyGitSnapshot } from "../src/upgrade-git.js";
import { publishCandidate } from "../src/upgrade-publication.js";

const roots: string[] = []; const agents: ChildProcess[] = [];
const blocked = "Governed upgrade host operation is unsupported.";
function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: Uint8Array | string): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", ...args], { cwd: root, env, input, maxBuffer: 2 * 1024 ** 2 });
}
async function fixture(linked = false) {
  const directory = await mkdtemp(path.join(await realpath(path.join(process.cwd(), "node_modules")), ".bootstrap-signing-test-")); roots.push(directory);
  const home = path.join(directory, "home"); const canonical = path.join(directory, "generator"); const empty = path.join(directory, "empty");
  await Promise.all([home, canonical, empty].map((name) => mkdir(name))); scaffold.home = home;
  for (const name of Object.keys(process.env)) if (name.startsWith("GIT_") || name === "EMAIL" || name === "XDG_CONFIG_HOME") vi.stubEnv(name, undefined);
  vi.stubEnv("HOME", home); const env = { ...neutralEnvironment(home, directory), GIT_AUTHOR_NAME: "Fixture Operator", GIT_AUTHOR_EMAIL: "local@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Fixture Operator", GIT_COMMITTER_EMAIL: "local@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const key = path.join(home, "fixture-key"); execFileSync("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key], { env, stdio: "ignore" });
  const agentDirectory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bs-agent-")); roots.push(agentDirectory);
  const socket = path.join(agentDirectory, "agent.sock"); const agent = spawn("/usr/bin/ssh-agent", ["-D", "-a", socket], { env, stdio: "ignore" }); agents.push(agent);
  for (let attempt = 0; attempt < 100; attempt++) { if (await lstat(socket).then((stat) => stat.isSocket(), () => false)) break; await new Promise((resolve) => setTimeout(resolve, 10)); }
  execFileSync("/usr/bin/ssh-add", [key], { env: { ...env, SSH_AUTH_SOCK: socket }, stdio: "ignore" }); vi.stubEnv("SSH_AUTH_SOCK", socket);
  await mkdir(path.join(home, ".config/git"), { recursive: true }); await writeFile(path.join(home, ".config/git/config"), "[user]\n name = XDG Fixture\n email = xdg@example.invalid\n");
  await writeFile(path.join(home, ".gitconfig"), "[user]\n name = Fixture Operator\n email = global@example.invalid\n[gpg]\n format = x509\n[gpg \"x509\"]\n program = irrelevant-global-program\n");
  git(canonical, env, ["init", "--quiet", "--initial-branch=codex/fixture", `--template=${empty}`]);
  const files = [{ path: "README.txt", mode: "100644" as const, bytes: Buffer.from("pinned generator source\n") },
    { path: ".gitignore", mode: "100644" as const, bytes: Buffer.from("ignored/\n") }, { path: ".gitattributes", mode: "100644" as const, bytes: Buffer.from("*.txt filter=canary\n") }];
  const index: Buffer[] = [];
  for (const file of files) { await writeFile(path.join(canonical, file.path), file.bytes); const oid = git(canonical, env, ["hash-object", "--no-filters", "-w", "--stdin"], file.bytes).toString().trim(); index.push(Buffer.from(`${file.mode} ${oid}\t${file.path}\0`)); }
  git(canonical, env, ["update-index", "-z", "--index-info"], Buffer.concat(index)); const tree = git(canonical, env, ["write-tree"]).toString().trim();
  const base = git(canonical, env, ["commit-tree", tree], "synthetic approved generator\n").toString().trim(); git(canonical, env, ["update-ref", "refs/heads/codex/fixture", base]);
  const config = (key: string, value: string) => git(canonical, env, ["config", "--local", key, value]);
  config("user.email", "local@example.invalid"); config("gpg.format", "ssh"); config("user.signingkey", key + ".pub");
  let root = canonical;
  if (linked) { root = path.join(directory, "linked"); git(canonical, env, ["worktree", "add", "--quiet", "--detach", root, base]); }
  await mkdir(path.join(root, "ignored")); await writeFile(path.join(root, "ignored", "private-sentinel"), "private fixture bytes\n");
  const publication = path.join(directory, "publication"); await mkdir(publication); const publicationEnv = { ...neutralEnvironment(empty, directory), GIT_DIR: path.join(publication, ".git"), GIT_WORK_TREE: publication, GIT_EXEC_PATH: empty };
  git(publication, publicationEnv, ["init", "--quiet", "--object-format=sha1", `--template=${empty}`]);
  for (const file of files) git(publication, publicationEnv, ["hash-object", "--no-filters", "-w", "--stdin"], file.bytes);
  git(publication, publicationEnv, ["update-index", "-z", "--index-info"], Buffer.concat(index)); git(publication, publicationEnv, ["write-tree"]);
  const commitBytes = git(canonical, env, ["cat-file", "commit", base]); git(publication, publicationEnv, ["hash-object", "-t", "commit", "-w", "--stdin"], commitBytes);
  const snapshot = verifyGitSnapshot({ baseCommit: base, commitBytes, files }); const repository = Object.freeze({ repository: "example/fixture", defaultBranch: "main", baseCommit: base, snapshot });
  const cleanup = { value: 0 }; const cancellation = new AbortController(); const context: TransportContext = { directory: publication, root: publication, gitdir: publicationEnv.GIT_DIR!, empty, git: "/usr/bin/git", prlimit: "/usr/bin/env", execPath: empty, env: publicationEnv, signal: cancellation.signal, preparedTree: tree, pending: new Set(), reserve: () => ({ bytes: 1, releaseAfterCleanup: async (work) => { await work(); cleanup.value++; } }) };
  scaffold.contexts.set(repository, context); return { directory, home, root, canonical, env, key, socket, base, tree, config, repository, context, cleanup, cancellation };
}
async function stopAgent(agent: ChildProcess): Promise<void> {
  const stopped = () => agent.exitCode !== null || agent.signalCode !== null;
  const wait = () => new Promise<boolean>((resolve) => { if (stopped()) { resolve(true); return; } const finish = (value: boolean) => { clearTimeout(timer); agent.removeListener("close", closed); resolve(value); }; const closed = () => finish(true); const timer = setTimeout(() => finish(stopped()), 1000); agent.once("close", closed); if (stopped()) finish(true); });
  if (stopped()) return; agent.kill("SIGTERM"); if (await wait()) return; agent.kill("SIGKILL"); if (!await wait()) throw new Error("The owned synthetic SSH agent did not terminate.");
}
afterEach(async () => {
  scaffold.calls = []; scaffold.afterSign = undefined; scaffold.afterCommand = undefined; scaffold.failVerify = false; scaffold.mutateKey = false; scaffold.reads = 0;
  let cleanupError: unknown; for (const agent of agents.splice(0)) try { await stopAgent(agent); } catch (error) { cleanupError = error; }
  vi.unstubAllEnvs(); await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); if (cleanupError) throw cleanupError;
});

describe("trusted generator SSH capture and exact candidate verification", () => {
  it.each([false, true])("uses XDG/global/common-local precedence and safe raw source for linked=%s", async (linked) => {
    const data = await fixture(linked); const marker = path.join(data.directory, "canary"); data.config("core.fsmonitor", `sh -c 'touch ${marker}'`); data.config("filter.canary.clean", `sh -c 'touch ${marker}'`); data.config("filter.canary.smudge", `sh -c 'touch ${marker}'`);
    await mkdir(path.join(data.canonical, ".git/hooks")); await writeFile(path.join(data.canonical, ".git/hooks/pre-commit"), `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
    const captured = await captureGeneratorSigning(data.root, data.base); expect(captured.identity).toEqual({ name: "Fixture Operator", email: "local@example.invalid" });
    expect(await lstat(marker).then(() => true, () => false)).toBe(false); expect(scaffold.calls.every((call) => !call.socket)).toBe(true);
    expect(JSON.stringify(captured.capability)).not.toContain(data.socket); expect(JSON.stringify(captured.capability)).not.toContain(data.key);
  });
  it("freezes one UTC identity/date and canonical DCO, then signs and verifies only with the captured key", async () => {
    const data = await fixture(); const captured = await captureGeneratorSigning(data.root, data.base);
    await writeFile(data.key + ".pub", "ssh-ed25519 AAAA replaced-after-capture\n");
    const plan = freezeCommitPlan(captured.identity, data.base, "codex/frozen", "test: frozen candidate\n", "none"); expect(plan.author).toBe(plan.committer); expect(plan.author.date).toMatch(/^\d+ \+0000$/);
    expect(plan.commitMessage).toBe("test: frozen candidate\n\nSigned-off-by: Fixture Operator <local@example.invalid>\n");
    const { commitPlanSha256, ...canonical } = plan; expect(commitPlanSha256).toBe(createHash("sha256").update(JSON.stringify(canonical)).digest("hex")); expect(Object.isFrozen(plan)).toBe(true);
    const candidate = await signAndVerify(data.repository, data.tree, plan, captured.capability); expect(data.context.candidate).toBe(candidate); expect(data.context.pending.size).toBe(0); expect(data.cleanup.value).toBe(1);
    expect(data.context.signedBranch).toBe(plan.branch); expect(data.context.signedPlanSha256).toBe(plan.commitPlanSha256);
    const raw = git(data.root, { ...data.env, GIT_DIR: data.context.gitdir, GIT_WORK_TREE: data.context.root }, ["cat-file", "commit", candidate]).toString();
    expect(raw).toContain(`author Fixture Operator <local@example.invalid> ${plan.author.date}\n`); expect(raw).toContain(`committer Fixture Operator <local@example.invalid> ${plan.committer.date}\n`);
    expect(raw.endsWith(plan.commitMessage)).toBe(true); expect(raw).toContain("gpgsig -----BEGIN SSH SIGNATURE-----");
    expect(scaffold.calls.filter((call) => call.socket).map((call) => call.args.includes("commit-tree"))).toEqual([true]);
    expect(await readFile(data.key + ".pub", "utf8")).toMatch(/^ssh-ed25519 /); expect(await lstat(data.socket).then((stat) => stat.isSocket())).toBe(true);
  });
  it("rejects publishing real branch-A signing evidence under branch B before provider access", async () => {
    const data = await fixture(); const captured = await captureGeneratorSigning(data.root, data.base); const plan = freezeCommitPlan(captured.identity, data.base, "codex/branch-a", "test: bind published branch", "none");
    const candidate = await signAndVerify(data.repository, data.tree, plan, captured.capability); expect(data.context.signedBranch).toBe("codex/branch-a"); expect(data.context.signedPlanSha256).toBe(plan.commitPlanSha256);
    const commands = scaffold.calls.length; const reads = scaffold.reads;
    await expect(publishCandidate(data.repository, candidate, "codex/branch-b", "test: wrong publication branch", "Synthetic fixture PR body\n")).rejects.toThrow(blocked);
    expect(scaffold.calls.length).toBe(commands); expect(scaffold.reads).toBe(reads); expect(data.context.candidate).toBe(candidate); expect(data.context.signedBranch).toBe("codex/branch-a");
  });
  it.each(["raw", "staged", "assume-unchanged", "skip-worktree", "mode", "untracked", "head"])("blocks %s source drift without hook/filter execution", async (kind) => {
    const data = await fixture(); const file = path.join(data.root, "README.txt");
    if (kind === "head") await writeFile(path.join(data.canonical, ".git/HEAD"), "0".repeat(40) + "\n");
    else if (kind === "untracked") await writeFile(path.join(data.root, "private-draft"), "private sentinel\n");
    else if (kind === "mode") await chmod(file, 0o755);
    else { if (["assume-unchanged", "skip-worktree"].includes(kind)) git(data.root, data.env, ["update-index", "--" + kind, "README.txt"]); await writeFile(file, "changed private fixture bytes\n"); if (kind === "staged") { const oid = git(data.root, data.env, ["hash-object", "--no-filters", "-w", "--stdin"], "changed private fixture bytes\n").toString().trim(); git(data.root, data.env, ["update-index", "--cacheinfo", `100644,${oid},README.txt`]); } }
    await expect(captureGeneratorSigning(data.root, data.base)).rejects.toThrow(blocked); expect(scaffold.calls.every((call) => !call.socket)).toBe(true);
  });
  it.each(["include.path", "includeIf.gitdir:/.path", "extensions.worktreeConfig", "gpg.ssh.allowedSignersFile", "gpg.ssh.revocationFile", "gpg.minTrustLevel", "gpg.ssh.program", "gpg.ssh.defaultKeyCommand", "author.name"])("rejects configured %s authority", async (key) => {
    const data = await fixture(); data.config(key, "unsupported-fixture-value"); await expect(captureGeneratorSigning(data.root, data.base)).rejects.toThrow(blocked);
  });
  it("preserves case-sensitive subsection names when rejecting configured SSH trust", async () => {
    const data = await fixture(); data.config("gpg.ssh.allowedSignersFile", "/fabricated/trust-policy"); data.config("gpg.SSH.allowedSignersFile", "");
    await expect(captureGeneratorSigning(data.root, data.base)).rejects.toThrow(blocked);
  });
  it("rejects configured global trust even when a local empty value clears it", async () => {
    const data = await fixture(); await writeFile(path.join(data.home, ".gitconfig"), "[user]\n name = Fixture Operator\n[gpg \"ssh\"]\n allowedSignersFile = /fabricated/trust-policy\n"); data.config("gpg.ssh.allowedSignersFile", "");
    await expect(captureGeneratorSigning(data.root, data.base)).rejects.toThrow(blocked);
  });
  it("rejects a loose ref appearing after packed-ref resolution", async () => {
    const data = await fixture(); git(data.root, data.env, ["pack-refs", "--all", "--prune"]);
    scaffold.afterCommand = async (args) => { if (args.includes("ls-files")) await writeFile(path.join(data.canonical, ".git/refs/heads/codex/fixture"), "0".repeat(40) + "\n"); };
    await expect(captureGeneratorSigning(data.root, data.base)).rejects.toThrow(blocked);
  });
  it.each(["mode", "abort"])("blocks late %s after the last Git child exits", async (kind) => {
    const data = await fixture(); const cancellation = new AbortController();
    scaffold.afterCommand = async (args) => { if (args.includes("check-ignore")) { if (kind === "mode") await chmod(path.join(data.root, "README.txt"), 0o755); else cancellation.abort(); } };
    await expect(captureGeneratorSigning(data.root, data.base, { signal: cancellation.signal })).rejects.toThrow(blocked);
  });
  it.each(["GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_AUTHOR_NAME", "EMAIL", "XDG_CONFIG_HOME"])("rejects ambient %s provenance override", async (key) => {
    const data = await fixture(); vi.stubEnv(key, "unsupported-fixture-value"); await expect(captureGeneratorSigning(data.root, data.base)).rejects.toThrow(blocked);
  });
  it.each(["x509", "openpgp", "private", "inline", "rsa", "symlink", "writable", "key-fifo", "worktree-config", "backlink"])("rejects unsupported %s signing layout", async (kind) => {
    const data = await fixture(kind === "backlink" || kind === "worktree-config");
    if (["x509", "openpgp"].includes(kind)) data.config("gpg.format", kind);
    if (kind === "private") data.config("user.signingkey", data.key);
    if (kind === "inline") data.config("user.signingkey", "key::ssh-ed25519 AAAA");
    if (kind === "rsa") await writeFile(data.key + ".pub", "ssh-rsa AAAA fixture\n");
    if (kind === "symlink") { const alias = path.join(data.home, "alias.pub"); await symlink(data.key + ".pub", alias); data.config("user.signingkey", alias); }
    if (kind === "writable") await chmod(data.key + ".pub", 0o666);
    if (kind === "key-fifo") { const fifo = path.join(data.home, "fifo.pub"); execFileSync("/usr/bin/mkfifo", [fifo]); data.config("user.signingkey", fifo); }
    if (kind === "worktree-config" || kind === "backlink") { const admin = (await readFile(path.join(data.root, ".git"), "utf8")).slice(8).trim(); await writeFile(path.join(admin, kind === "backlink" ? "gitdir" : "config.worktree"), "unsupported\n"); }
    await expect(captureGeneratorSigning(data.root, data.base)).rejects.toThrow(blocked);
  });
  it("does not substitute another available key when the selected key is absent from the agent", async () => {
    const data = await fixture(); execFileSync("/usr/bin/ssh-add", ["-D"], { env: { ...data.env, SSH_AUTH_SOCK: data.socket }, stdio: "ignore" });
    const other = path.join(data.home, "other-key"); execFileSync("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", other], { env: data.env, stdio: "ignore" }); execFileSync("/usr/bin/ssh-add", [other], { env: { ...data.env, SSH_AUTH_SOCK: data.socket }, stdio: "ignore" });
    const captured = await captureGeneratorSigning(data.root, data.base); const plan = freezeCommitPlan(captured.identity, data.base, "codex/no-fallback", "test: missing selected key", "none");
    await expect(signAndVerify(data.repository, data.tree, plan, captured.capability)).rejects.toThrow(blocked); expect(data.context.candidate).toBeUndefined(); expect(data.cleanup.value).toBe(1);
  });
  it("rejects a valid SSH signature made by a different available key", async () => {
    const data = await fixture(); const captured = await captureGeneratorSigning(data.root, data.base); const plan = freezeCommitPlan(captured.identity, data.base, "codex/wrong-signer", "test: selected signer", "none");
    const other = path.join(data.home, "other-key"); execFileSync("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", other], { env: data.env, stdio: "ignore" }); execFileSync("/usr/bin/ssh-add", [other], { env: { ...data.env, SSH_AUTH_SOCK: data.socket }, stdio: "ignore" });
    scaffold.afterSign = (candidate, options) => {
      const raw = git(options.cwd, options.env, ["cat-file", "commit", candidate]).toString(); const header = raw.slice(0, raw.indexOf("\ngpgsig ")); const unsigned = header + "\n\n" + plan.commitMessage;
      const signature = execFileSync("/usr/bin/ssh-keygen", ["-Y", "sign", "-n", "git", "-f", other + ".pub"], { env: options.env, input: unsigned, stdio: ["pipe", "pipe", "ignore"] }).toString().trimEnd();
      return git(options.cwd, options.env, ["hash-object", "-t", "commit", "-w", "--stdin"], header + "\ngpgsig " + signature.replaceAll("\n", "\n ") + "\n\n" + plan.commitMessage);
    };
    await expect(signAndVerify(data.repository, data.tree, plan, captured.capability)).rejects.toThrow(blocked); expect(data.context.candidate).toBeUndefined();
  });
  it.each(["tree", "parent", "author", "committer", "date", "message", "duplicate", "unsigned", "wrong-format"])("rejects a real candidate with tampered %s", async (kind) => {
    const data = await fixture(); const captured = await captureGeneratorSigning(data.root, data.base); const plan = freezeCommitPlan(captured.identity, data.base, "codex/tamper", "test: exact raw fields", "none");
    scaffold.afterSign = (candidate, options) => {
      let raw = git(options.cwd, options.env, ["cat-file", "commit", candidate]).toString();
      if (kind === "tree") raw = raw.replace(/^tree [a-f0-9]{40}/, "tree " + "0".repeat(40));
      if (kind === "parent") raw = raw.replace(/^parent [a-f0-9]{40}/m, "parent " + "0".repeat(40));
      if (kind === "author") raw = raw.replace(/^author .+$/m, `author Changed <local@example.invalid> ${plan.author.date}`);
      if (kind === "committer") raw = raw.replace(/^committer .+$/m, `committer Changed <local@example.invalid> ${plan.committer.date}`);
      if (kind === "date") raw = raw.replace(plan.author.date, "0 +0000");
      if (kind === "message") raw += "changed\n";
      if (kind === "duplicate") raw = raw.replace(/^parent .+$/m, (line) => line + "\n" + line);
      if (kind === "unsigned") raw = raw.replace(/\ngpgsig [\s\S]*?-----END SSH SIGNATURE-----\n/, "\n");
      if (kind === "wrong-format") raw = raw.replaceAll("SSH SIGNATURE", "PGP SIGNATURE");
      return git(options.cwd, options.env, ["hash-object", "-t", "commit", "-w", "--stdin"], raw);
    };
    await expect(signAndVerify(data.repository, data.tree, plan, captured.capability)).rejects.toThrow(blocked); expect(data.context.candidate).toBeUndefined(); expect(data.context.pending.size).toBe(0);
  });
  it.each(["verify-failure", "changed-key", "forged-capability", "forged-plan", "aborted", "wrong-base", "wrong-tree"])("blocks %s before granting candidate authority", async (kind) => {
    const data = await fixture(); const captured = await captureGeneratorSigning(data.root, data.base); const plan = freezeCommitPlan(captured.identity, data.base, "codex/blocked", "test: blocked authority", "none");
    scaffold.failVerify = kind === "verify-failure"; scaffold.mutateKey = kind === "changed-key"; if (kind === "aborted") data.cancellation.abort();
    const repository: PublicRepository = kind === "wrong-base" ? { ...data.repository, baseCommit: "0".repeat(40) } : data.repository; if (kind === "wrong-base") scaffold.contexts.set(repository, data.context);
    await expect(signAndVerify(repository, kind === "wrong-tree" ? "0".repeat(40) : data.tree, kind === "forged-plan" ? { ...plan } : plan, kind === "forged-capability" ? { identity: captured.identity } : captured.capability)).rejects.toThrow(blocked); expect(data.context.candidate).toBeUndefined();
    if (kind === "wrong-tree") expect(scaffold.calls.some((call) => call.args.includes("commit-tree"))).toBe(false);
  });
  it("rejects forged identities, invalid branches and conflicting DCO without signing", async () => {
    const data = await fixture(); const { identity } = await captureGeneratorSigning(data.root, data.base);
    expect(() => freezeCommitPlan({ ...identity }, data.base, "codex/valid", "test: forged", "none")).toThrow(blocked);
    for (const name of ["main", "codex/a..b", "codex/a//b", "codex/.hidden", "codex/a.lock", "codex/a."]) expect(() => freezeCommitPlan(identity, data.base, name, "test: branch", "none")).toThrow(blocked);
    expect(() => freezeCommitPlan(identity, data.base, "codex/valid", "test: DCO\n\nSigned-off-by: Other <other@example.invalid>\n", "none")).toThrow(blocked);
  });
  it("does not grant candidate authority after a cleanup failure", async () => {
    const data = await fixture(); const captured = await captureGeneratorSigning(data.root, data.base); const plan = freezeCommitPlan(captured.identity, data.base, "codex/cleanup", "test: truthful cleanup", "none");
    data.context.reserve = () => ({ bytes: 1, releaseAfterCleanup: async (cleanup) => { await cleanup(); throw new Error("synthetic cleanup failure"); } });
    await expect(signAndVerify(data.repository, data.tree, plan, captured.capability)).rejects.toThrow(blocked); expect(data.context.candidate).toBeUndefined(); expect(data.context.pending.size).toBe(0);
  });
});
