import { execFileSync, spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

// Only provider metadata, one literal public-fetch URL, and the fixture home origin
// are adapted. Linux eligibility, prlimit, Git, SSH, Docker and backend stay real.
// This composes the primitives; executor eligibility and governance policy remain a separate proof.
const fixtureState = vi.hoisted(() => ({ home: "", remote: "", base: "", prlimit: "", git: "", original: "", fetches: 0,
  launches: [] as Array<{ command: string; args: readonly string[]; agent: boolean; cwd?: string; gitdir?: string }>, requests: [] as string[] }));
vi.mock("node:os", async (original) => {
  const actual = await original<typeof import("node:os")>();
  return { ...actual, default: { ...actual, userInfo: () => ({ ...actual.userInfo(), homedir: fixtureState.home }) } };
});
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: (command: string, args: readonly string[], options: SpawnOptions) => {
    fixtureState.launches.push({ command, args: [...args], agent: !!options.env?.SSH_AUTH_SOCK, ...(options.cwd ? { cwd: String(options.cwd) } : {}), ...(options.env?.GIT_DIR ? { gitdir: options.env.GIT_DIR } : {}) });
    if (command !== fixtureState.prlimit || !args.includes("fetch")) return actual.spawn(command, args, options);
    const literal = "https://github.com/example/broker-composition.git"; expect(args.filter((arg) => arg === literal)).toHaveLength(1);
    const separator = args.indexOf("--"); expect(args[separator + 1]).toBe(fixtureState.git); const rewritten = [...args];
    rewritten[rewritten.indexOf(literal)] = pathToFileURL(fixtureState.remote).href;
    rewritten.splice(separator + 2, 0, "-c", "protocol.file.allow=always"); fixtureState.fetches++;
    return actual.spawn(command, rewritten, options);
  } };
});
vi.mock("node:https", async (original) => {
  const actual = await original<typeof import("node:https")>();
  const get = (options: { hostname: string; path: string; headers: Record<string, string> }, callback: (response: Readable) => void) => {
    expect(options.hostname).toBe("api.github.com"); expect(options.headers).not.toHaveProperty("Authorization"); fixtureState.requests.push(options.path);
    const metadata = { full_name: "example/broker-composition", private: false, visibility: "public", clone_url: "https://github.com/example/broker-composition.git", default_branch: "main", disabled: false, archived: false };
    expect(["/repos/example/broker-composition", "/repos/example/broker-composition/git/ref/heads/main"]).toContain(options.path);
    const request = new EventEmitter() as EventEmitter & { setTimeout: () => void; destroy: () => void }; request.setTimeout = () => {}; request.destroy = () => {};
    queueMicrotask(() => { const response = Readable.from([Buffer.from(JSON.stringify(options.path.endsWith("/heads/main") ? { ref: "refs/heads/main", object: { type: "commit", sha: fixtureState.base } } : metadata))]); Object.assign(response, { statusCode: 200, headers: { "content-type": "application/json" } }); callback(response); }); return request;
  };
  return { ...actual, default: { ...actual, get } };
});

import { NODE_ISOLATION_IMAGE, NODE_ISOLATION_PROFILE, ISOLATION_LIMITS, freezeNodeValidation, type IsolatedSourceFile } from "../src/isolation/node-profile.js";
import { validateIsolatedNode } from "../src/isolation/node-validation.js";
import { boundedCommand, neutralEnvironment, PRLIMIT_ARGS, requireLinuxHost, trustedExecutable } from "../src/upgrade-host.js";
import { captureGeneratorSigning, freezeCommitPlan, signAndVerify } from "../src/upgrade-signing.js";
import { acquirePublicBase, auditPublicCheckout, copyReservedSnapshotFiles, createBoundedBundle, disposePublicRepository, gitArguments, reserveUpgradePreparation, transportContext, writeFrozenTree, type PublicRepository } from "../src/upgrade-transport.js";

const required = process.env.BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS === "1"; const linux = process.platform === "linux";
const roots: string[] = []; const agents: ChildProcess[] = []; const publications: PublicRepository[] = [];
const file = (name: string, contents: string, executable = false): IsolatedSourceFile => ({ path: name, mode: executable ? "100755" : "100644", bytes: Buffer.from(contents) });
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
interface PublicToolMetadataFs {
  realpath(file: string): Promise<string>;
  lstat(file: string): Promise<{ uid: number; gid: number; mode: number; isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean }>;
}
const publicToolPaths = ["/usr/bin/ssh-agent", "/usr/bin/ssh-keygen", "/usr/bin/ssh-add", "/usr/bin/python3", "/usr/bin/node"] as const;
const publicToolMetadataPrefix = "BROKER_PUBLIC_TOOL_METADATA ";
function publicToolDiagnostic(io: PublicToolMetadataFs = { realpath, lstat }, write: (line: string) => void = (line) => console.log(line)): () => Promise<void> {
  let emitted = false;
  return async () => {
    if (emitted) return;
    emitted = true;
    let expired = false; let timer: ReturnType<typeof setTimeout> | undefined;
    const errorCode = (error: unknown) => {
      const code = (error as { code?: unknown } | null)?.code;
      return typeof code === "string" && ["ENOENT", "EACCES", "EPERM", "ENOTDIR", "ELOOP", "ENAMETOOLONG", "EIO"].includes(code) ? code : "OTHER";
    };
    const collect = async () => {
      const tools: Array<Record<string, unknown>> = [];
      for (const requested of publicToolPaths) {
        if (expired) break;
        const row: Record<string, unknown> = { path: requested }; tools.push(row);
        let resolved: string;
        try { resolved = await io.realpath(requested); }
        catch (error) { row.error = errorCode(error); continue; }
        if (expired) break;
        const prefixes = ["/usr/bin", "/usr/lib", "/usr/libexec", "/usr/local/bin", "/usr/local/lib", "/bin", "/lib", "/lib64", "/opt/hostedtoolcache"];
        if (typeof resolved !== "string" || Buffer.byteLength(resolved) > 512 || path.posix.normalize(resolved) !== resolved ||
          !resolved.split("/").slice(1).every((part) => /^[A-Za-z0-9_][A-Za-z0-9._+-]*$/.test(part)) ||
          !prefixes.some((prefix) => resolved === prefix || resolved.startsWith(prefix + "/"))) {
          row.error = "NON_PUBLIC_RESOLUTION"; continue;
        }
        row.realpath = resolved;
        const ancestors: Array<Record<string, unknown>> = []; row.ancestors = ancestors;
        let current = resolved;
        for (let depth = 0; depth < 16; depth++) {
          if (expired) break;
          try {
            const stat = await io.lstat(current);
            if (expired) break;
            if (![stat.uid, stat.gid, stat.mode].every((value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff)) {
              ancestors.push({ path: current, error: "INVALID_METADATA" }); break;
            }
            ancestors.push({ path: current, uid: stat.uid, gid: stat.gid, mode: (stat.mode & 0o7777).toString(8).padStart(4, "0"),
              type: stat.isFile() ? "file" : stat.isDirectory() ? "directory" : stat.isSymbolicLink() ? "symlink" : "other" });
          } catch (error) { ancestors.push({ path: current, error: errorCode(error) }); break; }
          if (current === "/") break;
          current = path.posix.dirname(current);
          if (depth === 15) row.error = "ANCESTOR_LIMIT";
        }
      }
      return { schema: 1, tools };
    };
    let record: unknown;
    try {
      record = await Promise.race([collect(), new Promise((resolve) => {
        timer = setTimeout(() => { expired = true; resolve({ schema: 1, error: "TIME_LIMIT" }); }, 2_000);
      })]);
    } catch { record = { schema: 1, error: "DIAGNOSTIC_ERROR" }; }
    finally { expired = true; if (timer !== undefined) clearTimeout(timer); }
    let line = publicToolMetadataPrefix + JSON.stringify(record);
    if (Buffer.byteLength(line + "\n") > 16_384) line = publicToolMetadataPrefix + JSON.stringify({ schema: 1, error: "OUTPUT_LIMIT" });
    try { write(line); } catch { /* Diagnostics never replace the original eligibility assertions. */ }
  };
}
const reportPublicTools = publicToolDiagnostic();

function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: string | Uint8Array): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", ...args], { cwd: root, env, ...(input !== undefined ? { input } : {}), maxBuffer: 4 * 1024 ** 2 });
}
async function rawRepository(root: string, env: NodeJS.ProcessEnv, files: readonly IsolatedSourceFile[], empty: string): Promise<{ commit: string; bytes: Buffer }> {
  await mkdir(root); git(root, env, ["init", "--quiet", "--object-format=sha1", "--initial-branch=main", `--template=${empty}`]); const index: Buffer[] = [];
  for (const entry of files) {
    await mkdir(path.dirname(path.join(root, entry.path)), { recursive: true }); await writeFile(path.join(root, entry.path), entry.bytes, { mode: entry.mode === "100755" ? 0o755 : 0o644 });
    const oid = git(root, env, ["hash-object", "--no-filters", "-w", "--stdin"], entry.bytes).toString().trim(); index.push(Buffer.from(`${entry.mode} ${oid}\t${entry.path}\0`));
  }
  git(root, env, ["update-index", "-z", "--index-info"], Buffer.concat(index)); const tree = git(root, env, ["write-tree"]).toString().trim(); const commit = git(root, env, ["commit-tree", tree], "Synthetic complete public history\n").toString().trim();
  git(root, env, ["update-ref", "refs/heads/main", commit]); return { commit, bytes: git(root, env, ["cat-file", "commit", commit]) };
}
async function fingerprint(root: string): Promise<string> {
  const rows: unknown[] = []; const walk = async (prefix: string): Promise<void> => {
    for (const name of (await readdir(path.join(root, prefix))).sort()) { const relative = prefix ? prefix + "/" + name : name; const location = path.join(root, relative); const stat = await lstat(location);
      expect(stat.isSymbolicLink()).toBe(false); rows.push([relative, stat.mode, stat.isDirectory() ? "directory" : sha256(await readFile(location))]); if (stat.isDirectory()) await walk(relative); }
  }; await walk(""); return sha256(Buffer.from(JSON.stringify(rows)));
}
async function stopAgent(agent: ChildProcess): Promise<void> {
  const stopped = () => agent.exitCode !== null || agent.signalCode !== null;
  const wait = () => new Promise<boolean>((resolve) => { if (stopped()) { resolve(true); return; } const finish = (value: boolean) => { clearTimeout(timer); agent.removeListener("close", closed); resolve(value); }; const closed = () => finish(true); const timer = setTimeout(() => finish(stopped()), 1000); agent.once("close", closed); if (stopped()) finish(true); });
  if (stopped()) return; agent.kill("SIGTERM"); if (await wait()) return; agent.kill("SIGKILL"); if (!await wait()) throw new Error("The owned synthetic SSH agent did not terminate.");
}
afterEach(async () => {
  let cleanupError: unknown;
  for (const publication of publications.splice(0)) try { await disposePublicRepository(publication); } catch (error) { cleanupError = error; }
  for (const agent of agents.splice(0)) try { await stopAgent(agent); } catch (error) { cleanupError = error; }
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); vi.unstubAllEnvs();
  fixtureState.launches = []; fixtureState.requests = []; fixtureState.fetches = 0; fixtureState.home = ""; fixtureState.remote = ""; if (cleanupError) throw cleanupError;
});

it("bounds public-tool diagnostics without changing eligibility failures", async () => {
  const lines: string[] = []; const metadata = publicToolDiagnostic({
    realpath: async (file) => {
      if (file === "/usr/bin/node") throw { code: "ENOENT", message: "fabricated-private-detail" };
      if (file === "/usr/bin/ssh-add") return "/home/fabricated/.config/private";
      return file;
    },
    lstat: async (file) => {
      expect(file.startsWith("/home/")).toBe(false);
      const regular = publicToolPaths.includes(file as typeof publicToolPaths[number]);
      return { uid: 0, gid: 0, mode: regular ? (file.endsWith("ssh-agent") ? 0o102755 : 0o100755) : 0o40755,
        isFile: () => regular, isDirectory: () => !regular, isSymbolicLink: () => false };
    }
  }, (line) => lines.push(line));
  await metadata(); await metadata();
  expect(lines).toHaveLength(1); expect(lines[0]!.split("\n")).toHaveLength(1); expect(Buffer.byteLength(lines[0]! + "\n")).toBeLessThanOrEqual(16_384);
  expect(lines[0]).not.toMatch(/fabricated-private-detail|\/home\/fabricated/);
  const record = JSON.parse(lines[0]!.slice(publicToolMetadataPrefix.length));
  expect(record.tools.find((tool: { path: string }) => tool.path.endsWith("/node")).error).toBe("ENOENT");
  expect(record.tools.find((tool: { path: string }) => tool.path.endsWith("/ssh-add")).error).toBe("NON_PUBLIC_RESOLUTION");
  expect(record.tools[0].ancestors[0]).toMatchObject({ uid: 0, gid: 0, mode: "2755", type: "file" });
  await expect((async () => { await metadata(); throw new Error("original eligibility failure"); })()).rejects.toThrow("original eligibility failure");
});

it.skipIf(!required)("requires actual unprivileged Linux x64 host-broker enforcement when mandatory", async () => {
  if (linux) await reportPublicTools();
  expect(process.platform, "The mandatory broker/backend proof cannot be satisfied by Darwin semantic tests.").toBe("linux");
  expect(process.arch).toBe("x64"); const tools = await requireLinuxHost(); expect(tools.prlimit).toBeTruthy(); await trustedExecutable("/usr/bin/ssh-keygen"); await trustedExecutable("/usr/bin/ssh-agent");
});

describe.skipIf(!required || !linux)("actual Linux brokers plus actual Docker backend (explicit opt-in)", () => {
  it("binds raw public acquisition, isolated hook, selected-key signing and isolated final candidate without touching the original", async () => {
    const tools = await requireLinuxHost(); fixtureState.prlimit = tools.prlimit; fixtureState.git = tools.git;
    const directory = await mkdtemp(path.join(await realpath(process.cwd()), ".broker-integration-")); roots.push(directory);
    const home = path.join(directory, "home"), empty = path.join(directory, "empty"); await mkdir(home); await mkdir(empty); fixtureState.home = home;
    for (const name of Object.keys(process.env)) if (name.startsWith("GIT_") || ["EMAIL", "XDG_CONFIG_HOME"].includes(name)) vi.stubEnv(name, undefined);
    vi.stubEnv("HOME", home); vi.stubEnv("GH_TOKEN", "inert-fabricated-integration-canary"); vi.stubEnv("GITHUB_TOKEN", "inert-fabricated-integration-canary"); vi.stubEnv("BOOTSTRAP_PRIVATE_CANARY", "inert-fabricated-integration-canary");
    const env = { ...neutralEnvironment(home, directory), GIT_AUTHOR_NAME: "Broker Fixture", GIT_AUTHOR_EMAIL: "broker@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Broker Fixture", GIT_COMMITTER_EMAIL: "broker@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
    let docker: string | undefined; for (const candidate of ["/usr/bin/docker", "/usr/local/bin/docker"]) try { docker = await trustedExecutable(candidate); break; } catch { /* Supported fixed locations only. */ }
    expect(docker, "A trusted Docker CLI must already exist; this test never installs tools.").toBeTruthy(); await mkdir(path.join(home, "docker"));
    const dockerCommand = (args: string[]) => boundedCommand(docker!, ["--host", "unix:///var/run/docker.sock", "--config", path.join(home, "docker"), ...args], { cwd: directory, env: neutralEnvironment(home, directory) });
    expect((await dockerCommand(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])) .toString().trim()).toBe("linux/amd64");
    expect((await dockerCommand(["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", NODE_ISOLATION_IMAGE])).toString().trim()).toBe("linux/amd64");
    const key = path.join(home, "fixture-key"); const ssh = await trustedExecutable("/usr/bin/ssh-keygen"); const sshAgent = await trustedExecutable("/usr/bin/ssh-agent"); const sshAdd = await trustedExecutable("/usr/bin/ssh-add");
    await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, ssh, "-q", "-t", "ed25519", "-N", "", "-f", key], { cwd: directory, env: neutralEnvironment(home, directory) });
    const agentDirectory = await mkdtemp(path.join(await realpath(os.tmpdir()), "broker-agent-")); roots.push(agentDirectory); const socket = path.join(agentDirectory, "agent.sock");
    const agent = spawn(sshAgent, ["-D", "-a", socket], { env: neutralEnvironment(home, directory), stdio: "ignore" }); agents.push(agent);
    for (let attempt = 0; attempt < 100; attempt++) { if (await lstat(socket).then((stat) => stat.isSocket(), () => false)) break; await new Promise((resolve) => setTimeout(resolve, 10)); }
    await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, sshAdd, key], { cwd: directory, env: { ...neutralEnvironment(home, directory), SSH_AUTH_SOCK: socket } }); vi.stubEnv("SSH_AUTH_SOCK", socket);
    await writeFile(path.join(home, ".gitconfig"), "[user]\n name = Broker Fixture\n email = global@example.invalid\n[gpg]\n format = x509\n[gpg \"x509\"]\n program = irrelevant-fixture-program\n");
    const generator = path.join(directory, "generator"); const generatorBase = await rawRepository(generator, env, [file("README.md", "Synthetic pinned generator\n")], empty);
    for (const [name, value] of [["user.email", "broker@example.invalid"], ["gpg.format", "ssh"], ["user.signingkey", key + ".pub"]]) git(generator, env, ["config", "--local", name!, value!]);
    const captured = await captureGeneratorSigning(generator, generatorBase.commit); expect(captured.identity).toEqual({ name: "Broker Fixture", email: "broker@example.invalid" });
    const original = path.join(directory, "original"); fixtureState.original = original; const hostCanary = path.join(directory, "host-target-ran");
    const baseFiles = [file("README.md", "Original public source\n"), file(".gitignore", "ignored/\n"), file("package.json", JSON.stringify({ name: "broker-composition-fixture", version: "1.0.0", private: true })),
      file("package-lock.json", JSON.stringify({ name: "broker-composition-fixture", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "broker-composition-fixture", version: "1.0.0" } } })),
      file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\nnode probe.cjs check\n", true), file(".githooks/pre-commit", "#!/bin/bash\nset -euo pipefail\nnode probe.cjs hook\n", true)];
    const originalBase = await rawRepository(original, env, baseFiles, empty); fixtureState.base = originalBase.commit;
    const cleanOriginal = path.join(directory, "clean-original"); const cleanBase = await rawRepository(cleanOriginal, env, baseFiles, empty);
    expect(cleanBase.commit).toBe(originalBase.commit); expect(cleanBase.bytes).toEqual(originalBase.bytes);
    git(cleanOriginal, env, ["config", "--local", "remote.origin.url", "https://github.com/example/broker-composition.git"]);
    await mkdir(path.join(cleanOriginal, "ignored")); await writeFile(path.join(cleanOriginal, "ignored/private-sentinel"), "Clean-checkout private preservation sentinel\n"); const cleanBefore = await fingerprint(cleanOriginal);
    const remote = path.join(directory, "remote.git"); const remoteEnv = { ...env, GIT_DIR: remote }; await mkdir(remote); git(directory, remoteEnv, ["init", "--quiet", "--bare", "--object-format=sha1", `--template=${empty}`]);
    const index: Buffer[] = []; for (const entry of baseFiles) { const oid = git(directory, remoteEnv, ["hash-object", "--no-filters", "-w", "--stdin"], entry.bytes).toString().trim(); index.push(Buffer.from(`${entry.mode} ${oid}\t${entry.path}\0`)); }
    git(directory, remoteEnv, ["update-index", "-z", "--index-info"], Buffer.concat(index)); git(directory, remoteEnv, ["write-tree"]); git(directory, remoteEnv, ["hash-object", "-t", "commit", "-w", "--stdin"], originalBase.bytes); git(directory, remoteEnv, ["update-ref", "refs/heads/main", originalBase.commit]); fixtureState.remote = remote;
    const trap = path.join(directory, "local-authority-canary"); await writeFile(trap, `#!/bin/sh\nprintf host-canary > '${hostCanary}'\nexit 1\n`, { mode: 0o755 });
    await mkdir(path.join(original, ".git/info"), { recursive: true }); await writeFile(path.join(original, ".git/info/attributes"), "* filter=canary diff=canary\n"); await mkdir(path.join(original, ".git/hooks")); await writeFile(path.join(original, ".git/hooks/pre-commit"), await readFile(trap), { mode: 0o755 });
    const originalConfig = await readFile(path.join(original, ".git/config"), "utf8"); await writeFile(path.join(original, ".git/config"), originalConfig + `\n[core]\n fsmonitor = ${trap}\n hooksPath = ${path.join(original, ".git/hooks")}\n[filter "canary"]\n clean = ${trap}\n smudge = ${trap}\n[diff "canary"]\n textconv = ${trap}\n[credential]\n helper = !${trap}\n[url "ext::${trap}"]\n insteadOf = https://fixture.invalid/\n`);
    await mkdir(path.join(original, "ignored")); await writeFile(path.join(original, "ignored/private-sentinel"), "Private synthetic preservation sentinel\n"); const before = await fingerprint(original);
    const repository = await acquirePublicBase("example/broker-composition", originalBase.commit); publications.push(repository);
    expect(fixtureState.fetches).toBe(1); expect(repository.snapshot.baseCommit).toBe(originalBase.commit); const reservedFiles = copyReservedSnapshotFiles(repository);
    expect(reservedFiles).toEqual([...baseFiles].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))));
    const audit = await auditPublicCheckout(repository, cleanOriginal); expect(audit).toMatchObject({ baseCommit: repository.baseCommit, tree: repository.snapshot.tree, sourceSha256: repository.snapshot.sourceSha256 }); expect(audit.originalStateSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(await fingerprint(cleanOriginal)).toBe(cleanBefore);
    // The hostile copy has unsupported local hooks/attributes. It is an unexecuted
    // authority trap, never an eligible checkout or authorization to run an executor.
    const plan = freezeCommitPlan(captured.identity, repository.baseCommit, "codex/broker-composition", "test: actual broker and backend composition", ".githooks/pre-commit");
    const probe = `const a=require('node:assert/strict'),fs=require('node:fs'),cp=require('node:child_process');
if(process.cwd()!=='/repo/project')fs.writeFileSync(${JSON.stringify(hostCanary)},'target code executed on host');
a.equal(process.cwd(),'/repo/project');a.equal(process.getuid(),1000);
const p=JSON.parse(fs.readFileSync('supervisor-plan.json','utf8'));const git=(args)=>cp.execFileSync('git',args,{encoding:'utf8'}).trim();
for(const name of ['GH_TOKEN','GITHUB_TOKEN','SSH_AUTH_SOCK','BOOTSTRAP_PRIVATE_CANARY','BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS'])a.equal(process.env[name],undefined);
for(const name of [${JSON.stringify(hostCanary)},'/var/run/docker.sock'])a.equal(fs.existsSync(name),false);
for(const name of ['README.md','.git/index'])a.throws(()=>fs.openSync(name,'r+'),e=>['EROFS','EACCES','EPERM'].includes(e.code));
a.equal(process.env.NPM_CONFIG_OFFLINE,'true');a.equal(git(['symbolic-ref','--short','HEAD']),p.branch);
if(process.argv[2]==='hook'){
 a.equal(process.env.GIT_INDEX_FILE,'.git/index');a.equal(process.env.GIT_PREFIX,'');a.equal(process.env.GIT_EDITOR,':');a.equal(process.env.GIT_EXEC_PATH,git(['--exec-path']));
 for(const kind of ['author','committer']){for(const field of ['name','email','date'])a.equal(process.env['GIT_'+kind.toUpperCase()+'_'+field.toUpperCase()],(field==='date'?'@':'')+p[kind][field]);a.equal(git(['var','GIT_'+kind.toUpperCase()+'_IDENT']),p[kind].name+' <'+p[kind].email+'> '+p[kind].date);}
 a.equal(git(['config','--local','--get','user.name']),p.committer.name);a.equal(git(['config','--local','--get','user.email']),p.committer.email);
 a.equal(fs.readFileSync('.git/COMMIT_EDITMSG','utf8'),p.commitMessage);a.equal(git(['rev-parse','HEAD']),p.baseCommit);a(git(['diff','--cached','--name-only','HEAD']).split('\\n').includes('README.md'));
 console.log('BROKER-INTEGRATION-HOOK-PASSED');
}else{a.equal(git(['diff','--cached','--name-only','HEAD']),'');console.log('BROKER-INTEGRATION-CHECK:'+git(['rev-parse','HEAD']));}
`;
    const files = [...reservedFiles.filter((entry) => entry.path !== "README.md"), file("README.md", "Prepared public source\n"), file("probe.cjs", probe), file("supervisor-plan.json", JSON.stringify(plan))];
    expect(files.every((entry) => !Buffer.from(entry.bytes).includes(Buffer.from(socket)) && !Buffer.from(entry.bytes).includes(Buffer.from(key)))).toBe(true);
    expect(reserveUpgradePreparation(repository, files).bytes).toBeGreaterThan(0);
    const written = await writeFrozenTree(repository, files); const baseBundle = await createBoundedBundle(repository);
    const common = { profile: NODE_ISOLATION_PROFILE, files, baseBundle, baseCommit: plan.baseCommit, branch: plan.branch, commitMessage: plan.commitMessage, author: plan.author, committer: plan.committer, hook: plan.hook } as const;
    const frozen = freezeNodeValidation({ ...common, phase: "prepared-hook" }); const independentlyHashed = [...files].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))).map(({ path, mode, bytes }) => ({ path, mode, sha256: sha256(bytes) }));
    expect(frozen.sourceSha256).toBe(sha256(Buffer.from(JSON.stringify(independentlyHashed)))); expect(frozen.commitPlanSha256).toBe(plan.commitPlanSha256);
    const expected = { profile: NODE_ISOLATION_PROFILE, image: NODE_ISOLATION_IMAGE, sourceSha256: frozen.sourceSha256, commitPlanSha256: plan.commitPlanSha256, baseCommit: repository.baseCommit, preparedTree: written.tree, hook: plan.hook };
    const replay = await validateIsolatedNode({ ...common, phase: "prepared-hook" }); expect(replay).toMatchObject({ ...expected, phase: "prepared-hook" }); if (replay.phase !== "prepared-hook") throw new Error("Expected hook phase evidence"); expect(replay.hookOutput).toContain("BROKER-INTEGRATION-HOOK-PASSED");
    const candidate = await signAndVerify(repository, written.tree, plan, captured.capability); const context = transportContext(repository);
    const raw = (await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, tools.git, ...gitArguments(context, ["cat-file", "commit", candidate])], { cwd: context.directory, env: context.env })).toString();
    expect(raw.startsWith(`tree ${written.tree}\nparent ${plan.baseCommit}\nauthor ${plan.author.name} <${plan.author.email}> ${plan.author.date}\ncommitter ${plan.committer.name} <${plan.committer.email}> ${plan.committer.date}\ngpgsig -----BEGIN SSH SIGNATURE-----\n`)).toBe(true); expect(raw.endsWith("\n\n" + plan.commitMessage)).toBe(true);
    const header = raw.slice(0, raw.indexOf("\n\n")).split("\n"); for (const name of ["tree", "parent", "author", "committer"]) expect(header.filter((line) => line.startsWith(name + " "))).toHaveLength(1);
    expect(raw.slice(raw.indexOf("\n\n") + 2)).toBe(plan.commitMessage); expect(createHash("sha1").update(`commit ${Buffer.byteLength(raw)}\0`).update(raw).digest("hex")).toBe(candidate);
    const finalBundle = await createBoundedBundle(repository, candidate); const final = await validateIsolatedNode({ ...common, phase: "final-check", candidateCommit: candidate, baseBundle: finalBundle });
    expect(final).toMatchObject({ ...expected, phase: "final-check", candidateCommit: candidate }); if (final.phase !== "final-check") throw new Error("Expected final phase evidence"); expect(final.checkOutput).toContain("BROKER-INTEGRATION-CHECK:" + candidate);
    for (const evidence of [replay, final]) { expect(Object.keys(evidence.tools).sort()).toEqual(["bash", "git", "jq", "node", "npm", "python"]); expect(Object.values(evidence.tools).every((value) => value.length > 0)).toBe(true); }
    expect(fixtureState.requests).toEqual(["/repos/example/broker-composition", "/repos/example/broker-composition/git/ref/heads/main"]);
    for (const launch of fixtureState.launches) { for (const untouched of [original, cleanOriginal]) { expect(launch.cwd).not.toBe(untouched); expect(launch.gitdir).not.toBe(path.join(untouched, ".git")); } if (launch.command === tools.prlimit) expect(launch.args.slice(0, PRLIMIT_ARGS.length)).toEqual(PRLIMIT_ARGS); }
    const socketLaunches = fixtureState.launches.filter((launch) => launch.agent); expect(socketLaunches).toHaveLength(2);
    for (const launch of socketLaunches) { expect(launch.command).toBe(tools.prlimit); expect(launch.args[PRLIMIT_ARGS.length]).toBe(launch.args.includes("commit-tree") ? tools.git : sshAdd); }
    expect(await lstat(hostCanary).then(() => true, () => false)).toBe(false); expect(await fingerprint(original)).toBe(before); expect(await fingerprint(cleanOriginal)).toBe(cleanBefore);
  }, ISOLATION_LIMITS.operationMs * 2 + 120_000);
});
