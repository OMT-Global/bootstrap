import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdir, mkdtemp, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { redactPublicText } from "../provenance.js";
import { CONTAINER_SETUP } from "./setup.js";
import { downloadArchive, freezeNodeValidation, ISOLATION_LIMITS, NODE_ISOLATION_IMAGE, NODE_ISOLATION_PROFILE,
  type NodeValidationInput } from "./node-profile.js";

export interface NodeToolVersions { bash: string; git: string; python: string; node: string; npm: string; jq: string }
interface NodeValidationEvidence {
  profile: typeof NODE_ISOLATION_PROFILE; image: string; sourceSha256: string; commitPlanSha256: string; baseCommit: string;
  preparedTree: string; hook: "none" | ".githooks/pre-commit"; tools: NodeToolVersions;
}
export type NodeValidationReport = NodeValidationEvidence & (
  { phase: "prepared-hook"; hookOutput: string } | { phase: "final-check"; candidateCommit: string; checkOutput: string });
class IsolationError extends Error {}
interface Budget { bytes: number }
function demand(value: unknown, message: string): asserts value { if (!value) throw new IsolationError(message); }
async function dockerPath(): Promise<string> {
  // PATH can contain repository-controlled npm/direnv bins. Only the profile's root-owned tool locations are trusted.
  for (const candidate of ["/usr/bin/docker", "/usr/local/bin/docker"]) {
    try {
      await access(candidate, constants.X_OK);
      const executable = await realpath(candidate); const file = await stat(executable);
      demand(file.isFile() && file.uid === 0 && (file.mode & 0o022) === 0, "Untrusted Docker executable.");
      for (let directory = path.dirname(executable); ; directory = path.dirname(directory)) {
        const parent = await stat(directory);
        demand(parent.isDirectory() && parent.uid === 0 && (parent.mode & 0o022) === 0, "Untrusted Docker executable ancestry.");
        if (directory === path.dirname(directory)) break;
      }
      return executable;
    } catch { /* Missing or untrusted profile locations never fall back to PATH. */ }
  }
  throw new IsolationError("The supported trusted Docker CLI is unavailable; no host fallback exists.");
}
async function command(executable: string, args: string[], home: string, budget: Budget, timeout = ISOLATION_LIMITS.phaseMs, signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const child = spawn(executable, ["--host", "unix:///var/run/docker.sock", "--config", path.join(home, "docker"), ...args], {
      cwd: home, env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: home }, stdio: ["ignore", "pipe", "pipe"]
    });
    const output: Buffer[] = []; let failed = false; let timedOut = false; let cancelled = false;
    const abort = () => { cancelled = true; child.kill("SIGKILL"); };
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeout);
    const take = (chunk: Buffer) => {
      budget.bytes += chunk.length;
      if (budget.bytes > ISOLATION_LIMITS.outputBytes) { failed = true; child.kill("SIGKILL"); } else output.push(chunk);
    };
    child.stdout.on("data", take); child.stderr.on("data", take);
    child.on("error", () => { clearTimeout(timer); signal?.removeEventListener("abort", abort); reject(new IsolationError("Docker operation could not start.")); });
    child.on("close", (code) => {
      clearTimeout(timer); signal?.removeEventListener("abort", abort);
      if (cancelled || timedOut || failed || code !== 0) reject(new IsolationError(cancelled ? "Isolated validation was cancelled." : timedOut ? "Isolated phase timed out." : failed ? "Isolated output exceeded its bound." : "Isolated phase or Docker operation failed."));
      else resolve(Buffer.concat(output).toString("utf8"));
    });
  });
}
const environment = ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp/home", "CI=true", "NPM_CONFIG_OFFLINE=true",
  "NPM_CONFIG_CACHE=/npm-cache", "NPM_CONFIG_USERCONFIG=/tmp/empty-npmrc", "NPM_CONFIG_GLOBALCONFIG=/tmp/empty-global-npmrc",
  "NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null",
  "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_EDITOR=:", "GIT_TERMINAL_PROMPT=0"];
const tmpfs = (target: string, size: number, executable = false) => ["--tmpfs", `${target}:rw,nosuid,nodev,${executable ? "exec" : "noexec"},size=${size},uid=1000,gid=1000,mode=0700`];
const volume = (name: string, target: string, readonly = true) => ["--mount", `type=volume,src=${name},dst=${target}${readonly ? ",readonly" : ""}`];

/** Backend only: public frozen bytes in; validation evidence out. Never signs or publishes a repository. */
export async function validateIsolatedNode(input: NodeValidationInput, options: { signal?: AbortSignal } = {}): Promise<NodeValidationReport> {
  const deadline = Date.now() + ISOLATION_LIMITS.operationMs;
  options.signal?.throwIfAborted();
  const frozen = freezeNodeValidation(input);
  demand(process.platform === "linux" && process.arch === "x64", "This profile requires a Linux/amd64 supervisor; no host fallback exists.");
  const executable = await dockerPath();
  const home = await mkdtemp(path.join(os.tmpdir(), "bootstrap-isolation-"));
  const budget = { bytes: 0 }; const id = `bootstrap-isolation-${randomUUID()}`;
  const volumes: string[] = []; const containers: string[] = [];
  const operation = new AbortController(); let operationTimedOut = false;
  const cancel = () => operation.abort(); options.signal?.addEventListener("abort", cancel, { once: true });
  if (options.signal?.aborted) cancel();
  const operationTimer = setTimeout(() => { operationTimedOut = true; cancel(); }, Math.max(1, deadline - Date.now()));
  const run = (args: string[], timeout?: number) => command(executable, args, home, budget, timeout, operation.signal);
  let failure: unknown; let report: NodeValidationReport | undefined;
  try {
    await mkdir(path.join(home, "docker"), { mode: 0o700 });
    demand((await run(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], 15_000)).trim() === "linux/amd64", "The Docker server does not match the supported platform.");
    demand((await run(["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", NODE_ISOLATION_IMAGE], 15_000)).trim() === "linux/amd64", "The pinned toolchain image is not available for Linux/amd64.");
    const source = `${id}-source`, cache = `${id}-cache`, data = `${id}-input`;
    for (const [name, size] of [[source, 1024 ** 3], [cache, 512 * 1024 ** 2], [data, 768 * 1024 ** 2]] as const) {
      volumes.push(name);
      await run(["volume", "create", "--driver", "local", "--label", `bootstrap.isolation=${id}`, "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", `o=size=${size},mode=1777,nosuid,nodev`, name]);
    }
    const transfer = path.join(home, "transfer");
    await mkdir(path.join(transfer, "files"), { recursive: true }); await mkdir(path.join(transfer, "archives")); await mkdir(path.join(transfer, "empty-template"));
    for (const file of frozen.files) {
      const target = path.join(transfer, "files", file.path); await mkdir(path.dirname(target), { recursive: true }); await writeFile(target, file.bytes, { mode: 0o600 });
    }
    await writeFile(path.join(transfer, "base.bundle"), frozen.baseBundle, { mode: 0o600 });
    await writeFile(path.join(transfer, "setup.cjs"), CONTAINER_SETUP, { mode: 0o600 });
    await writeFile(path.join(transfer, "manifest.json"), JSON.stringify({ ...frozen, files: frozen.files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })), baseBundle: undefined, archives: undefined }), { mode: 0o600 });
    const downloadController = new AbortController();
    const cancelDownload = () => downloadController.abort();
    operation.signal.addEventListener("abort", cancelDownload, { once: true });
    const downloadTimer = setTimeout(cancelDownload, ISOLATION_LIMITS.phaseMs);
    let downloaded = 0;
    try {
      if (operation.signal.aborted) downloadController.abort();
      for (const [index, request] of frozen.archives.entries()) {
        const bytes = await downloadArchive(request, downloadController.signal); downloaded += bytes.length;
        demand(downloaded <= ISOLATION_LIMITS.downloadBytes, "Dependency data exceeds the aggregate download bound.");
        await writeFile(path.join(transfer, "archives", `${index}.tgz`), bytes, { mode: 0o600 });
      }
    } finally { clearTimeout(downloadTimer); operation.signal.removeEventListener("abort", cancelDownload); }
    // Docker copies public input into its own bounded storage; no host bind mount is used.
    const common = ["--platform", "linux/amd64", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
      "--ipc", "private", "--cgroupns", "private", "--user", "1000:1000", "--no-healthcheck", "--log-driver", "none", "--entrypoint", "node",
      ...environment.flatMap((value) => ["--env", value])];
    const create = async (name: string, mounts: string[], mode: "prepare" | "check" | "hook" | "storage", working = "/repo/project") => {
      containers.push(name);
      const storage = mode === "storage", memory = storage ? "64m" : "4g";
      await run(["create", "--name", name, "--label", `bootstrap.isolation=${id}`, "--workdir", working, ...common, ...mounts,
        "--cpus", storage ? "0.1" : "2", "--memory", memory, "--memory-swap", memory, "--pids-limit", storage ? "16" : "256",
        ...tmpfs("/tmp", (storage ? 1 : 256) * 1024 ** 2, mode === "hook" || mode === "check"), NODE_ISOLATION_IMAGE,
        ...(storage ? ["-e", `setTimeout(() => process.exit(1), Math.max(1, ${deadline} - Date.now()))`] : ["/input/setup.cjs", mode])]);
    };
    // A live, inert mount holder prevents the local driver's tmpfs data disappearing between operations.
    const storage = `${id}-storage`;
    await create(storage, [...volume(data, "/input", false), ...volume(source, "/repo", false), ...volume(cache, "/pristine-cache", false)], "storage", "/");
    await run(["start", storage]);
    const storageAlive = async () => {
      const state = JSON.parse(await run(["inspect", "--format", "{{json .State}}", storage])) as { Running?: boolean; OOMKilled?: boolean; Error?: string };
      demand(state.Running === true && state.OOMKilled === false && state.Error === "", "The bounded isolated storage lifetime ended.");
    };
    await storageAlive();
    const prepare = `${id}-prepare`;
    await create(prepare, [...volume(data, "/input", false), ...volume(source, "/repo", false), ...volume(cache, "/pristine-cache", false), ...tmpfs("/install", 512 * 1024 ** 2)], "prepare", "/input");
    // The non-root process needs to read copied public files. It never receives an operator configuration.
    const { chmod } = await import("node:fs/promises");
    for (const file of [...frozen.files.map((entry) => path.join(transfer, "files", entry.path)), path.join(transfer, "base.bundle"), path.join(transfer, "setup.cjs"), path.join(transfer, "manifest.json"), ...frozen.archives.map((_, index) => path.join(transfer, "archives", `${index}.tgz`))]) await chmod(file, 0o644);
    const readableDirectories = async (directory: string): Promise<void> => {
      await chmod(directory, 0o755);
      for (const entry of await readdir(directory, { withFileTypes: true })) if (entry.isDirectory()) await readableDirectories(path.join(directory, entry.name));
    };
    await readableDirectories(transfer);
    await storageAlive();
    await run(["cp", `${transfer}/.`, `${prepare}:/input/`]);
    const stopped = async (name: string) => {
      const state = JSON.parse(await run(["inspect", "--format", "{{json .State}}", name])) as { Running?: boolean; ExitCode?: number; OOMKilled?: boolean; Error?: string };
      demand(state.Running === false && state.ExitCode === 0 && state.OOMKilled === false && state.Error === "", "The isolated process did not complete successfully.");
    };
    await storageAlive();
    const preparedText = await run(["start", "--attach", prepare]);
    await stopped(prepare);
    const prepared = JSON.parse(preparedText.trim().split("\n").at(-1)!) as { tools: NodeToolVersions; tree: string };
    demand(/^[a-f0-9]{40}$/.test(prepared.tree) && (["bash", "git", "python", "node", "npm", "jq"] as const).every((name) => typeof prepared.tools[name] === "string" && prepared.tools[name].length > 0 && prepared.tools[name].length <= 512) && prepared.tools.jq.startsWith("jq-"), "Toolchain preparation evidence is invalid.");
    await run(["rm", "--force", prepare]); containers.splice(containers.indexOf(prepare), 1);
    await storageAlive();
    const phase = async (mode: "check" | "hook") => {
      await storageAlive();
      const name = `${id}-${mode}`;
      // npm's shebang and native dependency tools execute only from this writable dependency mount.
      await create(name, [...volume(data, "/input"), ...volume(source, "/repo"), ...volume(cache, "/pristine-cache"),
        ...tmpfs("/npm-cache", 512 * 1024 ** 2), ...tmpfs("/repo/project/node_modules", 512 * 1024 ** 2, true), ...tmpfs("/repo/project/dist", 128 * 1024 ** 2)], mode);
      const output = await run(["start", "--attach", name]);
      await stopped(name);
      await run(["rm", "--force", name]); containers.splice(containers.indexOf(name), 1);
      await storageAlive();
      return redactPublicText(output).value;
    };
    const evidence: NodeValidationEvidence = { profile: NODE_ISOLATION_PROFILE, image: NODE_ISOLATION_IMAGE, sourceSha256: frozen.sourceSha256, commitPlanSha256: frozen.commitPlanSha256,
      baseCommit: frozen.baseCommit, preparedTree: prepared.tree, hook: frozen.hook, tools: prepared.tools };
    report = frozen.phase === "prepared-hook"
      ? { ...evidence, phase: "prepared-hook", hookOutput: frozen.hook === "none" ? "" : await phase("hook") }
      : { ...evidence, phase: "final-check", candidateCommit: frozen.candidateCommit, checkOutput: await phase("check") };
    await storageAlive();
  } catch (error) { failure = operationTimedOut ? new IsolationError("Isolated operation timed out.") : options.signal?.aborted ? new IsolationError("Isolated validation was cancelled.") : error; }
  finally {
    clearTimeout(operationTimer); options.signal?.removeEventListener("abort", cancel);
    let cleanupFailed = false;
    // Independent cleanup budget ensures an output-limit failure cannot prevent container removal.
    for (const name of containers.reverse()) try { await command(executable, ["rm", "--force", name], home, { bytes: 0 }, 30_000); } catch { cleanupFailed = true; }
    for (const name of volumes.reverse()) try { await command(executable, ["volume", "rm", "--force", name], home, { bytes: 0 }, 30_000); } catch { cleanupFailed = true; }
    await rm(home, { recursive: true, force: true }).catch(() => { cleanupFailed = true; });
    if (cleanupFailed) failure = new IsolationError(`${failure instanceof Error ? failure.message : "Isolation run did not complete cleanly."} Cleanup failed; inspect Docker resources labeled bootstrap.isolation=${id}.`);
  }
  if (failure) throw new IsolationError(failure instanceof IsolationError ? failure.message : "Isolated preparation or validation failed.");
  demand(report, "No isolated validation evidence was produced."); return report;
}
