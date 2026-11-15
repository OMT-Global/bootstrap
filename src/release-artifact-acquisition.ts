import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { lstat, mkdtemp, open, readFile, realpath, rm } from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import { immutablePreflightVerifierScript } from "./archetypes.js";
import { type ReviewedReleaseManifest, reviewedReleaseSelectors } from "./release-approval.js";
import { reviewedPreflightEnvironment } from "./release-reviewed-preflight.js";

const hex = /^[0-9a-f]{64}$/;
const hash = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");

async function pinnedExecutable(executable: string, expected: string): Promise<void> {
  if (!path.isAbsolute(executable) || !hex.test(expected) || await realpath(executable) !== executable) throw new Error();
  const file = await open(executable, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.size < 1 || before.size > 256 * 1024 * 1024 || !(before.mode & 0o111)) throw new Error();
    const bytes = await file.readFile();
    const after = await file.stat();
    if (bytes.length !== before.size || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || hash(bytes) !== expected) throw new Error();
  } finally { await file.close(); }
}

async function invoke(python: string, ghDirectory: string, environment: Record<string, string>, token: string, scratch: string, profile: "preflight" | "validation" = "preflight"): Promise<string> {
  return await new Promise((resolve, reject) => {
    const child = spawn(python, ["-I", "-S", "-"], { detached: true, stdio: ["pipe", "pipe", "pipe"],
      env: { ...environment, PATH: `${ghDirectory}:/usr/bin:/bin`, HOME: scratch, GH_CONFIG_DIR: scratch,
        GH_PROMPT_DISABLED: "1", GH_TOKEN: token, RUNNER_TEMP: scratch } });
    let output = ""; let bytes = 0; let failed = false;
    const stop = () => { failed = true; if (child.pid) { try { process.kill(-child.pid, "SIGKILL"); } catch {} } };
    const timeout = setTimeout(stop, 120_000);
    child.stdout.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 8192) stop(); else output += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 8192) stop(); });
    child.on("error", () => { clearTimeout(timeout); stop(); reject(new Error()); });
    child.stdin.on("error", () => {});
    child.on("close", (code, signal) => { clearTimeout(timeout); if (code !== 0 || signal || failed) { stop(); reject(new Error()); } else resolve(output); });
    child.stdin.end(immutablePreflightVerifierScript(profile));
  });
}

/**
 * Acquisition used by the trusted retry runtime. The caller must run in a protected POSIX
 * environment, authenticate the read-only token and reviewed observation, pin
 * immutable trusted executables, independently verify the workflow and target,
 * and recheck approval before publication. Same-user filesystem/process races,
 * executable replacement, network isolation and provenance beyond the verifier
 * are not established by this adapter.
 */
export async function acquireReviewedPreflight(input: {
  reviewed: ReviewedReleaseManifest; token: string; pythonPath: string; pythonSha256: string;
  ghPath: string; ghSha256: string; runtimeDir: string; maxAssetBytes: number;
  maxArchiveBytes: number; maxExpandedBytes: number; maxMembers: number;
}): Promise<{ assets: readonly { name: string; bytes: Uint8Array }[]; evidence: Readonly<{ version: string; channel: string; targetCommit: string; runId: string; attempt: string }> }> {
  let scratch = "";
  try {
    input = { ...input };
    if (process.platform === "win32" || !path.isAbsolute(input.runtimeDir) || path.basename(input.ghPath) !== "gh" ||
        !/^[\x21-\x7e]{1,4096}$/.test(input.token) || !Number.isSafeInteger(input.maxAssetBytes) ||
        input.maxAssetBytes < 1 || input.maxAssetBytes > 256 * 1024 * 1024 ||
        !Number.isSafeInteger(input.maxArchiveBytes) || input.maxArchiveBytes < 1 || input.maxArchiveBytes > 1024 ** 3 ||
        !Number.isSafeInteger(input.maxExpandedBytes) || input.maxExpandedBytes < 1 || input.maxExpandedBytes > 2 * 1024 ** 3 ||
        !Number.isSafeInteger(input.maxMembers) || input.maxMembers < 1 || input.maxMembers > 10000) throw new Error();
    const selection = reviewedReleaseSelectors(input.reviewed);
    const total = selection.assets.reduce((sum, asset) => sum + asset.size, 0);
    if (!Number.isSafeInteger(total) || total > input.maxAssetBytes) throw new Error();
    await pinnedExecutable(input.pythonPath, input.pythonSha256);
    await pinnedExecutable(input.ghPath, input.ghSha256);
    scratch = await mkdtemp(path.join(await realpath(input.runtimeDir), "bootstrap-approved-acquisition-"));
    const output = await invoke(input.pythonPath, path.dirname(input.ghPath), { ...reviewedPreflightEnvironment(input.reviewed),
      PREFLIGHT_MAX_ARCHIVE_BYTES: String(input.maxArchiveBytes), PREFLIGHT_MAX_EXPANDED_BYTES: String(input.maxExpandedBytes),
      PREFLIGHT_MAX_MEMBERS: String(input.maxMembers) }, input.token, scratch);
    if (!/^\/[^\n\r]+\n$/.test(output)) throw new Error();
    const root = output.slice(0, -1);
    const relative = path.relative(scratch, root).split(path.sep);
    if (relative.length !== 2 || !relative[0]?.startsWith("release-approved-") || relative[1] !== "files" ||
        await realpath(root) !== root || !(await lstat(root)).isDirectory()) throw new Error();
    const inventoryPath = path.join(path.dirname(root), "verified-files.json");
    const inventoryInfo = await lstat(inventoryPath);
    if (!inventoryInfo.isFile() || inventoryInfo.size > 1024 * 1024) throw new Error();
    const inventory = JSON.parse(await readFile(inventoryPath, "utf8")) as unknown;
    if (!inventory || typeof inventory !== "object" || Array.isArray(inventory)) throw new Error();
    const entries = Object.entries(inventory);
    const assets: { name: string; bytes: Uint8Array }[] = [];
    for (const asset of selection.assets) {
      const matches = entries.filter(([name]) => path.posix.basename(name) === asset.name);
      if (matches.length !== 1 || matches[0]![1] !== asset.sha256) throw new Error();
      const name = matches[0]![0];
      if (name.startsWith("/") || name.split("/").some((part) => !part || part === "." || part === "..") || name.includes("\\")) throw new Error();
      const filePath = path.join(root, ...name.split("/"));
      if (await realpath(filePath) !== filePath) throw new Error();
      const file = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const before = await file.stat();
        if (!before.isFile() || before.nlink !== 1 || before.size !== asset.size || before.size > input.maxAssetBytes) throw new Error();
        const data = await file.readFile();
        const after = await file.stat();
        if (data.length !== asset.size || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || hash(data) !== asset.sha256) throw new Error();
        assets.push({ name: asset.name, bytes: data });
      } finally { await file.close(); }
    }
    const evidenceHash = (inventory as Record<string, unknown>)["release-evidence.json"];
    if (typeof evidenceHash !== "string" || !hex.test(evidenceHash)) throw new Error();
    const evidenceFile = await open(path.join(root, "release-evidence.json"), constants.O_RDONLY | constants.O_NOFOLLOW);
    let evidenceBytes: Buffer;
    try {
      const before = await evidenceFile.stat();
      if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > 65536) throw new Error();
      evidenceBytes = await evidenceFile.readFile();
      const after = await evidenceFile.stat();
      if (evidenceBytes.length !== before.size || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || hash(evidenceBytes) !== evidenceHash) throw new Error();
    } finally { await evidenceFile.close(); }
    const evidenceText = new TextDecoder("utf-8", { fatal: true }).decode(evidenceBytes);
    const yaml = YAML.parseDocument(evidenceText, { uniqueKeys: true, schema: "json" });
    if (yaml.errors.length) throw new Error();
    const evidence = JSON.parse(evidenceText) as Record<string, unknown>;
    if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) || evidence.schema_version !== 1 ||
        evidence.repo !== selection.repository || evidence.version !== selection.version || evidence.channel !== selection.channel ||
        evidence.target_sha !== selection.targetCommit || evidence.preflight_run_id !== selection.runId || evidence.run_attempt !== selection.attempt ||
        !evidence.checks || typeof evidence.checks !== "object" || Array.isArray(evidence.checks)) throw new Error();
    const checks = evidence.checks as Record<string, unknown>;
    if (checks.prep !== "passed" || checks.preflight !== "passed" || checks.build !== "passed") throw new Error();
    if (reviewedReleaseSelectors(input.reviewed).manifestSha256 !== selection.manifestSha256) throw new Error();
    await pinnedExecutable(input.pythonPath, input.pythonSha256);
    await pinnedExecutable(input.ghPath, input.ghSha256);
    return { assets, evidence: Object.freeze({ version: selection.version, channel: selection.channel,
      targetCommit: selection.targetCommit, runId: selection.runId, attempt: selection.attempt }) };
  } catch {
    throw new Error("Reviewed artifact acquisition unavailable.");
  } finally {
    if (scratch) { try { await rm(scratch, { recursive: true, force: true }); } catch { throw new Error("Reviewed artifact acquisition unavailable."); } }
  }
}

/** Compatibility helper; evidence-aware callers should use acquireReviewedPreflight. */
export async function acquireReviewedArtifact(input: Parameters<typeof acquireReviewedPreflight>[0]): Promise<readonly { name: string; bytes: Uint8Array }[]> {
  return (await acquireReviewedPreflight(input)).assets;
}

/** Trusted provider-selected validation artifact; no target files are extracted outside
 * the private bounded verifier tree. Workflow/run/artifact metadata is rechecked by its caller. */
export async function acquireValidationEvidence(input: {
  repository: string; repositoryId: string; runId: string; attempt: string; artifactId: string; archiveSha256: string; targetCommit: string;
  token: string; pythonPath: string; pythonSha256: string; ghPath: string; ghSha256: string; runtimeDir: string;
}): Promise<void> {
  let scratch = "";
  try {
    input = { ...input };
    if (process.platform === "win32" || !path.isAbsolute(input.runtimeDir) || path.basename(input.ghPath) !== "gh" ||
        typeof input.token !== "string" || !/^[\x21-\x7e]{1,4096}$/.test(input.token)) throw new Error();
    await pinnedExecutable(input.pythonPath, input.pythonSha256); await pinnedExecutable(input.ghPath, input.ghSha256);
    scratch = await mkdtemp(path.join(await realpath(input.runtimeDir), "bootstrap-validation-acquisition-"));
    const output = await invoke(input.pythonPath, path.dirname(input.ghPath), {
      GITHUB_REPOSITORY: input.repository, GITHUB_REPOSITORY_ID: input.repositoryId, PREFLIGHT_RUN_ID: input.runId,
      PREFLIGHT_APPROVED_ATTEMPT: input.attempt, PREFLIGHT_ARTIFACT_ID: input.artifactId, PREFLIGHT_ARTIFACT_SHA256: input.archiveSha256,
      PREFLIGHT_TARGET_SHA: input.targetCommit, PREFLIGHT_MAX_ARCHIVE_BYTES: "1048576", PREFLIGHT_MAX_EXPANDED_BYTES: "65536", PREFLIGHT_MAX_MEMBERS: "1"
    }, input.token, scratch, "validation");
    if (!/^\/[^\n\r]+\n$/.test(output)) throw new Error();
    const root = output.slice(0, -1); const relative = path.relative(scratch, root).split(path.sep);
    if (relative.length !== 2 || !relative[0]?.startsWith("release-approved-") || relative[1] !== "files" || await realpath(root) !== root) throw new Error();
    await pinnedExecutable(input.pythonPath, input.pythonSha256); await pinnedExecutable(input.ghPath, input.ghSha256);
  } catch { throw new Error("Bounded full-validation evidence unavailable."); }
  finally { if (scratch) await rm(scratch, { recursive: true, force: true }); }
}
