import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseDocument } from "yaml";

import { HOST_LIMITS, PRLIMIT_ARGS, boundedCommand, decode, demand, hostFailure, neutralEnvironment, readRegular, trustedExecutable } from "./upgrade-host.js";
import { gitArguments, transportContext, type PublicRepository, type TransportContext } from "./upgrade-transport.js";

type Phase = "provider" | "push" | "confirm" | "create" | "readback" | "cleanup";
export type PublicationResult = Readonly<{
  repository: string; candidate: string; branch: string; ref: string; recoveryDirectory: string;
  push: "not-attempted" | "uncertain" | "confirmed"; pullRequestUrl?: string;
} & ({ ok: true; phase: "complete" } | { ok: false; phase: Phase; cleanupFailed?: true })>;
interface Recovery { directory?: string; lease?: ReturnType<TransportContext["reserve"]> }
const recoveries = new WeakMap<PublicRepository, Recovery>();
function record(value: unknown): Record<string, unknown> { demand(value && typeof value === "object" && !Array.isArray(value)); return value as Record<string, unknown>; }
function keys(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  const result = record(value); demand(Object.keys(result).every((key) => allowed.includes(key))); return result;
}
function yaml(bytes: Uint8Array): Record<string, unknown> {
  const document = parseDocument(decode(bytes), { schema: "failsafe", uniqueKeys: true });
  demand(!document.errors.length && !document.warnings.length); return record(document.toJS({ maxAliasCount: 0 }));
}
async function provider(): Promise<{ gh: string; node: string; config: string }> {
  demand(["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "GH_PATH"].every((key) => !process.env[key]));
  const home = os.userInfo().homedir; demand(!process.env.HOME || path.resolve(process.env.HOME) === home);
  const config = path.join(home, ".config/gh"); const settings = keys(yaml(await readRegular(path.join(config, "config.yml"), 65536, true)), ["version", "git_protocol", "prompt", "editor", "browser", "pager"]);
  demand(Object.values(settings).every((value) => typeof value === "string") && ["editor", "browser", "pager"].every((key) => !settings[key]) &&
    (!settings.git_protocol || settings.git_protocol === "https") && (!settings.version || settings.version === "1") && (!settings.prompt || ["enabled", "disabled"].includes(String(settings.prompt))));
  const hosts = keys(yaml(await readRegular(path.join(config, "hosts.yml"), 65536, true)), ["github.com"]);
  const selected = keys(hosts["github.com"], ["user", "oauth_token", "git_protocol", "users"]);
  demand(typeof selected.user === "string" && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(selected.user) && (!selected.git_protocol || selected.git_protocol === "https"));
  const token = (value: unknown) => typeof value === "string" && /^[^\s\x00-\x1f\x7f]{1,4096}$/.test(value);
  demand(token(selected.oauth_token));
  if (selected.users !== undefined) {
    const users = record(selected.users); demand(Object.keys(users).length <= 64);
    for (const value of Object.values(users)) demand(token(keys(value, ["oauth_token"]).oauth_token));
    demand(record(users[selected.user]).oauth_token === selected.oauth_token);
  }
  const gh = await trustedExecutable("/usr/bin/gh").catch(() => trustedExecutable("/usr/local/bin/gh"));
  const node = await trustedExecutable("/usr/bin/node"); demand(["/usr/bin/gh", "/usr/local/bin/gh"].includes(gh) && node === "/usr/bin/node");
  return { gh, node, config };
}
// This file contains public paths and fixed code only, never credential bytes.
function credentialWrapper(gh: string, repository: string, env: NodeJS.ProcessEnv, cwd: string): string {
  return `"use strict";
const { spawnSync } = require("node:child_process");
if (process.argv.length !== 3 || process.argv[2] !== "get") process.exit(1);
let size = 0; const chunks = [];
process.stdin.on("data", chunk => { size += chunk.length; if (size > 8192) process.exit(1); chunks.push(chunk); });
process.stdin.on("error", () => process.exit(1));
process.stdin.on("end", () => {
  const raw = Buffer.concat(chunks); let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(raw); } catch { process.exit(1); }
  if (!text.endsWith("\\n") || text.includes("\\r")) process.exit(1);
  const entries = text.slice(0, text.endsWith("\\n\\n") ? -2 : -1).split("\\n"); const expected = ${JSON.stringify(["protocol=https", "host=github.com", `path=${repository}.git`])};
  const capabilities = new Set();
  while (entries[0] && entries[0].startsWith("capability[]=")) {
    const item = entries.shift(); if (!["capability[]=authtype", "capability[]=state"].includes(item) || capabilities.has(item)) process.exit(1); capabilities.add(item);
  }
  if (entries.length !== 3 || !expected.every(line => entries.filter(entry => entry === line).length === 1)) process.exit(1);
  const result = spawnSync(${JSON.stringify(gh)}, ["auth", "git-credential", "get"], { cwd: ${JSON.stringify(cwd)}, env: ${JSON.stringify(env)}, input: Buffer.from(expected.join("\\n") + "\\n"), timeout: 30000, maxBuffer: 16384, windowsHide: true });
  if (result.error || result.signal || result.status !== 0 || !result.stdout || result.stdout.length > 16384 || result.stderr.length) process.exit(1);
  let output; try { output = new TextDecoder("utf-8", { fatal: true }).decode(result.stdout); } catch { process.exit(1); }
  const fields = output.endsWith("\\n") ? output.slice(0, -1).split("\\n") : [];
  if (fields.length !== 4 || fields[0] !== "protocol=https" || fields[1] !== "host=github.com" || !/^username=[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(fields[2]) || !/^password=[^\\s\\x00-\\x1f\\x7f]{1,4096}$/.test(fields[3])) process.exit(1);
  process.stdout.write(result.stdout);
});
`;
}
const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
function verifyPullRequest(value: unknown, repository: PublicRepository, candidate: string, branch: string, url: string): void {
  const pr = record(value); const base = record(pr.base); const head = record(pr.head);
  demand(Number.isSafeInteger(pr.number) && url === `https://github.com/${repository.repository}/pull/${pr.number}` && pr.html_url === url && pr.state === "open" && pr.draft === true && base.ref === repository.defaultBranch && base.sha === repository.baseCommit &&
    record(base.repo).full_name === repository.repository && head.ref === branch && head.sha === candidate && record(head.repo).full_name === repository.repository);
}
export async function finishRecovery(repository: PublicRepository): Promise<void> {
  try {
    const state = recoveries.get(repository); demand(state);
    if (state.directory) {
      const directory = state.directory; demand(state.lease);
      await state.lease.releaseAfterCleanup(() => rm(directory, { recursive: true, force: true })); delete state.directory; delete state.lease;
    }
  } catch { throw hostFailure(); }
}
export async function publishCandidate(repository: PublicRepository, candidate: string, branch: string, title: string, body: string): Promise<PublicationResult> {
  const context = transportContext(repository);
  const signedPlan = context.signedPlanSha256;
  demand(context.candidate === candidate && context.signedBranch === branch && typeof signedPlan === "string" && /^[a-f0-9]{64}$/.test(signedPlan) &&
    /^[a-f0-9]{40}$/.test(candidate) && !recoveries.has(repository) && branch.length <= 255 &&
    /^codex\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(branch) && !branch.includes("..") && !branch.includes("//") &&
    branch.split("/").every((part) => part.length > 0 && !part.startsWith(".") && !part.endsWith(".") && !part.endsWith(".lock")) &&
    title.trim().length > 0 && Buffer.byteLength(title) <= 256 && !/[\x00-\x1f\x7f]/.test(title) &&
    body.length > 0 && Buffer.byteLength(body) <= 65536 && !body.includes("\0") && Buffer.from(body).toString() === body);
  const state: Recovery = {}; recoveries.set(repository, state);
  const ref = `refs/heads/${branch}`; let phase: Phase = "provider"; let push: PublicationResult["push"] = "not-attempted"; let pullRequestUrl: string | undefined; let complete = false; let cleanupFailed = false;
  try {
    const selected = await provider(); state.lease = context.reserve(4 * HOST_LIMITS.output);
    state.directory = await mkdtemp(path.join(context.directory, "publication-")); const helper = path.join(state.directory, "credential.cjs");
    const env = { ...neutralEnvironment(state.directory, state.directory), GH_CONFIG_DIR: selected.config, GH_HOST: "github.com", GH_PROMPT_DISABLED: "1", GH_NO_UPDATE_NOTIFIER: "1", GH_NO_EXTENSION_UPDATE_NOTIFIER: "1", GH_TELEMETRY: "0" };
    await writeFile(helper, credentialWrapper(selected.gh, repository.repository, env, state.directory), { flag: "wx", mode: 0o600 });
    const run = async (executable: string, args: readonly string[], environment: NodeJS.ProcessEnv, input?: Uint8Array): Promise<Buffer> => {
      const pending = boundedCommand(context.prlimit, [...PRLIMIT_ARGS, executable, ...args], { cwd: context.directory, env: environment, signal: context.signal, ...(input ? { input } : {}) });
      context.pending.add(pending); try { return await pending; } finally { context.pending.delete(pending); }
    };
    const api = async (endpoint: string, input?: unknown): Promise<unknown> => JSON.parse(decode(await run(selected.gh,
      ["api", "--hostname", "github.com", "--method", input ? "POST" : "GET", "--header", "Accept: application/vnd.github+json", "--header", "X-GitHub-Api-Version: 2026-03-10", endpoint, ...(input ? ["--input", "-"] : [])], env, input ? Buffer.from(JSON.stringify(input)) : undefined)));
    demand(context.candidate === candidate && context.signedBranch === branch && context.signedPlanSha256 === signedPlan); phase = "push"; push = "uncertain";
    const pushed = decode(await run(context.git, gitArguments(context, ["-c", `credential.https://github.com/${repository.repository}.git.helper=!${quote(selected.node)} ${quote(helper)}`,
      "-c", `credential.https://github.com/${repository.repository}.git.useHttpPath=true`, "push", "--atomic", "--porcelain", "--no-verify", "--recurse-submodules=no", `--force-with-lease=${ref}:`, "--", `https://github.com/${repository.repository}.git`, `${candidate}:${ref}`]),
    { ...env, GIT_DIR: context.gitdir, GIT_WORK_TREE: context.root, GIT_EXEC_PATH: context.execPath }));
    // Git skips lease evaluation for an already identical, up-to-date ref.
    const updates = pushed.split("\n").filter((line) => line.includes("\t")); demand(updates.length === 1 && updates[0] === `*\t${candidate}:${ref}\t[new branch]`);
    phase = "confirm"; const remote = record(await api(`/repos/${repository.repository}/git/ref/heads/${encodeURIComponent(branch)}`));
    demand(remote.ref === ref && record(remote.object).type === "commit" && record(remote.object).sha === candidate); push = "confirmed";
    phase = "create"; const created = record(await api(`/repos/${repository.repository}/pulls`, { head: branch, base: repository.defaultBranch, title, body, draft: true, maintainer_can_modify: false }));
    demand(Number.isSafeInteger(created.number) && Number(created.number) > 0 && created.html_url === `https://github.com/${repository.repository}/pull/${created.number}`);
    const createdUrl = created.html_url as string; verifyPullRequest(created, repository, candidate, branch, createdUrl); pullRequestUrl = createdUrl;
    phase = "readback"; verifyPullRequest(await api(`/repos/${repository.repository}/pulls/${created.number}`), repository, candidate, branch, pullRequestUrl); complete = true;
  } catch { /* The exact public candidate/ref and verified URL survive every partial failure. */ }
  try { await finishRecovery(repository); } catch { cleanupFailed = true; if (complete) phase = "cleanup"; complete = false; }
  const recovery = { repository: repository.repository, candidate, branch, ref, recoveryDirectory: context.directory, push, ...(pullRequestUrl ? { pullRequestUrl } : {}) };
  return Object.freeze(complete ? { ...recovery, ok: true, phase: "complete" } : { ...recovery, ok: false, phase, ...(cleanupFailed ? { cleanupFailed: true as const } : {}) });
}
