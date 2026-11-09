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
async function provider(): Promise<{ gh: string; python: string; config: string }> {
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
  const python = await trustedExecutable("/usr/bin/python3"); demand(["/usr/bin/gh", "/usr/local/bin/gh"].includes(gh));
  return { gh, python, config };
}
// This file contains public paths and fixed code only, never credential bytes.
function credentialWrapper(gh: string, repository: string, env: NodeJS.ProcessEnv, cwd: string): string {
  const config = JSON.stringify({ gh, expected: ["protocol=https", "host=github.com", "path=" + repository + ".git"], env, cwd });
  return String.raw`import json
import os
import re
import selectors
import subprocess
import sys
import time

CONFIG = json.loads(${JSON.stringify(config)})


def request():
    if len(sys.argv) != 2 or sys.argv[1] != "get":
        raise ValueError()
    raw = bytearray()
    while True:
        block = os.read(0, min(4096, 8193 - len(raw)))
        if not block:
            break
        if len(raw) + len(block) > 8192:
            raise ValueError()
        raw.extend(block)
    text = bytes(raw).decode("utf-8-sig", "strict")
    if not text.endswith("\n") or "\r" in text:
        raise ValueError()
    entries = text[:-(2 if text.endswith("\n\n") else 1)].split("\n")
    capabilities = set()
    while entries and entries[0].startswith("capability[]="):
        item = entries.pop(0)
        if item not in ("capability[]=authtype", "capability[]=state") or item in capabilities:
            raise ValueError()
        capabilities.add(item)
    if len(entries) != 3 or not all(entries.count(item) == 1 for item in CONFIG["expected"]):
        raise ValueError()
    return ("\n".join(CONFIG["expected"]) + "\n").encode("utf-8")


def provider(payload):
    deadline = time.monotonic() + 30
    child = subprocess.Popen([CONFIG["gh"], "auth", "git-credential", "get"],
                             cwd=CONFIG["cwd"], env=CONFIG["env"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             bufsize=0, close_fds=True)
    try:
        output = bytearray()
        combined = 0
        written = 0
        with selectors.DefaultSelector() as selector:
            for stream, event, kind in ((child.stdin, selectors.EVENT_WRITE, "input"),
                                        (child.stdout, selectors.EVENT_READ, "output"),
                                        (child.stderr, selectors.EVENT_READ, "error")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event, kind)
            while selector.get_map() or child.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                for key, _ in selector.select(min(0.1, remaining)):
                    if key.data == "input":
                        try:
                            size = os.write(key.fd, payload[written:written + 4096])
                        except BlockingIOError:
                            continue
                        if size <= 0:
                            raise ValueError()
                        written += size
                        if written == len(payload):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        try:
                            block = os.read(key.fd, min(4096, 16385 - combined))
                        except BlockingIOError:
                            continue
                        if not block:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        combined += len(block)
                        if combined > 16384 or key.data == "error":
                            raise ValueError()
                        output.extend(block)
        if written != len(payload) or child.returncode != 0:
            raise ValueError()
        return bytes(output)
    finally:
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except OSError:
                pass
        if child.poll() is None:
            try:
                child.kill()
            except ProcessLookupError:
                pass
        child.wait(timeout=1)


def main():
    output = provider(request())
    text = output.decode("utf-8-sig", "strict")
    fields = text[:-1].split("\n") if text.endswith("\n") else []
    if len(fields) != 4 or fields[0] != "protocol=https" or fields[1] != "host=github.com":
        raise ValueError()
    if re.fullmatch(r"username=[A-Za-z0-9][A-Za-z0-9-]{0,38}", fields[2]) is None or not fields[3].startswith("password="):
        raise ValueError()
    password = fields[3][9:]
    spaces = {0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF} | set(range(0x2000, 0x200B))
    if not 1 <= len(password.encode("utf-16-le")) // 2 <= 4096:
        raise ValueError()
    if any(ord(value) < 0x20 or ord(value) == 0x7F or ord(value) in spaces for value in password):
        raise ValueError()
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        os._exit(1)
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
    state.directory = await mkdtemp(path.join(context.directory, "publication-")); const helper = path.join(state.directory, "credential.py");
    const env = { ...neutralEnvironment(state.directory, state.directory), GH_CONFIG_DIR: selected.config, GH_HOST: "github.com", GH_PROMPT_DISABLED: "1", GH_NO_UPDATE_NOTIFIER: "1", GH_NO_EXTENSION_UPDATE_NOTIFIER: "1", GH_TELEMETRY: "0" };
    await writeFile(helper, credentialWrapper(selected.gh, repository.repository, env, state.directory), { flag: "wx", mode: 0o600 });
    const run = async (executable: string, args: readonly string[], environment: NodeJS.ProcessEnv, input?: Uint8Array): Promise<Buffer> => {
      const pending = boundedCommand(context.prlimit, [...PRLIMIT_ARGS, executable, ...args], { cwd: context.directory, env: environment, signal: context.signal, ...(input ? { input } : {}) });
      context.pending.add(pending); try { return await pending; } finally { context.pending.delete(pending); }
    };
    const api = async (endpoint: string, input?: unknown): Promise<unknown> => JSON.parse(decode(await run(selected.gh,
      ["api", "--hostname", "github.com", "--method", input ? "POST" : "GET", "--header", "Accept: application/vnd.github+json", "--header", "X-GitHub-Api-Version: 2026-03-10", endpoint, ...(input ? ["--input", "-"] : [])], env, input ? Buffer.from(JSON.stringify(input)) : undefined)));
    demand(context.candidate === candidate && context.signedBranch === branch && context.signedPlanSha256 === signedPlan); phase = "push"; push = "uncertain";
    const pushed = decode(await run(context.git, gitArguments(context, ["-c", `credential.https://github.com/${repository.repository}.git.helper=!${quote(selected.python)} -I -S ${quote(helper)}`,
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
