import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { boundedCommand, decode, demand, neutralEnvironment, PRLIMIT_ARGS, requireLinuxHost, trustedExecutable } from "./upgrade-host.js";
import { readRuntimePolicy, type RuntimePolicy } from "./upgrade-runtime-policy.js";
import { completeSignedCandidate, copyCandidateSigningRequest, describeCheckedCandidate, discardCandidateHook, discardCheckedCandidate,
  type CheckedCandidate, type PreparedHookTicket } from "./upgrade-validation.js";

type AuthorizedSignature = Readonly<{ policy: RuntimePolicy; principal: string; publicKey: string; publicKeySha256: string;
  commitPlanSha256: string; repositoryId: number; signal?: AbortSignal }>;
const signatures = new WeakMap<CheckedCandidate, AuthorizedSignature>();
const consumed = new WeakSet<PreparedHookTicket>();
const sha = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
async function keyMetadata(file: string): Promise<string> {
  demand(await realpath(file) === file);
  for (let current = file; ; current = path.dirname(current)) {
    const info = await lstat(current);
    demand((info.uid === 0 || info.uid === process.getuid?.()) && !(info.mode & (current === file ? 0o077 : 0o022)) &&
      (current === file ? info.isFile() && info.nlink === 1 && info.size > 0 && info.size <= 16384 : info.isDirectory()));
    if (current === file) demand(!(info.mode & 0o111));
    if (current === path.dirname(current)) break;
  }
  const info = await lstat(file); return `${info.dev}:${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`;
}
/** The only private-key consumer: fixed explicit reference, neutral environment, no agent or default key search. */
export async function signCandidateHook(ticket: PreparedHookTicket, policy: RuntimePolicy, options: { signal?: AbortSignal } = {}): Promise<CheckedCandidate> {
  const parent = options.signal; const signal = AbortSignal.any([AbortSignal.timeout(90_000), ...(parent ? [parent] : [])]); signal.throwIfAborted();
  const runtime = readRuntimePolicy(policy); const selected = runtime.projection.signing;
  if (!selected) throw new Error("Authorized fleet signer is not configured.");
  const request = copyCandidateSigningRequest(ticket); const publicKey = selected.publicKey + "\n";
  demand(runtime.projection.repositories.some((repo) => repo.id === request.repositoryId && repo.repository === request.repository) &&
    publicKey === request.publicKey && !consumed.has(ticket)); consumed.add(ticket);
  let directory: string | undefined; let handedOff = false; let checked: CheckedCandidate | undefined;
  try {
    const tools = await requireLinuxHost(); const executable = await trustedExecutable("/usr/bin/ssh-keygen");
    const key = `/etc/bootstrap/fleet-signers/${selected.keyReference}.key`; const before = await keyMetadata(key);
    signal.throwIfAborted(); readRuntimePolicy(policy);
    directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-trusted-signing-")); const empty = path.join(directory, "empty"); await mkdir(empty);
    const signature = await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, executable, "-Y", "sign", "-f", key, "-n", "git"],
      { cwd: directory, env: neutralEnvironment(empty, directory), signal, input: request.unsignedCommit, output: 16384 });
    demand(await keyMetadata(key) === before); signal.throwIfAborted(); readRuntimePolicy(policy);
    const armor = decode(signature); demand(/^-----BEGIN SSH SIGNATURE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END SSH SIGNATURE-----\n$/.test(armor));
    const unsigned = decode(request.unsignedCommit); const boundary = unsigned.indexOf("\n\n"); demand(boundary > 0);
    const lines = armor.trimEnd().split("\n"); const raw = Buffer.from(unsigned.slice(0, boundary) + "\ngpgsig " + lines[0] + "\n" +
      lines.slice(1).map((line) => " " + line).join("\n") + unsigned.slice(boundary));
    await rm(directory, { recursive: true, force: true }); directory = undefined; signal.throwIfAborted(); readRuntimePolicy(policy);
    // The ticket owns the longer final-validation deadline; the key/signing budget ends at this handoff.
    handedOff = true; checked = await completeSignedCandidate(ticket, raw);
    const facts = describeCheckedCandidate(checked);
    demand(facts.repositoryId === request.repositoryId && facts.repository === request.repository && facts.baseCommit === request.baseCommit &&
      facts.sourceSha256 === request.sourceSha256 && facts.preparedTree === request.preparedTree &&
      facts.commitPlanSha256 === request.commitPlanSha256 && facts.publicKeySha256 === sha(Buffer.from(publicKey)));
    parent?.throwIfAborted(); readRuntimePolicy(policy);
    signatures.set(checked, Object.freeze({ policy, principal: selected.principal, publicKey, publicKeySha256: facts.publicKeySha256,
      repositoryId: facts.repositoryId, commitPlanSha256: facts.commitPlanSha256, ...(parent ? { signal: parent } : {}) }));
    const result = checked; checked = undefined; return result;
  } finally {
    if (checked) discardCheckedCandidate(checked);
    if (directory) await rm(directory, { recursive: true, force: true });
    if (!handedOff) await discardCandidateHook(ticket);
  }
}
export function readAuthorizedSignature(candidate: CheckedCandidate, policy: RuntimePolicy): AuthorizedSignature {
  const owned = signatures.get(candidate); demand(owned && owned.policy === policy);
  owned.signal?.throwIfAborted(); const runtime = readRuntimePolicy(policy); const facts = describeCheckedCandidate(candidate);
  demand(runtime.projection.signing?.principal === owned.principal && runtime.projection.signing.publicKey + "\n" === owned.publicKey &&
    facts.repositoryId === owned.repositoryId && facts.commitPlanSha256 === owned.commitPlanSha256 && facts.publicKeySha256 === owned.publicKeySha256);
  return owned;
}
