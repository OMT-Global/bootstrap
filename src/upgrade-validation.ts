import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";

import { freezeNodeValidation, ISOLATION_LIMITS, NODE_ISOLATION_IMAGE, NODE_ISOLATION_PROFILE, type FrozenNodeInput, type PlannedGitIdentity } from "./isolation/node-profile.js";
import { validateIsolatedNode, type NodeValidationReport } from "./isolation/node-validation.js";
import { acquirePreparedHistory, bundleSignedCandidate, copyPreparedHistoryBundle, discardPreparedHistory, type PreparedHistory } from "./upgrade-history.js";
import { boundedCommand, decode, demand, neutralEnvironment, PRLIMIT_ARGS, requireLinuxHost, trustedExecutable } from "./upgrade-host.js";
import { copyPreparedUpgradeSource, describePreparedUpgrade, type PreparedUpgrade } from "./upgrade-preparation.js";

export interface CandidateCommitPlan {
  branch: string; commitMessage: string; author: PlannedGitIdentity; committer: PlannedGitIdentity; hook: "none" | ".githooks/pre-commit";
  /** Public metadata selected by the trusted caller; it grants no signing authority. */
  publicKey: string;
}
declare const hookBrand: unique symbol;
export type PreparedHookTicket = { readonly [hookBrand]: true };
declare const checkedBrand: unique symbol;
export type CheckedCandidate = { readonly [checkedBrand]: true };
interface HookData {
  candidate: PreparedUpgrade; history: PreparedHistory; input: FrozenNodeInput; key: string; unsigned: Buffer;
  hook: NodeValidationReport; signal: AbortSignal; parent?: AbortSignal; busy: boolean; cleanupOnly: boolean; historyClosed: boolean;
}
interface CheckedData { facts: CheckedCandidateFacts; bundle: Buffer; parent?: AbortSignal }
export interface CheckedCandidateFacts {
  readonly repository: string; readonly repositoryId: number;
  readonly baseCommit: string; readonly candidateCommit: string; readonly preparedTree: string; readonly sourceSha256: string;
  readonly commitPlanSha256: string; readonly publicKeySha256: string; readonly branch: string;
  readonly hook: "completed"; readonly signature: "verified"; readonly finalCheck: "completed";
  readonly signerAuthorization: "unverified"; readonly authority: "none"; readonly pilot: "unverified"; readonly independentReview: "pending"; readonly publication: "pending";
}
const hooks = new WeakMap<PreparedHookTicket, HookData>();
const checked = new WeakMap<CheckedCandidate, CheckedData>();
const failure = () => new Error("Candidate validation unavailable.");
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const sourceFiles = (input: FrozenNodeInput) => input.files.map(({ path, mode, bytes }) => ({ path, mode, bytes: Buffer.from(bytes) }));
function publicKey(text: string): string {
  demand(typeof text === "string" && text.length <= 1024);
  const match = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})\n?$/.exec(text); demand(match);
  const wire = Buffer.from(match[1]!, "base64");
  demand(wire.length === 51 && wire.toString("base64") === match[1] && wire.readUInt32BE(0) === 11 &&
    wire.subarray(4, 15).toString("ascii") === "ssh-ed25519" && wire.readUInt32BE(15) === 32);
  return `ssh-ed25519 ${match[1]}\n`;
}
function prefix(input: FrozenNodeInput, tree: string): string[] {
  return [`tree ${tree}`, `parent ${input.baseCommit}`, `author ${input.author.name} <${input.author.email}> ${input.author.date}`,
    `committer ${input.committer.name} <${input.committer.email}> ${input.committer.date}`];
}
function reportMatches(report: NodeValidationReport, input: FrozenNodeInput, tree: string): void {
  demand(report.profile === NODE_ISOLATION_PROFILE && report.image === NODE_ISOLATION_IMAGE && report.sourceSha256 === input.sourceSha256 &&
    report.commitPlanSha256 === input.commitPlanSha256 && report.baseCommit === input.baseCommit && report.preparedTree === tree && report.hook === input.hook && report.phase === input.phase);
  demand(["bash", "git", "python", "node", "npm", "jq"].every((name) => {
    const value = report.tools[name as keyof typeof report.tools]; return typeof value === "string" && value.length > 0 && value.length <= 512;
  }));
  if (input.phase === "final-check") demand(report.phase === "final-check" && report.candidateCommit === input.candidateCommit);
}
function active(ticket: PreparedHookTicket): HookData {
  const value = hooks.get(ticket); demand(value && !value.busy && !value.cleanupOnly); value.signal.throwIfAborted(); describePreparedUpgrade(value.candidate); return value;
}
/** The fixed backend is invoked here; caller-supplied pass booleans/reports are never accepted. */
export async function prepareCandidateHook(candidate: PreparedUpgrade, plan: CandidateCommitPlan, options: { signal?: AbortSignal } = {}): Promise<PreparedHookTicket> {
  let history: PreparedHistory | undefined;
  try {
    const parent = options.signal; demand(parent === undefined || parent instanceof AbortSignal);
    const signal = AbortSignal.any([AbortSignal.timeout(ISOLATION_LIMITS.operationMs), ...(parent ? [parent] : [])]);
    signal.throwIfAborted(); const facts = describePreparedUpgrade(candidate); const source = copyPreparedUpgradeSource(candidate);
    const selected = { branch: plan.branch, commitMessage: plan.commitMessage, author: { ...plan.author }, committer: { ...plan.committer }, hook: plan.hook };
    const key = publicKey(plan.publicKey);
    history = await acquirePreparedHistory(candidate, { signal });
    const input = freezeNodeValidation({ profile: NODE_ISOLATION_PROFILE, files: source.files, baseBundle: copyPreparedHistoryBundle(history, candidate),
      baseCommit: facts.baseCommit, ...selected, phase: "prepared-hook" });
    demand(input.sourceSha256 === facts.sourceSha256);
    const report = await validateIsolatedNode({ profile: input.profile, files: sourceFiles(input), baseBundle: input.baseBundle, baseCommit: input.baseCommit,
      branch: input.branch, commitMessage: input.commitMessage, author: input.author, committer: input.committer, hook: input.hook, phase: "prepared-hook" }, { signal });
    reportMatches(report, input, facts.tree); signal.throwIfAborted(); describePreparedUpgrade(candidate);
    const unsigned = Buffer.from(prefix(input, facts.tree).join("\n") + "\n\n" + input.commitMessage);
    const ticket = Object.freeze({}) as PreparedHookTicket;
    hooks.set(ticket, { candidate, history, input, key, unsigned, hook: report, signal, ...(parent ? { parent } : {}), busy: false, cleanupOnly: false, historyClosed: false }); history = undefined; return ticket;
  } catch { throw failure(); }
  finally { if (history) await discardPreparedHistory(history).catch(() => { throw failure(); }); }
}
/** Only available after the owned prepared-hook result. No key or agent is selected. */
export function copyCandidateSigningRequest(ticket: PreparedHookTicket): { unsignedCommit: Buffer; publicKey: string; commitPlanSha256: string } {
  try { const value = active(ticket); return { unsignedCommit: Buffer.from(value.unsigned), publicKey: value.key, commitPlanSha256: value.input.commitPlanSha256 }; }
  catch { throw failure(); }
}
async function verifySignature(value: HookData, raw: Buffer): Promise<void> {
  let directory: string | undefined;
  try {
    demand(raw.length <= ISOLATION_LIMITS.manifestBytes); const text = decode(raw); demand(Buffer.from(text).equals(raw) && !text.includes("\0"));
    const boundary = text.indexOf("\n\n"); demand(boundary > 0);
    const lines = text.slice(0, boundary).split("\n"); const expected = prefix(value.input, describePreparedUpgrade(value.candidate).tree);
    demand(expected.every((line, index) => lines[index] === line) && lines[4] === "gpgsig -----BEGIN SSH SIGNATURE-----" &&
      lines.at(-1) === " -----END SSH SIGNATURE-----" && lines.slice(5, -1).every((line) => /^ [A-Za-z0-9+/=]+$/.test(line)) && text.slice(boundary + 2) === value.input.commitMessage);
    const tools = await requireLinuxHost(); const ssh = await trustedExecutable("/usr/bin/ssh-keygen");
    directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-signature-")); const empty = path.join(directory, "empty"); await mkdir(empty);
    const allowed = path.join(directory, "allowed"); const signature = path.join(directory, "signature");
    await writeFile(allowed, `bootstrap-upgrade namespaces="git" ${value.key}`, { flag: "wx", mode: 0o600 });
    await writeFile(signature, lines.slice(4).map((line, index) => index ? line.slice(1) : line.slice(7)).join("\n") + "\n", { flag: "wx", mode: 0o600 });
    await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, ssh, "-Y", "verify", "-f", allowed, "-I", "bootstrap-upgrade", "-n", "git", "-s", signature],
      { cwd: directory, env: neutralEnvironment(empty, directory), signal: value.signal, input: value.unsigned });
    value.signal.throwIfAborted();
  } finally { if (directory) await rm(directory, { recursive: true, force: true }); }
}
/** Caller supplies signed raw bytes; exact cryptographic binding is checked before final-check. */
export async function completeSignedCandidate(ticket: PreparedHookTicket, signedCommit: Uint8Array): Promise<CheckedCandidate> {
  let value: HookData | undefined;
  try {
    value = active(ticket); value.busy = true;
    demand(signedCommit instanceof Uint8Array && signedCommit.byteLength <= ISOLATION_LIMITS.manifestBytes);
    const raw = Buffer.from(signedCommit); await verifySignature(value, raw);
    const result = await bundleSignedCandidate(value.history, value.candidate, raw);
    const input = value.input; const facts = describePreparedUpgrade(value.candidate);
    const final = freezeNodeValidation({ profile: input.profile, files: sourceFiles(input), baseBundle: result.bundle, baseCommit: input.baseCommit,
      branch: input.branch, commitMessage: input.commitMessage, author: input.author, committer: input.committer, hook: input.hook, phase: "final-check", candidateCommit: result.commit });
    demand(final.sourceSha256 === input.sourceSha256 && final.commitPlanSha256 === input.commitPlanSha256);
    const report = await validateIsolatedNode({ profile: final.profile, files: sourceFiles(final), baseBundle: final.baseBundle, baseCommit: final.baseCommit,
      branch: final.branch, commitMessage: final.commitMessage, author: final.author, committer: final.committer, hook: final.hook, phase: "final-check", candidateCommit: result.commit }, { signal: value.signal });
    reportMatches(report, final, facts.tree); demand(isDeepStrictEqual(report.tools, value.hook.tools));
    await discardPreparedHistory(value.history); value.historyClosed = true; hooks.delete(ticket); value.signal.throwIfAborted(); describePreparedUpgrade(value.candidate);
    const completed: CheckedCandidateFacts = Object.freeze({ repository: facts.repository, repositoryId: facts.repositoryId, baseCommit: input.baseCommit, candidateCommit: result.commit, preparedTree: facts.tree,
      sourceSha256: input.sourceSha256, commitPlanSha256: input.commitPlanSha256, publicKeySha256: sha256(Buffer.from(value.key)), branch: input.branch,
      hook: "completed", signature: "verified", finalCheck: "completed", signerAuthorization: "unverified", authority: "none", pilot: "unverified", independentReview: "pending", publication: "pending" });
    const handle = Object.freeze({}) as CheckedCandidate;
    checked.set(handle, { facts: completed, bundle: Buffer.from(result.bundle), ...(value.parent ? { parent: value.parent } : {}) }); value = undefined; return handle;
  } catch { throw failure(); }
  finally {
    if (value) {
      value.busy = false; value.cleanupOnly = true;
      if (!value.historyClosed) await discardPreparedHistory(value.history).catch(() => { throw failure(); });
      hooks.delete(ticket);
    }
  }
}
export async function discardCandidateHook(ticket: PreparedHookTicket): Promise<void> {
  const value = hooks.get(ticket); if (!value || value.busy) throw failure();
  value.cleanupOnly = true; await discardPreparedHistory(value.history).catch(() => { throw failure(); }); hooks.delete(ticket);
}
function result(handle: CheckedCandidate): CheckedData { const value = checked.get(handle); if (!value || value.parent?.aborted) throw failure(); return value; }
export function describeCheckedCandidate(handle: CheckedCandidate): CheckedCandidateFacts { return result(handle).facts; }
export function copyCheckedCandidateBundle(handle: CheckedCandidate): Buffer { return Buffer.from(result(handle).bundle); }
export function discardCheckedCandidate(handle: CheckedCandidate): void { if (!checked.has(handle)) throw failure(); checked.delete(handle); }
