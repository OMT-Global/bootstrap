import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const fixture = vi.hoisted(() => ({ root: "", key: "", empty: "", policy: {} as object, projection: {} as any,
  hooks: new WeakMap<object, any>(), checked: new WeakMap<object, any>(), natives: new WeakMap<object, any>(),
  commands: [] as any[], keyCalls: 0, hookDisposals: 0, nativeFailure: false, cleanupFailure: false,
  duringReview: undefined as undefined | ((directory: string) => Promise<void>), workspaces: [] as string[],
  duringFinalCheck: undefined as undefined | (() => void) }));
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual,
    realpath: async (file: string) => file.startsWith("/etc/bootstrap") ? file : actual.realpath(file),
    lstat: async (file: string) => actual.lstat(file === "/etc/bootstrap/fleet-signers/fixture.key" ? fixture.key
      : ["/etc/bootstrap", "/etc/bootstrap/fleet-signers"].includes(file) ? fixture.empty : file === "/etc" && process.platform === "darwin" ? "/private/etc" : file),
    rm: async (file: string, options: any) => {
      if (fixture.cleanupFailure && path.basename(file).startsWith("bootstrap-review-workspace-")) throw new Error("fabricated cleanup failure");
      return actual.rm(file, options);
    }
  };
});
vi.mock("../src/upgrade-runtime-policy.js", () => ({ readRuntimePolicy(value: object) {
  if (value !== fixture.policy) throw new Error("unowned policy"); return { projection: fixture.projection };
} }));
vi.mock("../src/upgrade-host.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-host.js")>();
  const execute = async (_executable: string, args: string[], options: any) => {
    options.signal?.throwIfAborted(); const at = args.findIndex((arg) => arg === "/usr/bin/git" || arg === "/usr/bin/ssh-keygen");
    expect(at).toBeGreaterThanOrEqual(0); const executable = args[at]!;
    const command = args.slice(at + 1).map((arg) => arg === "/etc/bootstrap/fleet-signers/fixture.key" ? fixture.key : arg);
    fixture.commands.push({ executable, args: command, env: { ...options.env }, cwd: options.cwd });
    expect(options.env.SSH_AUTH_SOCK).toBeUndefined(); expect(options.env.GIT_CONFIG_COUNT).toBeUndefined();
    if (executable.endsWith("ssh-keygen") && command.includes("sign")) fixture.keyCalls++;
    return execFileSync(executable, command, { cwd: options.cwd, env: options.env, input: options.input,
      maxBuffer: options.output ?? 1024 ** 2, stdio: ["pipe", "pipe", "pipe"] });
  };
  return { ...actual, requireLinuxHost: vi.fn(async () => ({ git: "/usr/bin/git", prlimit: "/fixture/prlimit" })),
    trustedExecutable: vi.fn(async (file: string) => file), boundedCommand: execute, boundedGitCommand: execute };
});
vi.mock("../src/upgrade-validation.js", () => ({
  copyCandidateSigningRequest(ticket: object) {
    const data = fixture.hooks.get(ticket); if (!data) throw new Error("unowned hook"); return { ...data.request, unsignedCommit: Buffer.from(data.request.unsignedCommit) };
  },
  async completeSignedCandidate(ticket: object, raw: Uint8Array) {
    const data = fixture.hooks.get(ticket); if (!data) throw new Error("unowned hook");
    fixture.duringFinalCheck?.();
    const text = Buffer.from(raw).toString(); const boundary = text.indexOf("\n\n");
    const headers = text.slice(0, boundary).split("\n"); const sigStart = headers.findIndex((line) => line.startsWith("gpgsig "));
    expect(sigStart).toBe(4);
    const signature = headers.slice(sigStart).map((line, index) => index === 0 ? line.slice(7) : line.slice(1)).join("\n") + "\n";
    const unsigned = headers.slice(0, sigStart).join("\n") + text.slice(boundary);
    expect(Buffer.from(unsigned)).toEqual(data.request.unsignedCommit);
    const signatureFile = path.join(fixture.root, "signature"); const allowed = path.join(fixture.root, "allowed");
    await writeFile(signatureFile, signature); await writeFile(allowed, `fixture namespaces="git" ${data.request.publicKey}`);
    execFileSync("/usr/bin/ssh-keygen", ["-Y", "verify", "-f", allowed, "-I", "fixture", "-n", "git", "-s", signatureFile],
      { input: data.request.unsignedCommit, env: data.env, stdio: ["pipe", "pipe", "pipe"] });
    const commit = git(data.repo, data.env, ["hash-object", "-t", "commit", "-w", "--stdin"], raw).toString().trim();
    git(data.repo, data.env, ["update-ref", "refs/heads/codex/bootstrap-signed-candidate", commit]);
    const bundle = git(data.repo, data.env, ["bundle", "create", "--version=2", "-", "refs/heads/codex/bootstrap-public-base", "refs/heads/codex/bootstrap-signed-candidate"]);
    const handle = Object.freeze({}); fixture.checked.set(handle, { facts: { ...data.facts, candidateCommit: commit }, bundle, raw: Buffer.from(raw) });
    fixture.hooks.delete(ticket); return handle;
  },
  describeCheckedCandidate(value: object) { const data = fixture.checked.get(value); if (!data) throw new Error("unowned checked"); return data.facts; },
  copyCheckedCandidateBundle(value: object) { const data = fixture.checked.get(value); if (!data) throw new Error("unowned checked"); return Buffer.from(data.bundle); },
  discardCandidateHook(value: object) { if (!fixture.hooks.has(value)) throw new Error("unowned hook"); fixture.hooks.delete(value); fixture.hookDisposals++; },
  discardCheckedCandidate(value: object) { fixture.checked.delete(value); }
}));
vi.mock("../src/upgrade-review-native.js", () => ({
  async runOwnedNativeReview(request: any, policy: object) {
    if (policy !== fixture.policy || fixture.nativeFailure) throw new Error("fabricated native refusal");
    fixture.workspaces.push(request.directory); await fixture.duringReview?.(request.directory);
    const handle = Object.freeze({}); fixture.natives.set(handle, { schemaVersion: 1, helperSha256: "f".repeat(64), model: "gpt-6.1-sol", thinking: "high", priority: "P3",
      terminal: "complete", outcome: "clean", findings: [], baseCommit: request.baseCommit, candidateCommit: request.candidateCommit,
      authorSession: "author-fixture", executionSession: "new-reviewer-session", configuredPrincipal: "reviewer-fixture", childPid: 123,
      reportSha256: "a".repeat(64), statusSha256: "b".repeat(64), modelFamilyIndependence: "unproved", githubApproval: "not-issued" }); return handle;
  },
  async verifyNativeReviewCompletion(handle: object) { const result = fixture.natives.get(handle); if (!result) throw new Error("unowned native"); return result; },
  settleNativeReviewCompletion(handle: object) { const result = fixture.natives.get(handle); if (!result) throw new Error("unowned native"); fixture.natives.delete(handle); return result; }
}));
import { verifyGitSnapshot } from "../src/upgrade-git.js";
import { neutralEnvironment } from "../src/upgrade-host.js";
import { readAuthorizedSignature, signCandidateHook } from "../src/upgrade-signing.js";
import { reviewCheckedCandidate, readReviewedCandidate } from "../src/upgrade-review.js";
import { auditControlledReviewWorkspace, disposeControlledReviewWorkspace, openControlledReviewWorkspace, reviewWorkspaceContext } from "../src/upgrade-review-workspace.js";
import type { RuntimePolicy } from "../src/upgrade-runtime-policy.js";
import type { CheckedCandidate, PreparedHookTicket } from "../src/upgrade-validation.js";

function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: Uint8Array | string): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", ...args],
    { cwd: root, env, input, maxBuffer: 4 * 1024 ** 2, stdio: ["pipe", "pipe", "pipe"] });
}
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
let ticket: PreparedHookTicket;
let expectedFiles: Array<{ path: string; mode: "100644" | "100755"; bytes: Buffer }>;
beforeEach(async () => {
  fixture.root = await mkdtemp(path.join(os.tmpdir(), "fleet-native-fixture-")); fixture.empty = path.join(fixture.root, "empty"); await mkdir(fixture.empty, { mode: 0o700 });
  fixture.key = path.join(fixture.root, "ephemeral-key"); fixture.policy = Object.freeze({}); fixture.commands = []; fixture.workspaces = [];
  fixture.keyCalls = 0; fixture.hookDisposals = 0; fixture.nativeFailure = false; fixture.cleanupFailure = false; fixture.duringReview = undefined; fixture.duringFinalCheck = undefined;
  const repo = path.join(fixture.root, "repo"); await mkdir(repo);
  const env = { ...neutralEnvironment(fixture.empty, fixture.root), GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
    GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  git(repo, env, ["init", "--quiet", "--initial-branch=main", `--template=${fixture.empty}`]);
  expectedFiles = [{ path: "README.md", mode: "100644", bytes: Buffer.from("fixture\r\n") },
    { path: "opaque/é\nartifact.bin", mode: "100644", bytes: Buffer.from([0, 255, 10, 13, 1]) },
    { path: ".githooks/pre-commit", mode: "100755", bytes: Buffer.from(`#!/bin/sh\ntouch '${fixture.root}/must-not-run'\n`) }];
  const entries = [];
  for (const file of expectedFiles) {
    const blob = git(repo, env, ["hash-object", "-w", "--stdin"], file.bytes).toString().trim(); entries.push(Buffer.from(`${file.mode} ${blob}\t${file.path}\0`));
  }
  git(repo, env, ["update-index", "-z", "--index-info"], Buffer.concat(entries)); const tree = git(repo, env, ["write-tree"]).toString().trim();
  const first = git(repo, env, ["commit-tree", tree], "root\n").toString().trim();
  const left = git(repo, env, ["commit-tree", tree, "-p", first], "left\n").toString().trim();
  const right = git(repo, env, ["commit-tree", tree, "-p", first], "right\n").toString().trim();
  const base = git(repo, env, ["commit-tree", tree, "-p", left, "-p", right], "merge base\n").toString().trim();
  git(repo, env, ["update-ref", "refs/heads/codex/bootstrap-public-base", base]);
  execFileSync("/usr/bin/ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "", "-f", fixture.key], { env, stdio: ["ignore", "pipe", "pipe"] });
  const publicKey = (await readFile(fixture.key + ".pub", "utf8")).trim();
  const unsignedCommit = Buffer.from(`tree ${tree}\nparent ${base}\nauthor Fixture <fixture@example.invalid> 1767225600 +0000\ncommitter Fixture <fixture@example.invalid> 1767225600 +0000\n\nupgrade fixture\n`);
  const unsignedId = createHash("sha1").update(`commit ${unsignedCommit.length}\0`).update(unsignedCommit).digest("hex");
  const source = verifyGitSnapshot({ baseCommit: unsignedId, commitBytes: unsignedCommit, files: expectedFiles });
  const request = { unsignedCommit, publicKey: publicKey + "\n", commitPlanSha256: "c".repeat(64), repository: "OMT-Global/fixture", repositoryId: 42,
    baseCommit: base, sourceSha256: source.sourceSha256, preparedTree: tree };
  const facts = { repository: request.repository, repositoryId: 42, baseCommit: base, preparedTree: tree, sourceSha256: source.sourceSha256,
    commitPlanSha256: request.commitPlanSha256, publicKeySha256: sha(Buffer.from(publicKey + "\n")), branch: "codex/fixture-upgrade",
    hook: "completed", signature: "verified", finalCheck: "completed", signerAuthorization: "unverified", authority: "none", pilot: "unverified", independentReview: "pending", publication: "pending" };
  ticket = Object.freeze({}) as PreparedHookTicket; fixture.hooks.set(ticket, { request, facts, env, repo });
  fixture.projection = { repositories: [{ repository: request.repository, id: 42 }], signing: { principal: "signer-fixture", publicKey, keyReference: "fixture" },
    review: { profile: "fleet-native-sol-high-v1", authorSession: "author-fixture", reviewerPrincipal: "reviewer-fixture" } };
});
afterEach(async () => {
  fixture.cleanupFailure = false;
  for (const directory of fixture.workspaces) await rm(directory, { recursive: true, force: true });
  await rm(fixture.root, { recursive: true, force: true }); vi.clearAllMocks();
});
const policy = () => fixture.policy as RuntimePolicy;
describe("authorized SSH signing using only an ephemeral fixture key", () => {
  it("authorizes exact repository and key before signing the owned request", async () => {
    const checked = await signCandidateHook(ticket, policy()); expect(fixture.keyCalls).toBe(1);
    expect(readAuthorizedSignature(checked, policy()).principal).toBe("signer-fixture");
    expect(() => readAuthorizedSignature({ ...checked } as CheckedCandidate, policy())).toThrow();
    await expect(signCandidateHook(ticket, policy())).rejects.toThrow(); expect(fixture.keyCalls).toBe(1);
  });
  it.each(["wrong repository", "wrong key", "missing signer", "copied ticket"])("refuses %s before key use", async (kind) => {
    if (kind === "wrong repository") fixture.projection.repositories[0].id = 43;
    if (kind === "wrong key") fixture.projection.signing.publicKey = "ssh-ed25519 changed";
    if (kind === "missing signer") delete fixture.projection.signing;
    await expect(signCandidateHook(kind === "copied ticket" ? { ...ticket } as PreparedHookTicket : ticket, policy())).rejects.toThrow();
    expect(fixture.keyCalls).toBe(0);
  });
  it("refuses cancelled ownership before key use", async () => {
    const controller = new AbortController(); controller.abort();
    await expect(signCandidateHook(ticket, policy(), { signal: controller.signal })).rejects.toThrow(); expect(fixture.keyCalls).toBe(0);
  });
  it("rejects a deployed key that does not match its authorized public key", async () => {
    await rm(fixture.key); await rm(fixture.key + ".pub");
    execFileSync("/usr/bin/ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "", "-f", fixture.key],
      { env: neutralEnvironment(fixture.empty, fixture.root), stdio: ["ignore", "pipe", "pipe"] });
    await expect(signCandidateHook(ticket, policy())).rejects.toThrow(); expect(fixture.keyCalls).toBe(1);
  });
  it("disposes the hook after pre-signing key unavailability", async () => {
    await rm(fixture.key); await expect(signCandidateHook(ticket, policy())).rejects.toThrow();
    expect(fixture.keyCalls).toBe(0); expect(fixture.hookDisposals).toBe(1);
  });
  it("allows final validation to complete after the separate signing deadline expires", async () => {
    const deadline = new AbortController();
    const timeout = vi.spyOn(AbortSignal, "timeout").mockImplementation((milliseconds) => {
      expect(milliseconds).toBe(90_000); return deadline.signal;
    });
    // Model the final check passing 90 seconds without sleeping or weakening its owned bounds.
    fixture.duringFinalCheck = () => deadline.abort(new Error("fabricated elapsed signing deadline"));
    try {
      const checked = await signCandidateHook(ticket, policy());
      expect(deadline.signal.aborted).toBe(true); expect(fixture.keyCalls).toBe(1);
      expect(readAuthorizedSignature(checked, policy()).principal).toBe("signer-fixture");
    } finally { timeout.mockRestore(); }
  });
  it.each(["parent cancellation", "policy cancellation"])("still refuses %s during final validation", async (kind) => {
    const parent = new AbortController(); const originalPolicy = policy();
    fixture.duringFinalCheck = () => {
      if (kind === "parent cancellation") parent.abort(); else fixture.policy = Object.freeze({});
    };
    await expect(signCandidateHook(ticket, originalPolicy, { signal: parent.signal })).rejects.toThrow();
    expect(fixture.keyCalls).toBe(1);
  });
});
describe("exact candidate workspace with real temporary Git and SSH objects", () => {
  it("preserves signed OIDs, complete ancestry, raw bytes and executable modes without hooks", async () => {
    const checked = await signCandidateHook(ticket, policy()); const workspace = await openControlledReviewWorkspace(checked, policy());
    const context = reviewWorkspaceContext(workspace); fixture.workspaces.push(context.directory);
    const before = await auditControlledReviewWorkspace(workspace); expect(before.historyCommits).toBe(5);
    for (const file of expectedFiles) {
      expect(await readFile(path.join(context.root, file.path))).toEqual(file.bytes);
      expect(Boolean((await lstat(path.join(context.root, file.path))).mode & 0o100)).toBe(file.mode === "100755");
    }
    await expect(lstat(path.join(fixture.root, "must-not-run"))).rejects.toMatchObject({ code: "ENOENT" });
    await disposeControlledReviewWorkspace(workspace); await expect(lstat(context.directory)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(openControlledReviewWorkspace(checked, policy())).rejects.toThrow();
  });
  it.each(["source bytes", "Git configuration", "unexpected Git metadata", "candidate ref"])("refuses changed %s", async (kind) => {
    const checked = await signCandidateHook(ticket, policy()); const workspace = await openControlledReviewWorkspace(checked, policy());
    const context = reviewWorkspaceContext(workspace); fixture.workspaces.push(context.directory);
    if (kind === "source bytes") await writeFile(path.join(context.root, "README.md"), "changed\n");
    if (kind === "Git configuration") await writeFile(path.join(context.gitdir, "config"), "[include]\npath=/never-read\n");
    if (kind === "unexpected Git metadata") await writeFile(path.join(context.gitdir, "shallow"), context.baseCommit + "\n");
    if (kind === "candidate ref") await writeFile(path.join(context.gitdir, "refs/heads/codex/fixture-upgrade"), context.baseCommit + "\n");
    await expect(auditControlledReviewWorkspace(workspace)).rejects.toThrow(); await disposeControlledReviewWorkspace(workspace);
  });
  it("still disposes owned workspace after caller cancellation", async () => {
    const checked = await signCandidateHook(ticket, policy()); const controller = new AbortController();
    const workspace = await openControlledReviewWorkspace(checked, policy(), { signal: controller.signal });
    const context = reviewWorkspaceContext(workspace); fixture.workspaces.push(context.directory); controller.abort();
    await expect(auditControlledReviewWorkspace(workspace)).rejects.toThrow(); await disposeControlledReviewWorkspace(workspace);
    await expect(lstat(context.directory)).rejects.toMatchObject({ code: "ENOENT" });
  });
  it("retains cleanup ownership after removal failure and permits a disposal retry", async () => {
    const checked = await signCandidateHook(ticket, policy()); const workspace = await openControlledReviewWorkspace(checked, policy());
    const context = reviewWorkspaceContext(workspace); fixture.workspaces.push(context.directory); fixture.cleanupFailure = true;
    await expect(disposeControlledReviewWorkspace(workspace)).rejects.toThrow("cleanup is unconfirmed");
    await expect(auditControlledReviewWorkspace(workspace)).rejects.toThrow(); fixture.cleanupFailure = false;
    await disposeControlledReviewWorkspace(workspace); await expect(lstat(context.directory)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
describe("review consumer with fabricated native completion", () => {
  it("returns owned reviewed facts only after workspace audit and complete disposal", async () => {
    const checked = await signCandidateHook(ticket, policy()); const reviewed = await reviewCheckedCandidate(checked, policy());
    const owned = readReviewedCandidate(reviewed); expect(owned.checked).toBe(checked); expect(owned.facts.independentExecution).toBe("verified");
    expect(owned.facts.review.githubApproval).toBe("not-issued"); expect(owned.facts.publication).toBe("pending");
    for (const directory of fixture.workspaces) await expect(lstat(directory)).rejects.toMatchObject({ code: "ENOENT" });
    expect(() => readReviewedCandidate({ ...reviewed })).toThrow(); await expect(reviewCheckedCandidate(checked, policy())).rejects.toThrow();
  });
  it.each(["native failure", "source mutation", "cleanup uncertainty"])("cannot approve after %s", async (kind) => {
    const checked = await signCandidateHook(ticket, policy());
    if (kind === "native failure") fixture.nativeFailure = true;
    if (kind === "source mutation") fixture.duringReview = async (directory) => { await writeFile(path.join(directory, "source/README.md"), "changed\n"); };
    if (kind === "cleanup uncertainty") fixture.cleanupFailure = true;
    await expect(reviewCheckedCandidate(checked, policy())).rejects.toThrow();
  });
});
