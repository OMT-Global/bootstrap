import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const operator = vi.hoisted(() => ({ home: "", fixture: "", source: "", fetches: 0, historyFailure: "", failCleanup: false, holdHost: undefined as Promise<void> | undefined }));
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, rm: (...args: Parameters<typeof actual.rm>) => {
    if (operator.failCleanup && String(args[0]).includes("/bootstrap-history-")) return Promise.reject(new Error("fabricated deletion failure"));
    return actual.rm(...args);
  } };
});
vi.mock("node:os", async (original) => {
  const actual = await original<typeof import("node:os")>();
  return { ...actual, default: { ...actual, userInfo: () => ({ ...actual.userInfo(), homedir: operator.home }) } };
});
// Fixed production adapters stay fixed. Only the test replaces public transport
// with a real local Git fetch, and simulates Linux/prlimit/fixture ancestry.
vi.mock("../src/upgrade-host.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-host.js")>();
  return { ...actual, PRLIMIT_ARGS: [], requireLinuxHost: async () => { await operator.holdHost; return { git: "/usr/bin/git", prlimit: "/usr/bin/env" }; },
    trustedExecutable: (file: string) => path.basename(file) === "git-remote-https" ? Promise.resolve(file) : actual.trustedExecutable(file),
    readRegular: (file: string, limit: number, trusted = false, proc = false) => actual.readRegular(file, limit, trusted && !file.startsWith(operator.fixture + "/"), proc),
    boundedGitCommand: async (executable: string, args: readonly string[], options: Parameters<typeof actual.boundedGitCommand>[2]) => {
      const remote = args.indexOf("https://github.com/OMT-Global/bootstrap-fixture.git");
      if (remote < 0) return actual.boundedGitCommand(executable, args, options);
      expect(args).toContain("fetch"); operator.fetches++;
      const mapped = [...args]; mapped[remote] = operator.source; mapped.splice(mapped.indexOf("fetch"), 0, "-c", "protocol.file.allow=always");
      const result = await actual.boundedGitCommand(executable, mapped, options);
      const gitdir = options.env.GIT_DIR!;
      if (operator.historyFailure === "shallow") await writeFile(path.join(gitdir, "shallow"), args.at(-1)!.split(":")[0] + "\n");
      if (["missing", "corrupt"].includes(operator.historyFailure)) {
        const pack = (await readdir(path.join(gitdir, "objects/pack"))).find((name) => name.endsWith(".pack"))!;
        if (operator.historyFailure === "missing") await rm(path.join(gitdir, "objects/pack", pack));
        else await writeFile(path.join(gitdir, "objects/pack", pack), "corrupt fabricated transport");
      }
      return result;
    } };
});
import { freezeNodeValidation, NODE_ISOLATION_IMAGE, NODE_ISOLATION_PROFILE, type NodeValidationInput } from "../src/isolation/node-profile.js";
import * as backend from "../src/isolation/node-validation.js";
import { acquirePreparedHistory, copyPreparedHistoryBundle, discardPreparedHistory } from "../src/upgrade-history.js";
import { prepareObservedUpgrade, describePreparedUpgrade, discardPreparedUpgrade } from "../src/upgrade-preparation.js";
import { completeSignedCandidate, copyCandidateSigningRequest, copyCheckedCandidateBundle, describeCheckedCandidate, discardCandidateHook, discardCheckedCandidate, prepareCandidateHook, type CandidateCommitPlan } from "../src/upgrade-validation.js";
import { fixture, git, roots } from "./helpers/fleet-validation-fixture.js";

async function setup(options: { sourceSignal?: AbortSignal } = {}) {
  const data = await fixture(operator); operator.source = data.root; operator.fetches = 0; operator.historyFailure = "";
  const candidate = await prepareObservedUpgrade({ observation: data.observation, generator: data.generator, source: data.sourceSnapshot, originalRoot: data.root, signal: options.sourceSignal });
  const key = path.join(data.directory, "ephemeral-signing-key");
  execFileSync("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key], { env: data.env });
  const publicKey = (await readFile(key + ".pub", "utf8")).split(" ").slice(0, 2).join(" ").trim() + "\n";
  const plan: CandidateCommitPlan = { branch: "codex/fabricated-upgrade", commitMessage: "Fabricated candidate\n\nSigned-off-by: Fixture Author <author@example.invalid>\n",
    author: { name: "Fixture Author", email: "author@example.invalid", date: "1767225600 +0530" },
    committer: { name: "Fixture Committer", email: "committer@example.invalid", date: "1767225700 -0600" }, hook: ".githooks/pre-commit", publicKey };
  const calls: NodeValidationInput[] = []; let change: ((input: NodeValidationInput, report: backend.NodeValidationReport) => backend.NodeValidationReport | Promise<backend.NodeValidationReport>) | undefined;
  vi.spyOn(backend, "validateIsolatedNode").mockImplementation(async (input) => {
    calls.push(input); const frozen = freezeNodeValidation(input);
    const common = { profile: NODE_ISOLATION_PROFILE, image: NODE_ISOLATION_IMAGE, sourceSha256: frozen.sourceSha256, commitPlanSha256: frozen.commitPlanSha256,
      baseCommit: frozen.baseCommit, preparedTree: describePreparedUpgrade(candidate).tree, hook: frozen.hook,
      tools: { bash: "fabricated bash", git: "fabricated git", python: "fabricated python", node: "v24.fabricated", npm: "fabricated npm", jq: "jq-fabricated" } };
    const report: backend.NodeValidationReport = input.phase === "prepared-hook" ? { ...common, phase: input.phase, hookOutput: "fabricated hook result" }
      : { ...common, phase: input.phase, candidateCommit: input.candidateCommit, checkOutput: "fabricated check result" };
    return change ? change(input, report) : report;
  });
  return { ...data, candidate, key, plan, calls, change: (next: typeof change) => { change = next; } };
}
async function sign(data: Awaited<ReturnType<typeof setup>>, unsigned: Buffer, key = data.key): Promise<Buffer> {
  const file = path.join(data.directory, "unsigned-" + (await readdir(data.directory)).length); await writeFile(file, unsigned);
  execFileSync("/usr/bin/ssh-keygen", ["-Y", "sign", "-f", key, "-n", "git", file], { env: data.env, stdio: ["ignore", "ignore", "pipe"] });
  const signature = (await readFile(file + ".sig", "utf8")).trimEnd().split("\n");
  const boundary = unsigned.indexOf(Buffer.from("\n\n"));
  return Buffer.concat([unsigned.subarray(0, boundary), Buffer.from("\ngpgsig " + signature.join("\n ")), unsigned.subarray(boundary)]);
}
async function inspectBundle(data: Awaited<ReturnType<typeof setup>>, bytes: Buffer, selected: string) {
  const directory = path.join(data.directory, "bundle-inspection-" + (await readdir(data.directory)).length); await mkdir(directory);
  const bundle = path.join(directory, "source.bundle"); await writeFile(bundle, bytes);
  git(directory, data.env, ["init", "--quiet", "--bare", `--template=${path.join(data.directory, "empty")}`]);
  git(directory, data.env, ["bundle", "verify", bundle]);
  git(directory, data.env, ["fetch", "--quiet", "--no-tags", bundle, `${selected}:refs/heads/checked`]);
  git(directory, data.env, ["fsck", "--strict", "--no-reflogs"]);
  return { raw: git(directory, data.env, ["cat-file", "commit", selected]), count: Number(git(directory, data.env, ["rev-list", "--count", selected]).toString()) };
}
async function expectClean(data: Awaited<ReturnType<typeof setup>>) {
  expect((await readdir(data.directory)).filter((name) => name.startsWith("bootstrap-history-") || name.startsWith("bootstrap-signature-"))).toEqual([]);
}
afterEach(async () => { operator.failCleanup = false; operator.holdHost = undefined; vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

describe("candidate history, hook and signature composition (fabricated isolation adapter)", () => {
  it("preserves complete merge ancestry and exact planned identities through hook, ephemeral signing and final-check", async () => {
    const data = await setup(); const before = git(data.root, data.env, ["status", "--porcelain=v1", "-z"]);
    expect(() => copyCandidateSigningRequest({} as never)).toThrow("unavailable");
    const ticket = await prepareCandidateHook(data.candidate, data.plan); expect(data.calls.map((call) => call.phase)).toEqual(["prepared-hook"]);
    expect(() => copyCandidateSigningRequest({ ...ticket })).toThrow("unavailable");
    expect((await inspectBundle(data, Buffer.from(data.calls[0]!.baseBundle), data.head)).count).toBe(4);
    const request = copyCandidateSigningRequest(ticket); expect(request.unsignedCommit.toString()).toContain("author Fixture Author <author@example.invalid> 1767225600 +0530\ncommitter Fixture Committer <committer@example.invalid> 1767225700 -0600");
    const raw = await sign(data, request.unsignedCommit); request.unsignedCommit.fill(0);
    const checked = await completeSignedCandidate(ticket, raw); const facts = describeCheckedCandidate(checked);
    expect(data.calls.map((call) => call.phase)).toEqual(["prepared-hook", "final-check"]);
    expect(facts).toMatchObject({ repository: "OMT-Global/bootstrap-fixture", repositoryId: 42, baseCommit: data.head, preparedTree: describePreparedUpgrade(data.candidate).tree, sourceSha256: describePreparedUpgrade(data.candidate).sourceSha256,
      commitPlanSha256: request.commitPlanSha256, authority: "none", signerAuthorization: "unverified", pilot: "unverified", independentReview: "pending", publication: "pending", signature: "verified", hook: "completed", finalCheck: "completed" });
    const bundle = copyCheckedCandidateBundle(checked); const inspection = await inspectBundle(data, bundle, facts.candidateCommit);
    expect(inspection.count).toBe(5); expect(inspection.raw).toEqual(raw); expect(Object.isFrozen(facts)).toBe(true);
    bundle.fill(0); expect(copyCheckedCandidateBundle(checked)).not.toEqual(bundle);
    expect(() => copyCandidateSigningRequest(ticket)).toThrow("unavailable"); expect(() => describeCheckedCandidate({ ...checked })).toThrow("unavailable");
    discardCheckedCandidate(checked); expect(() => copyCheckedCandidateBundle(checked)).toThrow("unavailable");
    expect(git(data.root, data.env, ["status", "--porcelain=v1", "-z"])).toEqual(before); await expectClean(data);
  });
  it.each(["shallow", "missing", "corrupt"])("rejects %s acquired history before hook execution", async (kind) => {
    const data = await setup(); operator.historyFailure = kind;
    await expect(prepareCandidateHook(data.candidate, data.plan)).rejects.toThrow("unavailable"); expect(data.calls).toHaveLength(0); await expectClean(data);
  });
  it.each(["identity", "head"])("rechecks repository %s around history acquisition", async (kind) => {
    const data = await setup(); let reads = 0;
    data.network.change = (url, value) => url.pathname.endsWith(kind === "identity" ? "/bootstrap-fixture" : "/ref/heads/main") && ++reads > 1
      ? { ...(value as object), ...(kind === "identity" ? { id: 999 } : { object: { type: "commit", sha: "a".repeat(40) } }) } : value;
    await expect(prepareCandidateHook(data.candidate, data.plan)).rejects.toThrow("unavailable"); expect(operator.fetches).toBe(1); expect(data.calls).toHaveLength(0); await expectClean(data);
  });
  it("keeps the selected plan stable across acquisition awaits", async () => {
    const data = await setup(); const original = structuredClone(data.plan);
    data.network.change = (url, value) => { if (url.pathname.endsWith("/bootstrap-fixture")) { data.plan.author.name = "late mutation"; data.plan.commitMessage = "late mutation"; } return value; };
    const ticket = await prepareCandidateHook(data.candidate, data.plan);
    expect(data.calls[0]!.author).toEqual(original.author); expect(data.calls[0]!.commitMessage).toBe(original.commitMessage);
    await discardCandidateHook(ticket); await expectClean(data);
  });
  it.each(["tree", "plan", "image", "throw"])("rejects a mismatched/failed prepared-hook %s report without a signing request", async (kind) => {
    const data = await setup(); data.change((_input, report) => {
      if (kind === "throw") throw new Error("fabricated isolation failure");
      return { ...report, ...(kind === "tree" ? { preparedTree: "a".repeat(40) } : kind === "plan" ? { commitPlanSha256: "a".repeat(64) } : { image: "other image" }) };
    });
    await expect(prepareCandidateHook(data.candidate, data.plan)).rejects.toThrow("unavailable"); await expectClean(data);
  });
  it.each(["parent", "author", "message", "signature", "wrong-key"])("rejects %s tampering before final-check", async (kind) => {
    const data = await setup(); const ticket = await prepareCandidateHook(data.candidate, data.plan); const request = copyCandidateSigningRequest(ticket);
    let key = data.key;
    if (kind === "wrong-key") { key = path.join(data.directory, "different-ephemeral-key"); execFileSync("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key], { env: data.env }); }
    let raw = await sign(data, request.unsignedCommit, key);
    if (kind === "parent") raw = Buffer.from(raw.toString().replace(`parent ${data.head}`, `parent ${"a".repeat(40)}`));
    if (kind === "author") raw = Buffer.from(raw.toString().replace("author Fixture Author", "author Wrong Author"));
    if (kind === "message") raw = Buffer.from(raw.toString().replace("Fabricated candidate", "Altered candidate"));
    if (kind === "signature") raw = Buffer.from(raw.toString().replace(/\n ([A-Za-z0-9])/, (_match, char: string) => `\n ${char === "A" ? "B" : "A"}`));
    await expect(completeSignedCandidate(ticket, raw)).rejects.toThrow("unavailable"); expect(data.calls).toHaveLength(1); await expectClean(data);
  });
  it.each(["candidate", "tools", "throw"])("rejects final-check %s failure and consumes the ticket", async (kind) => {
    const data = await setup(); const ticket = await prepareCandidateHook(data.candidate, data.plan);
    data.change((input, report) => {
      if (input.phase !== "final-check") return report;
      if (kind === "throw") throw new Error("fabricated final-check failure");
      return kind === "candidate" ? { ...report, candidateCommit: "a".repeat(40) } : { ...report, tools: { ...report.tools, git: "changed version" } };
    });
    await expect(completeSignedCandidate(ticket, await sign(data, copyCandidateSigningRequest(ticket).unsignedCommit))).rejects.toThrow("unavailable");
    expect(() => copyCandidateSigningRequest(ticket)).toThrow("unavailable"); await expectClean(data);
  });
  it("cancels before acquisition and allows owned hook disposal after cancellation", async () => {
    const data = await setup(); const aborted = new AbortController(); aborted.abort();
    await expect(prepareCandidateHook(data.candidate, data.plan, { signal: aborted.signal })).rejects.toThrow("unavailable"); expect(operator.fetches).toBe(0);
    const controller = new AbortController(); const ticket = await prepareCandidateHook(data.candidate, data.plan, { signal: controller.signal }); controller.abort();
    expect(() => copyCandidateSigningRequest(ticket)).toThrow("unavailable"); await discardCandidateHook(ticket); await expectClean(data);
  });
  it("binds public history handles to their owned candidate and permits cleanup after abort", async () => {
    const data = await setup(); const controller = new AbortController(); const history = await acquirePreparedHistory(data.candidate, { signal: controller.signal });
    expect(() => copyPreparedHistoryBundle({ ...history }, data.candidate)).toThrow("unavailable");
    expect(() => copyPreparedHistoryBundle(history, { ...data.candidate })).toThrow("unavailable");
    controller.abort(); expect(() => copyPreparedHistoryBundle(history, data.candidate)).toThrow("unavailable"); await discardPreparedHistory(history); await expectClean(data);
  });
  it("retains only cleanup ownership after failed history disposal so deletion can be retried", async () => {
    const data = await setup(); const ticket = await prepareCandidateHook(data.candidate, data.plan);
    const raw = await sign(data, copyCandidateSigningRequest(ticket).unsignedCommit); operator.failCleanup = true;
    await expect(completeSignedCandidate(ticket, raw)).rejects.toThrow("unavailable");
    expect(() => copyCandidateSigningRequest(ticket)).toThrow("unavailable"); await expect(completeSignedCandidate(ticket, raw)).rejects.toThrow("unavailable");
    operator.failCleanup = false; await discardCandidateHook(ticket); await expectClean(data);
  });
  it("rejects late cancellation even if the fabricated final backend returns matching evidence", async () => {
    const data = await setup(); const controller = new AbortController(); const ticket = await prepareCandidateHook(data.candidate, data.plan, { signal: controller.signal });
    data.change((input, report) => { if (input.phase === "final-check") controller.abort(); return report; });
    await expect(completeSignedCandidate(ticket, await sign(data, copyCandidateSigningRequest(ticket).unsignedCommit))).rejects.toThrow("unavailable"); await expectClean(data);
  });
  it("captures cancellation before asynchronous host discovery even when the caller mutates options", async () => {
    const data = await setup(); let release!: () => void; operator.holdHost = new Promise<void>((resolve) => { release = resolve; });
    const controller = new AbortController(); const options: { signal?: AbortSignal } = { signal: controller.signal };
    const operation = acquirePreparedHistory(data.candidate, options); delete options.signal; controller.abort(); release();
    await expect(operation).rejects.toThrow("unavailable"); expect(operator.fetches).toBe(0); await expectClean(data);
  });
  it("keeps completed historical results independent of source lifetime but respects validation caller cancellation", async () => {
    const source = new AbortController(); const validation = new AbortController(); const data = await setup({ sourceSignal: source.signal });
    const ticket = await prepareCandidateHook(data.candidate, data.plan, { signal: validation.signal });
    const checked = await completeSignedCandidate(ticket, await sign(data, copyCandidateSigningRequest(ticket).unsignedCommit));
    source.abort(); discardPreparedUpgrade(data.candidate); expect(describeCheckedCandidate(checked).authority).toBe("none");
    expect(copyCheckedCandidateBundle(checked).length).toBeGreaterThan(0); validation.abort();
    expect(() => describeCheckedCandidate(checked)).toThrow("unavailable"); expect(() => copyCheckedCandidateBundle(checked)).toThrow("unavailable");
    discardCheckedCandidate(checked); await expectClean(data);
  });
});
