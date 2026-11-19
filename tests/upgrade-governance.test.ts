import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { flowPolicyDigest } from "../src/policy.js";
const fixtures = vi.hoisted(() => ({ runtime: {} as object, projection: {} as any, generator: {} as any,
  discovery: {} as any, policies: new Map<number, object>(), owned: new WeakMap<object, any>(),
  records: [] as any[], decisions: new WeakMap<object, any>(), ci: new WeakMap<object, any>(),
  ciFailure: false, reads: 0, changeOnRepeat: false, discoveryReads: 0, changedFleet: false, pr: {} as any,
  adrText: "# ADR\n\nStatus: Accepted\n", adrChanged: false, nativeDecisions: false,
  historicalPolicies: new Map<string, any>(), historicalCi: new Map<string, any>(), pulls: new Map<number, any>(), policyMoved: false, movePolicyOnRepeat: false, ciBytes: 100, runtimeBytes: 100, decisionBytes: 100, captureReads: 0 }));
vi.mock("../src/upgrade-runtime-policy.js", async (original) => ({
  ...await original<typeof import("../src/upgrade-runtime-policy.js")>(),
  readRuntimePolicy(value: object) {
    if (value !== fixtures.runtime) throw new Error("unowned runtime");
    return { generator: fixtures.generator, projection: fixtures.projection };
  },
  captureRuntimePolicy: vi.fn(async (generator: object) => {
    if (generator !== fixtures.generator) throw new Error("unowned generator"); fixtures.captureReads++;
    return Object.freeze({ ...fixtures.runtime, requests: 1, receivedBytes: fixtures.runtimeBytes });
  })
}));
vi.mock("../src/upgrade-discovery.js", () => ({ discoverPublicManifests: vi.fn(async () => {
  fixtures.discoveryReads++;
  if (fixtures.movePolicyOnRepeat && fixtures.discoveryReads > 1) fixtures.policyMoved = true;
  const value = structuredClone(fixtures.discovery);
  if (fixtures.changedFleet && fixtures.discoveryReads > 1) value.repositories.pop();
  return value;
}) }));
vi.mock("../src/upgrade-policy.js", () => ({
  POLICY_PUBLISHER: { repository: "OMT-Global/flow", id: 1232476439 },
  observePublicPolicies: vi.fn(async (_discovery: unknown, repo: { repositoryId: number }) => fixtures.policies.get(repo.repositoryId)),
  readOwnedPolicyObservation(value: object) {
    const owned = fixtures.owned.get(value); if (!owned) throw new Error("unowned policy"); return owned;
  }
}));
vi.mock("../src/upgrade-pilot-ci.js", async (original) => ({
  ...await original<typeof import("../src/upgrade-pilot-ci.js")>(),
  observeManagedCi: vi.fn(async (policy: object, options: { atCommit?: string }) => {
    const owned = fixtures.owned.get(policy); const handle = Object.freeze({ status: fixtures.ciFailure ? "failed" : "observed", requests: 450, receivedBytes: fixtures.ciBytes });
    const head = options.atCommit ?? owned.repository.head;
    if (!fixtures.ciFailure) fixtures.ci.set(handle, { policy, repositoryId: owned.repository.id, head,
      policyVersion: owned.source.policy.version, policyDigest: owned.sourceBinding.canonicalSha256,
      policyRef: owned.sourceBinding.ref, policyCommit: owned.sourceBinding.commit,
      run: { id: 700, attempt: 1 }, evidenceSha256: "7".repeat(64), workflowSha256: "8".repeat(64), ...fixtures.historicalCi.get(head) });
    return handle;
  }),
  readOwnedCiObservation(value: object) { const owned = fixtures.ci.get(value); if (!owned) throw new Error("unowned ci"); return owned; }
}));
vi.mock("../src/upgrade-approval-read.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-approval-read.js")>();
  return { ...actual,
  observeUpgradeDecisions: vi.fn(async (policy: object, options: { signal?: AbortSignal }) => {
    if (fixtures.nativeDecisions) return actual.observeUpgradeDecisions(policy as RuntimePolicy, options);
    fixtures.reads++;
    const handle = Object.freeze({ digest: JSON.stringify(fixtures.records) + (fixtures.changeOnRepeat && fixtures.reads > 1 ? "changed" : ""), requests: 1, receivedBytes: fixtures.decisionBytes });
    fixtures.decisions.set(handle, { policy, records: fixtures.records }); return handle;
  }),
  readOwnedDecisionObservation(value: object) {
    const result = fixtures.decisions.get(value); return result ?? actual.readOwnedDecisionObservation(value as never);
  },
  activeUpgradeDecisions(value: object) {
    const result = fixtures.decisions.get(value); if (!result) return actual.activeUpgradeDecisions(value as never);
    const revoked = new Set(result.records.filter((entry: any) => entry.value.kind === "revoke").map((entry: any) => entry.value.comment));
    return result.records.filter((entry: any) => entry.value.kind !== "revoke" && !revoked.has(entry.commentId));
  }
}; });
vi.mock("../src/upgrade-public-read.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-public-read.js")>();
  return { ...actual,
  resolvePublicCommit: vi.fn(async (read, repository, ref) => fixtures.policyMoved && ref === target.ref ? "f".repeat(40) : actual.resolvePublicCommit(read, repository, ref)),
  readPublicFile: vi.fn(async (_read, repository: string, head: string, file: string) => {
    const bundle = fixtures.historicalPolicies.get(head) ?? originalPolicy;
    const text = file === "project.bootstrap.yaml" ? JSON.stringify({ version: 1,
      project: { owner: "OMT-Global", name: repository.split("/")[1], visibility: "public", defaultBranch: "main" },
      archetype: { kind: "generic-empty" }, repo: { class: "cli" },
      policy: { flow: { ref: "refs/tags/v1.0.0", sha256: flowPolicyDigest(bundle), bundlePath: "policy/flow-public-standard.json" } } })
      : file === "policy/flow-public-standard.json" ? JSON.stringify(bundle) : fixtures.adrText;
    return { text, mode: "100644", oid: "9".repeat(40), sha256: fixtures.adrChanged ? "f".repeat(64) : "9".repeat(64) };
  })
}; });
import { observeUpgradeGovernance, readOwnedGovernance, recheckUpgradeGovernance } from "../src/upgrade-governance.js";
import { runtimeDigest, type RuntimePolicy } from "../src/upgrade-runtime-policy.js";
import { observeManagedCi } from "../src/upgrade-pilot-ci.js";
const originalPolicy = { ...JSON.parse(readFileSync(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8")), version: "1.0.0" };
const firstTargetPolicy = { ...originalPolicy, version: "1.0.1" };
const target = { version: "1.0.1", ref: "c".repeat(40), digest: flowPolicyDigest(firstTargetPolicy), commit: "c".repeat(40) };
function recordDecision(commentId: number, value: any): any {
  return { commentId, actorId: 42, actorLogin: "operator", url: `https://github.com/OMT-Global/bootstrap/issues/62#issuecomment-${commentId}`,
    bodyDigest: runtimeDigest(value), value };
}
function request(repositoryId = 1): any {
  return { repository: `OMT-Global/${repositoryId === 1 ? "a" : "b"}`, repositoryId, originalRoot: "/fixture/target", generatorRoot: "/fixture/generator",
    generatorCommit: "f".repeat(40), target: { ref: target.ref, sha256: target.digest }, cohortComment: 100 };
}
function source(repositoryId: number): any { return fixtures.owned.get(fixtures.policies.get(repositoryId)!); }
function passedPilot(): any {
  const owned = source(1); owned.sourceBinding.canonicalSha256 = target.digest; owned.source.policy.version = target.version;
  owned.sourceBinding.ref = target.ref; owned.sourceBinding.commit = target.commit;
  owned.repository.head = "e".repeat(40); fixtures.discovery.repositories[0].head = owned.repository.head;
  fixtures.historicalPolicies.set(owned.repository.head, firstTargetPolicy);
  fixtures.historicalCi.set(owned.repository.head, { policyVersion: target.version, policyDigest: target.digest, policyRef: target.ref, policyCommit: target.commit });
  const value = { schemaVersion: 1, kind: "pilot-outcome", cohort: 100, repositoryId: 1, targetDigest: target.digest,
    outcome: "passed", candidateCommit: "d".repeat(40), mergedCommit: owned.repository.head, pullNumber: 77,
    ci: { runId: 700, attempt: 1, evidenceSha256: "7".repeat(64), workflowSha256: "8".repeat(64) } };
  fixtures.records.push(recordDecision(101, value)); return value;
}
beforeEach(() => {
  fixtures.generator = { sourceCommit: "f".repeat(40) }; fixtures.runtime = Object.freeze({ projectionDigest: "runtime", controllerCommit: "f".repeat(40) });
  fixtures.projection = { organization: "OMT-Global", repositories: [{ repository: "OMT-Global/a", id: 1 }, { repository: "OMT-Global/b", id: 2 }],
    governance: { repository: "OMT-Global/bootstrap", id: 10, issue: 62 }, actors: [{ id: 42, login: "operator", roles: ["cohort", "pilot", "exception", "major"] }] };
  fixtures.policies.clear(); fixtures.reads = 0; fixtures.discoveryReads = 0; fixtures.changedFleet = false;
  fixtures.changeOnRepeat = false; fixtures.ciFailure = false; fixtures.adrChanged = false; fixtures.adrText = "# ADR\n\nStatus: Accepted\n";
  fixtures.nativeDecisions = false; fixtures.historicalCi.clear(); fixtures.historicalPolicies.clear(); fixtures.pulls.clear();
  fixtures.policyMoved = false; fixtures.movePolicyOnRepeat = false;
  fixtures.ciBytes = 100; fixtures.runtimeBytes = 100; fixtures.decisionBytes = 100; fixtures.captureReads = 0;
  fixtures.discovery = { status: "complete", organization: "OMT-Global", requests: 1, receivedBytes: 100, repositories: [] };
  const members = [];
  for (const id of [1, 2]) {
    const letter = id === 1 ? "a" : "b"; const repository = `OMT-Global/${letter}`;
    const head = letter.repeat(40); const sourceDigest = flowPolicyDigest(originalPolicy);
    fixtures.discovery.repositories.push({ repository, repositoryId: id, head, defaultBranch: "main", outcome: "managed", fork: false, archived: false, disabled: false });
    const handle = Object.freeze({ status: "observed", requests: 1, receivedBytes: 100 }); fixtures.policies.set(id, handle);
    fixtures.owned.set(handle, { repository: { repository, id, head, defaultBranch: "main" },
      manifest: { project: { owner: "OMT-Global", name: letter, visibility: "public" }, repo: { class: "cli" }, exceptions: [] },
      source: { policy: { version: "1.0.0" } }, target: { policy: { version: target.version } },
      sourceBinding: { ref: head, commit: head, canonicalSha256: sourceDigest }, targetBinding: { ref: target.ref, commit: target.commit, canonicalSha256: target.digest } });
    members.push({ repositoryId: id, repository, repoClass: "cli", sourceVersion: "1.0.0", sourceDigest, sourceHead: head });
  }
  fixtures.records = [recordDecision(100, { schemaVersion: 1, kind: "cohort", organization: "OMT-Global", members, target: { ...target },
    inventory: members.map(({ repositoryId, repository }) => ({ repositoryId, repository, managed: true })) })];
  fixtures.pr = { number: 77, html_url: "https://github.com/OMT-Global/a/pull/77", state: "closed", merged: true, merge_commit_sha: "e".repeat(40),
    head: { sha: "d".repeat(40), repo: { id: 1 } }, base: { ref: "main", sha: "a".repeat(40), repo: { id: 1 } } };
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input)); expect(init?.method).toBe("GET"); expect(url.origin).toBe("https://api.github.com");
    const id = url.pathname.startsWith("/repos/OMT-Global/a") ? 1 : 2; const repo = source(id).repository;
    let value: unknown;
    if (url.pathname === "/repos/OMT-Global/bootstrap") value = { id: 10, full_name: "OMT-Global/bootstrap", private: false, visibility: "public", default_branch: "main" };
    else if (url.pathname === "/repos/OMT-Global/flow") value = { id: 1232476439, full_name: "OMT-Global/flow", private: false, visibility: "public", default_branch: "main" };
    else if (url.pathname === "/repos/OMT-Global/bootstrap/issues/62") value = { id: 123, number: 62, html_url: "https://github.com/OMT-Global/bootstrap/issues/62", comments: fixtures.records.length };
    else if (url.pathname === "/repos/OMT-Global/bootstrap/issues/62/comments") value = fixtures.records.map((entry) => ({ id: entry.commentId,
      user: { id: 42, login: "operator", type: "User" }, body: "PRS-FLEET-GOVERNANCE-001\n" + JSON.stringify(entry.value),
      html_url: entry.url, url: `https://api.github.com/repos/OMT-Global/bootstrap/issues/comments/${entry.commentId}`,
      issue_url: "https://api.github.com/repos/OMT-Global/bootstrap/issues/62", created_at: "2026-11-15T00:00:00Z", updated_at: "2026-11-15T00:00:00Z" }));
    else if (url.pathname === `/repos/${repo.repository}`) value = { id, full_name: repo.repository, visibility: "public", private: false, default_branch: "main" };
    else if (url.pathname.endsWith("/git/ref/heads/main")) value = { ref: "refs/heads/main", object: { type: "commit", sha: repo.head } };
    else if (/\/pulls\/[0-9]+$/.test(url.pathname)) value = fixtures.pulls.get(Number(url.pathname.split("/").at(-1))) ?? fixtures.pr;
    else throw new Error(`unexpected fixture endpoint ${url.pathname}`);
    const body = JSON.stringify(value); const response = new Response(body, { headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) } });
    Object.defineProperty(response, "url", { value: url.href }); return response;
  }));
});
afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });
const observe = (id = 1) => observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, request(id));
describe("owned original cohort and current inventory", () => {
  it("allows a pending representative's reviewed pilot but blocks later class members", async () => {
    const handle = await observe(); expect(handle.role).toBe("pilot"); expect(handle.plan.pilotOutcome).toBe("pending");
    expect(handle.independentReview).toBe("pending"); expect(handle.authority).toBe("none");
    expect(() => readOwnedGovernance({ ...handle })).toThrow("unowned-governance");
    await expect(observe(2)).rejects.toThrow("representative-pilot-pending");
  });
  it("releases the next member after exact merged pilot and current target CI, without inventing an old current version", async () => {
    await observe(); passedPilot(); const handle = await observe(2);
    expect(handle.role).toBe("batch"); expect(handle.plan.status).toBe("eligible");
    const owned = readOwnedGovernance(handle);
    expect(owned.cohort.members[0]?.sourceVersion).toBe("1.0.0");
    expect(source(1).source.policy.version).toBe("1.0.1");
    expect(owned.current).toContain(fixtures.policies.get(1)); expect(observeManagedCi).toHaveBeenCalledWith(fixtures.policies.get(1), expect.anything());
    await expect(observe()).rejects.toThrow("selected-repository-already-target");
  });
  it.each(["wrong target", "wrong candidate", "wrong merge", "unmerged", "wrong CI", "failed CI", "no outcome", "wrong original base", "wrong historical version"])("blocks %s pilot proof", async (kind) => {
    const outcome = passedPilot();
    if (kind === "wrong target") outcome.targetDigest = "0".repeat(64);
    if (kind === "wrong candidate") outcome.candidateCommit = "0".repeat(40);
    if (kind === "wrong merge") outcome.mergedCommit = "0".repeat(40);
    if (kind === "unmerged") fixtures.pr.merged = false;
    if (kind === "wrong CI") outcome.ci.runId = 701;
    if (kind === "failed CI") fixtures.ciFailure = true;
    if (kind === "no outcome") fixtures.records.pop();
    if (kind === "wrong original base") fixtures.pr.base.sha = "0".repeat(40);
    if (kind === "wrong historical version") fixtures.records[0].value.members[0].sourceVersion = "0.9.0";
    await expect(observe(2)).rejects.toThrow();
  });
  it.each(["partial scan", "duplicate id", "duplicate alias", "new member", "new unmanaged repository", "reclassified", "source drift", "late fleet drift"])("rejects %s", async (kind) => {
    if (kind === "partial scan") fixtures.discovery.status = "incomplete";
    if (kind === "duplicate id") fixtures.discovery.repositories[1].repositoryId = 1;
    if (kind === "duplicate alias") fixtures.discovery.repositories[1].repository = "omt-global/A";
    if (kind === "new member") fixtures.records[0].value.members.pop();
    if (kind === "new unmanaged repository") fixtures.discovery.repositories.push({ repositoryId: 3, repository: "OMT-Global/unmanaged", outcome: "unmanaged" });
    if (kind === "reclassified") source(1).manifest.repo.class = "library";
    if (kind === "source drift") source(1).sourceBinding.canonicalSha256 = "0".repeat(64);
    if (kind === "late fleet drift") fixtures.changedFleet = true;
    await expect(observe()).rejects.toThrow();
  });
  it("rejects changed or revoked records on refresh and preserves cancellation", async () => {
    const handle = await observe(); fixtures.changeOnRepeat = true;
    await expect(recheckUpgradeGovernance(handle)).rejects.toThrow("governance-changed");
    fixtures.changeOnRepeat = false; fixtures.records.push(recordDecision(102, { schemaVersion: 1, kind: "revoke", comment: 100 }));
    await expect(observe()).rejects.toThrow("cohort-revoked");
    fixtures.records.pop(); const controller = new AbortController();
    const owned = await observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, request(), { signal: controller.signal });
    controller.abort(); expect(() => readOwnedGovernance(owned)).toThrow();
  });
  it("rechecks policy ref bindings after the final fleet scan", async () => {
    fixtures.movePolicyOnRepeat = true;
    await expect(observe()).rejects.toThrow("policy-changed");
  });
  it("refuses a new target or representative while the original cohort is unfinished", async () => {
    const value = structuredClone(fixtures.records[0].value); value.supersedes = 100; value.reconciliation = "proposed new cohort";
    value.target.digest = "0".repeat(64); fixtures.records.push(recordDecision(102, value));
    const input = request(); input.cohortComment = 102; input.target.sha256 = value.target.digest;
    await expect(observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, input)).rejects.toThrow("unfinished-cohort-replacement");
  });
  it("does not accept a fabricated prior pass as evidence to replace an unfinished cohort", async () => {
    const outcome = passedPilot(); outcome.candidateCommit = "0".repeat(40);
    const value = structuredClone(fixtures.records[0].value); value.supersedes = 100; value.reconciliation = "new cohort";
    fixtures.records.push(recordDecision(102, value)); const input = request(2); input.cohortComment = 102;
    await expect(observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, input)).rejects.toThrow("pilot-not-merged");
  });
  it("keeps failed pilots blocked even after revocation; exact later human remediation permits only the pilot to retry", async () => {
    const failed = { schemaVersion: 1, kind: "pilot-outcome", cohort: 100, repositoryId: 1, targetDigest: target.digest, outcome: "failed",
      candidateCommit: fixtures.pr.head.sha, pullNumber: 77, failure: "Premerge validation failed." };
    fixtures.pr.merged = false;
    fixtures.records.push(recordDecision(101, failed));
    await expect(observe()).rejects.toThrow("pilot-failed-remediation-required");
    fixtures.records.push(recordDecision(102, { schemaVersion: 1, kind: "revoke", comment: 101 }));
    await expect(observe()).rejects.toThrow("pilot-failed-remediation-required");
    fixtures.records.push(recordDecision(103, { schemaVersion: 1, kind: "remediation", cohort: 100, repositoryId: 1,
      targetDigest: target.digest, failedComment: 101, resolution: "Investigated failed validation; retry the representative." }));
    expect((await observe()).role).toBe("pilot"); await expect(observe(2)).rejects.toThrow("representative-pilot-pending");
  });
});
describe("current human decision gates", () => {
  it("requires the exact current exception decision and rejects expired declarations", async () => {
    const exception = { id: "temporary", policy: "example", scope: "repository", rationale: "fixture", approvedBy: "operator",
      issue: "https://github.com/OMT-Global/bootstrap/issues/62", permanent: false, expiresAt: "2099-01-01" };
    source(1).manifest.exceptions.push(exception);
    await expect(observe()).rejects.toThrow("exception-decision-required");
    fixtures.records.push(recordDecision(101, { schemaVersion: 1, kind: "exception", cohort: 100, repositoryId: 1,
      targetDigest: target.digest, exceptionDigest: runtimeDigest(exception), expiresAt: exception.expiresAt }));
    expect((await observe()).role).toBe("pilot");
    exception.expiresAt = "2000-01-01"; fixtures.records[1].value.exceptionDigest = runtimeDigest(exception); fixtures.records[1].value.expiresAt = exception.expiresAt;
    await expect(observe()).rejects.toThrow("exception-expired");
  });
  it("requires major notification plus an actual current Accepted ADR", async () => {
    fixtures.records[0].value.target.version = "2.0.0"; source(1).target.policy.version = "2.0.0"; source(2).target.policy.version = "2.0.0";
    await expect(observe()).rejects.toThrow("major-decisions-required");
    const common = { schemaVersion: 1, cohort: 100, repositoryId: 1, targetDigest: target.digest, baseCommit: source(1).repository.head };
    fixtures.records.push(recordDecision(101, { ...common, kind: "major-notice", explanation: "Major transition notice" }));
    fixtures.records.push(recordDecision(102, { ...common, kind: "accepted-adr", adr: { repository: "OMT-Global/a", repositoryId: 1,
      defaultBranch: "main", commit: source(1).repository.head, path: "docs/decisions/ADR-0001-fixture.md", sha256: "9".repeat(64) } }));
    expect((await observe()).plan.risk).toBe("major");
    fixtures.adrText = "```\nStatus: Accepted\n```\n"; await expect(observe()).rejects.toThrow("adr-not-accepted");
  });
});

describe("native decision reader into governance lifecycle", () => {
  it("accepts a truthful premerge failure, blocks only its class, and requires exact remediation", async () => {
    fixtures.nativeDecisions = true; source(2).manifest.repo.class = "library"; fixtures.records[0].value.members[1].repoClass = "library";
    fixtures.pr.merged = false;
    fixtures.records.push(recordDecision(101, { schemaVersion: 1, kind: "pilot-outcome", cohort: 100, repositoryId: 1,
      targetDigest: target.digest, outcome: "failed", candidateCommit: fixtures.pr.head.sha, pullNumber: 77, failure: "Premerge CI failed." }));
    await expect(observe()).rejects.toThrow("pilot-failed-remediation-required");
    expect((await observe(2)).role).toBe("pilot");
    fixtures.records.push(recordDecision(102, { schemaVersion: 1, kind: "remediation", cohort: 100, repositoryId: 1,
      targetDigest: target.digest, failedComment: 101, resolution: "The recorded failure was investigated; retry this representative." }));
    expect((await observe()).plan.pilotOutcome).toBe("pending");
  });
  it.each(["failed", "missing"])("isolates a post-merge %s CLI pilot outcome from a library pilot", async (outcome) => {
    fixtures.nativeDecisions = true;
    passedPilot(); fixtures.records.pop();
    source(2).manifest.repo.class = "library"; fixtures.records[0].value.members[1].repoClass = "library";
    if (outcome === "failed") fixtures.records.push(recordDecision(101, { schemaVersion: 1, kind: "pilot-outcome", cohort: 100,
      repositoryId: 1, targetDigest: target.digest, outcome: "failed", candidateCommit: fixtures.pr.head.sha,
      mergedCommit: fixtures.pr.merge_commit_sha, pullNumber: 77, failure: "Post-merge validation failed." }));
    const library = await observe(2);
    expect(library.role).toBe("pilot"); expect(library.plan.pilotOutcome).toBe("pending");
    expect(observeManagedCi).not.toHaveBeenCalled();
    const blocker = outcome === "failed" ? "pilot-failed-remediation-required" : "merged-outcome-required";
    await expect(observe()).rejects.toThrow(blocker);
    source(2).manifest.repo.class = "cli"; fixtures.records[0].value.members[1].repoClass = "cli";
    await expect(observe(2)).rejects.toThrow(blocker);
  });
  it("keeps authenticated failed-class memory when a successor selects another target", async () => {
    fixtures.nativeDecisions = true; fixtures.pr.merged = false;
    fixtures.records.push(recordDecision(101, { schemaVersion: 1, kind: "pilot-outcome", cohort: 100, repositoryId: 1,
      targetDigest: target.digest, outcome: "failed", candidateCommit: fixtures.pr.head.sha, pullNumber: 77, failure: "Premerge CI failed." }));
    const successor = structuredClone(fixtures.records[0].value); successor.supersedes = 100; successor.reconciliation = "A successor target is proposed.";
    successor.target.digest = "0".repeat(64); fixtures.records.push(recordDecision(102, successor));
    const input = request(2); input.cohortComment = 102; input.target.sha256 = successor.target.digest;
    await expect(observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, input)).rejects.toThrow("pilot-failed-remediation-required");
  });
  it("completes C1, prepares and merges C2's pilot, then releases C2's batch using historical C1 and current C2 evidence", async () => {
    fixtures.nativeDecisions = true;
    expect((await observe()).role).toBe("pilot"); passedPilot(); expect((await observe(2)).plan.status).toBe("eligible");
    fixtures.pulls.set(77, structuredClone(fixtures.pr));
    const policy2 = { ...originalPolicy, version: "1.0.2" };
    const nextTarget = { version: "1.0.2", ref: "4".repeat(40), digest: flowPolicyDigest(policy2), commit: "4".repeat(40) };
    const successor = structuredClone(fixtures.records[0].value); successor.supersedes = 100; successor.reconciliation = "Start the next approved target."; successor.target = nextTarget;
    for (const member of successor.members) {
      const current = source(member.repositoryId); member.sourceVersion = current.source.policy.version;
      member.sourceDigest = current.sourceBinding.canonicalSha256; member.sourceHead = current.repository.head;
      current.target.policy.version = nextTarget.version; current.targetBinding = { ref: nextTarget.ref, commit: nextTarget.commit, canonicalSha256: nextTarget.digest };
    }
    fixtures.records.push(recordDecision(110, successor));
    const next = (id: number) => ({ ...request(id), cohortComment: 110, target: { ref: nextTarget.ref, sha256: nextTarget.digest } });
    expect((await observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, next(1))).role).toBe("pilot");
    await expect(observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, next(2))).rejects.toThrow("representative-pilot-pending");
    const merged = "2".repeat(40); source(1).repository.head = merged; source(1).source.policy.version = nextTarget.version;
    source(1).sourceBinding.canonicalSha256 = nextTarget.digest; fixtures.discovery.repositories[0].head = merged;
    source(1).sourceBinding.ref = nextTarget.ref; source(1).sourceBinding.commit = nextTarget.commit;
    fixtures.historicalPolicies.set(merged, policy2);
    fixtures.historicalCi.set(merged, { policyVersion: nextTarget.version, policyDigest: nextTarget.digest, policyRef: nextTarget.ref, policyCommit: nextTarget.commit,
      run: { id: 701, attempt: 1 }, evidenceSha256: "9".repeat(64) });
    fixtures.pulls.set(78, { ...structuredClone(fixtures.pr), number: 78, html_url: "https://github.com/OMT-Global/a/pull/78",
      merge_commit_sha: merged, head: { sha: "1".repeat(40), repo: { id: 1 } }, base: { ref: "main", sha: "e".repeat(40), repo: { id: 1 } } });
    fixtures.records.push(recordDecision(111, { schemaVersion: 1, kind: "pilot-outcome", cohort: 110, repositoryId: 1, targetDigest: nextTarget.digest,
      outcome: "passed", candidateCommit: "1".repeat(40), mergedCommit: merged, pullNumber: 78,
      ci: { runId: 701, attempt: 1, evidenceSha256: "9".repeat(64), workflowSha256: "8".repeat(64) } }));
    const released = await observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, next(2));
    expect(released.plan.status).toBe("eligible"); expect(released.cohortComment).toBe(110);
    expect(observeManagedCi).toHaveBeenCalledWith(fixtures.policies.get(1), expect.objectContaining({ atCommit: "e".repeat(40) }));
    expect(source(1).source.policy.version).toBe("1.0.2");
    source(1).repository.head = "3".repeat(40); fixtures.discovery.repositories[0].head = source(1).repository.head;
    await expect(observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, next(2))).rejects.toThrow("pilot-target-binding");
  });
});

describe("operation-wide public observation budget", () => {
  it("charges every historical CI proof and stops before the next producer when their valid local totals exhaust the operation", async () => {
    fixtures.nativeDecisions = true;
    const outcome = passedPilot(); const original = structuredClone(fixtures.records[0].value);
    fixtures.ciBytes = 60 * 1024 ** 2; // Each fabricated native-CI producer remains below its actual 64 MiB local cap.
    let prior = 100;
    for (let index = 1; index <= 5; index++) {
      const cohortId = 100 + index * 10;
      const cohort = { ...structuredClone(original), supersedes: prior, reconciliation: "Authenticated cohort renewal." };
      fixtures.records.push(recordDecision(cohortId, cohort));
      if (index < 5) fixtures.records.push(recordDecision(cohortId + 1, { ...outcome, cohort: cohortId }));
      prior = cohortId;
    }
    const input = { ...request(2), cohortComment: prior };
    await expect(observeUpgradeGovernance(fixtures.runtime as RuntimePolicy, input)).rejects.toThrow("governance-budget");
    expect(observeManagedCi).toHaveBeenCalledTimes(5);
    expect(fixtures.discoveryReads).toBe(1);
    expect(fixtures.captureReads).toBe(1); // No final discovery, second decision catalog or policy recapture starts.
  });
  it("charges controller and both decision scans in addition to policy/discovery/CI reads", async () => {
    passedPilot(); fixtures.runtimeBytes = 60 * 1024 ** 2; fixtures.decisionBytes = 60 * 1024 ** 2;
    fixtures.ciBytes = 60 * 1024 ** 2;
    await expect(observe(2)).rejects.toThrow("governance-budget");
    expect(fixtures.reads).toBe(2);
    expect(fixtures.captureReads).toBe(2);
  });
  it("charges direct merged-PR reader bytes before the final discovery and publisher recheck", async () => {
    passedPilot(); fixtures.runtimeBytes = 0; fixtures.decisionBytes = 0; fixtures.ciBytes = 0;
    fixtures.discovery.receivedBytes = 64 * 1024 ** 2;
    for (const id of [1, 2]) {
      const previous = fixtures.policies.get(id)!; const handle = Object.freeze({ status: "observed", requests: 1, receivedBytes: 64 * 1024 ** 2 });
      fixtures.owned.set(handle, fixtures.owned.get(previous)); fixtures.policies.set(id, handle);
    }
    await expect(observe(2)).rejects.toThrow("governance-budget");
    expect(fixtures.discoveryReads).toBe(2); expect(fixtures.reads).toBe(1);
    expect(vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes("/repos/OMT-Global/flow"))).toBe(false);
  });
  it.each([NaN, -1, Number.MAX_SAFE_INTEGER + 1])("rejects invalid cost %s before subsequent reads", async (receivedBytes) => {
    fixtures.runtimeBytes = receivedBytes;
    await expect(observe()).rejects.toThrow("governance-budget");
    expect(fixtures.discoveryReads).toBe(0);
  });
});
