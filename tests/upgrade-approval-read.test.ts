import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ handle: Object.freeze({ projectionDigest: "fixture" }), projection: {} as Record<string, unknown> }));
vi.mock("../src/upgrade-runtime-policy.js", async (original) => ({
  ...await original<typeof import("../src/upgrade-runtime-policy.js")>(),
  readRuntimePolicy(value: object) { if (value !== state.handle) throw new Error("unowned policy"); return { projection: state.projection }; }
}));
import { activeUpgradeDecisions, GOVERNANCE_MARKER, observeUpgradeDecisions, readOwnedDecisionObservation } from "../src/upgrade-approval-read.js";
import type { RuntimePolicy } from "../src/upgrade-runtime-policy.js";
const repo = "OMT-Global/bootstrap";
const prefix = `/repos/${repo}`;
type Value = Record<string, unknown>;
let comments: Value[];
let calls: string[];
let responseBytes: number;
let mutate: ((pathname: string, occurrence: number) => void) | undefined;
function comment(id: number, value: unknown): Value {
  return { id, body: GOVERNANCE_MARKER + JSON.stringify(value), user: { id: 42, login: "operator", type: "User" },
    html_url: `https://github.com/${repo}/issues/62#issuecomment-${id}`, url: `https://api.github.com${prefix}/issues/comments/${id}`,
    issue_url: `https://api.github.com${prefix}/issues/62`, created_at: "2026-11-15T00:00:00Z", updated_at: "2026-11-15T00:00:00Z" };
}
function cohort() {
  return { schemaVersion: 1, kind: "cohort", organization: "OMT-Global", inventory: [{ repositoryId: 1, repository: "OMT-Global/a", managed: true }], members: [{ repositoryId: 1, repository: "OMT-Global/a",
    repoClass: "service", sourceVersion: "1.0.0", sourceDigest: "a".repeat(64), sourceHead: "a".repeat(40) }],
    target: { version: "1.0.1", ref: "b".repeat(40), digest: "b".repeat(64), commit: "b".repeat(40) } };
}
beforeEach(() => {
  state.projection = { governance: { repository: repo, id: 10, issue: 62 },
    actors: [{ id: 42, login: "operator", roles: ["cohort", "pilot", "exception", "major"] }] };
  comments = [comment(100, cohort())]; calls = []; responseBytes = 0; mutate = undefined;
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input)); calls.push(url.pathname);
    mutate?.(url.pathname, calls.filter((entry) => entry === url.pathname).length);
    expect(url.origin).toBe("https://api.github.com"); expect(init?.method).toBe("GET"); expect(init?.redirect).toBe("error");
    let value: unknown;
    if (url.pathname === prefix) value = { id: 10, full_name: repo, private: false, visibility: "public", default_branch: "main" };
    else if (url.pathname === `${prefix}/issues/62`) value = { id: 123, number: 62, html_url: `https://github.com/${repo}/issues/62`, comments: comments.length };
    else if (url.pathname === `${prefix}/issues/62/comments`) value = comments;
    else throw new Error("unexpected request");
    const body = JSON.stringify(value); responseBytes += Buffer.byteLength(body); const response = new Response(body, { headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) } });
    Object.defineProperty(response, "url", { value: url.href }); return response;
  }));
});
afterEach(() => vi.unstubAllGlobals());
const observe = () => observeUpgradeDecisions(state.handle as RuntimePolicy);
describe("native public decision records", () => {
  it("binds actor numeric identity, exact issue and complete repeated catalog", async () => {
    const handle = await observe(); expect(handle.count).toBe(1);
    expect(handle.requests).toBe(calls.length); expect(handle.receivedBytes).toBe(responseBytes);
    expect(activeUpgradeDecisions(handle)[0]?.actorId).toBe(42);
    expect(calls.filter((entry) => entry.endsWith("/comments"))).toHaveLength(2);
    expect(() => readOwnedDecisionObservation({ ...handle })).toThrow("unowned-decision-observation");
  });
  it.each(["same login wrong id", "same id wrong login", "bot"])("does not grant authority to %s", async (kind) => {
    comments[0]!.user = kind === "same login wrong id" ? { id: 43, login: "operator", type: "User" }
      : kind === "same id wrong login" ? { id: 42, login: "somebody", type: "User" } : { id: 42, login: "operator", type: "Bot" };
    expect((await observe()).count).toBe(0);
  });
  it.each(["wrong issue", "duplicate comment", "unknown field", "duplicate JSON key", "edited catalog", "wrong role"])("rejects %s", async (kind) => {
    if (kind === "wrong issue") comments[0]!.issue_url = `https://api.github.com${prefix}/issues/61`;
    if (kind === "duplicate comment") comments.push({ ...comments[0]! });
    if (kind === "unknown field") comments[0] = comment(100, { ...cohort(), approved: true });
    if (kind === "duplicate JSON key") comments[0]!.body = GOVERNANCE_MARKER + '{"schemaVersion":1,"schemaVersion":1}';
    if (kind === "edited catalog") mutate = (pathname, occurrence) => { if (pathname.endsWith("/comments") && occurrence === 2) comments[0]!.updated_at = "2026-11-15T00:00:01Z"; };
    if (kind === "wrong role") state.projection.actors = [{ id: 42, login: "operator", roles: ["pilot"] }];
    await expect(observe()).rejects.toThrow();
  });
  it("only an actor with the original decision role can revoke it", async () => {
    comments.push(comment(101, { schemaVersion: 1, kind: "revoke", comment: 100 }));
    expect(activeUpgradeDecisions(await observe())).toEqual([]);
    state.projection.actors = [{ id: 42, login: "operator", roles: ["cohort"] }, { id: 43, login: "pilot", roles: ["pilot"] }];
    comments[1]!.user = { id: 43, login: "pilot", type: "User" };
    await expect(observe()).rejects.toThrow("governance-revocation");
  });
  it("rejects cancellation and malformed selected sources", async () => {
    const controller = new AbortController(); controller.abort();
    await expect(observeUpgradeDecisions(state.handle as RuntimePolicy, { signal: controller.signal })).rejects.toThrow();
    await expect(observeUpgradeDecisions({ ...state.handle } as RuntimePolicy)).rejects.toThrow("unowned policy");
  });
  it("permits a truthful premerge failure but never a pass without merged and CI evidence", async () => {
    const failed = { schemaVersion: 1, kind: "pilot-outcome", cohort: 100, repositoryId: 1, targetDigest: "b".repeat(64),
      outcome: "failed", candidateCommit: "c".repeat(40), pullNumber: 77, failure: "Premerge validation failed." };
    comments.push(comment(101, failed)); expect((await observe()).count).toBe(2);
    comments[1] = comment(101, { ...failed, outcome: "passed" });
    await expect(observe()).rejects.toThrow();
  });
});
