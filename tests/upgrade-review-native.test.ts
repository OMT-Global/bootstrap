import { createHash, type BinaryToTextEncoding } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const calls = vi.hoisted(() => ({ spawn: vi.fn(), read: vi.fn(), policy: {} as object, active: true }));
vi.mock("node:child_process", () => ({ spawn: calls.spawn }));
vi.mock("node:crypto", async (original) => {
  const actual = await original<typeof import("node:crypto")>();
  return { ...actual, createHash: (...args: Parameters<typeof actual.createHash>) => {
    const hash = actual.createHash(...args); const originalUpdate = hash.update.bind(hash); const originalDigest = hash.digest.bind(hash);
    const pieces: Buffer[] = [];
    hash.update = ((value: Parameters<typeof hash.update>[0]) => { pieces.push(Buffer.from(value as Uint8Array)); originalUpdate(value); return hash; }) as typeof hash.update;
    hash.digest = ((encoding?: BinaryToTextEncoding) => {
      if (Buffer.concat(pieces).equals(Buffer.from("fabricated helper; never executed"))) {
        const fixed = Buffer.from("fa51b49fb8e835f314a3dc8a94f01c143222386daee9fd10c6609a4fe5d282f3", "hex"); return encoding ? fixed.toString(encoding) : fixed;
      }
      return encoding ? originalDigest(encoding) : originalDigest();
    }) as typeof hash.digest; return hash;
  } };
});
vi.mock("node:fs/promises", async (original) => ({ ...await original<typeof import("node:fs/promises")>(), realpath: vi.fn(async (file: string) => file) }));
vi.mock("../src/upgrade-host.js", () => ({
  decode: (bytes: Uint8Array) => new TextDecoder("utf-8", { fatal: true }).decode(bytes),
  demand: (value: unknown) => { if (!value) throw new Error("fixture host denied"); },
  readRegular: calls.read, trustedExecutable: vi.fn(async (file: string) => file)
}));
vi.mock("../src/upgrade-runtime-policy.js", () => ({ readRuntimePolicy(value: object) {
  if (value !== calls.policy || !calls.active) throw new Error("unowned fixture runtime");
  return { projection: { review: { profile: "fleet-native-sol-high-v1", authorSession: "author-fixture-session", reviewerPrincipal: "reviewer-fixture" } } };
} }));
import { runOwnedNativeReview, settleNativeReviewCompletion, verifyNativeReviewCompletion, type NativeReviewRequest } from "../src/upgrade-review-native.js";
import type { RuntimePolicy } from "../src/upgrade-runtime-policy.js";
const script = await readFile(new URL("../src/native/upgrade-review-owner.py", import.meta.url));
const actualProcess = globalThis.process;
class Control extends EventEmitter {
  writes: object[] = [];
  write(bytes: Buffer) { this.writes.push(JSON.parse(bytes.toString())); return true; }
}
class Child extends EventEmitter {
  control = new Control(); stdio = [null, null, null, this.control]; kill = vi.fn(() => true); closed = false;
  close(code = 0) { if (!this.closed) { this.closed = true; this.control.emit("end"); this.emit("close", code, null); } }
}
let children: Child[];
let files: Map<string, Buffer>;
let pending: Promise<unknown>[];
const root = "/fixture/workspace";
const helperPath = "/fixture/codex/skills/autoreview/scripts/autoreview";
const usage = { attempts: 1, reported_attempts: 1, unknown_attempts: 0, partial_attempts: 0, complete: true,
  tokens: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 10, reasoning_output_tokens: 5 } };
function report() {
  const value = { findings: [], overall_correctness: "patch is correct", overall_explanation: "Fabricated provider report", overall_confidence: 0.9 };
  return { ...value, provider_report: { ...value }, usage, review_status: "scoped-clean" };
}
function multiPassReport() {
  // Fabricated clean output in the pinned helper's merge_chunk_reports format.
  // Ordinary branch splitting labels each pass and adds usage/status only to the aggregate.
  const { usage: _usage, review_status: _status, ...first } = report();
  const second = { ...first, overall_confidence: 0.8, overall_explanation: "Second fabricated pass",
    provider_report: { ...first.provider_report, overall_confidence: 0.8, overall_explanation: "Second fabricated pass" } };
  return { findings: [], overall_correctness: "patch is correct", overall_confidence: 0.8,
    overall_explanation: "Review passes returned. chunk 1/2: 0 finding(s), chunk 2/2: 0 finding(s). See preserved pass reports for provider conclusions.",
    pass_reports: [{ label: "chunk 1/2", report: first }, { label: "chunk 2/2", report: second }],
    usage: { ...usage, attempts: 2, reported_attempts: 2 }, review_status: "scoped-clean" };
}
function status() { return { schema_version: 1, status: "scoped-clean", exit_code: 0, engine: "codex", report_produced: true,
  reason: null, reviewer_exit_code: null, timed_out: false, usage }; }
function source() { return { directory: root, baseCommit: "a".repeat(40), candidateCommit: "b".repeat(40), signal: new AbortController().signal }; }
async function flush() { for (let count = 0; count < 25; count++) await Promise.resolve(); }
function begin(request: NativeReviewRequest = source()) {
  const result = runOwnedNativeReview(request, calls.policy as RuntimePolicy); pending.push(result.catch(() => undefined)); return result;
}
function send(child: Child, frame: object) { child.control.emit("data", Buffer.from(JSON.stringify(frame) + "\n")); }
function finish(child: Child) {
  send(child, { v: 1, type: "started", helper: 456 }); send(child, { v: 1, type: "drained", exit: 0 });
  send(child, { v: 1, type: "complete", exit: 0, remainingNs: "20000000000" }); child.close();
}
beforeEach(() => {
  calls.active = true; calls.policy = Object.freeze({}); children = []; pending = [];
  vi.stubGlobal("process", new Proxy(actualProcess, { get(target, property) {
    if (property === "platform") return "linux"; if (property === "arch") return "x64"; if (property === "getuid") return () => 501;
    if (property === "env") return { CODEX_HOME: "/fixture/codex", SSH_AUTH_SOCK: "/fixture/must-not-forward", AWS_PROFILE: "fixture" };
    return Reflect.get(target, property, target);
  } }));
  files = new Map([[helperPath, Buffer.from("fabricated helper; never executed")],
    [new URL("../src/native/upgrade-review-owner.py", import.meta.url).pathname, script],
    [`${root}/output/review.json`, Buffer.from(JSON.stringify(report()))], [`${root}/output/status.json`, Buffer.from(JSON.stringify(status()))]]);
  calls.read.mockImplementation(async (file: string) => { const bytes = files.get(file); if (!bytes) throw new Error("fixture missing input"); return Buffer.from(bytes); });
  calls.spawn.mockImplementation(() => { const child = new Child(); children.push(child); return child; });
});
afterEach(async () => {
  for (const child of children) child.close(1); await Promise.all(pending); vi.unstubAllGlobals(); vi.clearAllMocks();
});
describe("fixed native completion with fabricated child/report boundaries", () => {
  it("requires the actual ordered terminal protocol, exact helper and clean report/status", async () => {
    const result = begin(); await flush(); expect(children).toHaveLength(1); const child = children[0]!; finish(child);
    const completed = await result; const facts = await verifyNativeReviewCompletion(completed);
    expect(facts).toMatchObject({ model: "gpt-6.1-sol", priority: "P3", terminal: "complete", childPid: 456, githubApproval: "not-issued", modelFamilyIndependence: "unproved" });
    expect(facts.executionSession).not.toBe(facts.authorSession);
    await expect(verifyNativeReviewCompletion({ ...completed })).rejects.toThrow();
    expect(child.control.writes).toEqual([{ v: 1, type: "start", directory: root, base: "a".repeat(40), candidate: "b".repeat(40) }, { v: 1, type: "finish" }]);
    const options = calls.spawn.mock.calls[0]![2]; expect(options.stdio).toEqual(["ignore", "ignore", "ignore", "pipe"]);
    expect(options.env.SSH_AUTH_SOCK).toBeUndefined(); expect(options.env.AWS_PROFILE).toBeUndefined();
  });
  it("accepts the pinned helper's genuine all-clean multi-pass aggregate shape", async () => {
    const value = multiPassReport();
    expect(value).not.toHaveProperty("provider_report");
    expect(value.pass_reports[0]!.report).not.toHaveProperty("review_status");
    files.set(`${root}/output/review.json`, Buffer.from(JSON.stringify(value)));
    files.set(`${root}/output/status.json`, Buffer.from(JSON.stringify({ ...status(), usage: value.usage })));
    const result = begin(); await flush(); finish(children[0]!);
    const handle = await result; const facts = await verifyNativeReviewCompletion(handle);
    expect(facts.outcome).toBe("clean"); expect(settleNativeReviewCompletion(handle)).toEqual(facts);
  });
  it.each(["pass finding", "provider finding", "incorrect pass", "missing provider", "duplicate label", "missing pass", "wrong count", "unknown mode", "partial aggregate", "confidence mismatch", "nonterminal status"])("rejects multi-pass %s despite a clean summary and zero exit", async (kind) => {
    const value: any = multiPassReport();
    if (kind === "pass finding") value.pass_reports[1].report.findings = [{ title: "Unresolved defect" }];
    if (kind === "provider finding") value.pass_reports[1].report.provider_report.findings = [{ title: "Unresolved defect" }];
    if (kind === "incorrect pass") value.pass_reports[1].report.overall_correctness = "patch is incorrect";
    if (kind === "missing provider") delete value.pass_reports[1].report.provider_report;
    if (kind === "duplicate label") value.pass_reports[1].label = "chunk 1/2";
    if (kind === "missing pass") value.pass_reports.pop();
    if (kind === "wrong count") value.pass_reports[1].label = "chunk 2/3";
    if (kind === "unknown mode") value.pass_reports[1].report.assignment = { id: "not-selected" };
    if (kind === "partial aggregate") value.review_status = "incomplete";
    if (kind === "confidence mismatch") value.overall_confidence = 0.99;
    files.set(`${root}/output/review.json`, Buffer.from(JSON.stringify(value)));
    files.set(`${root}/output/status.json`, Buffer.from(JSON.stringify({ ...status(), usage: value.usage,
      ...(kind === "nonterminal status" ? { status: "incomplete" } : {}) })));
    const result = begin(); await flush(); finish(children[0]!); await expect(result).rejects.toThrow();
  });
  it.each(["absent report", "malformed report", "partial report", "unknown report field", "duplicate field", "actionable finding", "filtered status", "oversized report", "invalid UTF8"])("rejects %s despite zero native exit", async (kind) => {
    const result = begin(); await flush();
    const name = `${root}/output/review.json`;
    if (kind === "absent report") files.delete(name);
    if (kind === "malformed report") files.set(name, Buffer.from("{"));
    if (kind === "partial report") files.set(name, Buffer.from(JSON.stringify({ ...report(), review_status: "incomplete" })));
    if (kind === "unknown report field") files.set(name, Buffer.from(JSON.stringify({ ...report(), approved: true })));
    if (kind === "duplicate field") files.set(name, Buffer.from(JSON.stringify(report()).replace('"findings":[]', '"findings":[],"findings":[]')));
    if (kind === "actionable finding") files.set(name, Buffer.from(JSON.stringify({ ...report(), findings: [{ title: "P1 defect" }] })));
    if (kind === "filtered status") files.set(`${root}/output/status.json`, Buffer.from(JSON.stringify({ ...status(), status: "filtered" })));
    if (kind === "oversized report") files.set(name, Buffer.alloc(131073));
    if (kind === "invalid UTF8") files.set(name, Buffer.from([0xff]));
    finish(children[0]!); await expect(result).rejects.toThrow();
  });
  it.each(["no completion", "wrong exit", "malformed frame", "extra frame", "truncated frame"])("rejects %s protocol", async (kind) => {
    const result = begin(); await flush(); const child = children[0]!;
    if (kind === "no completion") { send(child, { v: 1, type: "started", helper: 456 }); child.close(); }
    if (kind === "wrong exit") { send(child, { v: 1, type: "started", helper: 456 }); send(child, { v: 1, type: "drained", exit: 1 }); child.close(1); }
    if (kind === "malformed frame") { child.control.emit("data", Buffer.from("broken\n")); child.close(1); }
    if (kind === "extra frame") { send(child, { v: 1, type: "started", helper: 456 }); send(child, { v: 1, type: "started", helper: 457 }); child.close(1); }
    if (kind === "truncated frame") { child.control.emit("data", Buffer.from('{"v":1')); child.close(1); }
    await expect(result).rejects.toThrow();
  });
  it("captures mutable input, consumes once, and withdraws on cancellation", async () => {
    const controller = new AbortController(); const request = { ...source(), signal: controller.signal };
    const result = begin(request); request.directory = "/changed"; await flush(); const child = children[0]!;
    expect(child.control.writes[0]).toMatchObject({ directory: root });
    await expect(begin(request)).rejects.toThrow(); controller.abort(); expect(child.control.writes.at(-1)).toEqual({ v: 1, type: "cancel" });
    child.close(1); await expect(result).rejects.toThrow();
  });
  it("rejects changed helper inputs, changed reports and revoked runtime after completion", async () => {
    const result = begin(); await flush(); finish(children[0]!); const completed = await result;
    const reportBytes = files.get(`${root}/output/review.json`)!; files.set(`${root}/output/review.json`, Buffer.from("{}"));
    await expect(verifyNativeReviewCompletion(completed)).rejects.toThrow(); files.set(`${root}/output/review.json`, reportBytes);
    files.set(helperPath, Buffer.from("changed helper")); await expect(verifyNativeReviewCompletion(completed)).rejects.toThrow();
    files.set(helperPath, Buffer.from("fabricated helper; never executed")); calls.active = false;
    await expect(verifyNativeReviewCompletion(completed)).rejects.toThrow();
  });
  it("requires verified inputs before one-time settlement and refuses expired cleanup budget", async () => {
    const result = begin(); await flush(); finish(children[0]!); const completed = await result;
    expect(() => settleNativeReviewCompletion(completed)).toThrow(); await verifyNativeReviewCompletion(completed);
    expect(settleNativeReviewCompletion(completed).terminal).toBe("complete"); expect(() => settleNativeReviewCompletion(completed)).toThrow();
    const second = begin(); await flush(); finish(children[1]!); const late = await second; await verifyNativeReviewCompletion(late);
    const clock = vi.spyOn(actualProcess.hrtime, "bigint").mockReturnValue(9999999999999999999n);
    try { expect(() => settleNativeReviewCompletion(late)).toThrow(); } finally { clock.mockRestore(); }
  });
  it("does not issue completion if cancellation arrives during the last report read", async () => {
    const controller = new AbortController();
    const result = begin({ ...source(), signal: controller.signal }); await flush();
    calls.read.mockImplementation(async (file: string) => {
      const bytes = files.get(file); if (!bytes) throw new Error("missing fixture");
      if (file.endsWith("/output/status.json")) controller.abort(); return Buffer.from(bytes);
    });
    finish(children[0]!); await expect(result).rejects.toThrow();
  });
});
