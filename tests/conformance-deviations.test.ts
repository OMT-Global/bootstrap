import { afterEach, describe, expect, it, vi } from "vitest";

// Close external routes before importing the real local-file consumers.
const external = vi.hoisted(() => ({ blocked: vi.fn(() => { throw new Error("External route is closed in conformance predicate tests."); }) }));
vi.hoisted(() => { vi.stubGlobal("fetch", external.blocked); });
vi.mock("node:http", async (original) => {
  const actual = await original<typeof import("node:http")>();
  return { ...actual, request: external.blocked, get: external.blocked, default: { ...actual, request: external.blocked, get: external.blocked } };
});
vi.mock("node:https", async (original) => {
  const actual = await original<typeof import("node:https")>();
  return { ...actual, request: external.blocked, get: external.blocked, default: { ...actual, request: external.blocked, get: external.blocked } };
});
vi.mock("node:dns", async (original) => {
  const actual = await original<typeof import("node:dns")>();
  const closed = Object.fromEntries(Object.keys(actual).filter((key) => typeof actual[key as keyof typeof actual] === "function").map((key) => [key, external.blocked]));
  const promises = Object.fromEntries(Object.keys(actual.promises).map((key) => [key, external.blocked]));
  return { ...actual, ...closed, promises, default: { ...actual, ...closed, promises } };
});
vi.mock("node:dns/promises", async (original) => {
  const actual = await original<typeof import("node:dns/promises")>();
  const closed = Object.fromEntries(Object.keys(actual).filter((key) => typeof actual[key as keyof typeof actual] === "function").map((key) => [key, external.blocked]));
  return { ...actual, ...closed, default: { ...actual, ...closed } };
});
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  const closed = Object.fromEntries(["exec", "execFile", "execSync", "execFileSync", "spawn", "spawnSync", "fork"].map((key) => [key, external.blocked]));
  return { ...actual, ...closed, default: { ...actual, ...closed } };
});
afterEach(() => { expect(external.blocked).not.toHaveBeenCalled(); });

import { diagnosticForDeviation, evaluateConformanceDeviation, evaluateResponseCommitments } from "../src/conformance-deviations.js";
import type { ConformanceResult } from "../src/conformance.js";
import type { PolicyException } from "../src/types.js";

const target = { policy: "repository-files", scope: "repo.managed-artifacts" };
function diagnostic(severity: ConformanceResult["severity"] = "blocking"): ConformanceResult {
  return { ruleId: "PRS-REQUIRED-FILE-001", severity, classification: severity === "pass" ? "conformant" : "misconfigured", evidence: ["z missing", "a missing"], remediation: "Restore required files." };
}
function exception(id: string, fields: Partial<PolicyException> = {}): PolicyException {
  return { id, ...target, rationale: "Fabricated migration approval", approvedBy: "fixture-reviewer", issue: "#62", permanent: false, expiresAt: "2099-01-01", ...fields };
}

function expectFrozen(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) expectFrozen(child);
}

describe("neutral conformance deviation evaluation", () => {
  it.each(["warning", "blocking"] as const)("retains the full underlying %s while legacy display applies a candidate", (severity) => {
    const entry = diagnostic(severity);
    const waiver = exception("temporary-files");
    const evaluation = evaluateConformanceDeviation(entry, [waiver], new Set([waiver.id]), target);
    expect(evaluation).toEqual({ underlying: entry, target, candidates: [waiver] });
    expect(evaluation.underlying).not.toBe(entry);
    expect(evaluation.underlying.evidence).not.toBe(entry.evidence);
    expect(evaluation.target).not.toBe(target);
    expectFrozen(evaluation);
    expect(diagnosticForDeviation(evaluation)).toEqual({
      ruleId: entry.ruleId, severity: "pass", classification: "waived",
      evidence: ["a missing", "approved exception temporary-files", "z missing"],
      remediation: "Keep approved exception temporary-files current until the governed deviation is resolved."
    });
    expect(evaluation.underlying).toEqual(entry);
  });

  it("does not apply a stored matching waiver to an already passing diagnostic", () => {
    const entry = diagnostic("pass");
    const evaluation = evaluateConformanceDeviation(entry, [exception("stored")], new Set(["stored"]), target);
    expect(evaluation.candidates).toEqual([]);
    const displayed = diagnosticForDeviation(evaluation);
    expect(displayed).toEqual(entry);
    expect(displayed).not.toBe(entry);
    expect(displayed.evidence).not.toBe(entry.evidence);
  });

  it("requires exact policy, scope, and eligible ID without validating supplied eligibility", () => {
    const invalidByValidator = exception("caller-supplied-expired", { expiresAt: "2000-01-01" });
    const records = [
      exception("wrong-policy", { policy: "repository-files-extra" }),
      exception("wrong-scope", { scope: "repo.managed-artifacts-extra" }),
      exception("ineligible"), invalidByValidator
    ];
    const evaluation = evaluateConformanceDeviation(diagnostic(), records, new Set(["wrong-policy", "wrong-scope", invalidByValidator.id]), target);
    // This helper only matches supplied data; validation belongs to the real consumer.
    expect(evaluation.candidates).toEqual([invalidByValidator]);
    const unwaived = evaluateConformanceDeviation(diagnostic(), records, new Set(), target);
    expect(unwaived.candidates).toEqual([]);
    expect(diagnosticForDeviation(unwaived)).toEqual(diagnostic());
  });

  it("preserves original candidate order and legacy first selection rather than lexical ID order", () => {
    const records = [exception("z-first"), exception("a-second")];
    const evaluation = evaluateConformanceDeviation(diagnostic(), records, new Set(["a-second", "z-first"]), target);
    expect(evaluation.candidates.map((entry) => entry.id)).toEqual(["z-first", "a-second"]);
    expect(diagnosticForDeviation(evaluation).evidence).toEqual(["a missing", "approved exception z-first", "z missing"]);
  });

  it("snapshots complete temporary and permanent records including optional property presence", () => {
    const temporary = exception("temporary", { adr: "docs/adr/temporary-context.md" });
    const permanent = exception("permanent", { permanent: true, adr: "docs/adr/permanent.md" });
    // Deliberately distinguish a supplied own undefined property from an absent property.
    Object.defineProperty(permanent, "expiresAt", { value: undefined, enumerable: true, writable: true, configurable: true });
    const absentOptional: PolicyException = { id: "without-optionals", ...target, rationale: "Fabricated exception", approvedBy: "reviewer", issue: "#62", permanent: true };
    const records = [temporary, permanent, absentOptional];
    const entry = diagnostic();
    const mutableTarget = { ...target };
    const eligible = new Set(records.map((record) => record.id));
    const evaluation = evaluateConformanceDeviation(entry, records, eligible, mutableTarget);
    const expected = structuredClone({ underlying: entry, target: mutableTarget, candidates: records });
    expect(evaluation).toEqual(expected);
    expectFrozen(evaluation);
    expect(Object.hasOwn(evaluation.candidates[1]!, "expiresAt")).toBe(true);
    expect(Object.hasOwn(evaluation.candidates[2]!, "expiresAt")).toBe(false);
    expect(Object.hasOwn(evaluation.candidates[2]!, "adr")).toBe(false);
    entry.evidence.push("later evidence"); entry.remediation = "changed";
    temporary.rationale = "changed"; permanent.adr = "changed"; absentOptional.adr = "later";
    mutableTarget.scope = "changed"; records.reverse(); eligible.clear();
    expect(evaluation).toEqual(expected);
    const displayed = diagnosticForDeviation(evaluation);
    displayed.evidence.push("caller display mutation");
    expect(evaluation).toEqual(expected);
  });
});

describe("shared response commitment evaluation", () => {
  const acknowledge = "Acknowledge a complete private report within 2 business days";
  const triage = "Triage a confirmed report within 7 calendar days";

  it("returns whole normalized statements and their real paragraph lines", () => {
    expect(evaluateResponseCommitments(`# Response targets\n\n- ACKNOWLEDGE a complete\n  private report within 2 business days.\n\nSeparate paragraph.`, [acknowledge, triage])).toEqual({
      kind: "supported",
      statements: [
        { text: acknowledge.toLowerCase(), startLine: 3, endLine: 4 },
        { text: "separate paragraph", startLine: 6, endLine: 6 }
      ],
      missingCommitments: [triage]
    });
  });

  it.each([
    ["quoted", `> ${acknowledge}.`], ["inline code", `\`${acknowledge}.\``],
    ["emphasis", `*${acknowledge}.*`], ["negated", `Do not ${acknowledge}.`],
    ["one combined paragraph", `${acknowledge}.\n${triage}.`]
  ])("keeps %s text from satisfying an exact commitment", (_name, text) => {
    const evaluation = evaluateResponseCommitments(text, [acknowledge, triage]);
    expect(evaluation.kind).toBe("supported");
    if (evaluation.kind === "supported") expect(evaluation.missingCommitments).toEqual([acknowledge, triage]);
  });

  it("retains original missing strings and order, accepts ASCII case, and permits no expectations", () => {
    expect(evaluateResponseCommitments(`- ${acknowledge.toUpperCase()}.`, [triage, acknowledge, triage])).toMatchObject({ kind: "supported", missingCommitments: [triage, triage] });
    expect(evaluateResponseCommitments("", [])).toEqual({ kind: "supported", statements: [], missingCommitments: [] });
  });

  it.each([
    ["raw HTML", `${acknowledge}.\n\n<!-- later HTML -->`, "raw-html"],
    ["oversized Markdown", "x".repeat(4_097), "input-limit"]
  ])("returns an unsupported result without partial commitments for %s", (_name, text, reason) => {
    expect(evaluateResponseCommitments(text, [acknowledge])).toEqual({ kind: "unsupported", reason });
  });
});
