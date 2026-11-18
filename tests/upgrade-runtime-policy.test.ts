import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ capture: {} as object, snapshot: {} as object, bytes: Buffer.alloc(0), changed: false, head: "a".repeat(40) }));
vi.mock("../src/upgrade-generator.js", () => ({ generatorSnapshot(value: object) {
  if (value !== state.capture) throw new Error("unowned generator"); return state.snapshot;
} }));
vi.mock("../src/upgrade-git.js", () => ({ copySnapshotFiles(value: object) {
  if (value !== state.snapshot) throw new Error("unowned snapshot");
  return [{ path: "project.bootstrap.yaml", mode: "100644", bytes: Buffer.from(state.bytes) }];
} }));
vi.mock("../src/upgrade-public-read.js", async (original) => ({
  ...await original<typeof import("../src/upgrade-public-read.js")>(),
  publicRepository: vi.fn(async () => ({ repository: "OMT-Global/bootstrap", id: 1194768990, defaultBranch: "main" })),
  publicHead: vi.fn(async () => state.head),
  readPublicFile: vi.fn(async () => ({ mode: "100644", sha256: state.changed ? "f".repeat(64) : createHash("sha256").update(state.bytes).digest("hex") }))
}));
import { captureRuntimePolicy, missingRuntimeConfiguration, parseRuntimePolicyProjection, parseUpgradeRuntimeRequest, readRuntimePolicy } from "../src/upgrade-runtime-policy.js";
import type { PublicGeneratorCapture } from "../src/upgrade-generator.js";

function projection() {
  return { schemaVersion: 1, organization: "OMT-Global", repositories: [{ repository: "OMT-Global/a", id: 1 }],
    governance: { repository: "OMT-Global/bootstrap", id: 1194768990, issue: 62 },
    actors: [{ id: 42, login: "operator", roles: ["cohort", "pilot", "exception", "major"] }] };
}
beforeEach(() => {
  state.capture = { sourceCommit: "a".repeat(40), tree: "b".repeat(40), sourceSha256: "c".repeat(64) };
  state.snapshot = { baseCommit: "a".repeat(40), tree: "b".repeat(40), sourceSha256: "c".repeat(64) };
  state.bytes = Buffer.from(JSON.stringify({ fleetRuntime: projection() })); state.changed = false; state.head = "a".repeat(40);
});
describe("owned runtime policy", () => {
  it("requires a genuine generator, matching public current source and owned policy handle", async () => {
    const handle = await captureRuntimePolicy(state.capture as PublicGeneratorCapture);
    expect(readRuntimePolicy(handle).projection.organization).toBe("OMT-Global");
    expect(() => readRuntimePolicy({ ...handle })).toThrow("unowned-runtime-policy");
    await expect(captureRuntimePolicy({ ...state.capture } as PublicGeneratorCapture)).rejects.toThrow("unowned generator");
    expect(missingRuntimeConfiguration(handle)).toEqual(["authorized-signer-unconfigured", "native-review-profile-unconfigured", "publication-app-unconfigured", "attempt-directory-unconfigured"]);
  });
  it.each(["changed source", "stale generator"])("rejects %s", async (kind) => {
    if (kind === "changed source") state.changed = true; else state.head = "d".repeat(40);
    await expect(captureRuntimePolicy(state.capture as PublicGeneratorCapture)).rejects.toThrow();
  });
  it("retains cancellation of its original owner", async () => {
    const controller = new AbortController();
    const handle = await captureRuntimePolicy(state.capture as PublicGeneratorCapture, { signal: controller.signal }); controller.abort();
    expect(() => readRuntimePolicy(handle)).toThrow();
  });
  it.each(["missing", "duplicate YAML", "unknown setting"])("refuses %s configuration", async (kind) => {
    if (kind === "missing") state.bytes = Buffer.from("project: {}\n");
    if (kind === "duplicate YAML") state.bytes = Buffer.from("fleetRuntime: {}\nfleetRuntime: {}\n");
    if (kind === "unknown setting") state.bytes = Buffer.from(JSON.stringify({ fleetRuntime: { ...projection(), token: "forbidden" } }));
    await expect(captureRuntimePolicy(state.capture as PublicGeneratorCapture)).rejects.toThrow();
  });
});
describe("bounded projections and request claims", () => {
  it.each(["duplicate id", "duplicate name", "duplicate actor", "duplicate role"])("rejects %s", (kind) => {
    const value = projection();
    if (kind === "duplicate id") value.repositories.push({ id: 1, repository: "OMT-Global/b" });
    if (kind === "duplicate name") value.repositories.push({ id: 2, repository: "omt-global/A" });
    if (kind === "duplicate actor") value.actors.push({ ...value.actors[0]! });
    if (kind === "duplicate role") value.actors[0]!.roles.push("cohort");
    expect(() => parseRuntimePolicyProjection(value)).toThrow();
  });
  it("rejects executable/token/URL overrides and keeps caller objects separate", () => {
    const value = { repository: "OMT-Global/a", repositoryId: 1, originalRoot: "/fixture/target", generatorRoot: "/fixture/generator",
      generatorCommit: "a".repeat(40), target: { ref: "b".repeat(40), sha256: "c".repeat(64) } };
    const parsed = parseUpgradeRuntimeRequest(value); value.target.sha256 = "d".repeat(64);
    expect(parsed.target.sha256).toBe("c".repeat(64)); expect(Object.isFrozen(parsed.target)).toBe(true);
    for (const extra of [{ command: "sh" }, { token: "forbidden" }, { origin: "https://elsewhere.invalid" }]) {
      expect(() => parseUpgradeRuntimeRequest({ ...value, ...extra })).toThrow();
    }
  });
});
