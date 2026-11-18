import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { normalizeManifest } from "../src/manifest.js";
import { flowPolicyDigest, resolveFlowPolicy } from "../src/policy.js";
import { resolveRepositoryProjection } from "../src/render.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const policyFixtures = vi.hoisted(() => new WeakMap<object, unknown>());
vi.mock("../src/upgrade-policy.js", () => ({
  POLICY_PUBLISHER: { repository: "OMT-Global/flow", id: 1232476439, bundlePath: "policies/public-repository-standard-v1.json" },
  readOwnedPolicyObservation(value: object) {
    const owned = policyFixtures.get(value);
    if (!owned) throw new Error("not an actual policy observation");
    return owned;
  }
}));
vi.mock("../src/upgrade-public-read.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-public-read.js")>();
  return { ...actual, readPublicFile: vi.fn(async (_read, repository: string, _head, file: string) => {
    const text = fixture.historical ? file === "project.bootstrap.yaml" ? fixture.historical.manifest
      : file === WORKFLOW ? fixture.historical.workflow : repository.endsWith("/flow") && fixture.historical.wrongPublished
        ? JSON.stringify({ ...JSON.parse(fixture.historical.bundle), version: "9.0.0" }) : fixture.historical.bundle : workflowText;
    return { text, oid: "b".repeat(40), sha256: createHash("sha256").update(text).digest("hex"), mode: "100644" };
  }) };
});
import { observeManagedCi, readOwnedCiObservation } from "../src/upgrade-pilot-ci.js";
import type { PolicyObservation } from "../src/upgrade-policy.js";

// These tests exercise actual bounded HTTP/native-CI logic. The policy producer
// is a separate fixture boundary; its Git/renderer proof belongs to policy tests.
const workflowText = readFileSync(new URL("../.github/workflows/extended-validation.yml", import.meta.url), "utf8");
const workflowSha = createHash("sha256").update(workflowText).digest("hex");
const REPO = "OMT-Global/example";
const PREFIX = `/repos/${REPO}`;
const HEAD = "a".repeat(40);
const START = "2026-11-09T12:00:00Z";
const END = "2026-11-09T12:05:00Z";
const WORKFLOW = ".github/workflows/extended-validation.yml";
type Item = Record<string, unknown>;
const object = (value: unknown) => value as Item;
const items = (value: unknown) => value as Item[];

interface Fixture {
  repo: Item;
  workflow: Item;
  runs: Item[];
  jobs: Item[];
  checks: Map<number, Item>;
  requestCounts: Map<string, number>;
  requests: { url: string; init: RequestInit | undefined }[];
  currentHead?: string;
  badAncestry?: boolean;
  historical?: { manifest: string; bundle: string; workflow: string; wrongPublished?: boolean };
  mutate?: (pathname: string, occurrence: number) => void;
}
let fixture: Fixture;
let responseBytes: number;

function run(overrides: Item = {}): Item {
  return { id: 700, run_attempt: 2, check_suite_id: 800, workflow_id: 900,
    path: WORKFLOW, name: "Extended Validation", head_sha: HEAD, head_branch: "main", event: "push",
    html_url: `https://github.com/${REPO}/actions/runs/700`, repository: fixture.repo,
    head_repository: fixture.repo, status: "completed", conclusion: "success", created_at: START,
    updated_at: END, run_started_at: START, referenced_workflows: [], ...overrides };
}
function makeFixture(): Fixture {
  const value: Fixture = { repo: { id: 101, name: "example", full_name: REPO, private: false,
    visibility: "public", default_branch: "main", owner: { login: "OMT-Global", id: 10, type: "Organization" },
    fork: false, archived: false, disabled: false }, workflow: { id: 900, path: WORKFLOW, name: "Extended Validation", state: "active" },
    runs: [], jobs: [], checks: new Map(), requestCounts: new Map(), requests: [] };
  const names = [
    ["Detect Extended Validation Scope", "Run dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d"],
    ["Fast Checks", "Run fast checks"], ["Extended Checks", "Run extended validation"],
    ["Validate Secrets", "Scan repository for secret patterns"], ["Extended Validation Gate", "Check extended validation jobs"]
  ];
  for (const [index, [name, stepName]] of names.entries()) {
    const id = 1000 + index;
    const checkId = 2000 + index;
    const htmlUrl = `https://github.com/${REPO}/actions/runs/700/job/${id}`;
    const steps: Item[] = [{ number: 1, name: "Set up job", status: "completed", conclusion: "success", started_at: START, completed_at: START }];
    if (index !== 4) steps.push({ number: 2, name: "Run actions/checkout@11d5960a326750d5838078e36cf38b85af677262", status: "completed", conclusion: "success", started_at: START, completed_at: START });
    steps.push({ number: steps.length + 1, name: stepName, status: "completed", conclusion: "success", started_at: START, completed_at: END });
    value.jobs.push({ id, run_id: 700, run_attempt: 2, head_sha: HEAD, head_branch: "main", workflow_name: "Extended Validation",
      name, status: "completed", conclusion: "success", started_at: START, completed_at: END, html_url: htmlUrl,
      check_run_url: `https://api.github.com${PREFIX}/check-runs/${checkId}`,
      steps });
    value.checks.set(checkId, { id: checkId, name, status: "completed", conclusion: "success", head_sha: HEAD,
      started_at: START, completed_at: END, html_url: htmlUrl, app: { id: 15368 }, check_suite: { id: 800 } });
  }
  return value;
}

function policy(archetype = "generic-empty"): PolicyObservation {
  const handle = Object.freeze({ status: "observed" }) as unknown as PolicyObservation;
  policyFixtures.set(handle, Object.freeze({
    repository: { repository: REPO, id: 101, defaultBranch: "main", head: fixture.currentHead ?? HEAD, tree: "b".repeat(40) },
    workflow: { path: WORKFLOW, text: workflowText, sha256: workflowSha }, manifest: { archetype: { kind: archetype } },
    source: { policy: { version: "2.0.0" } }, sourceBinding: { ref: "2".repeat(40), commit: "2".repeat(40), canonicalSha256: "2".repeat(64) }
  }));
  return handle;
}
function response(url: string, value: unknown): Response {
  const body = JSON.stringify(value); responseBytes += Buffer.byteLength(body);
  const result = new Response(body, { status: 200, headers: {
    "content-type": "application/json", "content-length": String(Buffer.byteLength(body))
  } });
  Object.defineProperty(result, "url", { value: url });
  return result;
}
function installFetch(): void {
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    fixture.requests.push({ url: url.href, init });
    if (url.origin !== "https://api.github.com") throw new Error("unexpected origin");
    if (url.pathname === "/repos/OMT-Global/flow") return response(url.href, { ...fixture.repo, id: 1232476439, full_name: "OMT-Global/flow" });
    if (!url.pathname.startsWith(PREFIX)) throw new Error("unexpected endpoint");
    const occurrence = (fixture.requestCounts.get(url.pathname) ?? 0) + 1;
    fixture.requestCounts.set(url.pathname, occurrence);
    fixture.mutate?.(url.pathname, occurrence);
    if (url.pathname === PREFIX) return response(url.href, fixture.repo);
    if (url.pathname === `${PREFIX}/git/ref/heads/main`) return response(url.href, { ref: "refs/heads/main", object: { type: "commit", sha: fixture.currentHead ?? HEAD } });
    if (url.pathname.startsWith(`${PREFIX}/compare/`)) return response(url.href, { status: fixture.badAncestry ? "diverged" : "ahead", base_commit: { sha: HEAD },
      merge_base_commit: { sha: HEAD }, total_commits: 1, commits: [{ sha: fixture.currentHead }] });
    if (url.pathname === `${PREFIX}/actions/workflows/extended-validation.yml`) return response(url.href, fixture.workflow);
    if (url.pathname === `${PREFIX}/actions/workflows/900/runs`) {
      const page = Number(url.searchParams.get("page") ?? "1");
      const result = response(url.href, { total_count: fixture.runs.length, workflow_runs: fixture.runs.slice((page - 1) * 100, page * 100) });
      if (page * 100 < fixture.runs.length) {
        const next = new URL(url); next.searchParams.set("page", String(page + 1));
        result.headers.set("link", `<${next.href}>; rel="next"`);
      }
      return result;
    }
    const detail = new RegExp(`^${PREFIX}/actions/runs/([0-9]+)$`).exec(url.pathname);
    if (detail) return response(url.href, fixture.runs.find((entry) => entry.id === Number(detail[1])));
    const jobs = new RegExp(`^${PREFIX}/actions/runs/([0-9]+)/attempts/([0-9]+)/jobs$`).exec(url.pathname);
    if (jobs) {
      const selected = Number(jobs[1]) === 700 ? fixture.jobs : [];
      return response(url.href, { total_count: selected.length, jobs: selected });
    }
    const check = new RegExp(`^${PREFIX}/check-runs/([0-9]+)$`).exec(url.pathname);
    if (check) return response(url.href, fixture.checks.get(Number(check[1])));
    throw new Error(`unhandled test endpoint ${url.pathname}`);
  }));
}
function pair(index: number, updates: Item): void {
  Object.assign(fixture.jobs[index]!, updates);
  Object.assign(fixture.checks.get(2000 + index)!, updates);
}
function commandStep(index: number): Item { return items(fixture.jobs[index]!.steps).at(-1)!; }

beforeEach(() => {
  fixture = makeFixture(); responseBytes = 0;
  fixture.runs.push(run());
  installFetch();
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function historicalFixture(): Promise<void> {
  const bundle = { ...JSON.parse(readFileSync(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8")), version: "1.0.1" };
  const raw = { version: 1 as const, project: { owner: "OMT-Global", name: "example", visibility: "public" as const, defaultBranch: "main" },
    archetype: { kind: "generic-empty" as const }, repo: { class: "cli" as const },
    ci: { codeqlLanguages: ["javascript-typescript" as const] },
    policy: { flow: { ref: "c".repeat(40), sha256: flowPolicyDigest(bundle), bundlePath: "policy/flow-public-standard.json" } } };
  const manifest = normalizeManifest(raw); const policy = resolveFlowPolicy(manifest, bundle, manifest.policy!.flow!);
  const workflow = (await resolveRepositoryProjection(manifest, "/", policy)).files.find((file) => file.path === WORKFLOW)!.contents;
  fixture.currentHead = "e".repeat(40);
  fixture.historical = { manifest: JSON.stringify(raw), bundle: JSON.stringify(bundle), workflow };
}

describe("historical completed managed CI", () => {
  it("verifies ancestor source, published policy and exact old workflow/run despite a later current head", async () => {
    await historicalFixture(); const source = policy(); const result = await observeManagedCi(source, { atCommit: HEAD });
    expect(result.status).toBe("observed");
    expect(result.requests).toBe(fixture.requests.length); expect(result.receivedBytes).toBe(responseBytes);
    expect(readOwnedCiObservation(result)).toMatchObject({ policy: source, head: HEAD, policyVersion: "1.0.1",
      policyDigest: flowPolicyDigest(JSON.parse(fixture.historical!.bundle)), run: { id: 700, attempt: 2 } });
    expect(fixture.requests.some((call) => call.url.includes(`/compare/${HEAD}...${fixture.currentHead}`))).toBe(true);
  });
  it.each(["unrelated ancestry", "unpublished policy", "different workflow", "wrong historical run", "changed current head"])("refuses %s", async (kind) => {
    await historicalFixture(); const source = policy();
    if (kind === "unrelated ancestry") fixture.badAncestry = true;
    if (kind === "unpublished policy") fixture.historical!.wrongPublished = true;
    if (kind === "different workflow") fixture.historical!.workflow += "# changed\n";
    if (kind === "wrong historical run") fixture.runs[0]!.head_sha = fixture.currentHead;
    if (kind === "changed current head") fixture.mutate = (pathname, occurrence) => {
      if (pathname.endsWith("/git/ref/heads/main") && occurrence > 1) fixture.currentHead = "f".repeat(40);
    };
    const result = await observeManagedCi(source, { atCommit: HEAD });
    expect(result.status).not.toBe("observed"); expect(() => readOwnedCiObservation(result)).toThrow();
  });
});

describe("actual current native CI observation", () => {
  it("binds the exact native run attempt, executed jobs, checks and private policy owner", async () => {
    const source = policy();
    const result = await observeManagedCi(source);
    expect(result.status).toBe("observed");
    expect(result.run).toEqual({ id: 700, attempt: 2, url: `https://github.com/${REPO}/actions/runs/700` });
    const owned = readOwnedCiObservation(result);
    expect(owned.policy).toBe(source);
    expect(owned.run).toEqual({ id: 700, attempt: 2, suiteId: 800, event: "push" });
    expect(owned.jobs).toHaveLength(5);
    expect(owned.evidenceSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(() => readOwnedCiObservation({ ...result })).toThrow();
    expect(fixture.requestCounts.get(`${PREFIX}/actions/runs/700/attempts/2/jobs`)).toBe(2);
    expect(fixture.requests.every(({ init }) => init?.method === "GET" && init.credentials === "omit" && init.redirect === "error")).toBe(true);
    expect(fixture.requests.every(({ init }) => !new Headers(init?.headers).has("authorization"))).toBe(true);
  });

  it("does not require an undocumented job-attempt property or a modern-only native URL form", async () => {
    for (const [index, job] of fixture.jobs.entries()) {
      delete job.run_attempt;
      job.html_url = `https://github.com/${REPO}/runs/700/jobs/${job.id}`;
      fixture.checks.get(2000 + index)!.html_url = `https://github.com/${REPO}/runs/${2000 + index}`;
    }
    expect((await observeManagedCi(policy())).status).toBe("observed");
  });

  it("accepts documented RFC3339 offsets while rejecting invalid calendar dates", async () => {
    for (const job of fixture.jobs) {
      for (const step of items(job.steps)) { step.started_at = "2026-11-09T04:00:00.000-08:00"; step.completed_at = "2026-11-09T04:05:00.000-08:00"; }
    }
    expect((await observeManagedCi(policy())).status).toBe("observed");
    commandStep(1).started_at = "2026-02-31T04:00:00Z";
    expect((await observeManagedCi(policy())).status).toBe("incomplete");
  });

  it.each(["schedule", "workflow_dispatch"])("requires the actual full-suite preset for %s", async (event) => {
    fixture.runs[0]!.event = event;
    commandStep(0).name = "Run full suite for nightly or manual invocations";
    Object.assign(items(fixture.jobs[0]!.steps)[1]!, { conclusion: "skipped", started_at: null, completed_at: null });
    expect((await observeManagedCi(policy())).status).toBe("observed");
  });

  it("permits conditional non-validation skips without accepting a skipped validation command", async () => {
    items(fixture.jobs[0]!.steps).push({ number: 4, name: "Run full suite for nightly or manual invocations", status: "completed", conclusion: "skipped" });
    expect((await observeManagedCi(policy())).status).toBe("observed");
    commandStep(1).conclusion = "skipped";
    const result = await observeManagedCi(policy());
    expect(result.status).toBe("pending");
    expect(() => readOwnedCiObservation(result)).toThrow();
  });

  it.each(["skipped", "neutral"])("never promotes a %s validation job under a green run", async (conclusion) => {
    pair(1, { conclusion, started_at: null, completed_at: null });
    fixture.jobs[1]!.steps = [];
    expect((await observeManagedCi(policy())).status).toBe("pending");
  });

  it.each(["failure", "cancelled", "timed_out", "action_required"])("reports a native %s as failed", async (conclusion) => {
    fixture.runs[0]!.conclusion = conclusion;
    const result = await observeManagedCi(policy());
    expect(result.status).toBe("failed");
    expect(() => readOwnedCiObservation(result)).toThrow();
  });

  it("reports actual job/step failure even if the run or job summary is green", async () => {
    pair(2, { conclusion: "failure" });
    expect((await observeManagedCi(policy())).status).toBe("failed");
    pair(2, { conclusion: "success" });
    commandStep(2).conclusion = "failure";
    expect((await observeManagedCi(policy())).status).toBe("failed");
  });

  it("reports missing validations as pending and rejects extra or duplicate job profiles", async () => {
    const last = fixture.jobs.pop()!;
    expect((await observeManagedCi(policy())).status).toBe("pending");
    fixture.jobs.push(last, { ...last, id: 9999 });
    expect((await observeManagedCi(policy())).status).toBe("unsupported");
    fixture.jobs.pop();
    fixture.jobs[4]!.name = "Fast Checks";
    expect((await observeManagedCi(policy())).status).toBe("unsupported");
  });

  it("does not choose an older passing run over a newer pending run or a newly rerun older ID", async () => {
    fixture.runs.push(run({ id: 701, status: "queued", conclusion: null,
      html_url: `https://github.com/${REPO}/actions/runs/701`, updated_at: "2026-11-09T12:06:00Z" }));
    const newer = await observeManagedCi(policy());
    expect(newer.status).toBe("pending");
    expect(newer.run?.id).toBe(701);
    fixture.runs[1]!.id = 699;
    fixture.runs[1]!.html_url = `https://github.com/${REPO}/actions/runs/699`;
    fixture.runs[1]!.run_attempt = 3;
    const rerun = await observeManagedCi(policy());
    expect(rerun.status).toBe("pending");
    expect(rerun.run).toMatchObject({ id: 699, attempt: 3 });
  });

  it("keeps no native success when there is no qualifying run", async () => {
    fixture.runs.length = 0;
    const result = await observeManagedCi(policy());
    expect(result.status).toBe("pending");
    expect(result.reason).toBe("ci-no-run");
    expect(() => readOwnedCiObservation(result)).toThrow();
  });

  it.each([
    ["wrong repository", (value: Fixture) => { object(value.runs[0]!.repository).id = 999; }],
    ["wrong head", (value: Fixture) => { value.runs[0]!.head_sha = "c".repeat(40); }],
    ["wrong workflow", (value: Fixture) => { value.runs[0]!.workflow_id = 999; }],
    ["wrong suite", (value: Fixture) => { object(value.checks.get(2000)!.check_suite).id = 999; }],
    ["wrong App", (value: Fixture) => { object(value.checks.get(2000)!.app).id = 999; }],
    ["wrong check name", (value: Fixture) => { value.checks.get(2000)!.name = "fake"; }],
    ["wrong attempt", (value: Fixture) => { value.jobs[0]!.run_attempt = 3; }],
    ["wrong run", (value: Fixture) => { value.jobs[0]!.run_id = 701; }],
    ["wrong check URL", (value: Fixture) => { value.jobs[0]!.check_run_url = "https://evil.example/check-runs/2000"; }],
    ["wrong job URL", (value: Fixture) => { value.jobs[0]!.html_url = `https://github.com/${REPO}/actions/runs/999/job/1000`; }]
  ] as const)("rejects %s native associations", async (_, mutate) => {
    mutate(fixture);
    const result = await observeManagedCi(policy());
    expect(result.status).toBe("incomplete");
    expect(() => readOwnedCiObservation(result)).toThrow();
    expect(fixture.requests.every(({ url }) => url.startsWith(`https://api.github.com${PREFIX}`))).toBe(true);
  });

  it("rejects unsupported native event and reusable-workflow profiles", async () => {
    fixture.runs[0]!.event = "pull_request";
    expect((await observeManagedCi(policy())).status).toBe("unsupported");
    fixture.runs[0]!.event = "push";
    fixture.runs[0]!.referenced_workflows = [{ path: "unreviewed/workflow.yml" }];
    expect((await observeManagedCi(policy())).status).toBe("unsupported");
  });

  it.each(["attempt", "jobs", "check", "new run", "workflow"])("rejects changed %s during collection", async (kind) => {
    fixture.mutate = (pathname, occurrence) => {
      if (kind === "attempt" && pathname.endsWith("/actions/runs/700") && occurrence === 2) fixture.runs[0]!.run_attempt = 3;
      if (kind === "jobs" && pathname.endsWith("/attempts/2/jobs") && occurrence === 2) fixture.jobs[0]!.name = "changed";
      if (kind === "check" && pathname.endsWith("/check-runs/2000") && occurrence === 2) fixture.checks.get(2000)!.completed_at = "2026-11-09T12:04:00Z";
      if (kind === "new run" && pathname.endsWith("/workflows/900/runs") && occurrence === 2) fixture.runs.push(run({ id: 701, html_url: `https://github.com/${REPO}/actions/runs/701`, updated_at: "2026-11-09T12:06:00Z" }));
      if (kind === "workflow" && pathname.endsWith("/workflows/extended-validation.yml") && occurrence === 2) fixture.workflow.state = "disabled_manually";
    };
    const result = await observeManagedCi(policy());
    expect(["incomplete", "unsupported"]).toContain(result.status);
    expect(() => readOwnedCiObservation(result)).toThrow();
  });

  it("rejects copied policy descriptions before any network request", async () => {
    const result = await observeManagedCi({ ...policy() });
    expect(result.status).toBe("incomplete");
    expect(fixture.requests).toHaveLength(0);
  });

  it("honors cancellation with no accepted native observation", async () => {
    const controller = new AbortController();
    controller.abort();
    const result = await observeManagedCi(policy(), { signal: controller.signal });
    expect(result.status).toBe("incomplete");
    expect(() => readOwnedCiObservation(result)).toThrow();
  });

  it("rejects an invalid cancellation input before network reads", async () => {
    const result = await observeManagedCi(policy(), { signal: "invalid" as unknown as AbortSignal });
    expect(result.status).toBe("incomplete");
    expect(fixture.requests).toHaveLength(0);
  });

  it.each([0, 1, 2, 3])("rejects missing or skipped checkout despite green job %i", async (index) => {
    const checkout = items(fixture.jobs[index]!.steps).splice(1, 1)[0]!;
    expect((await observeManagedCi(policy())).status).toBe("pending");
    items(fixture.jobs[index]!.steps).splice(1, 0, { ...checkout, conclusion: "skipped", started_at: null, completed_at: null });
    expect((await observeManagedCi(policy())).status).toBe("pending");
  });

  it.each([
    ["nextjs-web", "Run actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"],
    ["node-ts-service", "Run actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"],
    ["python-service", "Run actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"]
  ])("requires actual declared setup for %s validation jobs", async (kind, setupName) => {
    expect((await observeManagedCi(policy(kind))).status).toBe("pending");
    for (const index of [1, 2]) {
      const steps = items(fixture.jobs[index]!.steps);
      commandStep(index).number = 4;
      steps.splice(2, 0, { number: 3, name: setupName, status: "completed", conclusion: "success", started_at: START, completed_at: START });
    }
    expect((await observeManagedCi(policy(kind))).status).toBe("observed");
    items(fixture.jobs[2]!.steps)[2]!.conclusion = "skipped";
    expect((await observeManagedCi(policy(kind))).status).toBe("pending");
  });

  it("rejects the provider's exact 1000-run search cap even with ten apparently complete pages", async () => {
    fixture.runs.push(...Array.from({ length: 999 }, (_, index) => run({ id: 10000 + index,
      html_url: `https://github.com/${REPO}/actions/runs/${10000 + index}`, updated_at: START })));
    const result = await observeManagedCi(policy());
    expect(result.status).toBe("incomplete");
    expect(result.reason).toBe("ci-run-limit");
    expect(() => readOwnedCiObservation(result)).toThrow();
    expect(fixture.requestCounts.get(`${PREFIX}/actions/workflows/900/runs`)).toBe(10);
  });

  it.each(["pending rerun", "success summary"])("does not resolve tied latest native timestamps using IDs: %s", async (kind) => {
    fixture.runs.push(run({ id: 699, run_attempt: 3, html_url: `https://github.com/${REPO}/actions/runs/699`,
      updated_at: END, run_started_at: END, ...(kind === "pending rerun" ? { status: "queued", conclusion: null } : {}) }));
    const result = await observeManagedCi(policy());
    expect(result.status).toBe("incomplete");
    expect(result.reason).toBe("ci-ambiguous-run");
    expect(() => readOwnedCiObservation(result)).toThrow();
  });
});
