import { createHash } from "node:crypto";
import { parseDocument } from "yaml";
import { normalizeManifest } from "./manifest.js";
import { flowPolicyDigest, resolveFlowPolicy } from "./policy.js";
import { resolveRepositoryProjection } from "./render.js";

import { POLICY_PUBLISHER, readOwnedPolicyObservation, type OwnedPolicyObservation, type PolicyObservation } from "./upgrade-policy.js";
import {
  boundedValue, ObservationFailure, PublicObservationRead, objectId, positiveId, publicHead,
  publicRepository, readPublicFile, record, repositoryPath, resolvePublicCommit
} from "./upgrade-public-read.js";

const WORKFLOW = ".github/workflows/extended-validation.yml";
const PROFILE = "managed-inline-extended-v1";
const ACTIONS_APP = 15368;
const JOBS = Object.freeze([
  ["Detect Extended Validation Scope", ""],
  ["Fast Checks", "Run fast checks"],
  ["Extended Checks", "Run extended validation"],
  ["Validate Secrets", "Scan repository for secret patterns"],
  ["Extended Validation Gate", "Check extended validation jobs"]
] as const);
const EVENTS = new Set(["push", "schedule", "workflow_dispatch"]);
const FAILED = new Set(["failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale"]);
type Value = Record<string, unknown>;
type Status = "observed" | "pending" | "failed" | "unsupported" | "incomplete";

export interface CiObservation {
  readonly status: Status;
  readonly repository: string;
  readonly head: string;
  readonly profile: typeof PROFILE;
  readonly workflowId?: number;
  readonly run?: Readonly<{ id: number; attempt: number; url: string }>;
  readonly reason?: string;
  readonly requests: number;
  readonly receivedBytes: number;
}
export interface OwnedCiObservation {
  readonly observationWindow: Readonly<{ beganMonotonic: number; endedMonotonic: number }>;
  readonly policy: PolicyObservation;
  readonly repositoryId: number;
  readonly head: string;
  readonly workflowId: number;
  readonly workflowSha256: string;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly policyRef: string;
  readonly policyCommit: string;
  readonly run: Readonly<{ id: number; attempt: number; suiteId: number; event: string }>;
  readonly jobs: readonly Readonly<{ id: number; checkId: number; name: string }>[];
  readonly evidenceSha256: string;
}
const observations = new WeakMap<CiObservation, OwnedCiObservation>();
const fail = (code: string): never => { throw new ObservationFailure(code); };
const demand = (value: unknown): void => { if (!value) fail("ci-invalid-response"); };
const digest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");

type CiSource = Pick<OwnedPolicyObservation, "repository" | "manifest" | "workflow"> & { policyVersion: string; policyDigest: string; policyRef: string; policyCommit: string };
async function selectCiSource(owned: OwnedPolicyObservation, atCommit: string | undefined, read: PublicObservationRead): Promise<CiSource> {
  if (atCommit === undefined || atCommit === owned.repository.head) return { ...owned,
    policyVersion: owned.source.policy.version, policyDigest: owned.sourceBinding.canonicalSha256, policyRef: owned.sourceBinding.ref, policyCommit: owned.sourceBinding.commit };
  const head = objectId(atCommit); const repository = owned.repository.repository;
  const ancestry = record((await read.json(`${repositoryPath(repository)}/compare/${head}...${owned.repository.head}`)).value);
  demand(ancestry.status === "ahead" && record(ancestry.base_commit).sha === head && record(ancestry.merge_base_commit).sha === head &&
    Number.isSafeInteger(ancestry.total_commits) && Number(ancestry.total_commits) > 0 && Number(ancestry.total_commits) <= 250 &&
    Array.isArray(ancestry.commits) && ancestry.commits.length === ancestry.total_commits && ancestry.commits.some((commit) => record(commit).sha === owned.repository.head));
  const parse = (text: string) => {
    const document = parseDocument(text, { uniqueKeys: true, customTags: [], schema: "core" });
    demand(!document.errors.length && !document.warnings.length);
    const value: unknown = document.toJS({ maxAliasCount: 0 }); boundedValue(value); return record(value);
  };
  const manifestFile = await readPublicFile(read, repository, head, "project.bootstrap.yaml");
  const manifest = normalizeManifest(parse(manifestFile.text) as Parameters<typeof normalizeManifest>[0]);
  demand(manifestFile.mode === "100644" && !manifest.unknownSettings.length && manifest.policy?.flow &&
    `${manifest.project.owner}/${manifest.project.name}` === repository && manifest.project.visibility === "public");
  const pin = manifest.policy!.flow!;
  const local = await readPublicFile(read, repository, head, pin.bundlePath);
  const parsed = parse(local.text); const policy = resolveFlowPolicy(manifest, parsed, pin);
  await publicRepository(read, POLICY_PUBLISHER); const commit = await resolvePublicCommit(read, POLICY_PUBLISHER.repository, pin.ref);
  const published = await readPublicFile(read, POLICY_PUBLISHER.repository, commit, POLICY_PUBLISHER.bundlePath);
  demand(flowPolicyDigest(parse(published.text), pin.canonicalization) === flowPolicyDigest(parsed, pin.canonicalization));
  const expected = (await resolveRepositoryProjection(manifest, "/", policy)).files.find((file) => file.path === WORKFLOW);
  const workflow = await readPublicFile(read, repository, head, WORKFLOW);
  demand(expected && !expected.executable && workflow.mode === "100644" && workflow.text === expected.contents);
  demand(await resolvePublicCommit(read, POLICY_PUBLISHER.repository, pin.ref) === commit); await publicRepository(read, POLICY_PUBLISHER);
  return { repository: { ...owned.repository, head }, manifest, workflow: { path: WORKFLOW, text: workflow.text, sha256: workflow.sha256 },
    policyVersion: policy.policy.version, policyDigest: policy.source.sha256, policyRef: pin.ref, policyCommit: commit };
}

function timestamp(value: unknown): number {
  demand(typeof value === "string");
  const text = value as string;
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,3}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(text);
  demand(match);
  const wall = `${match![1]}.${(match![2] ?? "").padEnd(3, "0")}Z`;
  demand(Number.isFinite(Date.parse(wall)) && new Date(wall).toISOString() === wall);
  const result = Date.parse(text);
  demand(Number.isFinite(result));
  return result;
}

function terminal(value: Value): "success" | "pending" | "failed" {
  demand(typeof value.status === "string" && ["queued", "in_progress", "completed", "waiting", "pending", "requested"].includes(value.status));
  if (value.status !== "completed") {
    demand(value.conclusion === null);
    return "pending";
  }
  demand(typeof value.conclusion === "string");
  if (value.conclusion === "success") return "success";
  if (FAILED.has(value.conclusion as string)) return "failed";
  if (["skipped", "neutral"].includes(value.conclusion as string)) return "pending";
  return fail("ci-invalid-response");
}

function repositoryBinding(value: unknown, repository: string, id: number): void {
  const repo = record(value);
  demand(repo.id === id && repo.full_name === repository && repo.private === false);
}

function runBinding(value: unknown, repository: string, id: number, branch: string, head: string, workflowId: number): Value {
  const run = record(value);
  const runId = positiveId(run.id);
  positiveId(run.run_attempt);
  positiveId(run.check_suite_id);
  demand(run.workflow_id === workflowId && run.path === WORKFLOW && run.name === "Extended Validation" &&
    run.head_sha === head && run.head_branch === branch && typeof run.event === "string" &&
    run.html_url === `https://github.com/${repository}/actions/runs/${runId}`);
  if (!EVENTS.has(run.event as string)) fail("ci-unsupported-event");
  repositoryBinding(run.repository, repository, id);
  repositoryBinding(run.head_repository, repository, id);
  demand(timestamp(run.created_at) <= timestamp(run.updated_at));
  if (run.referenced_workflows !== undefined) {
    demand(Array.isArray(run.referenced_workflows));
    if ((run.referenced_workflows as unknown[]).length) fail("ci-unsupported-reusable");
  }
  terminal(run);
  return run;
}

function runFacts(run: Value): unknown {
  return [run.id, run.run_attempt, run.workflow_id, run.check_suite_id, run.head_sha, run.head_branch,
    run.event, run.status, run.conclusion, run.created_at, run.updated_at, run.run_started_at];
}

async function currentRun(read: PublicObservationRead, prefix: string, repository: string, id: number,
  branch: string, head: string, workflowId: number): Promise<{ run?: Value; fingerprint: string }> {
  const values = await readPages(read,
    `${prefix}/actions/workflows/${workflowId}/runs?branch=${encodeURIComponent(branch)}&head_sha=${head}`, "workflow_runs");
  // GitHub caps these filtered searches; exactly reaching the cap is not proof of completeness.
  if (values.length >= 1000) fail("ci-run-limit");
  const runs = values.map((value) => runBinding(value, repository, id, branch, head, workflowId));
  demand(new Set(runs.map((run) => run.id)).size === runs.length);
  runs.sort((left, right) => timestamp(right.updated_at) - timestamp(left.updated_at) || Number(right.id) - Number(left.id));
  // Native IDs do not order an older run's new attempt within a timestamp tie.
  if (runs.length > 1 && timestamp(runs[0]!.updated_at) === timestamp(runs[1]!.updated_at)) fail("ci-ambiguous-run");
  const fingerprint = digest(runs.map(runFacts));
  return runs.length ? { run: runs[0]!, fingerprint } : { fingerprint };
}

function stepFacts(value: unknown): unknown {
  const step = record(value);
  positiveId(step.number);
  demand(typeof step.name === "string" && step.name.length > 0 && step.name.length <= 1024);
  terminal(step);
  return [step.number, step.name, step.status, step.conclusion, step.started_at, step.completed_at];
}

function completedTimes(value: Value): void {
  demand(timestamp(value.started_at) <= timestamp(value.completed_at));
}

async function jobEvidence(read: PublicObservationRead, prefix: string, repository: string, branch: string,
  head: string, run: Value, setup: string | undefined): Promise<{ state: "success" | "pending" | "failed"; jobs: OwnedCiObservation["jobs"]; fingerprint: string }> {
  const runId = positiveId(run.id);
  const attempt = positiveId(run.run_attempt);
  const values = await readPages(read, `${prefix}/actions/runs/${runId}/attempts/${attempt}/jobs`, "jobs");
  const jobs = values.map(record);
  demand(new Set(jobs.map((job) => positiveId(job.id))).size === jobs.length);
  if (jobs.length > JOBS.length) fail("ci-unsupported-jobs");
  let state: "success" | "pending" | "failed" = jobs.length === JOBS.length ? "success" : "pending";
  const facts: unknown[] = [];
  const bindings: { id: number; checkId: number; name: string }[] = [];
  const names = new Set<string>();
  for (const job of jobs) {
    const id = positiveId(job.id);
    demand(job.run_id === runId && (job.run_attempt === undefined || job.run_attempt === attempt) && job.head_sha === head &&
      job.head_branch === branch && job.workflow_name === "Extended Validation" && typeof job.name === "string");
    const expected = JOBS.find(([name]) => name === job.name);
    if (!expected || names.has(expected[0])) throw new ObservationFailure("ci-unsupported-jobs");
    names.add(expected[0]);
    const jobUrl = `https://github.com/${repository}/actions/runs/${runId}/job/${id}`;
    const legacyJobUrl = `https://github.com/${repository}/runs/${runId}/jobs/${id}`;
    demand([jobUrl, legacyJobUrl].includes(job.html_url as string) && typeof job.check_run_url === "string");
    const match = new RegExp(`^https://api\\.github\\.com${prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/check-runs/([1-9][0-9]*)$`).exec(job.check_run_url as string);
    demand(match);
    const checkId = positiveId(Number(match![1]));
    const check = record((await read.json(`${prefix}/check-runs/${checkId}`)).value);
    demand(check.id === checkId && check.head_sha === head && check.name === job.name &&
      record(check.check_suite).id === run.check_suite_id && record(check.app).id === ACTIONS_APP &&
      [jobUrl, legacyJobUrl, `https://github.com/${repository}/runs/${checkId}`].includes(check.html_url as string) &&
      check.status === job.status && check.conclusion === job.conclusion);
    const result = terminal(job);
    if (result === "failed") state = "failed";
    else if (result === "pending" && state !== "failed") state = "pending";
    if (result === "success") {
      completedTimes(job);
      completedTimes(check);
      demand(Array.isArray(job.steps) && job.steps.length > 0 && job.steps.length <= 200);
      const steps = (job.steps as unknown[]).map(record);
      demand(new Set(steps.map((step) => positiveId(step.number))).size === steps.length);
      steps.forEach(stepFacts);
      const requiredNames = [expected[1] || (run.event === "push"
        ? "Run dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d"
        : "Run full suite for nightly or manual invocations")];
      if (expected[0] !== "Extended Validation Gate" && (expected[0] !== "Detect Extended Validation Scope" || run.event === "push")) {
        requiredNames.push("Run actions/checkout@11d5960a326750d5838078e36cf38b85af677262");
      }
      if (setup && ["Fast Checks", "Extended Checks"].includes(expected[0])) requiredNames.push(setup);
      for (const name of requiredNames) {
        const required = steps.filter((step) => step.name === name);
        if (required.length !== 1 || terminal(required[0]!) !== "success") state = state === "failed" ? state : "pending";
        else completedTimes(required[0]!);
      }
      if (steps.some((step) => terminal(step) === "failed")) state = "failed";
    }
    facts.push([id, job.run_id, job.run_attempt, job.head_sha, job.head_branch, job.name, job.status,
      job.conclusion, job.started_at, job.completed_at, job.steps, check]);
    bindings.push(Object.freeze({ id, checkId, name: expected[0] }));
  }
  bindings.sort((left, right) => left.id - right.id);
  facts.sort((left, right) => Number((left as unknown[])[0]) - Number((right as unknown[])[0]));
  return { state, jobs: Object.freeze(bindings), fingerprint: digest(facts) };
}

/** A current native CI observation; it supplies no pilot, human approval or publication authority. */
export async function observeManagedCi(policy: PolicyObservation, options: { signal?: AbortSignal; atCommit?: string } = {}): Promise<CiObservation> {
  const parent = options.signal;
  const atCommit = options.atCommit;
  const validSignal = parent === undefined || parent instanceof AbortSignal;
  let read: PublicObservationRead | undefined;
  let repository = "";
  let head = "";
  let workflowId: number | undefined;
  let runDescription: CiObservation["run"];
  let status: Status = "incomplete";
  let reason: string | undefined;
  let owned: OwnedCiObservation | undefined;
  try {
    if (!validSignal) fail("ci-invalid-input");
    const current = readOwnedPolicyObservation(policy);
    read = new PublicObservationRead(parent, current.repository.repository);
    await publicRepository(read, current.repository);
    demand(await publicHead(read, current.repository.repository, current.repository.defaultBranch) === current.repository.head);
    const source = await selectCiSource(current, atCommit, read);
    const kind = source.manifest.archetype.kind;
    const setup = ["nextjs-web", "node-ts-service"].includes(kind)
      ? "Run actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
      : kind === "python-service" ? "Run actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" : undefined;
    ({ repository, head } = source.repository);
    objectId(head);
    demand(source.workflow.path === WORKFLOW);
    const prefix = `/repos/${repository.split("/").map(encodeURIComponent).join("/")}`;
    await publicRepository(read, source.repository);
    if (await publicHead(read, repository, source.repository.defaultBranch) !== current.repository.head) fail("ci-changed-head");
    const file = await readPublicFile(read, repository, head, WORKFLOW);
    demand(file.text === source.workflow.text && file.sha256 === source.workflow.sha256);
    const workflow = record((await read.json(`${prefix}/actions/workflows/extended-validation.yml`)).value);
    workflowId = positiveId(workflow.id);
    if (workflow.path !== WORKFLOW || workflow.name !== "Extended Validation" || workflow.state !== "active") fail("ci-unsupported-workflow");
    const selected = await currentRun(read, prefix, repository, source.repository.id, source.repository.defaultBranch, head, workflowId);
    if (!selected.run) {
      status = "pending";
      reason = "ci-no-run";
    } else {
      const runId = positiveId(selected.run.id);
      const run = runBinding((await read.json(`${prefix}/actions/runs/${runId}`)).value,
        repository, source.repository.id, source.repository.defaultBranch, head, workflowId);
      demand(digest(runFacts(run)) === digest(runFacts(selected.run)));
      runDescription = Object.freeze({ id: runId, attempt: positiveId(run.run_attempt), url: run.html_url as string });
      const evidence = await jobEvidence(read, prefix, repository, source.repository.defaultBranch, head, run, setup);
      const repeated = await jobEvidence(read, prefix, repository, source.repository.defaultBranch, head, run, setup);
      if (repeated.fingerprint !== evidence.fingerprint) fail("ci-changed-evidence");
      const runAgain = runBinding((await read.json(`${prefix}/actions/runs/${runId}`)).value,
        repository, source.repository.id, source.repository.defaultBranch, head, workflowId);
      if (digest(runFacts(runAgain)) !== digest(runFacts(run))) fail("ci-changed-evidence");
      const runsAgain = await currentRun(read, prefix, repository, source.repository.id, source.repository.defaultBranch, head, workflowId);
      if (runsAgain.fingerprint !== selected.fingerprint) fail("ci-changed-evidence");
      const runState = terminal(run);
      status = runState === "failed" || evidence.state === "failed" ? "failed"
        : runState === "pending" || evidence.state === "pending" ? "pending" : "observed";
      if (status === "observed") {
        demand(timestamp(run.run_started_at) <= timestamp(run.updated_at));
        owned = Object.freeze({ observationWindow: read.observationWindow, policy, repositoryId: source.repository.id, head, workflowId,
          workflowSha256: source.workflow.sha256, policyVersion: source.policyVersion, policyDigest: source.policyDigest,
          policyRef: source.policyRef, policyCommit: source.policyCommit,
          run: Object.freeze({ id: runId, attempt: positiveId(run.run_attempt), suiteId: positiveId(run.check_suite_id), event: run.event as string }),
          jobs: evidence.jobs, evidenceSha256: digest([runFacts(run), evidence.fingerprint, source.workflow.sha256]) });
      } else reason = status === "failed" ? "ci-validation-failed" : "ci-validation-pending";
    }
    const workflowAgain = record((await read.json(`${prefix}/actions/workflows/extended-validation.yml`)).value);
    if (workflowAgain.id !== workflowId || workflowAgain.path !== WORKFLOW || workflowAgain.state !== "active" || workflowAgain.name !== "Extended Validation") fail("ci-changed-evidence");
    await publicRepository(read, source.repository);
    if (await publicHead(read, repository, source.repository.defaultBranch) !== current.repository.head) fail("ci-changed-head");
    read.check();
  } catch (error) {
    reason = error instanceof ObservationFailure ? error.code : "ci-invalid-input";
    status = reason.startsWith("ci-unsupported") ? "unsupported" : "incomplete";
    owned = undefined;
  } finally { await read?.close(); }
  const result: CiObservation = Object.freeze({ status, repository, head, profile: PROFILE,
    ...(workflowId !== undefined ? { workflowId } : {}), ...(runDescription ? { run: runDescription } : {}),
    ...(reason ? { reason } : {}), requests: read?.stats.requests ?? 0, receivedBytes: read?.stats.receivedBytes ?? 0 });
  if (status === "observed" && owned) observations.set(result, owned);
  return result;
}

export function readOwnedCiObservation(observation: CiObservation): OwnedCiObservation {
  const owned = observations.get(observation);
  if (!owned) throw new Error("CI observation is not bound to a completed native verification.");
  return owned;
}

export async function readPages(read: PublicObservationRead, path: string, property?: string, expectedTotal?: number): Promise<unknown[]> {
  const base = new URL(path, "https://api.github.com");
  if (base.searchParams.has("page") || base.searchParams.has("per_page")) throw new ObservationFailure("invalid-input");
  base.searchParams.set("per_page", "100");
  const result: unknown[] = [];
  const ids = new Set<number>();
  let total: number | undefined;
  for (let page = 1; page <= 10; page++) {
    base.searchParams.set("page", String(page));
    const response = await read.json(base.pathname + base.search, true);
    const value = property ? record(response.value) : { items: response.value, total_count: expectedTotal };
    const field = property ?? "items";
    if (!Array.isArray(value[field]) || value[field].length > 100 || !Number.isSafeInteger(value.total_count) || Number(value.total_count) < 0 || Number(value.total_count) > 1000) throw new ObservationFailure("pagination");
    total ??= Number(value.total_count);
    if (total !== value.total_count) throw new ObservationFailure("changed-evidence");
    for (const item of value[field]) { const id = positiveId(record(item).id); if (ids.has(id)) throw new ObservationFailure("pagination"); ids.add(id); result.push(item); }
    let next = false;
    const relations = new Set<string>();
    for (const item of response.link?.split(/,\s*(?=<)/) ?? []) {
      const match = /^\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(item);
      if (!match || relations.has(match[2]!)) throw new ObservationFailure("pagination");
      relations.add(match[2]!);
      const linked = new URL(match[1]!);
      if (linked.searchParams.getAll("page").length !== 1) throw new ObservationFailure("pagination");
      const linkedPage = linked.searchParams.get("page");
      linked.searchParams.delete("page");
      const expected = new URL(base); expected.searchParams.delete("page");
      const parameters = (url: URL) => JSON.stringify([...url.searchParams.entries()].sort(([ak, av], [bk, bv]) => ak.localeCompare(bk) || av.localeCompare(bv)));
      if (linked.origin !== expected.origin || linked.username || linked.password || linked.hash || linked.pathname !== expected.pathname || parameters(linked) !== parameters(expected) ||
        !linkedPage || !/^[1-9][0-9]*$/.test(linkedPage) || Number(linkedPage) > 10) throw new ObservationFailure("pagination");
      if (match[2] === "next") { if (Number(linkedPage) !== page + 1) throw new ObservationFailure("pagination"); next = true; }
    }
    if (!next) { if (result.length !== total) throw new ObservationFailure("pagination"); return result; }
    if (value[field].length === 0) throw new ObservationFailure("pagination");
  }
  throw new ObservationFailure("pagination");
}
