import { activeUpgradeDecisions, observeUpgradeDecisions, readOwnedDecisionObservation, type DecisionRecord, type GovernanceDecision } from "./upgrade-approval-read.js";
import { parseDocument } from "yaml";
import { normalizeManifest } from "./manifest.js";
import { resolveFlowPolicy } from "./policy.js";
import { discoverPublicManifests, type PublicManifestDiscovery } from "./upgrade-discovery.js";
import { observeManagedCi, readOwnedCiObservation } from "./upgrade-pilot-ci.js";
import { observePublicPolicies, POLICY_PUBLISHER, readOwnedPolicyObservation, type PolicyObservation } from "./upgrade-policy.js";
import { boundedValue, PublicObservationRead, publicHead, publicRepository, readPublicFile, record, repositoryPath, resolvePublicCommit } from "./upgrade-public-read.js";
import { captureRuntimePolicy, freezeRuntimeValue, parseUpgradeRuntimeRequest, readRuntimePolicy, runtimeDemand as demand,
  runtimeDigest, type RuntimePolicy, type UpgradeRuntimeRequest } from "./upgrade-runtime-policy.js";
import { extractPolicyStatements } from "./security-response-markdown.js";
import { classifyPolicyUpgrade, planFleetPolicyUpgrades, type FleetUpgradePlanEntry } from "./upgrades.js";

type ReadCost = Readonly<{ requests: number; receivedBytes: number }>;
type Account = (value: ReadCost | PublicObservationRead) => void;
type Cohort = Extract<GovernanceDecision, { kind: "cohort" }>;
type Outcome = Extract<GovernanceDecision, { kind: "pilot-outcome"; outcome: "passed" }>;
type FailedOutcome = Extract<GovernanceDecision, { kind: "pilot-outcome"; outcome: "failed" }>;
export type GovernanceObservation = Readonly<{ repository: string; repositoryId: number; baseCommit: string; cohortComment: number;
  targetDigest: string; role: "pilot" | "batch"; plan: FleetUpgradePlanEntry; decisionDigest: string; evidenceDigest: string;
  independentReview: "pending"; authority: "none"; publication: "pending" }>;
type OwnedGovernance = Readonly<{ runtimePolicy: RuntimePolicy; request: UpgradeRuntimeRequest; policy: PolicyObservation;
  cohort: Cohort; current: readonly PolicyObservation[]; signal?: AbortSignal }>;
const observations = new WeakMap<GovernanceObservation, OwnedGovernance>();
const equal = (left: unknown, right: unknown) => runtimeDigest(left) === runtimeDigest(right);
const cohortIdentity = (members: Cohort["members"]) => members.map(({ repositoryId, repository, repoClass }) => ({ repositoryId, repository, repoClass })).sort((a, b) => a.repositoryId - b.repositoryId);
const representative = (cohort: Cohort, repoClass: string) => [...cohort.members].filter((item) => item.repoClass === repoClass)
  .sort((a, b) => a.repository < b.repository ? -1 : a.repository > b.repository ? 1 : 0)[0]!;

async function mergedOutcome(policy: PolicyObservation, outcome: Outcome, original: Cohort["members"][number], target: Cohort["target"], signal: AbortSignal, account: Account, historical = false): Promise<string> {
  const owned = readOwnedPolicyObservation(policy); const repo = owned.repository;
  demand(outcome.repositoryId === repo.id && outcome.targetDigest === target.digest && (historical || outcome.mergedCommit === repo.head &&
    outcome.targetDigest === owned.sourceBinding.canonicalSha256 && owned.source.policy.version === target.version), "pilot-target-binding");
  const read = new PublicObservationRead(signal, repo.repository);
  const check = async () => {
    await publicRepository(read, repo);
    demand(await publicHead(read, repo.repository, repo.defaultBranch) === repo.head, "pilot-changed-head");
    const pr = record((await read.json(`${repositoryPath(repo.repository)}/pulls/${outcome.pullNumber}`)).value);
    demand(pr.number === outcome.pullNumber && pr.html_url === `https://github.com/${repo.repository}/pull/${outcome.pullNumber}` &&
      pr.state === "closed" && pr.merged === true && pr.merge_commit_sha === outcome.mergedCommit &&
      record(pr.head).sha === outcome.candidateCommit && record(pr.base).ref === repo.defaultBranch && record(pr.base).sha === original.sourceHead &&
      record(record(pr.base).repo).id === repo.id && record(record(pr.head).repo).id === repo.id, "pilot-not-merged");
    return runtimeDigest(pr);
  };
  try {
    const before = await check();
    const parse = (text: string) => {
      const document = parseDocument(text, { uniqueKeys: true, customTags: [], schema: "core" });
      demand(!document.errors.length && !document.warnings.length, "pilot-original-source");
      const value: unknown = document.toJS({ maxAliasCount: 0 }); boundedValue(value); return record(value);
    };
    const manifestFile = await readPublicFile(read, repo.repository, original.sourceHead, "project.bootstrap.yaml");
    const manifest = normalizeManifest(parse(manifestFile.text) as Parameters<typeof normalizeManifest>[0]);
    demand(manifestFile.mode === "100644" && !manifest.unknownSettings.length && manifest.policy?.flow && manifest.repo.class === original.repoClass &&
      `${manifest.project.owner}/${manifest.project.name}` === original.repository && manifest.project.visibility === "public", "pilot-original-source");
    const bundle = await readPublicFile(read, repo.repository, original.sourceHead, manifest.policy!.flow!.bundlePath);
    const source = resolveFlowPolicy(manifest, parse(bundle.text), manifest.policy!.flow!);
    demand(source.policy.version === original.sourceVersion && source.source.sha256 === original.sourceDigest, "pilot-original-transition");
    account(read);
    const observed = await observeManagedCi(policy, { signal, ...(historical ? { atCommit: outcome.mergedCommit } : {}) });
    account(observed); const ci = readOwnedCiObservation(observed);
    demand(observed.status === "observed" && ci.policy === policy && ci.repositoryId === repo.id && ci.head === outcome.mergedCommit &&
      ci.policyDigest === target.digest && ci.policyVersion === target.version && ci.policyRef === target.ref && ci.policyCommit === target.commit &&
      ci.run.id === outcome.ci.runId && ci.run.attempt === outcome.ci.attempt && ci.evidenceSha256 === outcome.ci.evidenceSha256 &&
      ci.workflowSha256 === outcome.ci.workflowSha256, "pilot-ci-binding");
    demand(await check() === before, "pilot-changed-evidence"); read.check(); return runtimeDigest([before, outcome.ci]);
  } finally { await read.close(); account(read); }
}
async function failedOutcome(outcome: FailedOutcome, original: Cohort["members"][number], signal: AbortSignal, account: Account): Promise<void> {
  const read = new PublicObservationRead(signal, original.repository);
  try {
    const repo = await publicRepository(read, { repository: original.repository, id: original.repositoryId });
    const pr = record((await read.json(`${repositoryPath(repo.repository)}/pulls/${outcome.pullNumber}`)).value);
    demand(pr.number === outcome.pullNumber && pr.html_url === `https://github.com/${repo.repository}/pull/${outcome.pullNumber}` &&
      record(pr.head).sha === outcome.candidateCommit && record(pr.base).sha === original.sourceHead &&
      record(pr.base).ref === repo.defaultBranch && record(record(pr.head).repo).id === repo.id && record(record(pr.base).repo).id === repo.id &&
      (outcome.mergedCommit === undefined ? pr.merged === false : pr.merged === true && pr.merge_commit_sha === outcome.mergedCommit), "failed-pilot-candidate-binding");
    await publicRepository(read, repo); read.check();
  } finally { await read.close(); account(read); }
}
async function acceptedAdr(entry: DecisionRecord, policy: RuntimePolicy, signal: AbortSignal, account: Account): Promise<void> {
  demand(entry.value.kind === "accepted-adr"); if (entry.value.kind !== "accepted-adr") return;
  const source = entry.value.adr; const projection = readRuntimePolicy(policy).projection;
  demand([projection.governance, ...projection.repositories].some((repo) => repo.id === source.repositoryId && repo.repository === source.repository), "adr-scope");
  const read = new PublicObservationRead(signal, source.repository);
  try {
    const repo = await publicRepository(read, { repository: source.repository, id: source.repositoryId, defaultBranch: source.defaultBranch });
    const head = await publicHead(read, repo.repository, repo.defaultBranch);
    if (head !== source.commit) {
      const comparison = record((await read.json(`${repositoryPath(repo.repository)}/compare/${source.commit}...${head}`)).value);
      demand(comparison.status === "ahead" && record(comparison.base_commit).sha === source.commit &&
        record(comparison.merge_base_commit).sha === source.commit && Number(comparison.total_commits) > 0 && Number(comparison.total_commits) <= 250, "adr-ancestry");
    }
    const old = await readPublicFile(read, repo.repository, source.commit, source.path);
    const current = await readPublicFile(read, repo.repository, head, source.path); const statements = extractPolicyStatements(old.text);
    demand(old.mode === "100644" && current.mode === old.mode && current.oid === old.oid && old.sha256 === source.sha256 &&
      statements.kind === "supported" && statements.statements.filter((item) => item.startLine === item.endLine &&
        old.text.split(/\r?\n/)[item.startLine - 1] === "Status: Accepted").length === 1, "adr-not-accepted");
    demand(await publicHead(read, repo.repository, repo.defaultBranch) === head, "adr-changed"); await publicRepository(read, repo);
  } finally { await read.close(); account(read); }
}

/** Complete current observations remain separate from the authenticated historical cohort. No candidate review or write authority is issued. */
export async function observeUpgradeGovernance(runtimePolicy: RuntimePolicy, input: unknown, options: { signal?: AbortSignal } = {}): Promise<GovernanceObservation> {
  const parent = options.signal; const signal = AbortSignal.any([AbortSignal.timeout(300_000), ...(parent ? [parent] : [])]);
  signal.throwIfAborted(); const request = parseUpgradeRuntimeRequest(input); const runtime = readRuntimePolicy(runtimePolicy);
  const { projection, generator } = runtime;
  demand(request.generatorCommit === generator.sourceCommit && projection.repositories.some((repo) => repo.id === request.repositoryId && repo.repository === request.repository), "repository-not-authorized");
  let requests = 0; let bytes = 0; const charged = new WeakMap<PublicObservationRead, ReadCost>();
  const account: Account = (value) => {
    const result = value instanceof PublicObservationRead ? value.stats : value;
    const prior = value instanceof PublicObservationRead ? charged.get(value) : undefined;
    demand(Number.isSafeInteger(result.requests) && Number.isSafeInteger(result.receivedBytes) &&
      result.requests >= (prior?.requests ?? 0) && result.receivedBytes >= (prior?.receivedBytes ?? 0), "governance-budget");
    requests += result.requests - (prior?.requests ?? 0); bytes += result.receivedBytes - (prior?.receivedBytes ?? 0);
    if (value instanceof PublicObservationRead) charged.set(value, result);
    demand(requests <= 10_000 && bytes <= 256 * 1024 ** 2, "governance-budget"); signal.throwIfAborted();
  };
  const freshPolicy = await captureRuntimePolicy(generator, { signal }); account(freshPolicy);
  demand(freshPolicy.projectionDigest === runtimePolicy.projectionDigest, "runtime-policy-changed");
  const discovery = await discoverPublicManifests(projection.organization, { signal }); account(discovery);
  demand(discovery.status === "complete" && discovery.repositories.every((repo) => repo.outcome !== "unsupported"), "fleet-incomplete");
  demand(new Set(discovery.repositories.map((repo) => repo.repositoryId)).size === discovery.repositories.length &&
    new Set(discovery.repositories.map((repo) => repo.repository.toLowerCase())).size === discovery.repositories.length, "fleet-duplicate-identity");
  const current: PolicyObservation[] = [];
  for (const repo of discovery.repositories.filter((item) => item.outcome === "managed")) {
    demand(!repo.fork && !repo.archived && !repo.disabled, "fleet-inactive-member");
    const observed = await observePublicPolicies(discovery, repo, generator, request.target, { signal }); account(observed);
    const owned = readOwnedPolicyObservation(observed);
    demand(owned.repository.id === repo.repositoryId && owned.repository.repository === repo.repository && owned.repository.head === repo.head &&
      owned.manifest.project.visibility === "public" && `${owned.manifest.project.owner}/${owned.manifest.project.name}` === repo.repository, "fleet-policy-identity"); current.push(observed);
  }
  const decisions = await observeUpgradeDecisions(runtimePolicy, { signal }); account(decisions); const all = readOwnedDecisionObservation(decisions).records;
  const active = activeUpgradeDecisions(decisions); const cohorts = all.filter((entry) => entry.value.kind === "cohort");
  demand(cohorts.length > 0, "cohort-required"); const selected = cohorts.at(-1)!; demand(active.includes(selected), "cohort-revoked");
  const cohort = selected.value as Cohort;
  demand(!request.cohortComment || request.cohortComment === selected.commentId, "cohort-not-current");
  for (let index = 0; index < cohorts.length; index++) {
    const item = cohorts[index]!; const value = item.value as Cohort;
    demand(value.organization === projection.organization && (index === 0 ? value.supersedes === undefined :
      value.supersedes === cohorts[index - 1]!.commentId && !!value.reconciliation), "cohort-reconciliation-required");
    demand(new Set(value.members.map((member) => member.repositoryId)).size === value.members.length &&
      new Set(value.members.map((member) => member.repository.toLowerCase())).size === value.members.length &&
      value.members.every((member) => classifyPolicyUpgrade(member.sourceVersion, value.target.version) !== "invalid"), "cohort-invalid-transition");
    demand(new Set(value.inventory.map((item) => item.repositoryId)).size === value.inventory.length &&
      new Set(value.inventory.map((item) => item.repository.toLowerCase())).size === value.inventory.length &&
      equal(value.inventory.filter((item) => item.managed).map(({ repositoryId, repository }) => ({ repositoryId, repository })).sort((a, b) => a.repositoryId - b.repositoryId),
        value.members.map(({ repositoryId, repository }) => ({ repositoryId, repository })).sort((a, b) => a.repositoryId - b.repositoryId)), "cohort-inventory-invalid");
  }
  demand(cohort.target.ref === request.target.ref && cohort.target.digest === request.target.sha256, "cohort-target-mismatch");
  const identities = current.map((value) => { const owned = readOwnedPolicyObservation(value); return { repositoryId: owned.repository.id,
    repository: owned.repository.repository, repoClass: owned.manifest.repo.class! }; }).sort((a, b) => a.repositoryId - b.repositoryId);
  demand(equal(cohortIdentity(cohort.members), identities), "cohort-membership-changed");
  const selectedIdentity = identities.find((entry) => entry.repositoryId === request.repositoryId); demand(selectedIdentity, "selected-repository-missing");
  demand(equal([...cohort.inventory].sort((a, b) => a.repositoryId - b.repositoryId), discovery.repositories.map((repo) => ({ repositoryId: repo.repositoryId,
    repository: repo.repository, managed: repo.outcome === "managed" })).sort((a, b) => a.repositoryId - b.repositoryId)), "cohort-inventory-changed");
  for (const entry of all) if ("cohort" in entry.value) {
    const value = entry.value; const bound = cohorts.find((item) => item.commentId === value.cohort && item.commentId < entry.commentId)?.value as Cohort | undefined;
    demand(bound && bound.target.digest === value.targetDigest && bound.members.some((member) => member.repositoryId === value.repositoryId), "decision-cohort-binding");
  }
  const remediated = (failure: DecisionRecord) => active.some((entry) => entry.value.kind === "remediation" &&
    entry.value.failedComment === failure.commentId && "cohort" in failure.value && entry.value.cohort === failure.value.cohort &&
    entry.value.repositoryId === failure.value.repositoryId && entry.value.targetDigest === failure.value.targetDigest && entry.commentId > failure.commentId);
  const failures = all.filter((entry) => {
    if (entry.value.kind !== "pilot-outcome" || entry.value.outcome !== "failed" || remediated(entry)) return false;
    const value = entry.value; const original = (cohorts.find((item) => item.commentId === value.cohort)!.value as Cohort).members.find((member) => member.repositoryId === value.repositoryId)!;
    return original.repoClass === selectedIdentity!.repoClass || original.repositoryId === request.repositoryId ||
      identities.find((member) => member.repositoryId === original.repositoryId)?.repoClass === selectedIdentity!.repoClass;
  });
  for (const failure of failures) {
    const value = failure.value as FailedOutcome; const original = (cohorts.find((item) => item.commentId === value.cohort)!.value as Cohort).members.find((member) => member.repositoryId === value.repositoryId)!;
    await failedOutcome(value, original, signal, account);
  }
  demand(failures.length === 0, "pilot-failed-remediation-required");
  // A new record cannot silently replace an unfinished representative or target.
  for (const prior of cohorts.slice(0, -1)) {
    const old = prior.value as Cohort;
    for (const repoClass of new Set(old.members.map((member) => member.repoClass))) {
      const pilot = representative(old, repoClass);
      if (repoClass !== selectedIdentity!.repoClass && pilot.repositoryId !== request.repositoryId &&
        identities.find((member) => member.repositoryId === pilot.repositoryId)?.repoClass !== selectedIdentity!.repoClass) continue;
      const completed = active.filter((entry) => entry.value.kind === "pilot-outcome" && entry.value.cohort === prior.commentId &&
        entry.value.repositoryId === pilot.repositoryId && entry.value.outcome === "passed" && entry.value.targetDigest === old.target.digest);
      demand(completed.length <= 1, "ambiguous-pilot-outcome");
      if (completed.length) {
        const currentPilot = current.find((policy) => readOwnedPolicyObservation(policy).repository.id === pilot.repositoryId);
        demand(currentPilot, "historical-pilot-unavailable");
        await mergedOutcome(currentPilot!, completed[0]!.value as Outcome, pilot, old.target, signal, account, true);
      } else demand(cohort.members.some((member) => member.repositoryId === pilot.repositoryId && member.repoClass === repoClass) &&
        representative(cohort, repoClass).repositoryId === pilot.repositoryId && cohort.target.digest === old.target.digest, "unfinished-cohort-replacement");
    }
  }
  const passed = new Set<number>(); const proofs: string[] = [];
  for (const policy of current) {
    const owned = readOwnedPolicyObservation(policy); const original = cohort.members.find((member) => member.repositoryId === owned.repository.id)!;
    demand(owned.targetBinding.commit === cohort.target.commit && owned.targetBinding.canonicalSha256 === cohort.target.digest && owned.target.policy.version === cohort.target.version, "cohort-policy-changed");
    const outcomes = active.filter((entry) => entry.value.kind === "pilot-outcome" && entry.value.outcome === "passed" &&
      entry.value.cohort === selected.commentId && entry.value.repositoryId === owned.repository.id);
    demand(outcomes.length <= 1, "ambiguous-pilot-outcome");
    if (owned.sourceBinding.canonicalSha256 === cohort.target.digest && owned.source.policy.version === cohort.target.version) {
      // Only the selected class consumes a completed pilot as authority; other classes remain independently pending.
      if (original.repoClass !== selectedIdentity!.repoClass) continue;
      demand(outcomes.length === 1, "merged-outcome-required"); proofs.push(await mergedOutcome(policy, outcomes[0]!.value as Outcome, original, cohort.target, signal, account)); passed.add(owned.repository.id);
    } else demand(owned.sourceBinding.canonicalSha256 === original.sourceDigest && owned.source.policy.version === original.sourceVersion &&
      owned.repository.head === original.sourceHead && outcomes.length === 0, "cohort-source-changed");
  }
  const selectedPolicy = current.find((policy) => readOwnedPolicyObservation(policy).repository.id === request.repositoryId);
  demand(selectedPolicy, "selected-repository-missing"); const owned = readOwnedPolicyObservation(selectedPolicy!);
  demand(!passed.has(request.repositoryId), "selected-repository-already-target");
  const plans = planFleetPolicyUpgrades(cohort.members.map((member) => ({ repo: member.repository, repoClass: member.repoClass,
    currentPolicy: member.sourceVersion, targetPolicy: cohort.target.version, pilotOutcome: passed.has(member.repositoryId) ? "passed" : "pending" })));
  const plan = plans.find((entry) => entry.repo === request.repository)!; demand(plan.status !== "blocked", "representative-pilot-pending");
  const applicable = active.filter((entry) => "cohort" in entry.value && entry.value.cohort === selected.commentId && entry.value.repositoryId === request.repositoryId && entry.value.targetDigest === cohort.target.digest);
  for (const exception of owned.manifest.exceptions) {
    const matching = applicable.filter((entry) => entry.value.kind === "exception" && entry.value.exceptionDigest === runtimeDigest(exception));
    demand(matching.length === 1 && matching[0]!.value.kind === "exception" && matching[0]!.value.expiresAt === exception.expiresAt, "exception-decision-required");
    if (exception.permanent) {
      const adrs = applicable.filter((entry) => entry.value.kind === "accepted-adr" && entry.value.baseCommit === owned.repository.head && entry.value.adr.path === exception.adr);
      demand(adrs.length === 1, "permanent-exception-adr-required"); await acceptedAdr(adrs[0]!, runtimePolicy, signal, account);
    } else demand(exception.expiresAt && new Date(`${exception.expiresAt}T00:00:00Z`).toISOString().slice(0, 10) === exception.expiresAt &&
      exception.expiresAt >= new Date().toISOString().slice(0, 10), "exception-expired");
  }
  if (plan.risk === "major") {
    const notices = applicable.filter((entry) => entry.value.kind === "major-notice" && entry.value.baseCommit === owned.repository.head);
    const adrs = applicable.filter((entry) => entry.value.kind === "accepted-adr" && entry.value.baseCommit === owned.repository.head);
    demand(notices.length === 1 && adrs.length === 1, "major-decisions-required"); await acceptedAdr(adrs[0]!, runtimePolicy, signal, account);
  }
  const fresh: PublicManifestDiscovery = await discoverPublicManifests(projection.organization, { signal }); account(fresh);
  demand(fresh.status === "complete" && equal(fresh.repositories, discovery.repositories), "fleet-changed");
  const publisher = new PublicObservationRead(signal, POLICY_PUBLISHER.repository);
  try {
    await publicRepository(publisher, POLICY_PUBLISHER);
    for (const observation of current) for (const binding of [readOwnedPolicyObservation(observation).sourceBinding, readOwnedPolicyObservation(observation).targetBinding]) {
      demand(await resolvePublicCommit(publisher, POLICY_PUBLISHER.repository, binding.ref) === binding.commit, "policy-changed");
    }
    await publicRepository(publisher, POLICY_PUBLISHER); publisher.check();
  } finally { await publisher.close(); account(publisher); }
  const finalDecisions = await observeUpgradeDecisions(runtimePolicy, { signal }); account(finalDecisions);
  demand(finalDecisions.digest === decisions.digest, "governance-changed");
  const finalPolicy = await captureRuntimePolicy(generator, { signal }); account(finalPolicy);
  demand(finalPolicy.projectionDigest === runtimePolicy.projectionDigest, "runtime-policy-changed");
  signal.throwIfAborted(); readRuntimePolicy(runtimePolicy);
  const handle: GovernanceObservation = freezeRuntimeValue({ repository: request.repository, repositoryId: request.repositoryId,
    baseCommit: owned.repository.head, cohortComment: selected.commentId, targetDigest: cohort.target.digest, role: plan.role, plan,
    decisionDigest: decisions.digest, evidenceDigest: runtimeDigest([discovery.repositories, decisions.digest, proofs]),
    independentReview: "pending", authority: "none", publication: "pending" });
  observations.set(handle, Object.freeze({ runtimePolicy, request, policy: selectedPolicy!, cohort, current: Object.freeze(current), ...(parent ? { signal: parent } : {}) })); return handle;
}
export function readOwnedGovernance(handle: GovernanceObservation): OwnedGovernance {
  const owned = observations.get(handle); demand(owned, "unowned-governance"); readRuntimePolicy(owned!.runtimePolicy); owned!.signal?.throwIfAborted(); return owned!;
}
export async function recheckUpgradeGovernance(handle: GovernanceObservation): Promise<void> {
  const owned = readOwnedGovernance(handle); const fresh = await observeUpgradeGovernance(owned.runtimePolicy, owned.request, owned.signal ? { signal: owned.signal } : {});
  demand(fresh.evidenceDigest === handle.evidenceDigest && fresh.baseCommit === handle.baseCommit, "governance-changed");
}
