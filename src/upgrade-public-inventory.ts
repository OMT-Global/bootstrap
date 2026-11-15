import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Readable } from "node:stream";
import { discoverPublicManifests, isValidPublicDiscoveryOrganization } from "./upgrade-discovery.js";
import { readPublicReadToken } from "./upgrade-discovery-command.js";
import { capturePublicGenerator } from "./upgrade-generator.js";
import { observePublicPolicies, readOwnedPolicyObservation, POLICY_PUBLISHER, type OwnedPolicyObservation } from "./upgrade-policy.js";
import { ObservationFailure, PublicObservationRead, publicHead, publicRepository, readPublicDirectory, readPublicFile, resolvePublicCommit } from "./upgrade-public-read.js";
import { BOOTSTRAP_STATE_OUTPUT_PATHS, parseOwnershipSidecar, resolveRepositoryProjection } from "./render.js";
import { projectLicensePolicy } from "./licensing.js";
import { createOwnershipSidecar, OWNERSHIP_SIDECAR_PATH } from "./state.js";
import { planFleetPolicyUpgrades, type FleetUpgradeCandidate, type FleetUpgradePlanEntry } from "./upgrades.js";
import type { PolicyException, RenderedFile } from "./types.js";

const LIMITS = { milliseconds: 300_000, requests: 10_000, bytes: 256 * 1024 ** 2, paths: 250 };
type DriftPath = { path: string; status: "unchanged" | "changed" | "missing" };
type Drift = { status: "observed" | "unsupported" | "incomplete"; paths: DriftPath[]; unassessedPaths: string[]; reason?: string };
type Row = { repository: string; repositoryId: number; status: "observed" | "unmanaged" | "unsupported" | "incomplete";
  reason?: string; class?: string; head?: string; pins?: { source: OwnedPolicyObservation["sourceBinding"]; target: OwnedPolicyObservation["targetBinding"] };
  versions?: { current: string; target: string }; exceptions?: PolicyException[]; drift?: Drift; plan?: FleetUpgradePlanEntry };
export type PublicFleetInventory = { schemaVersion: 1; scope: "public-fleet-inventory"; status: "complete" | "incomplete";
  organization: string; repositories: Row[]; requests: number; receivedBytes: number; failure?: string;
  authority: "none"; pilots: "unverified"; exceptionApprovals: "unverified" };
export type InventoryOptions = { org: string; targetRef: string; targetSha256: string; generatorRoot: string; generatorCommit: string;
  json?: boolean; readTokenStdin?: boolean; signal?: AbortSignal };
const digest = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const reason = (error: unknown) => error instanceof ObservationFailure ? error.code : "unsupported-projection";

/** Compare source-policy outputs only; no mutable sidecar claim grants write or legal-transition authority. */
async function observeDrift(owned: OwnedPolicyObservation, read: PublicObservationRead): Promise<Drift> {
  const { repository: repo, head, tree } = owned.repository;
  const projected = (await resolveRepositoryProjection(owned.manifest, "/", owned.source)).files;
  const paths: DriftPath[] = [];
  const unassessed = new Set<string>([...projected.map((file) => file.path), OWNERSHIP_SIDECAR_PATH, ...(owned.manifest.license ? ["LICENSE", "THIRD_PARTY_NOTICES.md"] : [])]);
  const found = new Map<string, Awaited<ReturnType<typeof readPublicFile>> | undefined>();
  let scratch: string | undefined;
  const readFile = async (name: string) => {
    if (!found.has(name)) {
      if (found.size >= LIMITS.paths) throw new ObservationFailure("path-limit");
      try { found.set(name, await readPublicFile(read, repo, head, name, tree)); }
      catch (error) { if (error instanceof ObservationFailure && error.code === "missing-source") found.set(name, undefined); else throw error; }
    }
    return found.get(name);
  };
  const compare = async (file: RenderedFile) => {
    const actual = await readFile(file.path);
    paths.push({ path: file.path, status: !actual ? "missing" : actual.sha256 === digest(Buffer.from(file.contents)) && actual.mode === (file.executable ? "100755" : "100644") ? "unchanged" : "changed" });
    unassessed.delete(file.path);
  };
  try {
    for (const file of projected) await compare(file);
    const sidecar = await readFile(OWNERSHIP_SIDECAR_PATH);
    const ownership = sidecar ? parseOwnershipSidecar(sidecar.text, projected) : undefined;
    if (ownership && Object.keys(ownership.hashes).length > LIMITS.paths) throw new ObservationFailure("path-limit");
    const files = [...projected];
    if (owned.manifest.license) {
      unassessed.add("LICENSE"); unassessed.add("THIRD_PARTY_NOTICES.md");
      const root = await readPublicDirectory(read, repo, head, "", tree);
      scratch = await mkdtemp(path.join(os.tmpdir(), "bootstrap-public-legal-"));
      // Reproduce root names/types for the existing alternate-license detector;
      // only legal inputs below receive contents, and no target code is executed.
      for (const entry of root.entries) {
        if (!["100644", "100755", "040000"].includes(entry.mode)) throw new ObservationFailure("unsupported-root-entry");
        if ([".", "..", ".git"].includes(entry.path) || /[\\\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(entry.path) || Buffer.from(entry.path).toString() !== entry.path) throw new ObservationFailure("unsupported-path");
        const location = path.join(scratch, entry.path);
        if (entry.type === "tree") await mkdir(location);
        else await writeFile(location, "", { flag: "wx", mode: 0o600 });
      }
      for (const name of ["LICENSE", "THIRD_PARTY_NOTICES.md", owned.manifest.license.template.path]) {
        const file = await readFile(name);
        if (file) { const location = path.join(scratch, name); await mkdir(path.dirname(location), { recursive: true }); await writeFile(location, file.bytes, { mode: 0o600 }); }
      }
      const legal = await projectLicensePolicy(owned.manifest, scratch, undefined,
        [...projected.map((file) => file.path), ...BOOTSTRAP_STATE_OUTPUT_PATHS], ownership?.license);
      if (!legal || legal.summary.transitionRequired) throw new ObservationFailure("unsupported-legal-transition");
      files.push(...legal.files);
      for (const file of legal.files) await compare(file);
    } else if (ownership?.claimsLicense) {
      unassessed.add("LICENSE"); throw new ObservationFailure("unsupported-legal-transition");
    }
    const planned = new Set(files.map((file) => file.path));
    for (const claimed of Object.keys(ownership?.hashes ?? {})) if (!planned.has(claimed)) unassessed.add(claimed);
    await compare(createOwnershipSidecar(owned.manifest, files));
    return { status: unassessed.size ? "unsupported" : "observed", paths, unassessedPaths: [...unassessed].sort(),
      ...(unassessed.size ? { reason: "unsupported-extra-ownership-claims" } : {}) };
  } catch (error) {
    const code = reason(error);
    return { status: code.startsWith("unsupported-") ? "unsupported" : "incomplete", paths, unassessedPaths: [...unassessed].sort(), reason: code };
  } finally { if (scratch) await rm(scratch, { recursive: true, force: true }); }
}

/** Discovery, owned policy facts and managed drift; never runs hooks, validates pilots or publishes. */
export async function collectPublicFleetInventory(options: InventoryOptions, publicReadToken?: string): Promise<PublicFleetInventory> {
  if (!isValidPublicDiscoveryOrganization(options.org) || !/^(?:[0-9a-f]{40}|refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+)$/.test(options.targetRef) ||
      !/^[0-9a-f]{64}$/.test(options.targetSha256) || !path.isAbsolute(options.generatorRoot) || !/^[0-9a-f]{40}$/.test(options.generatorCommit)) throw new Error("Invalid public inventory selectors.");
  const selected = { org: options.org, targetRef: options.targetRef, targetSha256: options.targetSha256, generatorRoot: options.generatorRoot, generatorCommit: options.generatorCommit };
  const signal = AbortSignal.any([AbortSignal.timeout(LIMITS.milliseconds), ...(options.signal ? [options.signal] : [])]);
  const report: PublicFleetInventory = { schemaVersion: 1, scope: "public-fleet-inventory", status: "incomplete", organization: selected.org,
    repositories: [], requests: 0, receivedBytes: 0, authority: "none", pilots: "unverified", exceptionApprovals: "unverified" };
  const invalidateWindow = (code: string) => {
    report.repositories = report.repositories.map((row) => ({ repository: row.repository, repositoryId: row.repositoryId, status: "incomplete", reason: code }));
  };
  const add = (stats: { requests: number; receivedBytes: number }) => {
    report.requests += stats.requests; report.receivedBytes += stats.receivedBytes;
    if (report.requests > LIMITS.requests || report.receivedBytes > LIMITS.bytes) throw new ObservationFailure("inventory-budget");
  };
  const reservePhase = (requests = 501) => {
    if (signal.aborted) throw new ObservationFailure("aborted-or-deadline");
    // Reserve the adapter bound plus its locally rejected over-limit attempt.
    if (report.requests + requests > LIMITS.requests || report.receivedBytes + 64 * 1024 ** 2 > LIMITS.bytes) throw new ObservationFailure("inventory-budget");
  };
  try {
    const generator = await capturePublicGenerator(selected.generatorRoot, selected.generatorCommit, { signal }).catch(() => { throw new ObservationFailure("generator-unavailable"); });
    const discovery = await discoverPublicManifests(selected.org, { signal, ...(publicReadToken ? { publicReadToken } : {}) });
    add(discovery);
    report.repositories = discovery.repositories.map((repo) => ({ repository: repo.repository, repositoryId: repo.repositoryId,
      status: repo.outcome === "managed" ? "incomplete" : repo.outcome, ...(repo.reason ? { reason: repo.reason } : {}) }));
    if (discovery.status !== "complete") { report.failure = discovery.failure?.code ?? "discovery-incomplete"; return report; }
    const candidates: FleetUpgradeCandidate[] = [];
    for (let index = 0; index < discovery.repositories.length; index++) {
      const repository = discovery.repositories[index]!; const row = report.repositories[index]!;
      if (repository.outcome !== "managed") continue;
      reservePhase();
      const observed = await observePublicPolicies(discovery, repository, generator,
        { ref: selected.targetRef, sha256: selected.targetSha256 }, { signal, ...(publicReadToken ? { publicReadToken } : {}) });
      add(observed);
      if (observed.status !== "observed") { row.status = observed.status; row.reason = observed.reason ?? "policy-unavailable"; continue; }
      const owned = readOwnedPolicyObservation(observed);
      if (owned.manifest.project.visibility !== "public" || `${owned.manifest.project.owner}/${owned.manifest.project.name}`.toLowerCase() !== repository.repository.toLowerCase()) {
        row.status = "unsupported"; row.reason = "manifest-repository-mismatch"; continue;
      }
      reservePhase();
      const read = new PublicObservationRead(signal, repository.repository, publicReadToken);
      try {
        await publicRepository(read, owned.repository);
        if (await publicHead(read, repository.repository, repository.defaultBranch) !== owned.repository.head) throw new ObservationFailure("changed-repository");
        const drift = await observeDrift(owned, read);
        await publicRepository(read, owned.repository);
        if (await publicHead(read, repository.repository, repository.defaultBranch) !== owned.repository.head) throw new ObservationFailure("changed-repository");
        Object.assign(row, { status: drift.status, ...(drift.reason ? { reason: drift.reason } : {}), class: owned.manifest.repo.class, head: owned.repository.head, drift,
          pins: { source: owned.sourceBinding, target: owned.targetBinding }, versions: { current: owned.source.policy.version, target: owned.target.policy.version },
          exceptions: structuredClone(owned.manifest.exceptions) });
        if (repository.fork || repository.archived || repository.disabled) { row.status = "unsupported"; row.reason = "inactive-or-fork-repository"; }
        if (row.status === "observed") candidates.push({ repo: repository.repository, repoClass: owned.manifest.repo.class!, currentPolicy: owned.source.policy.version,
          targetPolicy: owned.target.policy.version, pilotOutcome: "pending", ...(row.exceptions?.length ? { exceptionId: row.exceptions[0]!.id } : {}) });
      } catch (error) { row.status = "incomplete"; row.reason = reason(error); }
      finally { const stats = read.stats; await read.close(); add(stats); }
    }
    // Repeat complete discovery: repository additions/removals, visibility,
    // flags, default branches and early-row heads must not silently change the pilot set.
    reservePhase(5001);
    const fresh = await discoverPublicManifests(selected.org, { signal, ...(publicReadToken ? { publicReadToken } : {}) });
    add(fresh);
    const latest = new Map(fresh.repositories.map((repo) => [repo.repositoryId, repo]));
    if (fresh.status !== "complete" || latest.size !== discovery.repositories.length ||
        discovery.repositories.some((repo) => JSON.stringify(latest.get(repo.repositoryId)) !== JSON.stringify(repo))) {
      report.failure = fresh.failure?.code ?? "changed-fleet";
      invalidateWindow("changed-fleet");
    }
    if (!report.failure) {
      reservePhase();
      const bindings = new Map<string, string>();
      for (const row of report.repositories) for (const binding of row.pins ? [row.pins.source, row.pins.target] : []) {
        if (bindings.has(binding.ref) && bindings.get(binding.ref) !== binding.commit) throw new ObservationFailure("changed-policy");
        bindings.set(binding.ref, binding.commit);
      }
      const read = new PublicObservationRead(signal, POLICY_PUBLISHER.repository);
      try {
        await publicRepository(read, POLICY_PUBLISHER);
        for (const [ref, commit] of bindings) if (await resolvePublicCommit(read, POLICY_PUBLISHER.repository, ref) !== commit) throw new ObservationFailure("changed-policy");
        await publicRepository(read, POLICY_PUBLISHER);
      } finally { const stats = read.stats; await read.close(); add(stats); }
    }
    report.status = !report.failure && report.repositories.every((row) => row.status === "observed" || row.status === "unmanaged") ? "complete" : "incomplete";
    const plans = planFleetPolicyUpgrades(candidates);
    for (const row of report.repositories) {
      const plan = plans.find((entry) => entry.repo === row.repository);
      if (plan && row.status === "observed") row.plan = report.status === "complete" ? plan : { ...plan, status: "blocked", reason: "Complete the fleet observations before selecting a representative pilot." };
    }
  } catch (error) { report.failure = reason(error); invalidateWindow(report.failure); }
  return report;
}

export function formatPublicInventory(report: PublicFleetInventory): string {
  return [`Public fleet inventory: ${report.status}. No write authority; pilot and exception approvals remain unverified.`,
    ...report.repositories.map((row) => `- ${JSON.stringify(row.repository)}: ${row.status}${row.reason ? ` (${row.reason})` : ""}` +
      `${row.class ? `; class=${JSON.stringify(row.class)}` : ""}${row.versions ? `; policy=${row.versions.current} -> ${row.versions.target}` : ""}` +
      `${row.pins ? `; pin=${row.pins.source.ref}@${row.pins.source.canonicalSha256} -> ${row.pins.target.ref}@${row.pins.target.canonicalSha256}` : ""}` +
      `${row.exceptions ? `; declared-exceptions=${JSON.stringify(row.exceptions.map((entry) => entry.id))}` : ""}` +
      `${row.drift ? `; drift=${row.drift.status}; changed=${JSON.stringify(row.drift.paths.filter((file) => file.status !== "unchanged"))}; unassessed=${JSON.stringify(row.drift.unassessedPaths)}` : ""}` +
      `${row.plan ? `; ${row.plan.status}: ${row.plan.reason}` : ""}`),
    ...(report.failure ? [`Inventory incomplete: ${report.failure}.`] : [])].join("\n");
}
export async function runPublicInventory(options: InventoryOptions, input: Readable & { isTTY?: boolean }): Promise<{ output: string; exitCode: number }> {
  const token = options.readTokenStdin ? await readPublicReadToken(input) : undefined;
  const report = await collectPublicFleetInventory(options, token);
  return { output: options.json ? JSON.stringify(report, null, 2) : formatPublicInventory(report), exitCode: report.status === "complete" ? 0 : 1 };
}
