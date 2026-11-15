import { createHash } from "node:crypto";
import { parseDocument } from "yaml";

import { normalizeManifest } from "./manifest.js";
import { flowPolicyDigest, resolveFlowPolicy, type ResolvedPolicyContract } from "./policy.js";
import { resolveRepositoryProjection } from "./render.js";
import type { BootstrapManifest } from "./types.js";
import { readDiscoveredManifest, type DiscoveredPublicRepository, type PublicManifestDiscovery } from "./upgrade-discovery.js";
import { generatorSnapshot, type PublicGeneratorCapture } from "./upgrade-generator.js";
import { copySnapshotFiles } from "./upgrade-git.js";
import { boundedValue, objectId, ObservationFailure, PublicObservationRead, publicHead, publicRepository, readPublicFile, record, resolvePublicCommit } from "./upgrade-public-read.js";
import { classifyPolicyUpgrade, type UpgradeRisk } from "./upgrades.js";

export const POLICY_PUBLISHER = Object.freeze({ repository: "OMT-Global/flow", id: 1232476439, bundlePath: "policies/public-repository-standard-v1.json" });
const workflowPath = ".github/workflows/extended-validation.yml";
export interface PublicPolicyTarget { readonly ref: string; readonly sha256: string }
export interface PolicyObservation {
  readonly status: "observed" | "unsupported" | "incomplete";
  readonly repository: string;
  readonly reason?: string;
  readonly sourceVersion?: string;
  readonly targetVersion?: string;
  readonly transition?: UpgradeRisk;
  readonly sourceDigest?: string;
  readonly targetDigest?: string;
  readonly workflowSha256?: string;
  readonly requests: number;
  readonly receivedBytes: number;
}
interface PolicyBinding {
  readonly ref: string;
  readonly commit: string;
  readonly oid: string;
  readonly rawSha256: string;
  readonly canonicalSha256: string;
  readonly canonicalization?: "sorted-utf16-v1";
}
export interface OwnedPolicyObservation {
  readonly observationWindow: Readonly<{ beganMonotonic: number; endedMonotonic: number }>;
  readonly repository: Readonly<{ repository: string; id: number; defaultBranch: string; head: string; tree: string }>;
  readonly manifest: BootstrapManifest;
  readonly source: ResolvedPolicyContract;
  readonly target: ResolvedPolicyContract;
  readonly sourceBinding: Readonly<PolicyBinding>;
  readonly localBinding: Readonly<{ commit: string; oid: string; rawSha256: string; canonicalSha256: string }>;
  readonly targetBinding: Readonly<PolicyBinding>;
  readonly targetRawByteLength: number;
  readonly generator: Readonly<{ sourceCommit: string; sourceSha256: string }>;
  readonly workflow: Readonly<{ path: string; text: string; sha256: string }>;
}
const observations = new WeakMap<PolicyObservation, OwnedPolicyObservation>();
const targetPolicyBytes = new WeakMap<PolicyObservation, Buffer>();
export function readOwnedPolicyObservation(observation: PolicyObservation): OwnedPolicyObservation {
  const owned = observations.get(observation);
  if (!owned) throw new ObservationFailure("unowned-observation");
  return owned;
}
export function copyOwnedTargetPolicyBytes(observation: PolicyObservation): Buffer {
  const owned = readOwnedPolicyObservation(observation); const bytes = targetPolicyBytes.get(observation);
  if (!bytes || bytes.length !== owned.targetRawByteLength) throw new ObservationFailure("unowned-observation");
  return Buffer.from(bytes);
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function parse(text: string, limit: number): unknown {
  if (Buffer.byteLength(text) > limit) throw new ObservationFailure("response-limit");
  const document = parseDocument(text, { strict: true, uniqueKeys: true, prettyErrors: false, customTags: [], schema: "core", version: "1.2" });
  if (document.errors.length || document.warnings.length) throw new ObservationFailure("invalid-source");
  const value: unknown = document.toJS({ maxAliasCount: 0 });
  boundedValue(value);
  return value;
}
function validateLocator(locator: PublicPolicyTarget): void {
  if (typeof locator.ref !== "string" || !/^(?:[0-9a-f]{40}|refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+)$/.test(locator.ref) ||
    typeof locator.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(locator.sha256)) throw new ObservationFailure("invalid-input");
}
async function publishedBundle(read: PublicObservationRead, locator: PublicPolicyTarget & { canonicalization?: "sorted-utf16-v1" }): Promise<{ value: unknown; binding: PolicyBinding; bytes: Buffer }> {
  validateLocator(locator);
  const commit = await resolvePublicCommit(read, POLICY_PUBLISHER.repository, locator.ref);
  const file = await readPublicFile(read, POLICY_PUBLISHER.repository, commit, POLICY_PUBLISHER.bundlePath);
  const value = parse(file.text, 1024 ** 2);
  if (flowPolicyDigest(value, locator.canonicalization) !== locator.sha256) throw new ObservationFailure("policy-digest");
  return { value, bytes: file.bytes, binding: { ref: locator.ref, commit, oid: file.oid, rawSha256: file.sha256, canonicalSha256: locator.sha256,
    ...(locator.canonicalization === undefined ? {} : { canonicalization: locator.canonicalization }) } };
}

/** Native public data observations only; no rollout, human decision, pilot pass or permission to write. */
export async function observePublicPolicies(
  discovery: PublicManifestDiscovery, repository: DiscoveredPublicRepository, generator: PublicGeneratorCapture,
  target: PublicPolicyTarget, options: { signal?: AbortSignal; publicReadToken?: string } = {}
): Promise<PolicyObservation> {
  let read: PublicObservationRead | undefined;
  let repositoryName = "";
  let cleanupComplete = false;
  try {
    if (!options || typeof options !== "object" || Array.isArray(options) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(options)) ||
      Reflect.ownKeys(options).some((key) => key !== "signal" && key !== "publicReadToken")) throw new ObservationFailure("invalid-input");
    const fields = Object.getOwnPropertyDescriptors(options);
    if (Object.values(fields).some((field) => !("value" in field))) throw new ObservationFailure("invalid-input");
    const signal: unknown = fields.signal?.value;
    const publicReadToken: unknown = fields.publicReadToken?.value;
    if (signal !== undefined && !(signal instanceof AbortSignal) || publicReadToken !== undefined &&
      (typeof publicReadToken !== "string" || publicReadToken.length < 20 || publicReadToken.length > 4096 || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(publicReadToken))) throw new ObservationFailure("invalid-input");
    const selection = Object.freeze({ ref: target.ref, sha256: target.sha256 });
    validateLocator(selection);
    const original = readDiscoveredManifest(discovery, repository);
    const snapshot = generatorSnapshot(generator);
    const raw = record(parse(original, 256 * 1024));
    const manifest = normalizeManifest(raw as Parameters<typeof normalizeManifest>[0]);
    if (!manifest.repo.class || record(raw.repo).class !== manifest.repo.class || manifest.unknownSettings.length || !manifest.policy?.flow) throw new ObservationFailure("unsupported-policy");
    if (snapshot.baseCommit !== generator.sourceCommit || snapshot.sourceSha256 !== generator.sourceSha256) throw new ObservationFailure("unowned-generator");
    validateLocator(manifest.policy.flow);
    repositoryName = repository.repository;
    const head = objectId(repository.head);
    const tree = objectId(repository.tree);
    read = new PublicObservationRead(signal, repositoryName, publicReadToken);
    const identity = await publicRepository(read, { repository: repository.repository, id: repository.repositoryId, defaultBranch: repository.defaultBranch });
    if (await publicHead(read, identity.repository, identity.defaultBranch) !== head) throw new ObservationFailure("changed-repository");
    const actualManifest = await readPublicFile(read, identity.repository, head, "project.bootstrap.yaml", tree);
    if (actualManifest.text !== original || actualManifest.oid !== repository.manifest?.oid || actualManifest.sha256 !== repository.manifest.sha256) throw new ObservationFailure("changed-repository");
    await publicRepository(read, POLICY_PUBLISHER);
    const local = await readPublicFile(read, identity.repository, head, manifest.policy.flow.bundlePath, tree);
    const localBundle = parse(local.text, 1024 ** 2);
    const source = resolveFlowPolicy(manifest, localBundle, manifest.policy.flow, manifest.unknownSettings);
    const sourcePublished = await publishedBundle(read, manifest.policy.flow);
    if (flowPolicyDigest(localBundle, manifest.policy.flow.canonicalization) !== flowPolicyDigest(sourcePublished.value, manifest.policy.flow.canonicalization)) throw new ObservationFailure("policy-digest");
    // Preserve the existing algorithm; migration needs a separately governed all-reader rollout.
    const targetSelection = { ...selection, ...(manifest.policy.flow.canonicalization === undefined ? {} : { canonicalization: manifest.policy.flow.canonicalization }) };
    const targetPublished = await publishedBundle(read, targetSelection);
    const targetRaw = { ...raw, policy: { ...record(raw.policy), flow: { ...record(record(raw.policy).flow), ref: selection.ref, sha256: selection.sha256 } } };
    const targetManifest = normalizeManifest(targetRaw as Parameters<typeof normalizeManifest>[0]);
    const resolvedTarget = resolveFlowPolicy(targetManifest, targetPublished.value, targetSelection, targetManifest.unknownSettings);
    const projection = await resolveRepositoryProjection(manifest, "/", source);
    const expected = projection.files.find((file) => file.path === workflowPath);
    const trustedFiles = copySnapshotFiles(snapshot);
    const trustedWorkflow = trustedFiles.find((file) => file.path === workflowPath);
    if (!expected || !trustedWorkflow || trustedWorkflow.mode !== "100644" || expected.executable) throw new ObservationFailure("unsupported-ci-profile");
    // Bind the renderer to the audited generator's own committed projection;
    // the same trusted renderer then handles supported repository settings.
    const trustedText = new TextDecoder("utf-8", { fatal: true }).decode(trustedWorkflow.bytes);
    const generatorManifestFile = trustedFiles.find((file) => file.path === "project.bootstrap.yaml");
    if (!generatorManifestFile) throw new ObservationFailure("unsupported-ci-profile");
    const generatorManifest = normalizeManifest(record(parse(new TextDecoder("utf-8", { fatal: true }).decode(generatorManifestFile.bytes), 256 * 1024)) as Parameters<typeof normalizeManifest>[0]);
    const generatorBundle = trustedFiles.find((file) => file.path === generatorManifest.policy?.flow?.bundlePath);
    if (!generatorManifest.policy?.flow || !generatorBundle) throw new ObservationFailure("unsupported-ci-profile");
    const generatorPolicy = resolveFlowPolicy(generatorManifest, parse(new TextDecoder("utf-8", { fatal: true }).decode(generatorBundle.bytes), 1024 ** 2), generatorManifest.policy.flow);
    const generatorProjection = await resolveRepositoryProjection(generatorManifest, "/", generatorPolicy);
    if (generatorProjection.files.find((file) => file.path === workflowPath)?.contents !== trustedText) throw new ObservationFailure("unsupported-ci-profile");
    const workflow = await readPublicFile(read, identity.repository, head, workflowPath, tree);
    if (workflow.text !== expected.contents || workflow.mode !== "100644") throw new ObservationFailure("unsupported-ci-profile");
    if (await resolvePublicCommit(read, POLICY_PUBLISHER.repository, sourcePublished.binding.ref) !== sourcePublished.binding.commit ||
      await resolvePublicCommit(read, POLICY_PUBLISHER.repository, targetPublished.binding.ref) !== targetPublished.binding.commit) throw new ObservationFailure("changed-policy");
    await publicRepository(read, POLICY_PUBLISHER);
    await publicRepository(read, identity);
    if (await publicHead(read, identity.repository, identity.defaultBranch) !== head) throw new ObservationFailure("changed-repository");
    read.check();
    const result: PolicyObservation = freeze({ status: "observed", repository: identity.repository,
      sourceVersion: source.policy.version, targetVersion: resolvedTarget.policy.version,
      transition: classifyPolicyUpgrade(source.policy.version, resolvedTarget.policy.version),
      sourceDigest: source.source.sha256, targetDigest: resolvedTarget.source.sha256, workflowSha256: workflow.sha256, ...read.stats });
    const bytes = Buffer.from(targetPublished.bytes);
    if (bytes.length > 1024 ** 2 || createHash("sha256").update(bytes).digest("hex") !== targetPublished.binding.rawSha256) throw new ObservationFailure("invalid-response");
    const owned: OwnedPolicyObservation = freeze({ observationWindow: read.observationWindow, repository: { ...identity, head, tree }, manifest, source, target: resolvedTarget,
      sourceBinding: sourcePublished.binding, targetBinding: targetPublished.binding, targetRawByteLength: bytes.length,
      localBinding: { commit: head, oid: local.oid, rawSha256: local.sha256, canonicalSha256: source.source.sha256 },
      generator: { sourceCommit: generator.sourceCommit, sourceSha256: generator.sourceSha256 },
      workflow: { path: workflowPath, text: workflow.text, sha256: createHash("sha256").update(expected.contents).digest("hex") } });
    await read.close();
    cleanupComplete = true;
    const completed = freeze({ ...owned, observationWindow: read.observationWindow });
    read.check();
    observations.set(result, completed); targetPolicyBytes.set(result, bytes);
    return result;
  } catch (error) {
    const reason = error instanceof ObservationFailure ? error.code : "invalid-source";
    return freeze({ status: reason.startsWith("unsupported-") || reason === "invalid-source" ? "unsupported" : "incomplete", repository: repositoryName, reason,
      ...(read?.stats ?? { requests: 0, receivedBytes: 0 }) });
  } finally { if (!cleanupComplete) await read?.close(); }
}
