import { createHash } from "node:crypto";
import path from "node:path";
import { parseDocument } from "yaml";
import { z } from "zod";
import { generatorSnapshot, type PublicGeneratorCapture } from "./upgrade-generator.js";
import { copySnapshotFiles } from "./upgrade-git.js";
import { boundedValue, ObservationFailure, PublicObservationRead, publicHead, publicRepository, readPublicFile, record } from "./upgrade-public-read.js";

export const RUNTIME_CONTROLLER = Object.freeze({ repository: "OMT-Global/bootstrap", id: 1194768990 });
export const runtimeDigest = (value: unknown): string => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const runtimeDemand = (condition: unknown, code = "governance-invalid"): void => { if (!condition) throw new ObservationFailure(code); };
const oid = z.string().regex(/^[0-9a-f]{40}$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const positive = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const slug = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/);
const reference = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
export const governanceRole = z.enum(["cohort", "pilot", "exception", "major"]);
const identity = z.object({ repository: slug, id: positive }).strict();
const policySchema = z.object({
  schemaVersion: z.literal(1), organization: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/),
  repositories: z.array(identity).min(1).max(500),
  governance: identity.extend({ issue: positive }),
  actors: z.array(z.object({ id: positive, login: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/),
    roles: z.array(governanceRole).min(1).max(4) }).strict()).min(1).max(100),
  signing: z.object({ principal: reference, publicKey: z.string().regex(/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/), keyReference: reference }).strict().optional(),
  review: z.object({ profile: z.literal("fleet-native-sol-high-v1"), authorSession: reference, reviewerPrincipal: reference }).strict().optional(),
  app: z.object({ appId: positive, installationId: positive, keyReference: reference,
    profile: z.enum(["fleet-publication-v1", "fleet-workflow-publication-v1"]) }).strict().optional(),
  attemptDirectory: z.string().max(4096).refine(path.isAbsolute).optional()
}).strict();
const requestSchema = z.object({ repository: slug, repositoryId: positive, originalRoot: z.string().max(4096).refine(path.isAbsolute),
  generatorRoot: z.string().max(4096).refine(path.isAbsolute), generatorCommit: oid,
  target: z.object({ ref: z.string().regex(/^(?:[0-9a-f]{40}|refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+)$/), sha256: digest }).strict(),
  cohortComment: positive.optional()
}).strict();
export type UpgradeRuntimeRequest = z.infer<typeof requestSchema>;
export type RuntimePolicyProjection = z.infer<typeof policySchema>;
export type RuntimePolicy = Readonly<{ controllerCommit: string; projectionDigest: string; requests: number; receivedBytes: number }>;
type OwnedPolicy = Readonly<{ generator: PublicGeneratorCapture; projection: RuntimePolicyProjection; manifestSha256: string; signal?: AbortSignal }>;
const policies = new WeakMap<RuntimePolicy, OwnedPolicy>();
export function freezeRuntimeValue<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.values(value).forEach(freezeRuntimeValue); Object.freeze(value); }
  return value;
}
export function parseUpgradeRuntimeRequest(value: unknown): UpgradeRuntimeRequest {
  boundedValue(value); return freezeRuntimeValue(requestSchema.parse(value));
}
/** Parsing configuration alone grants no authority; the producer below binds its source. */
export function parseRuntimePolicyProjection(value: unknown): RuntimePolicyProjection {
  boundedValue(value); const parsed = policySchema.parse(value);
  runtimeDemand(new Set(parsed.repositories.map((repo) => repo.id)).size === parsed.repositories.length &&
    new Set(parsed.repositories.map((repo) => repo.repository.toLowerCase())).size === parsed.repositories.length, "duplicate-repository");
  runtimeDemand(new Set(parsed.actors.map((actor) => actor.id)).size === parsed.actors.length &&
    new Set(parsed.actors.map((actor) => actor.login.toLowerCase())).size === parsed.actors.length, "duplicate-actor");
  for (const actor of parsed.actors) runtimeDemand(new Set(actor.roles).size === actor.roles.length, "duplicate-role");
  return freezeRuntimeValue(parsed);
}
export function readRuntimePolicy(handle: RuntimePolicy): OwnedPolicy {
  const owned = policies.get(handle); runtimeDemand(owned, "unowned-runtime-policy"); owned!.signal?.throwIfAborted(); return owned!;
}
export async function captureRuntimePolicy(generator: PublicGeneratorCapture, options: { signal?: AbortSignal } = {}): Promise<RuntimePolicy> {
  const signal = options.signal; signal?.throwIfAborted(); const snapshot = generatorSnapshot(generator);
  runtimeDemand(snapshot.baseCommit === generator.sourceCommit && snapshot.tree === generator.tree && snapshot.sourceSha256 === generator.sourceSha256, "generator-binding");
  const file = copySnapshotFiles(snapshot).find((entry) => entry.path === "project.bootstrap.yaml");
  runtimeDemand(file?.mode === "100644", "runtime-policy-missing");
  const document = parseDocument(new TextDecoder("utf-8", { fatal: true }).decode(file!.bytes), { uniqueKeys: true, customTags: [], schema: "core" });
  runtimeDemand(!document.errors.length && !document.warnings.length, "runtime-policy-invalid");
  const raw: unknown = document.toJS({ maxAliasCount: 0 }); boundedValue(raw);
  const projection = parseRuntimePolicyProjection(record(raw).fleetRuntime);
  const sha = createHash("sha256").update(file!.bytes).digest("hex");
  const read = new PublicObservationRead(signal, RUNTIME_CONTROLLER.repository);
  try {
    const repo = await publicRepository(read, RUNTIME_CONTROLLER);
    runtimeDemand(await publicHead(read, repo.repository, repo.defaultBranch) === generator.sourceCommit, "controller-not-current");
    const current = await readPublicFile(read, repo.repository, generator.sourceCommit, "project.bootstrap.yaml", snapshot.tree);
    runtimeDemand(current.sha256 === sha && current.mode === file!.mode, "runtime-policy-changed");
    await publicRepository(read, repo);
    runtimeDemand(await publicHead(read, repo.repository, repo.defaultBranch) === generator.sourceCommit, "controller-not-current"); read.check();
  } finally { await read.close(); }
  signal?.throwIfAborted();
  const handle = Object.freeze({ controllerCommit: generator.sourceCommit, projectionDigest: runtimeDigest(projection), ...read.stats });
  policies.set(handle, Object.freeze({ generator, projection, manifestSha256: sha, ...(signal ? { signal } : {}) })); return handle;
}
export function missingRuntimeConfiguration(handle: RuntimePolicy): string[] {
  const { projection } = readRuntimePolicy(handle);
  return [!projection.signing && "authorized-signer-unconfigured", !projection.review && "native-review-profile-unconfigured",
    !projection.app && "publication-app-unconfigured", !projection.attemptDirectory && "attempt-directory-unconfigured"].filter((value): value is string => typeof value === "string");
}
