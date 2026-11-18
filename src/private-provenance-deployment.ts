import { createPublicKey, verify } from "node:crypto";
import { z } from "zod";
import { provenanceSigningKeyFingerprint } from "./provenance.js";
import {
  PrivateControlError, controlBase, controlCategory, controlCounter, controlDigest, controlHash,
  controlId, controlPurpose, controlText, controlTime, controlWire,
  parsePrivateControl, requireControl, verifyPrivateControl, type PrivateControlKey
} from "./private-provenance-control.js";

// Configuration bounds are separate from the existing envelope/receipt wire bounds.
const BINDING_BYTES = 65_536;
const BINDING_DEPTH = 8;
const physicalText = (max: number) => controlText(max).refine(
  (v) => !/[\u0000-\u001f\u007f*?]/.test(v) && !v.includes("${")
);
const numericId = z.string().regex(/^[1-9][0-9]{0,19}$/);
const accountId = z.string().regex(/^[0-9]{12}$/);
const sha = z.string().regex(/^[0-9a-f]{40}$/);
const repositoryName = physicalText(201).refine((v) => /^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9_.-]+$/.test(v));
const branchRef = physicalText(255).refine((v) => /^refs\/heads\/[A-Za-z0-9_./-]+$/.test(v)
  && !v.includes("..") && !v.includes("//") && !v.endsWith("/") && !v.endsWith(".")
  && v.split("/").every((part) => !part.startsWith(".") && !part.endsWith(".lock")));
const bucket = physicalText(63).refine((v) => /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(v)
  && !v.includes("..") && !/^\d+\.\d+\.\d+\.\d+$/.test(v)
  && !/^(xn--|sthree-|amzn-s3-demo-)/.test(v) && !/(-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)$/.test(v));
const arn = physicalText(2048);
const publicJwk = z.object({
  kty: z.literal("OKP"), crv: z.literal("Ed25519"),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine((v) => {
    const bytes = Buffer.from(v, "base64url");
    return bytes.length === 32 && bytes.toString("base64url") === v;
  })
}).strict();
const signature = z.object({
  keyFingerprint: controlDigest, value: z.string().regex(/^[A-Za-z0-9+/]{86}==$/)
}).strict();
const signed = z.object({ payload: z.unknown(), signature }).strict();

export const deploymentRolePurposes = ["controller", "public-signer", "capture", "ciphertext-verifier",
  "codex-approver", "read-broker", "audit", "gate-verifier", "public-exporter", "check-publisher"] as const;
const rolePurpose = z.enum(deploymentRolePurposes);
const keyPurpose = z.enum(["deployment-root", "controller-admission", "public-manifest", "capture-receipt",
  "codex-read-approval", "audit-ack", "gate-observation", "requester-request", "producer-submission",
  "requester-transport", "producer-transport", "workload-transport"]);
const endpointPurpose = z.enum(["capture", "read", "audit"]);
const semanticPurpose = {
  controller: "controller-admission", "public-signer": "public-manifest", capture: null,
  "ciphertext-verifier": "capture-receipt", "codex-approver": "codex-read-approval", "read-broker": null,
  audit: "audit-ack", "gate-verifier": "gate-observation", "public-exporter": null, "check-publisher": null
} as const;
const repository = z.object({ id: numericId, ownerId: numericId, nameWithOwner: repositoryName, baseRef: branchRef }).strict();
const controlRepository = z.object({
  id: numericId, ownerId: numericId, nameWithOwner: repositoryName, defaultRef: branchRef
}).strict();
const deploymentKey = z.object({
  purpose: keyPurpose, fingerprint: controlDigest, publicJwk,
  notBefore: controlTime, notAfter: controlTime, revoked: z.boolean()
}).strict();
const role = z.object({
  purpose: rolePurpose, arn, oidcSubject: physicalText(2048), sessionSeconds: z.number().int().min(900).max(3600)
}).strict();
const workload = z.object({
  id: controlId, purpose: rolePurpose, repositoryId: numericId,
  workflowRef: physicalText(512).refine((v) => /^[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+\/\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}$/.test(v)),
  workflowSha: sha, environment: controlId, eventName: controlId,
  ref: branchRef, runnerClass: z.enum(["self-hosted", "github-hosted"]), artifactSha256: controlDigest,
  signingKeyFingerprint: controlDigest.nullable(), transportKeyFingerprint: controlDigest.nullable()
}).strict();
const principal = z.object({
  id: controlId, kind: z.enum(["requester", "producer", "authority", "workload"]), signingKeyFingerprint: controlDigest,
  transportKeyFingerprint: controlDigest.nullable(), repositoryIds: z.array(numericId).max(16),
  categoryIds: z.array(controlCategory).max(3), purposeIds: z.array(controlPurpose).max(3)
}).strict();
const origin = physicalText(512).refine((v) => {
  try {
    const url = new URL(v);
    return url.protocol === "https:" && url.origin === v && !url.username && !url.password
      && !url.search && !url.hash && url.pathname === "/";
  } catch { return false; }
});
const endpoint = z.object({ purpose: endpointPurpose, origin, tlsSpkiSha256: controlDigest }).strict();
const administration = z.object({
  configOwnerId: controlId, keyRecoveryOwnerId: controlId, retentionExceptionOwnerId: controlId, auditOwnerId: controlId
}).strict();
export const deploymentBindingSchema = z.object({
  ...controlBase("bootstrap-provenance-deployment"), configId: controlId, epoch: controlCounter,
  issuedAt: controlTime, validUntil: controlTime, controlRepository,
  repositories: z.array(repository).min(1).max(16),
  aws: z.object({
    accountId, region: z.literal("us-east-2"),
    buckets: z.object({ payload: bucket, evidence: bucket, audit: bucket, state: bucket, custody: bucket, config: bucket }).strict(),
    keys: z.object({ clientArn: arn, serviceArn: arn, custodyArn: arn }).strict(),
    roles: z.array(role).length(deploymentRolePurposes.length)
  }).strict(),
  workloads: z.array(workload).length(deploymentRolePurposes.length), keys: z.array(deploymentKey).min(1).max(64),
  principals: z.array(principal).min(1).max(64), endpoints: z.array(endpoint).length(3),
  github: z.object({ publisherAppId: numericId, installationId: numericId,
    requiredCheckName: z.literal("provenance/material-capture"), artifactWorkflowId: numericId }).strict(),
  policy: z.object({
    categoryPolicyId: controlId, materialPolicyId: controlId, retentionPolicyId: controlId,
    evidenceDays: z.literal(90), mode: z.literal("GOVERNANCE"), auditDays: z.literal(90),
    approvalMaxSeconds: z.number().int().min(1).max(300), challengeMaxSeconds: z.number().int().min(1).max(300),
    clockSkewSeconds: z.literal(60), controlEpoch: controlCounter
  }).strict(), admin: administration
}).strict();
export const activeConfigSchema = z.object({
  ...controlBase("bootstrap-active-config"), configId: controlId, epoch: controlCounter,
  bindingSha256: controlDigest, issuedAt: controlTime, validUntil: controlTime
}).strict();
export type DeploymentBinding = z.infer<typeof deploymentBindingSchema>;
export type ActiveConfig = z.infer<typeof activeConfigSchema>;

/** Protected local installation inputs. Never derive these from the signed document or a PR. */
export interface DeploymentBootstrap {
  rootKeys: readonly PrivateControlKey[];
  minimumEpoch: number;
  accountId: string;
  region: "us-east-2";
  configBucket: string;
  configKey: "config/active.json";
  workloadId: string;
  workloadPurpose: DeploymentBinding["workloads"][number]["purpose"];
  roleArn: string;
  oidcSubject: string;
  admin: DeploymentBinding["admin"];
}
type Immutable<T> = T extends object ? { readonly [P in keyof T]: Immutable<T[P]> } : T;
export interface InstalledDeployment {
  readonly binding: Immutable<DeploymentBinding>;
  readonly bindingSha256: string;
  readonly rootFingerprint: string;
  readonly verifiedAt: string;
  readonly localWorkloadId: string;
  readonly configLocation: Readonly<{ bucket: string; key: "config/active.json" }>;
  readonly keys: readonly Readonly<{ ownerId: string; purpose: z.infer<typeof keyPurpose>;
    fingerprint: string; publicJwk: z.infer<typeof publicJwk>; notBefore: string; notAfter: string; revoked: boolean }>[];
}
export interface CurrentDeployment {
  readonly installed: InstalledDeployment;
  readonly pointer: Immutable<ActiveConfig>;
  readonly pointerSha256: string;
  readonly verifiedAt: string;
}
const installations = new WeakMap<InstalledDeployment, { bytes: Buffer; bootstrap: DeploymentBootstrap }>();
const currents = new WeakSet<CurrentDeployment>();

function freeze<T>(value: T): Immutable<T> {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value as Immutable<T>;
}
function unique(values: readonly string[]) { requireControl(new Set(values).size === values.length); }
function window(value: { issuedAt: string; validUntil: string }, now: Date) {
  requireControl(Number.isFinite(now.getTime()) && Date.parse(value.issuedAt) <= now.getTime()
    && now.getTime() < Date.parse(value.validUntil));
}
function keyWindow(key: { notBefore: string; notAfter: string; revoked: boolean }, now: Date) {
  requireControl(!key.revoked && Date.parse(key.notBefore) <= now.getTime() && now.getTime() < Date.parse(key.notAfter));
}

// DeploymentBinding has a larger, separately approved bound than online control messages.
// Reuse the same full canonical payload signature, external JWK fingerprint and Ed25519 primitives.
function verifyBindingSignature(bytes: Uint8Array, bootstrap: DeploymentBootstrap, now: Date) {
  const envelope = signed.parse(parsePrivateControl(bytes, BINDING_BYTES, BINDING_DEPTH));
  const roots = z.array(z.object({ ownerId: controlId, purpose: z.literal("deployment-root"), publicKey: publicJwk,
    notBefore: controlTime, notAfter: controlTime, revoked: z.boolean() }).strict()).min(1).max(64).parse(bootstrap.rootKeys);
  const fingerprints = roots.map((root) => provenanceSigningKeyFingerprint(root.publicKey));
  unique(fingerprints);
  const root = roots[fingerprints.indexOf(envelope.signature.keyFingerprint)];
  requireControl(root && root.ownerId === bootstrap.admin.configOwnerId);
  keyWindow(root, now);
  const signatureBytes = Buffer.from(envelope.signature.value, "base64");
  requireControl(signatureBytes.length === 64 && signatureBytes.toString("base64") === envelope.signature.value);
  requireControl(verify(null, controlWire(envelope.payload), createPublicKey({ key: root.publicKey, format: "jwk" }), signatureBytes));
  return { binding: deploymentBindingSchema.parse(envelope.payload), root, fingerprint: envelope.signature.keyFingerprint };
}

function validateResources(binding: DeploymentBinding) {
  const { aws } = binding;
  unique(Object.values(aws.buckets));
  unique(Object.values(aws.keys));
  const keyPrefix = `arn:aws:kms:${aws.region}:${aws.accountId}:key/`;
  for (const key of Object.values(aws.keys)) {
    requireControl(key.startsWith(keyPrefix) && /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/.test(key.slice(keyPrefix.length)));
  }
  unique(aws.roles.map((r) => r.purpose));
  unique(aws.roles.map((r) => r.arn));
  unique(aws.roles.map((r) => r.oidcSubject));
  const rolePrefix = `arn:aws:iam::${aws.accountId}:role/`;
  for (const item of aws.roles) {
    requireControl(item.arn.startsWith(rolePrefix));
    const resource = item.arn.slice(rolePrefix.length);
    requireControl(/^[A-Za-z0-9+=,.@_/-]+$/.test(resource) && !resource.includes("//")
      && resource.split("/").every((part) => part !== "." && part !== ".." && part.length > 0));
  }
  unique(binding.endpoints.map((e) => e.purpose));
}

function validateRepositories(binding: DeploymentBinding) {
  unique(binding.repositories.map((r) => r.id));
  unique(binding.repositories.map((r) => r.nameWithOwner.toLowerCase()));
  const control = binding.controlRepository;
  const sameId = binding.repositories.find((r) => r.id === control.id);
  if (sameId) requireControl(sameId.ownerId === control.ownerId && sameId.nameWithOwner === control.nameWithOwner
    && sameId.baseRef === control.defaultRef);
  for (const repo of binding.repositories) {
    if (repo.nameWithOwner.toLowerCase() === control.nameWithOwner.toLowerCase()) requireControl(repo.id === control.id);
  }
}

function validateAuthority(binding: DeploymentBinding, rootFingerprint: string, now: Date): InstalledDeployment["keys"] {
  unique(binding.keys.map((k) => k.fingerprint));
  unique(binding.keys.map((k) => provenanceSigningKeyFingerprint(k.publicJwk)));
  for (const key of binding.keys) {
    requireControl(key.fingerprint === provenanceSigningKeyFingerprint(key.publicJwk));
    requireControl(Date.parse(key.notBefore) < Date.parse(key.notAfter));
  }
  const owned = new Map<string, string>();
  function enroll(fingerprint: string | null, purpose: z.infer<typeof keyPurpose>, ownerId: string) {
    requireControl(fingerprint !== null && !owned.has(fingerprint));
    const key = binding.keys.find((k) => k.fingerprint === fingerprint);
    requireControl(key && key.purpose === purpose);
    keyWindow(key, now);
    owned.set(fingerprint, ownerId);
  }
  enroll(rootFingerprint, "deployment-root", binding.admin.configOwnerId);
  unique(binding.workloads.map((w) => w.id));
  unique(binding.workloads.map((w) => w.purpose));
  unique(binding.principals.map((p) => p.id));
  for (const worker of binding.workloads) {
    requireControl(worker.id !== binding.admin.configOwnerId);
    const purpose = semanticPurpose[worker.purpose];
    if (purpose === null) requireControl(worker.signingKeyFingerprint === null);
    else enroll(worker.signingKeyFingerprint, purpose, worker.id);
    if (worker.purpose === "public-exporter" || worker.purpose === "check-publisher") {
      requireControl(worker.transportKeyFingerprint === null);
    } else if (worker.purpose !== "audit" || worker.transportKeyFingerprint !== null) {
      enroll(worker.transportKeyFingerprint, "workload-transport", worker.id);
    }
  }
  for (const actor of binding.principals) {
    unique(actor.repositoryIds); unique(actor.categoryIds); unique(actor.purposeIds);
    if (actor.kind === "requester" || actor.kind === "producer") {
      requireControl(!binding.workloads.some((w) => w.id === actor.id) && actor.id !== binding.admin.configOwnerId
        && actor.repositoryIds.length > 0 && actor.categoryIds.length > 0 && actor.purposeIds.length > 0);
      enroll(actor.signingKeyFingerprint, actor.kind === "requester" ? "requester-request" : "producer-submission", actor.id);
      enroll(actor.transportKeyFingerprint, actor.kind === "requester" ? "requester-transport" : "producer-transport", actor.id);
    } else if (actor.kind === "authority") {
      requireControl(actor.id === binding.admin.configOwnerId && actor.signingKeyFingerprint === rootFingerprint
        && actor.transportKeyFingerprint === null && actor.repositoryIds.length === 0
        && actor.categoryIds.length === 0 && actor.purposeIds.length === 0);
    } else {
      const worker = binding.workloads.find((w) => w.id === actor.id);
      requireControl(worker && worker.signingKeyFingerprint === actor.signingKeyFingerprint
        && worker.transportKeyFingerprint === actor.transportKeyFingerprint
        && actor.repositoryIds.length === 1 && actor.repositoryIds[0] === worker.repositoryId);
    }
    requireControl(actor.repositoryIds.every((id) => binding.repositories.some((r) => r.id === id)));
  }
  // Rotation/history semantic keys remain available for separate historical verification;
  // they have no current owner or authority. Every transport key must have a current owner.
  for (const key of binding.keys) {
    if (key.purpose.endsWith("-transport")) requireControl(owned.has(key.fingerprint));
  }
  return binding.keys.filter((key) => owned.has(key.fingerprint)).map((key) => ({ ...key, ownerId: owned.get(key.fingerprint)! }));
}

function validateWorkloads(binding: DeploymentBinding) {
  for (const worker of binding.workloads) {
    const repo = worker.repositoryId === binding.controlRepository.id ? binding.controlRepository
      : binding.repositories.find((r) => r.id === worker.repositoryId);
    requireControl(repo);
    requireControl(worker.workflowRef.startsWith(`${binding.controlRepository.nameWithOwner}/.github/workflows/`)
      && worker.workflowRef.endsWith(`@${worker.workflowSha}`));
    requireControl(worker.ref === ("defaultRef" in repo ? repo.defaultRef : repo.baseRef));
    const role = binding.aws.roles.find((r) => r.purpose === worker.purpose);
    requireControl(role);
    const [owner, name] = repo.nameWithOwner.split("/");
    const subjectRepo = role.oidcSubject.split(":")[1];
    const expectedRepo = subjectRepo?.includes("@") ? `${owner}@${repo.ownerId}/${name}@${repo.id}` : repo.nameWithOwner;
    const tail = `:environment:${worker.environment.replaceAll(":", "%3A")}:job_workflow_ref:${worker.workflowRef}`;
    requireControl(role.oidcSubject === `repo:${expectedRepo}${tail}`);
    if (worker.purpose === "capture" || worker.purpose === "read-broker") requireControl(worker.runnerClass === "self-hosted");
  }
}

function validateBootstrap(binding: DeploymentBinding, bootstrap: DeploymentBootstrap) {
  controlCounter.parse(bootstrap.minimumEpoch);
  accountId.parse(bootstrap.accountId);
  bucket.parse(bootstrap.configBucket);
  controlId.parse(bootstrap.workloadId);
  administration.parse(bootstrap.admin);
  requireControl(bootstrap.region === "us-east-2" && bootstrap.configKey === "config/active.json");
  requireControl(binding.epoch >= bootstrap.minimumEpoch && binding.policy.controlEpoch === binding.epoch);
  requireControl(binding.aws.accountId === bootstrap.accountId && binding.aws.region === bootstrap.region
    && binding.aws.buckets.config === bootstrap.configBucket);
  requireControl(controlWire(binding.admin).equals(controlWire(bootstrap.admin)));
  const worker = binding.workloads.find((w) => w.id === bootstrap.workloadId);
  requireControl(worker && worker.purpose === bootstrap.workloadPurpose);
  const role = binding.aws.roles.find((r) => r.purpose === worker.purpose);
  requireControl(role && role.arn === bootstrap.roleArn && role.oidcSubject === bootstrap.oidcSubject);
}

/** Verify installed bytes against protected local pins. Does not fetch config or authorize runtime execution. */
export function verifyInstalledDeployment(bytes: Uint8Array, bootstrap: DeploymentBootstrap, now: Date): InstalledDeployment {
  try {
    requireControl(bytes instanceof Uint8Array && bytes.byteLength <= BINDING_BYTES && Number.isFinite(now.getTime()));
    const ownedBytes = Buffer.from(bytes);
    const pins = structuredClone(bootstrap);
    const verified = verifyBindingSignature(ownedBytes, pins, now);
    const binding = verified.binding;
    window(binding, now);
    validateBootstrap(binding, pins);
    validateResources(binding);
    validateRepositories(binding);
    validateWorkloads(binding);
    const keys = validateAuthority(binding, verified.fingerprint, now);
    const evidence: InstalledDeployment = freeze({ binding, bindingSha256: controlHash(ownedBytes),
      rootFingerprint: verified.fingerprint, verifiedAt: now.toISOString(), localWorkloadId: pins.workloadId,
      configLocation: { bucket: pins.configBucket, key: pins.configKey }, keys });
    installations.set(evidence, { bytes: ownedBytes, bootstrap: pins });
    return evidence;
  } catch { throw new PrivateControlError(); }
}

/** Bytes must come from a fresh authenticated exact-object read by the fixed provider adapter.
 * This verifies signed content/location, not network origin, service encryption, or cache freshness.
 */
export function verifyCurrentPointer(input: { bytes: Uint8Array; bucket: string; key: string }, installed: InstalledDeployment, now: Date): CurrentDeployment {
  try {
    const state = installations.get(installed);
    requireControl(state && Number.isFinite(now.getTime()) && now.getTime() >= Date.parse(installed.verifiedAt));
    const refreshed = verifyInstalledDeployment(state.bytes, state.bootstrap, now);
    requireControl(input.bucket === refreshed.configLocation.bucket && input.key === refreshed.configLocation.key);
    requireControl(input.bytes instanceof Uint8Array && input.bytes.byteLength <= 16_384);
    const bytes = Buffer.from(input.bytes);
    const verified = verifyPrivateControl(bytes, activeConfigSchema, "deployment-root", state.bootstrap.rootKeys, now);
    const pointer = verified.payload;
    window(pointer, now);
    requireControl(verified.ownerId === refreshed.binding.admin.configOwnerId && verified.fingerprint === refreshed.rootFingerprint);
    requireControl(pointer.configId === refreshed.binding.configId && pointer.epoch === refreshed.binding.epoch
      && pointer.bindingSha256 === refreshed.bindingSha256 && pointer.epoch >= state.bootstrap.minimumEpoch);
    requireControl(Date.parse(pointer.issuedAt) >= Date.parse(refreshed.binding.issuedAt)
      && Date.parse(pointer.validUntil) <= Date.parse(refreshed.binding.validUntil));
    const evidence: CurrentDeployment = freeze({ installed: refreshed, pointer, pointerSha256: verified.sha256, verifiedAt: now.toISOString() });
    currents.add(evidence);
    return evidence;
  } catch { throw new PrivateControlError(); }
}

/** Fixed consumers must call this, not trust a structural/serialized InstalledDeployment. */
export function inspectInstalledDeployment(installed: InstalledDeployment, now: Date): InstalledDeployment {
  try {
    const state = installations.get(installed);
    requireControl(state && now.getTime() >= Date.parse(installed.verifiedAt));
    return verifyInstalledDeployment(state.bytes, state.bootstrap, now);
  } catch { throw new PrivateControlError(); }
}

/** Rechecks local validity/ownership only; the provider must obtain a new pointer for each required fresh read. */
export function inspectCurrentDeployment(current: CurrentDeployment, now: Date): CurrentDeployment {
  try {
    requireControl(currents.has(current) && now.getTime() >= Date.parse(current.verifiedAt));
    inspectInstalledDeployment(current.installed, now);
    window(current.pointer, now);
    return current;
  } catch { throw new PrivateControlError(); }
}
