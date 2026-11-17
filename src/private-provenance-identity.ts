import { createHash } from "node:crypto";
import { AssumeRoleWithWebIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { GetObjectCommand, GetObjectRetentionCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { parseCanonical, PRIVATE_PROVENANCE_LIMITS, RETENTION_MS, timestamp } from "./private-provenance-codec.js";
import { createPrivateCiphertextWriter, createPrivateCiphertextVerifier, type PrivateCaptureStorageIntent,
  type PrivateCiphertextStorage, type PrivateCiphertextInspection } from "./private-provenance-storage.js";
import { createLocalJWKSet, jwtVerify, type JWTPayload } from "jose";
import {
  inspectInstalledDeployment, verifyCurrentPointer,
  type InstalledDeployment, type CurrentDeployment
} from "./private-provenance-deployment.js";

const ISSUER = "https://token.actions.githubusercontent.com";
const JWKS = `${ISSUER}/.well-known/jwks`;
const AUDIENCE = "sts.amazonaws.com";
const REGION = "us-east-2";
const MAX_DOCUMENT = 16_384;
const DEADLINE = 10_000;
const numeric = (v: unknown): v is string => typeof v === "string" && /^[1-9][0-9]{0,19}$/.test(v);
const sha = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{40}$/.test(v);
const text = (v: unknown, max: number): v is string => typeof v === "string" && v.length > 0
  && Buffer.byteLength(v) <= max && !/[\u0000-\u001f\u007f]/.test(v);
const id = (v: unknown): string => {
  insist(typeof v === "number" && Number.isSafeInteger(v) && v > 0); return String(v);
};
type Json = Record<string, any>;
export class PrivateIdentityError extends Error {
  constructor() { super("Private provenance identity unavailable or invalid."); }
}
function insist(value: unknown): asserts value { if (!value) throw new PrivateIdentityError(); }

/** Opaque, process-owned observation. It exposes no token, credential, SDK client or arbitrary operation. */
export interface PrivateRoleIdentity {
  readonly workloadId: string;
  readonly purpose: InstalledDeployment["binding"]["workloads"][number]["purpose"];
  readonly expiresAt: string;
}
interface Session {
  installed: InstalledDeployment; s3: S3Client; githubToken: string; token: string;
  claims: JWTPayload; expires: number; controller: AbortController;
  runId: string; attempt: string;
}
const sessions = new WeakMap<PrivateRoleIdentity, Session>();

async function bounded<T>(parents: readonly AbortSignal[], operation: (signal: AbortSignal) => Promise<T>, milliseconds = DEADLINE): Promise<T> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  for (const parent of parents) {
    if (parent.aborted) abort();
    parent.addEventListener("abort", abort, { once: true });
  }
  const timer = setTimeout(abort, milliseconds);
  let rejectAbort: (() => void) | undefined;
  try {
    insist(!controller.signal.aborted);
    return await Promise.race([operation(controller.signal), new Promise<never>((_, reject) => {
      rejectAbort = () => reject(new PrivateIdentityError());
      controller.signal.addEventListener("abort", rejectAbort, { once: true });
    })]);
  } catch { throw new PrivateIdentityError(); }
  finally {
    clearTimeout(timer); for (const parent of parents) parent.removeEventListener("abort", abort);
    if (rejectAbort) controller.signal.removeEventListener("abort", rejectAbort);
    controller.abort();
  }
}
async function json(url: string, token: string | undefined, signal: AbortSignal, limit = 262_144): Promise<Json> {
  const response = await fetch(url, { method: "GET", redirect: "error", signal, cache: "no-store",
    headers: { accept: "application/json", ...(url.startsWith("https://api.github.com/") ? { "x-github-api-version": "2022-11-28" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}) } });
  insist(response.status === 200 && !response.redirected && !response.headers.has("link") && response.body);
  const reader = response.body.getReader(); const parts: Uint8Array[] = []; let total = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    for (;;) {
      const next = await reader.read(); insist(!signal.aborted);
      if (next.done) break;
      total += next.value.byteLength; insist(total <= limit); parts.push(next.value);
    }
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(parts)));
    insist(value !== null && typeof value === "object" && !Array.isArray(value)); return value as Json;
  } finally { signal.removeEventListener("abort", cancel); cancel(); }
}

function runtime() {
  const token = process.env.GITHUB_TOKEN;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const runId = process.env.GITHUB_RUN_ID; const attempt = process.env.GITHUB_RUN_ATTEMPT;
  const rawUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  insist(process.env.GITHUB_ACTIONS === "true" && text(token, 16_384) && text(requestToken, 16_384)
    && numeric(runId) && numeric(attempt) && text(rawUrl, 4096));
  const url = new URL(rawUrl);
  // GitHub supplies a per-job URL. Only its HTTPS Actions service namespace and idtoken route are admitted.
  insist(url.protocol === "https:" && !url.username && !url.password && !url.port && !url.hash
    && /^[a-z0-9-]+\.actions\.githubusercontent\.com$/.test(url.hostname)
    && /^\/[A-Za-z0-9._/-]+\/idtoken$/.test(url.pathname)
    && [...url.searchParams.keys()].every((key) => key === "api-version" || key === "audience")
    && (!url.searchParams.has("audience") || url.searchParams.get("audience") === AUDIENCE));
  url.searchParams.set("audience", AUDIENCE);
  return { githubToken: token, requestToken, tokenUrl: url.href, runId, attempt };
}
function enrollment(installed: InstalledDeployment) {
  inspectInstalledDeployment(installed, new Date());
  const binding = installed.binding;
  const workload = binding.workloads.find((w) => w.id === installed.localWorkloadId)!;
  const role = binding.aws.roles.find((r) => r.purpose === workload.purpose)!;
  const repository = workload.repositoryId === binding.controlRepository.id ? binding.controlRepository
    : binding.repositories.find((r) => r.id === workload.repositoryId)!;
  insist(workload && role && repository); return { binding, workload, role, repository };
}
async function verifyToken(token: string, installed: InstalledDeployment, runId: string, attempt: string, signal: AbortSignal) {
  const { workload, role, repository } = enrollment(installed);
  insist(text(token, MAX_DOCUMENT));
  const keys = await json(JWKS, undefined, signal, 65_536);
  insist(Array.isArray(keys.keys) && keys.keys.length > 0 && keys.keys.length <= 16);
  const { payload: c, protectedHeader } = await jwtVerify(token, createLocalJWKSet(keys as { keys: any[] }), {
    issuer: ISSUER, audience: AUDIENCE, subject: role.oidcSubject, algorithms: ["RS256"], typ: "JWT",
    clockTolerance: 0, maxTokenAge: 600, requiredClaims: ["iat", "nbf", "exp", "jti"], currentDate: new Date()
  });
  insist(text(protectedHeader.kid, 256) && Object.keys(protectedHeader).every((k) => ["alg", "kid", "typ", "x5t"].includes(k))
    && c.aud === AUDIENCE && typeof c.iat === "number" && Number.isSafeInteger(c.iat)
    && typeof c.exp === "number" && Number.isSafeInteger(c.exp) && c.exp > c.iat && c.exp - c.iat <= 600
    && text(c.jti, 256) && c.repository === repository.nameWithOwner && c.repository_id === repository.id
    && c.repository_owner_id === repository.ownerId && c.run_id === runId && c.run_attempt === attempt
    && c.environment === workload.environment && c.event_name === workload.eventName && c.ref === workload.ref
    && c.runner_environment === workload.runnerClass && sha(c.sha) && sha(c.workflow_sha)
    && numeric(c.actor_id) && numeric(c.check_run_id) && text(c.workflow_ref, 1024));
  // Enrollment includes job_workflow_ref in its exact subject: only the pinned reusable-job contract is supported.
  insist(c.job_workflow_ref === workload.workflowRef && c.job_workflow_sha === workload.workflowSha);
  return c;
}
async function nativeContext(session: Pick<Session, "installed" | "githubToken" | "claims" | "runId" | "attempt">, signal: AbortSignal) {
  const { workload, repository } = enrollment(session.installed); const c = session.claims;
  const prefix = `https://api.github.com/repos/${repository.nameWithOwner}`;
  const get = (path: string) => json(prefix + path, session.githubToken, signal);
  const sameRepository = (r: Json) => r && id(r.id) === repository.id && r.full_name === repository.nameWithOwner
    && r.owner && id(r.owner.id) === repository.ownerId;
  insist(sameRepository(await get("")));
  const runPath = `/actions/runs/${session.runId}`;
  const run = await get(`${runPath}/attempts/${session.attempt}`);
  insist(id(run.id) === session.runId && id(run.run_attempt) === session.attempt && sameRepository(run.repository)
    && sameRepository(run.head_repository) && run.head_sha === c.sha && run.event === workload.eventName
    && run.head_branch === workload.ref.slice("refs/heads/".length) && run.status === "in_progress"
    && run.conclusion === null && run.actor && id(run.actor.id) === c.actor_id);
  insist(text(run.path, 1024));
  const callerPath = /^(\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml)(?:@(.+))?$/.exec(run.path);
  // GitHub returns either a bare workflow path or a ref-qualified path. Never ignore a supplied ref.
  insist(callerPath && (callerPath[2] === undefined || callerPath[2] === workload.ref
    || callerPath[2] === workload.ref.slice("refs/heads/".length))
    && c.workflow_ref === `${repository.nameWithOwner}/${callerPath[1]}@${workload.ref}`);
  insist(Array.isArray(run.referenced_workflows) && run.referenced_workflows.length <= 100
    && run.referenced_workflows.filter((w: Json) => w.path === workload.workflowRef && w.sha === workload.workflowSha).length === 1);
  // One bounded complete page is sufficient for this fixed workload; larger/ambiguous runs fail closed.
  const jobs = await get(`${runPath}/attempts/${session.attempt}/jobs?per_page=100`);
  insist(Number.isSafeInteger(jobs.total_count) && jobs.total_count > 0 && jobs.total_count <= 100
    && Array.isArray(jobs.jobs) && jobs.jobs.length === jobs.total_count);
  const matching = jobs.jobs.filter((j: Json) => j.check_run_url === `${prefix}/check-runs/${c.check_run_id}`);
  insist(matching.length === 1); const job = matching[0];
  insist(id(job.run_id) === session.runId && job.run_url === prefix + runPath && job.head_sha === c.sha
    && job.status === "in_progress" && job.conclusion === null && job.completed_at === null
    && Array.isArray(job.labels) && job.labels.every((v: unknown) => typeof v === "string")
    && job.labels.includes("self-hosted") === (workload.runnerClass === "self-hosted") && id(job.runner_id));
  // Re-read current attempt so an older still-readable attempt cannot authenticate after a rerun/cancellation.
  const current = await get(runPath);
  insist(id(current.id) === session.runId && id(current.run_attempt) === session.attempt
    && current.status === "in_progress" && current.conclusion === null && current.head_sha === c.sha);
}
function sessionPolicy(installed: InstalledDeployment): string {
  const { binding } = enrollment(installed);
  const resource = `arn:aws:s3:::${installed.configLocation.bucket}/${installed.configLocation.key}`;
  return JSON.stringify({ Version: "2012-10-17", Statement: [
    { Effect: "Allow", Action: "s3:GetObject", Resource: resource },
    { Effect: "Allow", Action: "kms:Decrypt", Resource: binding.aws.keys.serviceArn, Condition: { StringEquals: {
      "kms:ViaService": `s3.${REGION}.amazonaws.com`, "kms:CallerAccount": binding.aws.accountId,
      "kms:EncryptionContext:aws:s3:arn": resource
    } } }
  ] });
}
async function pointer(session: Session, signal: AbortSignal): Promise<CurrentDeployment> {
  insist(!session.controller.signal.aborted && Date.now() < session.expires);
  const { binding } = enrollment(session.installed); const location = session.installed.configLocation;
  const output = await session.s3.send(new GetObjectCommand({ Bucket: location.bucket, Key: location.key,
    ExpectedBucketOwner: binding.aws.accountId, ChecksumMode: "ENABLED" }), { abortSignal: signal });
  const body = output.Body;
  const destroy = () => { if (body && "destroy" in body && typeof body.destroy === "function") body.destroy(); };
  signal.addEventListener("abort", destroy, { once: true });
  try {
    insist(output.$metadata.httpStatusCode === 200 && Number.isSafeInteger(output.ContentLength)
      && output.ContentLength! > 0 && output.ContentLength! <= MAX_DOCUMENT
      && output.ServerSideEncryption === "aws:kms" && output.SSEKMSKeyId === binding.aws.keys.serviceArn
      && output.BucketKeyEnabled !== true && !output.DeleteMarker && !output.ContentRange
      && body && Symbol.asyncIterator in body);
    const parts: Buffer[] = []; let length = 0;
    for await (const chunk of body as AsyncIterable<Uint8Array>) {
      insist(!signal.aborted && chunk instanceof Uint8Array); length += chunk.byteLength;
      insist(length <= MAX_DOCUMENT); parts.push(Buffer.from(chunk));
    }
    const bytes = Buffer.concat(parts);
    insist(!signal.aborted && !session.controller.signal.aborted && Date.now() < session.expires
      && length === output.ContentLength && (output.ChecksumSHA256 === undefined
        || createHash("sha256").update(bytes).digest("base64") === output.ChecksumSHA256));
    return verifyCurrentPointer({ bytes, bucket: location.bucket, key: location.key }, session.installed, new Date());
  } finally { signal.removeEventListener("abort", destroy); destroy(); }
}

// Credentials stay inside this module; every exchange uses the already verified exact role/token.
async function exchange(session: Pick<Session, "installed" | "token" | "claims" | "runId" | "attempt">,
  policy: string, signal: AbortSignal): Promise<{ s3: S3Client; expires: number }> {
  const { binding, role } = enrollment(session.installed);
  insist(!signal.aborted && Date.now() < session.claims.exp! * 1000 && Buffer.byteLength(policy) <= 2048);
  const config = { region: REGION, maxAttempts: 1, useFipsEndpoint: false, useDualstackEndpoint: false,
    requestHandler: { connectionTimeout: 2000, socketTimeout: 5000 } };
  const sts = new STSClient({ ...config, endpoint: `https://sts.${REGION}.amazonaws.com`,
    credentials: async () => { throw new PrivateIdentityError(); } });
  try {
    const sessionName = `bootstrap-${session.runId}-${session.attempt}`; insist(sessionName.length <= 64);
    const started = Date.now();
    const result = await sts.send(new AssumeRoleWithWebIdentityCommand({ RoleArn: role.arn,
      RoleSessionName: sessionName, WebIdentityToken: session.token, DurationSeconds: role.sessionSeconds,
      Policy: policy }), { abortSignal: signal });
    const c = result.Credentials; const expires = c?.Expiration?.getTime();
    insist(!signal.aborted && result.$metadata.httpStatusCode === 200 && result.SubjectFromWebIdentityToken === role.oidcSubject
      && result.Audience === AUDIENCE && result.AssumedRoleUser?.Arn ===
        `arn:aws:sts::${binding.aws.accountId}:assumed-role/${role.arn.split("/").at(-1)}/${sessionName}`
      && c && text(c.AccessKeyId, 128) && text(c.SecretAccessKey, 256) && text(c.SessionToken, 16_384)
      && expires && Number.isFinite(expires) && expires > Date.now() + 30_000 && expires <= started + role.sessionSeconds * 1000 + 5000);
    const s3 = new S3Client({ ...config, endpoint: `https://s3.${REGION}.amazonaws.com`, forcePathStyle: true,
      followRegionRedirects: false, useArnRegion: false, credentials: {
        accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken, expiration: c.Expiration!
      } });
    return { s3, expires: Math.min(expires, session.claims.exp! * 1000, Date.parse(binding.validUntil)) };
  } finally { sts.destroy(); }
}
/** Fixed Actions-runtime entrypoint; importing the module performs no credential lookup or provider operation. */
export async function establishPrivateRoleIdentity(installed: InstalledDeployment, signal?: AbortSignal): Promise<PrivateRoleIdentity> {
  return bounded(signal ? [signal] : [], async (abortSignal) => {
    const { workload } = enrollment(installed); const inputs = runtime();
    const acquired = await json(inputs.tokenUrl, inputs.requestToken, abortSignal, MAX_DOCUMENT + 1024);
    insist(text(acquired.value, MAX_DOCUMENT)); const token = acquired.value;
    const claims = await verifyToken(token, installed, inputs.runId, inputs.attempt, abortSignal);
    const context = { installed, token, claims, githubToken: inputs.githubToken, runId: inputs.runId, attempt: inputs.attempt };
    await nativeContext(context, abortSignal);
    const lease = await exchange(context, sessionPolicy(installed), abortSignal);
    let owned = false;
    try {
      const session: Session = { ...context, ...lease, controller: new AbortController() };
      await pointer(session, abortSignal); insist(!abortSignal.aborted);
      const handle = Object.freeze({ workloadId: workload.id, purpose: workload.purpose, expiresAt: new Date(session.expires).toISOString() });
      sessions.set(handle, session); owned = true; return handle;
    } finally { if (!owned) lease.s3.destroy(); }
  });
}
export async function refreshPrivateRoleIdentity(identity: PrivateRoleIdentity, signal?: AbortSignal): Promise<CurrentDeployment> {
  const session = sessions.get(identity); insist(session && !session.controller.signal.aborted && Date.now() < session.expires);
  return bounded([session.controller.signal, ...(signal ? [signal] : [])], async (abortSignal) => {
    await nativeContext(session, abortSignal);
    return await pointer(session, abortSignal);
  });
}
export function disposePrivateRoleIdentity(identity: PrivateRoleIdentity): void {
  const session = sessions.get(identity); insist(session); sessions.delete(identity);
  session.controller.abort(); session.s3.destroy(); session.token = ""; session.githubToken = "";
}

const PAYLOAD_PREFIX = "payloads/captures/";
function payloadSession(identity: PrivateRoleIdentity, purpose: "capture" | "ciphertext-verifier") {
  const session = sessions.get(identity);
  insist(session && !session.controller.signal.aborted && Date.now() < session.expires);
  const { binding, workload } = enrollment(session.installed); insist(workload.purpose === purpose);
  return { session, binding, config: { region: REGION as "us-east-2", bucket: binding.aws.buckets.payload,
    prefix: PAYLOAD_PREFIX, serviceKeyArn: binding.aws.keys.serviceArn } };
}
function payloadPolicy(session: Session, key: string, versionId: string | undefined, retainUntil?: string) {
  const { binding } = enrollment(session.installed);
  const resource = `arn:aws:s3:::${binding.aws.buckets.payload}/${key}`;
  const policy = JSON.parse(sessionPolicy(session.installed));
  if (versionId === undefined) {
    const retention = { StringEquals: { "s3:object-lock-mode": "GOVERNANCE" },
      DateEquals: { "s3:object-lock-retain-until-date": retainUntil } };
    policy.Statement.push({ Effect: "Allow", Action: "s3:PutObject", Resource: resource,
      Condition: { ...retention, Null: { "s3:if-none-match": "false" }, StringEquals: {
        ...retention.StringEquals, "s3:x-amz-server-side-encryption": "aws:kms",
        "s3:x-amz-server-side-encryption-aws-kms-key-id": binding.aws.keys.serviceArn
      } } }, { Effect: "Allow", Action: "s3:PutObjectRetention", Resource: resource, Condition: retention });
  } else {
    policy.Statement.push({ Effect: "Allow", Action: "s3:GetObjectVersion", Resource: resource,
      Condition: { StringEquals: { "s3:VersionId": versionId } } },
    // S3 exposes no version-id IAM condition for retention metadata; the fixed request still pins it.
    { Effect: "Allow", Action: "s3:GetObjectRetention", Resource: resource });
  }
  policy.Statement.push({ Effect: "Allow", Action: versionId === undefined ? "kms:GenerateDataKey" : "kms:Decrypt",
    Resource: binding.aws.keys.serviceArn, Condition: { StringEquals: {
      "kms:ViaService": `s3.${REGION}.amazonaws.com`, "kms:CallerAccount": binding.aws.accountId,
      "kms:EncryptionContext:aws:s3:arn": resource
    } } });
  return JSON.stringify(policy);
}
async function fresh(session: Session, signal: AbortSignal) {
  insist(!signal.aborted && !session.controller.signal.aborted && Date.now() < session.expires);
  await nativeContext(session, signal); await pointer(session, signal);
}
function clientKey(bytes: Uint8Array, keyArn: string) {
  const value = parseCanonical(bytes, PRIVATE_PROVENANCE_LIMITS.envelope, 5) as { header?: { kmsKeyArn?: unknown } };
  insist(value?.header?.kmsKeyArn === keyArn);
}
function normalizedObject(output: Json) {
  insist(output.DeleteMarker !== true && output.ContentRange === undefined && output.PartsCount === undefined
    && output.BucketKeyEnabled !== true && output.SSECustomerAlgorithm === undefined);
  return { statusCode: output.$metadata?.httpStatusCode, VersionId: output.VersionId,
    ChecksumSHA256: output.ChecksumSHA256, ChecksumType: output.ChecksumType,
    ServerSideEncryption: output.ServerSideEncryption, SSEKMSKeyId: output.SSEKMSKeyId,
    ...(output.BucketKeyEnabled === undefined ? {} : { BucketKeyEnabled: output.BucketKeyEnabled }) };
}
/** Fixed SDK upload; intent is checked data, not capture admission or a receipt. Never retry an uncertain write. */
export async function putPrivateRoleCiphertext(identity: PrivateRoleIdentity, bytes: Uint8Array,
  intent: PrivateCaptureStorageIntent, signal?: AbortSignal): Promise<PrivateCiphertextStorage> {
  try {
    const { session, binding, config } = payloadSession(identity, "capture");
    insist(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= PRIVATE_PROVENANCE_LIMITS.envelope);
    const owned = Buffer.from(bytes); const admitted = structuredClone(intent);
    clientKey(owned, binding.aws.keys.clientArn);
    const captured = Date.parse(timestamp.parse(admitted.capturedAt));
    insist(captured <= Date.now() && Date.now() - captured <= binding.policy.clockSkewSeconds * 1000
      && admitted.retainUntil === new Date(captured + RETENTION_MS).toISOString());
    return await bounded([session.controller.signal, ...(signal ? [signal] : [])], async (abortSignal) => {
      const writer = createPrivateCiphertextWriter(config, { region: REGION,
        async putObject(request) {
          await fresh(session, abortSignal);
          const lease = await exchange(session, payloadPolicy(session, request.Key, undefined, admitted.retainUntil), abortSignal);
          try {
            const scoped = { ...session, ...lease }; await pointer(scoped, abortSignal);
            insist(!abortSignal.aborted && Date.now() - captured <= binding.policy.clockSkewSeconds * 1000);
            const result = await lease.s3.send(new PutObjectCommand({ ...request,
              ObjectLockRetainUntilDate: new Date(request.ObjectLockRetainUntilDate) }), { abortSignal });
            const normalized = normalizedObject(result);
            await fresh(session, abortSignal); return normalized;
          } finally { lease.s3.destroy(); }
        } });
      return await writer.put(owned, admitted);
    }, 30_000);
  } catch { throw new PrivateIdentityError(); }
}
/** Ciphertext-only verifier. No receipt signing, client-key unwrap, plaintext or caller SDK client. */
export async function inspectPrivateRoleCiphertext(identity: PrivateRoleIdentity, storage: PrivateCiphertextStorage,
  capturedAt: string, signal?: AbortSignal): Promise<PrivateCiphertextInspection> {
  try {
    const { session, binding, config } = payloadSession(identity, "ciphertext-verifier");
    const locator = structuredClone(storage); const captured = Date.parse(timestamp.parse(capturedAt));
    insist(captured <= Date.now() && Date.now() < captured + RETENTION_MS);
    return await bounded([session.controller.signal, ...(signal ? [signal] : [])], async (abortSignal) => {
      let lease: Awaited<ReturnType<typeof exchange>> | undefined; let destroyBody: (() => void) | undefined;
      const verifier = createPrivateCiphertextVerifier(config, { region: REGION,
        async getObject(request) {
          await fresh(session, abortSignal);
          lease = await exchange(session, payloadPolicy(session, request.Key, request.VersionId), abortSignal);
          await pointer({ ...session, ...lease }, abortSignal);
          insist(!abortSignal.aborted && captured <= Date.now() && Date.now() < captured + RETENTION_MS);
          const output = await lease.s3.send(new GetObjectCommand(request), { abortSignal }); const body = output.Body;
          destroyBody = () => { if (body && "destroy" in body && typeof body.destroy === "function") body.destroy(); };
          if (abortSignal.aborted) { destroyBody(); throw new PrivateIdentityError(); }
          abortSignal.addEventListener("abort", destroyBody, { once: true });
          const normalized = normalizedObject(output);
          insist(output.LastModified instanceof Date && Number.isFinite(output.LastModified.getTime())
            && Math.abs(output.LastModified.getTime() - captured) <= binding.policy.clockSkewSeconds * 1000
            && output.LastModified.getTime() <= Date.now() + binding.policy.clockSkewSeconds * 1000
            && body && Symbol.asyncIterator in body && !abortSignal.aborted);
          return { ...normalized, ContentLength: output.ContentLength, Body: {
            async *[Symbol.asyncIterator]() {
              const chunks: Buffer[] = []; let size = 0; let count = 0;
              for await (const chunk of body as AsyncIterable<Uint8Array>) {
                insist(!abortSignal.aborted && Date.now() < session.expires && chunk instanceof Uint8Array
                  && ++count <= 65_536 && (size += chunk.byteLength) <= PRIVATE_PROVENANCE_LIMITS.envelope);
                chunks.push(Buffer.from(chunk));
              }
              const bytes = Buffer.concat(chunks); clientKey(bytes, binding.aws.keys.clientArn); yield bytes;
            }
          } };
        },
        async getObjectRetention(request) {
          insist(lease && !abortSignal.aborted && Date.now() < lease.expires
            && captured <= Date.now() && Date.now() < captured + RETENTION_MS);
          const output = await lease.s3.send(new GetObjectRetentionCommand(request), { abortSignal });
          const date = output.Retention?.RetainUntilDate;
          insist(date instanceof Date && Number.isFinite(date.getTime()) && date.getTime() === captured + RETENTION_MS);
          return { statusCode: output.$metadata?.httpStatusCode,
            Retention: { Mode: output.Retention?.Mode, RetainUntilDate: date.toISOString() } };
        } });
      try {
        const result = await verifier.inspect(locator); await fresh(session, abortSignal);
        insist(captured <= Date.now() && Date.now() < captured + RETENTION_MS); return result;
      } finally {
        if (destroyBody) { abortSignal.removeEventListener("abort", destroyBody); destroyBody(); }
        lease?.s3.destroy();
      }
    }, 30_000);
  } catch { throw new PrivateIdentityError(); }
}
