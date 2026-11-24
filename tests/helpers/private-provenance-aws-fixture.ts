import { createHash, createPrivateKey, sign } from "node:crypto";
import { Readable } from "node:stream";
import { vi } from "vitest";
import { STSClient } from "@aws-sdk/client-sts";
import { S3Client } from "@aws-sdk/client-s3";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { generateProvenanceSigningKeyPair, provenanceSigningKeyFingerprint } from "../../src/provenance.js";
import { controlHash, controlWire, type PrivateControlKey } from "../../src/private-provenance-control.js";
import { deploymentRolePurposes, verifyCurrentPointer, verifyInstalledDeployment, type DeploymentBootstrap } from "../../src/private-provenance-deployment.js";
import { establishPrivateRoleIdentity } from "../../src/private-provenance-identity.js";

const issuedAt = "2026-11-15T00:00:00.000Z";
const validUntil = "2026-11-16T00:00:00.000Z";
export const now = new Date("2026-11-15T01:00:00.000Z");
const controlBase = (domain: string) => ({ domain, version: 1, canonicalization: "sorted-json-v1" });

type Purpose = typeof deploymentRolePurposes[number];
function fixture(purpose: Purpose) {
  const pairs = new Map<string, ReturnType<typeof generateProvenanceSigningKeyPair>>();
  const keys: any[] = [];
  function key(purpose: string) {
    const pair = generateProvenanceSigningKeyPair();
    const fingerprint = provenanceSigningKeyFingerprint(pair.publicKey);
    pairs.set(fingerprint, pair);
    keys.push({ purpose, fingerprint, publicJwk: pair.publicKey, notBefore: issuedAt,
      notAfter: "2027-01-01T00:00:00.000Z", revoked: false });
    return fingerprint;
  }
  const rootFingerprint = key("deployment-root");
  const semantics: Record<string, string> = { controller: "controller-admission", "public-signer": "public-manifest",
    "ciphertext-verifier": "capture-receipt", "codex-approver": "codex-read-approval", audit: "audit-ack", "gate-verifier": "gate-observation" };
  const workloads = deploymentRolePurposes.map((purpose) => ({ id: `worker-${purpose}`, purpose, repositoryId: "123",
    workflowRef: `fixture/control/.github/workflows/${purpose}.yml@${"a".repeat(40)}`, workflowSha: "a".repeat(40),
    environment: "production", eventName: "workflow_dispatch", ref: "refs/heads/main",
    runnerClass: purpose === "capture" || purpose === "read-broker" ? "self-hosted" : "github-hosted",
    artifactSha256: "b".repeat(64), signingKeyFingerprint: semantics[purpose] ? key(semantics[purpose]!) : null,
    transportKeyFingerprint: ["public-exporter", "check-publisher", "audit"].includes(purpose) ? null : key("workload-transport") }));
  const roles = workloads.map((worker) => ({ purpose: worker.purpose,
    arn: `arn:aws:iam::123456789012:role/provenance/${worker.purpose}`, sessionSeconds: 900,
    oidcSubject: `repo:fixture/control:environment:production:job_workflow_ref:${worker.workflowRef}` }));
  const principals = ["requester", "producer"].map((kind) => ({ id: kind, kind,
    signingKeyFingerprint: key(kind === "requester" ? "requester-request" : "producer-submission"),
    transportKeyFingerprint: key(kind === "requester" ? "requester-transport" : "producer-transport"),
    repositoryIds: ["123"], categoryIds: ["validation-summary"], purposeIds: ["provenance-verification"] }));
  const binding: any = { ...controlBase("bootstrap-provenance-deployment"), configId: "config-1", epoch: 4, issuedAt, validUntil,
    controlRepository: { id: "123", ownerId: "456", nameWithOwner: "fixture/control", defaultRef: "refs/heads/main" },
    repositories: [{ id: "123", ownerId: "456", nameWithOwner: "fixture/control", baseRef: "refs/heads/main" }],
    aws: { accountId: "123456789012", region: "us-east-2",
      buckets: Object.fromEntries(["payload", "evidence", "audit", "state", "custody", "config"].map((name) => [name, `fabricated-${name}`])),
      keys: Object.fromEntries(["clientArn", "serviceArn", "custodyArn"].map((name, index) => [name,
        `arn:aws:kms:us-east-2:123456789012:key/00000000-0000-4000-8000-00000000000${index}`])), roles },
    workloads, keys, principals,
    endpoints: ["capture", "read", "audit"].map((purpose) => ({ purpose, origin: `https://${purpose}.invalid`, tlsSpkiSha256: "c".repeat(64) })),
    github: { publisherAppId: "11", installationId: "22", artifactWorkflowId: "33", requiredCheckName: "provenance/material-capture" },
    policy: { categoryPolicyId: "summary-v1", materialPolicyId: "all-changed-v1", retentionPolicyId: "governance90-v1",
      evidenceDays: 90, mode: "GOVERNANCE", auditDays: 90, approvalMaxSeconds: 300, challengeMaxSeconds: 300, clockSkewSeconds: 60, controlEpoch: 4 },
    admin: { configOwnerId: "owner-100", keyRecoveryOwnerId: "owner-100", retentionExceptionOwnerId: "owner-100", auditOwnerId: "owner-100" } };
  const root = pairs.get(rootFingerprint)!;
  const rootKey: PrivateControlKey = { ownerId: "owner-100", purpose: "deployment-root", publicKey: root.publicKey,
    notBefore: issuedAt, notAfter: "2027-01-01T00:00:00.000Z", revoked: false };
  const local = workloads.find((worker) => worker.purpose === purpose)!;
  const localRole = roles.find((role) => role.purpose === local.purpose)!;
  const bootstrap: DeploymentBootstrap = { rootKeys: [rootKey], minimumEpoch: 4, accountId: binding.aws.accountId,
    region: "us-east-2", configBucket: "fabricated-config", configKey: "config/active.json", workloadId: local.id,
    workloadPurpose: purpose, roleArn: localRole.arn, oidcSubject: localRole.oidcSubject, admin: { ...binding.admin } };
  const signed = (payload: unknown, fingerprint = rootFingerprint) => controlWire({ payload, signature: { keyFingerprint: fingerprint,
    value: sign(null, controlWire(payload), createPrivateKey({ key: pairs.get(fingerprint)!.privateKey, format: "jwk" })).toString("base64") } });
  const install = () => verifyInstalledDeployment(signed(binding), bootstrap, now);
  const pointer = (bytes = signed(binding)) => ({ ...controlBase("bootstrap-active-config"), configId: binding.configId,
    epoch: binding.epoch, bindingSha256: controlHash(bytes), issuedAt: now.toISOString(), validUntil });
  const current = (payload = pointer(), installed = install()) => verifyCurrentPointer({ bytes: signed(payload),
    bucket: bootstrap.configBucket, key: bootstrap.configKey }, installed, now);
  return { binding, bootstrap, rootKey, rootFingerprint, key, signed, install, pointer, current };
}

const jwtPair = await generateKeyPair("RS256");
const jwk = { ...await exportJWK(jwtPair.publicKey), kid: "payload-fixture-rsa", alg: "RS256", use: "sig" };
export const captureId = "12345678-1234-4123-8123-123456789abc";
export const capturedAt = now.toISOString();
export const retainUntil = new Date(now.getTime() + 90 * 86_400_000).toISOString();
export const intent = { captureId, capturedAt, retainUntil };
export type Hook = (phase: string, value: any, command?: any) => unknown;
export async function payloadHarness(purpose: Purpose = "capture", hook?: Hook) {
  const f = fixture(purpose); const installed = f.install();
  const worker = f.binding.workloads.find((w: any) => w.purpose === purpose);
  const role = f.binding.aws.roles.find((r: any) => r.purpose === purpose);
  const seconds = now.getTime() / 1000;
  const claims = { iss: "https://token.actions.githubusercontent.com", aud: "sts.amazonaws.com", sub: role.oidcSubject,
    iat: seconds, nbf: seconds, exp: seconds + 300, jti: "fixture-jti", repository: "fixture/control", repository_id: "123",
    repository_owner_id: "456", run_id: "100", run_attempt: "2", actor_id: "9", check_run_id: "300",
    environment: "production", event_name: "workflow_dispatch", ref: "refs/heads/main", runner_environment: worker.runnerClass,
    sha: "b".repeat(40), workflow_ref: "fixture/control/.github/workflows/caller.yml@refs/heads/main", workflow_sha: "b".repeat(40),
    job_workflow_ref: worker.workflowRef, job_workflow_sha: worker.workflowSha };
  const token = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: jwk.kid, typ: "JWT" }).sign(jwtPair.privateKey);
  vi.stubEnv("GITHUB_ACTIONS", "true"); vi.stubEnv("GITHUB_TOKEN", "fabricated-github-token");
  vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fabricated-actions-token");
  vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://pipelines.actions.githubusercontent.com/fabricated/idtoken?api-version=2.0");
  vi.stubEnv("GITHUB_RUN_ID", "100"); vi.stubEnv("GITHUB_RUN_ATTEMPT", "2");
  const repo = { id: 123, full_name: "fixture/control", owner: { id: 456 } };
  const run = { id: 100, run_attempt: 2, repository: repo, head_repository: repo, head_sha: "b".repeat(40), event: "workflow_dispatch",
    head_branch: "main", status: "in_progress", conclusion: null, actor: { id: 9 }, path: ".github/workflows/caller.yml@main",
    referenced_workflows: [{ path: worker.workflowRef, sha: worker.workflowSha }] };
  const prefix = "https://api.github.com/repos/fixture/control";
  const job = { id: 999, run_id: 100, run_url: prefix + "/actions/runs/100", head_sha: run.head_sha, status: "in_progress",
    conclusion: null, completed_at: null, labels: worker.runnerClass === "self-hosted" ? ["self-hosted", "linux"] : ["ubuntu-latest"],
    runner_id: 555, check_run_url: prefix + "/check-runs/300" };
  const fetchCalls: any[] = []; const stsCalls: any[] = []; const s3Calls: any[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input, init) => {
    const url = String(input); fetchCalls.push({ url, init }); let phase: string; let value: any;
    if (url.startsWith("https://pipelines.actions.githubusercontent.com/")) { phase = "token"; value = { value: token }; }
    else if (url === "https://token.actions.githubusercontent.com/.well-known/jwks") { phase = "jwks"; value = { keys: [jwk] }; }
    else if (url === prefix) { phase = "repository"; value = repo; }
    else if (url.endsWith("/attempts/2/jobs?per_page=100")) { phase = "jobs"; value = { total_count: 1, jobs: [job] }; }
    else if (url.endsWith("/attempts/2")) { phase = "attempt"; value = run; }
    else if (url.endsWith("/actions/runs/100")) { phase = "current"; value = run; }
    else throw new Error("Unexpected mocked URL");
    value = await hook?.(phase, structuredClone(value)) ?? value;
    return value instanceof Response ? value : new Response(JSON.stringify(value), { status: 200 });
  }));
  vi.spyOn(STSClient.prototype, "send").mockImplementation(async function(this: STSClient, command: any, options: any) {
    stsCalls.push({ input: command.input, config: this.config, options });
    const value = { $metadata: { httpStatusCode: 200 }, SubjectFromWebIdentityToken: role.oidcSubject, Audience: "sts.amazonaws.com",
      AssumedRoleUser: { Arn: `arn:aws:sts::123456789012:assumed-role/${purpose}/bootstrap-100-2` },
      Credentials: { AccessKeyId: `fabricated-access-${stsCalls.length}`, SecretAccessKey: "fabricated-secret", SessionToken: "fabricated-session",
        Expiration: new Date(now.getTime() + 900_000) } };
    return await hook?.("sts", value, command) ?? value;
  } as any);
  const makeEnvelope = () => {
    const wrapped = Buffer.alloc(32, 8);
    return { header: { domain: "bootstrap-private-bundle", envelopeVersion: 1, canonicalization: "sorted-json-v1", algorithm: "aes-256-gcm",
      subject: { repository: "fixture/control", commitSha: "b".repeat(40) }, runId: "gh-100-2", publicEnvelopeSha256: "c".repeat(64),
      kmsKeyArn: f.binding.aws.keys.clientArn, wrappedKeySha256: createHash("sha256").update(wrapped).digest("hex") },
      nonce: Buffer.alloc(12, 1).toString("base64"), ciphertext: Buffer.alloc(40, 2).toString("base64"),
      tag: Buffer.alloc(16, 3).toString("base64"), wrappedKey: wrapped.toString("base64") };
  };
  const bytes = controlWire(makeEnvelope()); let storedBytes = bytes; let pointerPayload: any = f.pointer();
  const storage = { region: "us-east-2" as const, bucket: "fabricated-payload", key: `payloads/captures/${captureId}.json`, versionId: "payload-version-1" };
  const common = (input = storedBytes) => ({ $metadata: { httpStatusCode: 200 }, VersionId: storage.versionId,
    ChecksumSHA256: createHash("sha256").update(input).digest("base64"), ChecksumType: "FULL_OBJECT", ServerSideEncryption: "aws:kms",
    SSEKMSKeyId: f.binding.aws.keys.serviceArn, BucketKeyEnabled: false });
  vi.spyOn(S3Client.prototype, "send").mockImplementation(async function(this: S3Client, command: any, options: any) {
    const kind = command.constructor.name; const entry = { kind, input: command.input, config: this.config, options }; s3Calls.push(entry);
    let phase: string; let value: any;
    if (command.input.Bucket === "fabricated-config") {
      phase = "config"; const pointerBytes = f.signed(pointerPayload);
      value = { $metadata: { httpStatusCode: 200 }, Body: Readable.from([pointerBytes]), ContentLength: pointerBytes.length,
        ServerSideEncryption: "aws:kms", SSEKMSKeyId: f.binding.aws.keys.serviceArn, BucketKeyEnabled: false,
        ChecksumSHA256: createHash("sha256").update(pointerBytes).digest("base64") };
    } else if (kind === "PutObjectCommand") { phase = "put"; value = common(command.input.Body); }
    else if (kind === "GetObjectCommand") { phase = "get"; value = { ...common(), Body: Readable.from([storedBytes]), ContentLength: storedBytes.length, LastModified: new Date(capturedAt) }; }
    else if (kind === "GetObjectRetentionCommand") { phase = "retention"; value = { $metadata: { httpStatusCode: 200 }, Retention: { Mode: "GOVERNANCE", RetainUntilDate: new Date(retainUntil) } }; }
    else throw new Error("Unexpected mocked S3 operation");
    return await hook?.(phase, value, command) ?? value;
  } as any);
  return { f, installed, token, bytes, storage, makeEnvelope, common, fetchCalls, stsCalls, s3Calls,
    setHook: (next?: Hook) => { hook = next; }, setBytes: (value: Buffer) => { storedBytes = value; },
    setPointer: (value: any) => { pointerPayload = value; }, start: (signal?: AbortSignal) => establishPrivateRoleIdentity(installed, signal),
    payloadCalls: () => s3Calls.filter((c) => c.input.Bucket === "fabricated-payload") };
}
