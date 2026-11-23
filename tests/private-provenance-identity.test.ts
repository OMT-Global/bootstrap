import { createHash, createPrivateKey, sign } from "node:crypto";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { STSClient } from "@aws-sdk/client-sts";
import { S3Client } from "@aws-sdk/client-s3";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { generateProvenanceSigningKeyPair, provenanceSigningKeyFingerprint } from "../src/provenance.js";
import { controlHash, controlWire, type PrivateControlKey } from "../src/private-provenance-control.js";
import { deploymentRolePurposes, verifyCurrentPointer, verifyInstalledDeployment, type DeploymentBootstrap } from "../src/private-provenance-deployment.js";
import { establishPrivateRoleIdentity, refreshPrivateRoleIdentity, disposePrivateRoleIdentity } from "../src/private-provenance-identity.js";

const issuedAt = "2026-11-15T00:00:00.000Z";
const validUntil = "2026-11-16T00:00:00.000Z";
const now = new Date("2026-11-15T01:00:00.000Z");
const controlBase = (domain: string) => ({ domain, version: 1, canonicalization: "sorted-json-v1" });

function fixture() {
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
  const local = workloads.find((worker) => worker.purpose === "read-broker")!;
  const localRole = roles.find((role) => role.purpose === local.purpose)!;
  const bootstrap: DeploymentBootstrap = { rootKeys: [rootKey], minimumEpoch: 4, accountId: binding.aws.accountId,
    region: "us-east-2", configBucket: "fabricated-config", configKey: "config/active.json", workloadId: local.id,
    workloadPurpose: "read-broker", roleArn: localRole.arn, oidcSubject: localRole.oidcSubject, admin: { ...binding.admin } };
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
const jwk = { ...await exportJWK(jwtPair.publicKey), kid: "fixture-rsa", alg: "RS256", use: "sig" };
const denied = (promise: Promise<unknown>) => expect(promise).rejects.toThrow("Private provenance identity unavailable or invalid.");
type Hook = (phase: string, value: any) => unknown;
async function harness(changeClaims: Record<string, unknown> = {}, hook?: Hook) {
  const f = fixture(); const installed = f.install();
  const worker = f.binding.workloads.find((w: any) => w.purpose === "read-broker");
  const role = f.binding.aws.roles.find((r: any) => r.purpose === "read-broker");
  const seconds = now.getTime() / 1000;
  const claims: any = { iss: "https://token.actions.githubusercontent.com", aud: "sts.amazonaws.com", sub: role.oidcSubject,
    iat: seconds, nbf: seconds, exp: seconds + 300, jti: "fixture-jti", repository: "fixture/control", repository_id: "123",
    repository_owner_id: "456", run_id: "100", run_attempt: "2", actor_id: "9", check_run_id: "300",
    environment: "production", event_name: "workflow_dispatch", ref: "refs/heads/main", runner_environment: "self-hosted",
    sha: "b".repeat(40), workflow_ref: "fixture/control/.github/workflows/caller.yml@refs/heads/main", workflow_sha: "b".repeat(40),
    job_workflow_ref: worker.workflowRef, job_workflow_sha: worker.workflowSha, ...changeClaims };
  for (const key of Object.keys(claims)) if (claims[key] === undefined) delete claims[key];
  const token = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "fixture-rsa", typ: "JWT" }).sign(jwtPair.privateKey);
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
    conclusion: null, completed_at: null, labels: ["self-hosted", "linux"], runner_id: 555, check_run_url: prefix + "/check-runs/300" };
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
      AssumedRoleUser: { Arn: "arn:aws:sts::123456789012:assumed-role/read-broker/bootstrap-100-2" },
      Credentials: { AccessKeyId: "fabricated-access", SecretAccessKey: "fabricated-secret", SessionToken: "fabricated-session",
        Expiration: new Date(now.getTime() + 900_000) } };
    return await hook?.("sts", value) ?? value;
  } as any);
  let pointerPayload: any = f.pointer();
  vi.spyOn(S3Client.prototype, "send").mockImplementation(async function(this: S3Client, command: any, options: any) {
    s3Calls.push({ input: command.input, config: this.config, options });
    const bytes = f.signed(pointerPayload);
    const value = { $metadata: { httpStatusCode: 200 }, Body: Readable.from([bytes]), ContentLength: bytes.length,
      VersionId: "fixture-version", ServerSideEncryption: "aws:kms", SSEKMSKeyId: f.binding.aws.keys.serviceArn,
      BucketKeyEnabled: false, ChecksumSHA256: createHash("sha256").update(bytes).digest("base64") };
    return await hook?.("s3", value) ?? value;
  } as any);
  return { f, installed, claims, token, fetchCalls, stsCalls, s3Calls, setPointer: (value: any) => { pointerPayload = value; },
    start: (signal?: AbortSignal) => establishPrivateRoleIdentity(installed, signal) };
}
beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers(); });

describe("fixed private identity foundation", () => {
  it("binds signed GitHub/native identity and config-only STS credentials before minting an opaque handle", async () => {
    const h = await harness(); const handle = await h.start();
    expect(handle).toEqual({ workloadId: "worker-read-broker", purpose: "read-broker", expiresAt: "2026-11-15T01:05:00.000Z" });
    expect(Object.isFrozen(handle)).toBe(true); expect(JSON.stringify(handle)).not.toContain("fabricated");
    expect(h.stsCalls).toHaveLength(1); expect(h.s3Calls).toHaveLength(1);
    expect(h.stsCalls[0].input).toMatchObject({ RoleArn: h.f.bootstrap.roleArn, RoleSessionName: "bootstrap-100-2", DurationSeconds: 900 });
    const policy = JSON.parse(h.stsCalls[0].input.Policy);
    expect(policy.Statement.map((s: any) => s.Action)).toEqual(["s3:GetObject", "kms:Decrypt"]);
    expect(policy.Statement[0].Resource).toBe("arn:aws:s3:::fabricated-config/config/active.json");
    expect(policy.Statement[1].Condition.StringEquals["kms:EncryptionContext:aws:s3:arn"]).toBe(policy.Statement[0].Resource);
    expect(h.s3Calls[0].input).toEqual({ Bucket: "fabricated-config", Key: "config/active.json", ExpectedBucketOwner: "123456789012", ChecksumMode: "ENABLED" });
    expect(await h.stsCalls[0].config.maxAttempts()).toBe(1); expect(await h.s3Calls[0].config.maxAttempts()).toBe(1);
    await expect(h.stsCalls[0].config.credentials()).rejects.toThrow("Private provenance identity unavailable or invalid.");
    expect(await h.s3Calls[0].config.credentials()).toMatchObject({ accessKeyId: "fabricated-access", secretAccessKey: "fabricated-secret" });
    expect(h.fetchCalls.every((c) => c.init.redirect === "error" && c.init.signal)).toBe(true);
    expect(h.fetchCalls.find((c) => c.url.includes("/.well-known/jwks")).init.headers.authorization).toBeUndefined();
    const current = await refreshPrivateRoleIdentity(handle); expect(current.pointer.epoch).toBe(4);
    expect(h.s3Calls).toHaveLength(2); expect(h.stsCalls).toHaveLength(1);
    disposePrivateRoleIdentity(handle); await denied(refreshPrivateRoleIdentity(handle));
  });
  it.each(["iss", "aud", "sub", "repository", "repository_id", "repository_owner_id", "run_id", "run_attempt", "environment",
    "event_name", "ref", "runner_environment", "job_workflow_ref", "job_workflow_sha", "sha", "workflow_sha", "actor_id", "check_run_id"])(
    "rejects wrong signed %s before STS", async (claim) => {
      const h = await harness({ [claim]: "incorrect" }); await denied(h.start()); expect(h.stsCalls).toHaveLength(0);
    });
  it.each([".github/workflows/caller.yml", ".github/workflows/caller.yml@main", ".github/workflows/caller.yml@refs/heads/main"])(
    "accepts supported native workflow path %s with the same exact signed caller binding", async (path) => {
      const h = await harness({}, (phase, value) => phase === "attempt" ? { ...value, path } : undefined);
      const handle = await h.start(); expect(h.stsCalls).toHaveLength(1); disposePrivateRoleIdentity(handle);
    });
  it.each([".github/workflows/caller.yml@other", ".github/workflows/caller.yml@refs/heads/other",
    ".github/workflows/caller.yml@refs/tags/main", ".github/workflows/caller.yml@main@refs/heads/main",
    ".github/workflows/caller.yml@", ".github/workflows/caller.yml@refs%2Fheads%2Fmain",
    ".github/workflows/other.yml@main", ".github/workflows/../caller.yml@main", null])(
    "rejects mismatched or ambiguous native workflow path %s before STS", async (path) => {
      const h = await harness({}, (phase, value) => phase === "attempt" ? { ...value, path } : undefined);
      await denied(h.start()); expect(h.stsCalls).toHaveLength(0);
    });
  it.each([{ exp: now.getTime() / 1000 }, { nbf: now.getTime() / 1000 + 1 }, { iat: now.getTime() / 1000 + 1 },
    { exp: now.getTime() / 1000 + 601 }, { jti: undefined }, { environment: undefined }])("rejects time or missing required claims %j", async (claims) => {
    const h = await harness(claims); await denied(h.start()); expect(h.stsCalls).toHaveLength(0);
  });
  it.each(["repository", "attempt", "current", "jobs", "sts", "s3"])("rejects failed %s observations with sanitized errors", async (phase) => {
    const h = await harness({}, (which) => { if (which === phase) throw new Error("fabricated-secret upstream disclosure"); });
    await denied(h.start());
  });
  it.each([
    ["repository ID", "repository", (v: any) => ({ ...v, id: 987 })],
    ["owner ID", "repository", (v: any) => ({ ...v, owner: { id: 987 } })],
    ["fork", "attempt", (v: any) => ({ ...v, head_repository: { ...v.head_repository, id: 987 } })],
    ["rerun", "current", (v: any) => ({ ...v, run_attempt: 3 })],
    ["cancelled", "current", (v: any) => ({ ...v, status: "completed", conclusion: "cancelled" })],
    ["workflow", "attempt", (v: any) => ({ ...v, referenced_workflows: [] })],
    ["incomplete jobs", "jobs", (v: any) => ({ ...v, total_count: 2 })],
    ["ambiguous jobs", "jobs", (v: any) => ({ total_count: 2, jobs: [v.jobs[0], v.jobs[0]] })],
    ["wrong check", "jobs", (v: any) => ({ ...v, jobs: [{ ...v.jobs[0], check_run_url: "https://elsewhere.invalid/check-runs/300" }] })],
    ["wrong runner", "jobs", (v: any) => ({ ...v, jobs: [{ ...v.jobs[0], labels: ["ubuntu-latest"] }] })],
    ["finished job", "jobs", (v: any) => ({ ...v, jobs: [{ ...v.jobs[0], status: "completed" }] })],
    ["foreign ARN", "sts", (v: any) => ({ ...v, AssumedRoleUser: { Arn: "arn:aws:sts::999999999999:assumed-role/read-broker/bootstrap-100-2" } })],
    ["long STS expiry", "sts", (v: any) => ({ ...v, Credentials: { ...v.Credentials, Expiration: new Date(now.getTime() + 3600_000) } })],
    ["short STS expiry", "sts", (v: any) => ({ ...v, Credentials: { ...v.Credentials, Expiration: new Date(now.getTime() + 10_000) } })],
    ["wrong STS subject", "sts", (v: any) => ({ ...v, SubjectFromWebIdentityToken: "other" })],
    ["wrong S3 key", "s3", (v: any) => ({ ...v, SSEKMSKeyId: "wrong" })],
    ["bucket key", "s3", (v: any) => ({ ...v, BucketKeyEnabled: true })],
    ["wrong checksum", "s3", (v: any) => ({ ...v, ChecksumSHA256: "wrong" })],
    ["oversize", "s3", (v: any) => ({ ...v, ContentLength: 16385 })]
  ] as const)("rejects %s without capability", async (_name, phase, modify) => {
    const h = await harness({}, (which, value) => which === phase ? modify(value) : undefined); await denied(h.start());
  });
  it.each(["token", "jwks", "repository", "attempt", "jobs", "current"])("rejects redirect in %s", async (phase) => {
    const h = await harness({}, (which) => which === phase ? new Response(null, { status: 302, headers: { location: "https://elsewhere.invalid/" } }) : undefined);
    await denied(h.start());
  });
  it("denies changed/expired current configuration and expires the handle at JWT expiry", async () => {
    const h = await harness(); const handle = await h.start(); h.setPointer({ ...h.f.pointer(), epoch: 5 });
    await denied(refreshPrivateRoleIdentity(handle)); h.setPointer(h.f.pointer());
    vi.setSystemTime(new Date(now.getTime() + 300_000)); await denied(refreshPrivateRoleIdentity(handle));
    disposePrivateRoleIdentity(handle);
  });
  it("rejects copied installation and identity handles before side effects", async () => {
    const h = await harness(); await denied(establishPrivateRoleIdentity({ ...h.installed })); expect(h.fetchCalls).toHaveLength(0);
    const handle = await h.start(); const count = h.fetchCalls.length; await denied(refreshPrivateRoleIdentity({ ...handle }));
    expect(h.fetchCalls).toHaveLength(count); disposePrivateRoleIdentity(handle);
  });
  it.each(["https://attacker.invalid/fabricated/idtoken", "http://pipelines.actions.githubusercontent.com/fabricated/idtoken",
    "https://user:pass@pipelines.actions.githubusercontent.com/fabricated/idtoken", "https://pipelines.actions.githubusercontent.com/fabricated/idtoken?audience=other"])(
    "rejects unapproved runtime request URL %s without transmitting Actions bearer", async (url) => {
      const h = await harness(); vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_URL", url); await denied(h.start()); expect(h.fetchCalls).toHaveLength(0);
    });
  it("propagates cancellation before acquisition and during native reads", async () => {
    const first = await harness(); const pre = new AbortController(); pre.abort(); await denied(first.start(pre.signal)); expect(first.fetchCalls).toHaveLength(0);
    const controller = new AbortController(); const h = await harness({}, (which) => { if (which === "attempt") controller.abort(); });
    await denied(h.start(controller.signal)); expect(h.stsCalls).toHaveLength(0);
  });
  it("rejects absent reusable claims required by the exact enrolled subject", async () => {
    const h = await harness({ job_workflow_ref: undefined, job_workflow_sha: undefined });
    await denied(h.start()); expect(h.stsCalls).toHaveLength(0);
  });
  it("does not invent version/checksum requirements for the signed mutable config pointer", async () => {
    const h = await harness({}, (phase, value) => phase === "s3" ? { ...value, BucketKeyEnabled: undefined, VersionId: undefined, ChecksumSHA256: undefined } : undefined);
    const handle = await h.start(); disposePrivateRoleIdentity(handle);
  });
  it.each([
    ["bad signature", "token", (v: any) => ({ value: v.value.slice(0, -10) + "invalid000" })],
    ["no key", "jwks", () => ({ keys: [] })],
    ["other key", "jwks", (v: any) => ({ keys: [{ ...v.keys[0], kid: "unrecognized" }] })],
    ["ambiguous key", "jwks", (v: any) => ({ keys: [v.keys[0], v.keys[0]] })],
    ["incomplete API page", "jobs", () => new Response("{}", { headers: { link: '<https://api.github.com/next>; rel="next"' } })],
    ["oversized JWKS", "jwks", () => new Response(" ".repeat(65_537))]
  ] as const)("rejects %s", async (_label, phase, modify) => {
    const h = await harness({}, (which, value) => which === phase ? modify(value) : undefined); await denied(h.start());
    expect(h.stsCalls).toHaveLength(0);
  });
  it("disposal cancels an in-flight native refresh without waiting for the overall deadline", async () => {
    let calls = 0; let enter!: () => void;
    const entered = new Promise<void>((resolve) => { enter = resolve; });
    const h = await harness({}, (phase) => {
      if (phase === "repository" && ++calls === 2) { enter(); return new Promise(() => {}); }
    });
    const handle = await h.start(); const checking = refreshPrivateRoleIdentity(handle); await entered;
    disposePrivateRoleIdentity(handle); await denied(checking); expect(h.s3Calls).toHaveLength(1);
  });
  it("bounds a stalled acquisition independently of a mocked transport's abort cooperation", async () => {
    const h = await harness({}, (phase) => phase === "token" ? new Promise(() => {}) : undefined);
    vi.useFakeTimers(); const result = h.start(); const assertion = denied(result);
    await vi.advanceTimersByTimeAsync(10_000); await assertion; expect(h.stsCalls).toHaveLength(0);
  });
});
