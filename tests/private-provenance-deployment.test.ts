import { createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateProvenanceSigningKeyPair, provenanceSigningKeyFingerprint } from "../src/provenance.js";
import { controlHash, controlWire, type PrivateControlKey } from "../src/private-provenance-control.js";
import { deploymentRolePurposes, inspectCurrentDeployment, inspectInstalledDeployment,
  verifyCurrentPointer, verifyInstalledDeployment, type DeploymentBootstrap } from "../src/private-provenance-deployment.js";

const issuedAt = "2026-11-15T00:00:00.000Z";
const validUntil = "2026-11-16T00:00:00.000Z";
const now = new Date("2026-11-15T01:00:00.000Z");
const denied = (run: () => unknown) => expect(run).toThrow("Private provenance control unavailable or invalid.");
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

describe("installed private deployment authority", () => {
  it("verifies the complete role registry and returns immutable owned evidence", () => {
    const f = fixture(); const bytes = f.signed(f.binding);
    const installed = verifyInstalledDeployment(bytes, f.bootstrap, now);
    expect(installed.bindingSha256).toBe(controlHash(bytes));
    expect(installed.keys.find((k) => k.purpose === "codex-read-approval")!.ownerId).toBe("worker-codex-approver");
    expect(Object.isFrozen(installed.binding.aws.roles)).toBe(true);
    expect(() => { (installed.binding.aws.roles as any[]).push({}); }).toThrow();
    bytes.fill(0); f.bootstrap.rootKeys[0]!.publicKey.x = "changed";
    expect(inspectInstalledDeployment(installed, now).bindingSha256).toBe(installed.bindingSha256);
  });

  const invalidBindings: [string, (b: any) => void][] = [
    ["unknown root field", (b) => { b.extra = true; }],
    ["unknown nested field", (b) => { b.aws.roles[0].extra = true; }],
    ["wrong domain", (b) => { b.domain = "bootstrap-active-config"; }],
    ["future issuance", (b) => { b.issuedAt = "2026-11-15T02:00:00.000Z"; }],
    ["expiry boundary", (b) => { b.validUntil = now.toISOString(); }],
    ["invalid date", (b) => { b.issuedAt = "2026-02-30T00:00:00.000Z"; }],
    ["fractional epoch", (b) => { b.epoch = 4.5; }],
    ["rollback", (b) => { b.epoch = b.policy.controlEpoch = 3; }],
    ["control epoch mismatch", (b) => { b.policy.controlEpoch = 5; }],
    ["unselected region", (b) => { b.aws.region = "us-east-1"; }],
    ["wrong account", (b) => { b.aws.accountId = "999999999999"; }],
    ["shared buckets", (b) => { b.aws.buckets.config = b.aws.buckets.state; }],
    ["KMS alias", (b) => { b.aws.keys.clientArn = "arn:aws:kms:us-east-2:123456789012:alias/client"; }],
    ["KMS account", (b) => { b.aws.keys.clientArn = b.aws.keys.clientArn.replace("123456789012", "999999999999"); }],
    ["KMS region", (b) => { b.aws.keys.clientArn = b.aws.keys.clientArn.replace("us-east-2", "us-east-1"); }],
    ["KMS partition", (b) => { b.aws.keys.clientArn = b.aws.keys.clientArn.replace("arn:aws:", "arn:aws-cn:"); }],
    ["shared KMS keys", (b) => { b.aws.keys.custodyArn = b.aws.keys.clientArn; }],
    ["placeholder", (b) => { b.aws.buckets.payload = "${PAYLOAD_BUCKET}"; }],
    ["missing role", (b) => { b.aws.roles.pop(); }],
    ["duplicate role purpose", (b) => { b.aws.roles[1].purpose = b.aws.roles[0].purpose; }],
    ["shared role ARN", (b) => { b.aws.roles[1].arn = b.aws.roles[0].arn; }],
    ["role wildcard", (b) => { b.aws.roles[0].arn += "*"; }],
    ["role wrong account", (b) => { b.aws.roles[0].arn = b.aws.roles[0].arn.replace("123456789012", "999999999999"); }],
    ["role session bound", (b) => { b.aws.roles[0].sessionSeconds = 3601; }],
    ["role subject mismatch", (b) => { b.aws.roles[0].oidcSubject = b.aws.roles[0].oidcSubject.replace("fixture/control", "other/control"); }],
    ["subject lacks workflow", (b) => { b.aws.roles[0].oidcSubject = "repo:fixture/control:environment:production"; }],
    ["wrong environment", (b) => { b.workloads[0].environment = "other"; }],
    ["wrong workflow SHA", (b) => { b.workloads[0].workflowSha = "f".repeat(40); }],
    ["mutable workflow ref", (b) => { b.workloads[0].workflowRef = b.workloads[0].workflowRef.replace(/@[a-f0-9]+$/, "@refs/heads/main"); }],
    ["wrong workflow repository", (b) => { b.workloads[0].workflowRef = b.workloads[0].workflowRef.replace("fixture/control", "other/control"); }],
    ["unregistered workflow repository ID", (b) => { b.workloads[0].repositoryId = "999"; }],
    ["duplicate workload", (b) => { b.workloads[1].id = b.workloads[0].id; }],
    ["wrong workload base ref", (b) => { b.workloads[0].ref = "refs/heads/other"; }],
    ["capture hosted isolation", (b) => { b.workloads.find((w: any) => w.purpose === "capture").runnerClass = "github-hosted"; }],
    ["repository rename mismatch", (b) => { b.repositories[0].nameWithOwner = "other/control"; }],
    ["repository owner mismatch", (b) => { b.repositories[0].ownerId = "999"; }],
    ["duplicate repository", (b) => { b.repositories.push({ ...b.repositories[0] }); }],
    ["missing key", (b) => { b.keys.pop(); }],
    ["key purpose substitution", (b) => { b.keys.find((k: any) => k.purpose === "codex-read-approval").purpose = "deployment-root"; }],
    ["key fingerprint mismatch", (b) => { b.keys[0].fingerprint = "f".repeat(64); }],
    ["revoked current key", (b) => { b.keys.find((k: any) => k.purpose === "audit-ack").revoked = true; }],
    ["expired current key", (b) => { b.keys.find((k: any) => k.purpose === "audit-ack").notAfter = now.toISOString(); }],
    ["semantic/transport key reuse", (b) => { b.principals[0].transportKeyFingerprint = b.principals[0].signingKeyFingerprint; }],
    ["wrong enrolled owner", (b) => { b.principals[1].signingKeyFingerprint = b.principals[0].signingKeyFingerprint; }],
    ["unregistered principal repo", (b) => { b.principals[0].repositoryIds = ["999"]; }],
    ["duplicate principal repo", (b) => { b.principals[0].repositoryIds.push("123"); }],
    ["unapproved category", (b) => { b.principals[0].categoryIds = ["raw-prompt"]; }],
    ["unapproved purpose", (b) => { b.principals[0].purposeIds = ["anything"]; }],
    ["exporter semantic key", (b) => { b.workloads.find((w: any) => w.purpose === "public-exporter").signingKeyFingerprint = b.keys[0].fingerprint; }],
    ["publisher transport key", (b) => { b.workloads.find((w: any) => w.purpose === "check-publisher").transportKeyFingerprint = b.keys[0].fingerprint; }],
    ["missing endpoint", (b) => { b.endpoints.pop(); }],
    ["endpoint path", (b) => { b.endpoints[0].origin += "/path"; }],
    ["endpoint userinfo", (b) => { b.endpoints[0].origin = "https://user@capture.invalid"; }],
    ["endpoint query", (b) => { b.endpoints[0].origin += "?query"; }],
    ["endpoint insecure", (b) => { b.endpoints[0].origin = "http://capture.invalid"; }],
    ["wrong check name", (b) => { b.github.requiredCheckName = "alternate"; }],
    ["missing audit retention", (b) => { delete b.policy.auditDays; }],
    ["new retention duration", (b) => { b.policy.evidenceDays = 91; }],
    ["new WORM mode", (b) => { b.policy.mode = "COMPLIANCE"; }],
    ["long approval", (b) => { b.policy.approvalMaxSeconds = 301; }],
    ["long challenge", (b) => { b.policy.challengeMaxSeconds = 301; }],
    ["clock tolerance changed", (b) => { b.policy.clockSkewSeconds = 61; }],
    ["changed administrator", (b) => { b.admin.configOwnerId = "caller"; }]
  ];
  it.each(invalidBindings)("rejects signed invalid binding: %s", (_name, mutate) => {
    const f = fixture(); mutate(f.binding); denied(f.install);
  });

  it.each(["ownerId", "purpose", "revoked", "notBefore", "notAfter"])("requires external current root %s", (field) => {
    const f = fixture(); (f.rootKey as any)[field] = ({ ownerId: "other", purpose: "codex-read-approval", revoked: true,
      notBefore: "2026-11-15T02:00:00.000Z", notAfter: now.toISOString() } as any)[field]; denied(f.install);
  });
  it.each(["workloadId", "workloadPurpose", "roleArn", "oidcSubject", "configBucket", "configKey"])("requires exact bootstrap %s", (field) => {
    const f = fixture(); (f.bootstrap as any)[field] = "wrong"; denied(f.install);
  });
  it("permits historical semantic keys without current owner authority", () => {
    const f = fixture(); const history = f.key("capture-receipt");
    const installed = f.install(); expect(installed.binding.keys.some((key) => key.fingerprint === history)).toBe(true);
    expect(installed.keys.some((key) => key.fingerprint === history)).toBe(false);
  });
  it("permits explicit authority/workload principal associations without granting requester authority", () => {
    const f = fixture(); const worker = f.binding.workloads.find((w: any) => w.purpose === "codex-approver");
    f.binding.principals.push({ id: f.binding.admin.configOwnerId, kind: "authority", signingKeyFingerprint: f.rootFingerprint,
      transportKeyFingerprint: null, repositoryIds: [], categoryIds: [], purposeIds: [] });
    f.binding.principals.push({ id: worker.id, kind: "workload", signingKeyFingerprint: worker.signingKeyFingerprint,
      transportKeyFingerprint: worker.transportKeyFingerprint, repositoryIds: ["123"], categoryIds: ["validation-summary"], purposeIds: ["provenance-verification"] });
    expect(f.install().keys.filter((key) => key.ownerId === worker.id)).toHaveLength(2);
    f.binding.principals.at(-1).signingKeyFingerprint = f.binding.principals[0].signingKeyFingerprint;
    denied(f.install);
  });
  it("permits optional audit transport only with a distinct enrolled key", () => {
    const f = fixture(); f.binding.workloads.find((w: any) => w.purpose === "audit").transportKeyFingerprint = f.key("workload-transport");
    expect(f.install().keys.filter((key) => key.ownerId === "worker-audit")).toHaveLength(2);
  });
  it("rejects transport keys without a current owner", () => { const f = fixture(); f.key("workload-transport"); denied(f.install); });
  it("permits a custody descriptor only on the enrolled broker's workload transport key", () => {
    const f = fixture();
    const descriptor = { versionId: "transport-key-version", ciphertextSha256: "d".repeat(64) };
    const broker = f.binding.workloads.find((w: any) => w.purpose === "read-broker");
    const controller = f.binding.workloads.find((w: any) => w.purpose === "controller");
    f.binding.keys.find((key: any) => key.fingerprint === broker.transportKeyFingerprint).custody = descriptor;
    expect(f.install().keys.find((key) => key.fingerprint === broker.transportKeyFingerprint)?.custody).toEqual(descriptor);
    f.binding.keys.find((key: any) => key.fingerprint === controller.transportKeyFingerprint).custody = descriptor;
    denied(f.install);
  });
  it("supports explicitly pinned immutable GitHub subject format without fallback to name-only", () => {
    const f = fixture();
    for (const role of f.binding.aws.roles) role.oidcSubject = role.oidcSubject.replace("fixture/control", "fixture@456/control@123");
    denied(f.install);
    f.bootstrap.oidcSubject = f.binding.aws.roles.find((r: any) => r.purpose === "read-broker").oidcSubject;
    expect(f.install().binding.epoch).toBe(4);
    f.binding.aws.roles[0].oidcSubject = f.binding.aws.roles[0].oidcSubject.replace("@123:", "@999:"); denied(f.install);
  });
  it("retains the 64KiB configuration bound without enlarging online messages", () => {
    const f = fixture(); while (f.binding.keys.length < 64) f.key("public-manifest");
    expect(f.signed(f.binding).length).toBeGreaterThan(16_384); expect(f.install().binding.keys.length).toBe(64);
    denied(() => verifyInstalledDeployment(Buffer.alloc(65_537), f.bootstrap, now));
  });
  it("rejects noncanonical JWK aliases before fingerprint authority mapping", () => {
    const f = fixture(); const x = f.binding.keys[0].publicJwk.x;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    f.binding.keys[0].publicJwk.x = x.slice(0, -1) + alphabet[alphabet.indexOf(x.at(-1)!) + 1];
    denied(f.install);
  });
  it("rejects duplicate mathematical root identity in the external ring", () => {
    const f = fixture(); const clone = structuredClone(f.rootKey);
    f.bootstrap.rootKeys = [f.rootKey, clone]; denied(f.install);
  });
  it("rejects edited signatures, duplicate JSON keys, noncanonical bytes and malformed UTF-8", () => {
    const f = fixture(); const original = f.signed(f.binding);
    const parsed = JSON.parse(original.toString()); parsed.signature.value = Buffer.alloc(64).toString("base64");
    for (const bytes of [controlWire(parsed), Buffer.from(" " + original), Buffer.from(original.toString().replace('"payload":', '"extra":0,"extra":1,"payload":')),
      Buffer.from([0xff]), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), original])]) denied(() => verifyInstalledDeployment(bytes, f.bootstrap, now));
  });
});

describe("current configuration content evidence", () => {
  it("binds the pointer to the exact signed installation and returns owned immutable evidence", () => {
    const f = fixture(); const evidence = f.current();
    expect(evidence.pointer.bindingSha256).toBe(evidence.installed.bindingSha256);
    expect(inspectCurrentDeployment(evidence, now)).toBe(evidence);
    denied(() => inspectCurrentDeployment(structuredClone(evidence), now));
    denied(() => inspectInstalledDeployment(structuredClone(evidence.installed), now));
    denied(() => f.current(f.pointer(), structuredClone(evidence.installed)));
  });
  it.each(["configId", "epoch", "bindingSha256", "issuedAt", "validUntil"])("rejects pointer mismatch: %s", (field) => {
    const f = fixture(); const pointer: any = f.pointer(); pointer[field] = ({ configId: "other", epoch: 5,
      bindingSha256: controlHash(controlWire(f.binding)), issuedAt: "2026-11-15T02:00:00.000Z", validUntil: now.toISOString() } as any)[field];
    denied(() => f.current(pointer));
  });
  it.each(["bucket", "key"])("requires pinned configuration-only %s", (field) => {
    const f = fixture(); const input = { bytes: f.signed(f.pointer()), bucket: "fabricated-config", key: "config/active.json", [field]: "wrong" };
    denied(() => verifyCurrentPointer(input, f.install(), now));
  });
  it("rejects expired installation/current keys at a later pointer read", () => {
    const f = fixture(); const installed = f.install();
    denied(() => verifyCurrentPointer({ bytes: f.signed(f.pointer()), bucket: "fabricated-config", key: "config/active.json" }, installed, new Date(validUntil)));
    denied(() => inspectCurrentDeployment(f.current(), new Date(validUntil)));
  });
  it("rechecks current workload key expiration independently of pointer expiration", () => {
    const f = fixture(); f.binding.keys.find((key: any) => key.purpose === "audit-ack").notAfter = "2026-11-15T01:01:00.000Z";
    const installed = f.install(); const pointer = f.signed(f.pointer());
    denied(() => verifyCurrentPointer({ bytes: pointer, bucket: "fabricated-config", key: "config/active.json" }, installed, new Date("2026-11-15T01:01:00.000Z")));
  });
  it("rejects clock rollback rather than refreshing an old installation into earlier authority", () => {
    const f = fixture(); const installed = f.install(); const pointer = f.pointer(); pointer.issuedAt = issuedAt;
    denied(() => verifyCurrentPointer({ bytes: f.signed(pointer), bucket: "fabricated-config", key: "config/active.json" }, installed, new Date(issuedAt)));
  });
  it("rejects a pointer signed with an enrolled nonroot authority", () => {
    const f = fixture(); const approver = f.binding.keys.find((key: any) => key.purpose === "codex-read-approval").fingerprint;
    denied(() => verifyCurrentPointer({ bytes: f.signed(f.pointer(), approver), bucket: "fabricated-config", key: "config/active.json" }, f.install(), now));
  });
  it("does not widen pointer lifetime or online size bounds", () => {
    const f = fixture(); const pointer = f.pointer(); pointer.validUntil = "2027-01-01T00:00:00.000Z";
    denied(() => f.current(pointer));
    denied(() => verifyCurrentPointer({ bytes: Buffer.alloc(16_385), bucket: "fabricated-config", key: "config/active.json" }, f.install(), now));
  });
});
