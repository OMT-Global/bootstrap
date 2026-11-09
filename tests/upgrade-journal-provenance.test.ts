import { sign } from "node:crypto";
import { chmod, link, readFile, rename, symlink, writeFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { approvalFixture, canonical, copyHarness, moduleImport, sha, signPayload, testApprovers,
  writeApproval, type CopyHarness } from "./helpers/upgrade-approval-fixture.js";

const harnesses: CopyHarness[] = [];
async function fixture(options: { sameKey?: boolean; disabled?: boolean; empty?: boolean } = {}) {
  const approvers = testApprovers();
  if (options.sameKey) { approvers.anchors[1]!.jwk = approvers.anchors[0]!.jwk; approvers.privateKeys[1] = approvers.privateKeys[0]!; }
  if (options.disabled) approvers.anchors[1]!.enabled = false;
  const h = await copyHarness(options.empty ? [] : approvers.anchors); harnesses.push(h);
  return { h, approvers, data: await approvalFixture(h, approvers) };
}
async function outcome(h: CopyHarness) {
  return h.run<{ kind: string; reason?: string }>(`
    const p=await import(${moduleImport(h, "upgrade-journal-provenance")});
    const result=await p.authenticateFixedApproval();
    console.log(JSON.stringify(result.kind==="authenticated"?{kind:result.kind}:{kind:result.kind,reason:result.reason}));
  `);
}
afterEach(async () => { await Promise.all(harnesses.splice(0).map((h) => h.close())); });

describe("fixed offline approval authentication facts", () => {
  it("authenticates both actual Ed25519 signatures and exact evidence without creating execution authority", async () => {
    const { h, data } = await fixture();
    const digest = sha(await readFile(path.join(h.approvalDirectory, "approved-installation.v1.json")));
    const result = await h.run<{ kind: string; facts: Record<string, unknown>; frozen: boolean; exports: string[] }>(`
      const p=await import(${moduleImport(h, "upgrade-journal-provenance")}); const r=await p.authenticateFixedApproval();
      if(r.kind!=="authenticated") throw new Error(JSON.stringify(r));
      const facts=p.authenticationFacts(r.approval);
      console.log(JSON.stringify({kind:r.kind,facts,frozen:Object.isFrozen(r.approval)&&Object.isFrozen(facts)&&Object.isFrozen(facts.evidenceSha256),exports:Object.keys(p).sort()}));
    `);
    expect(result.kind).toBe("authenticated"); expect(result.frozen).toBe(true);
    expect(result.facts).toEqual({ kind: "authentication-facts", approvalSha256: digest,
      approvalEpoch: data.payload.approvalEpoch, installationId: data.payload.installationId,
      sourceCommit: data.payload.sourceBuild.sourceCommit, evidenceSha256: data.payload.evidence });
    expect(result.exports).toEqual(["authenticateFixedApproval", "authenticationFacts", "recheckAuthenticatedApproval"]);
  });

  it.each([{ empty: true }, { sameKey: true }, { disabled: true }])("requires configured distinct enabled role anchors: %j", async (options) => {
    const { h } = await fixture(options);
    expect(await outcome(h)).toEqual({ kind: "unsupported", reason: "invalid-approval" });
  });

  it.each(["signature", "domain", "unknown-kid", "role-order", "missing-role", "noncanonical-base64"] as const)("rejects %s without accepting a JSON success field", async (fault) => {
    const { h, data, approvers } = await fixture();
    const envelope = signPayload(data.payload, approvers.privateKeys, approvers.anchors);
    if (fault === "signature") {
      const bytes = Buffer.from(envelope.approvals[0]!.signature, "base64"); bytes[0] = bytes[0]! ^ 1;
      envelope.approvals[0]!.signature = bytes.toString("base64");
    } else if (fault === "domain") {
      const bytes = Buffer.from("different-domain\0" + canonical(data.payload));
      envelope.approvals[0]!.signature = sign(null, bytes, approvers.privateKeys[0]!).toString("base64");
    } else if (fault === "unknown-kid") envelope.approvals[0]!.kid = "not-an-anchor";
    else if (fault === "role-order") envelope.approvals.reverse();
    else if (fault === "missing-role") envelope.approvals.pop();
    else envelope.approvals[0]!.signature = envelope.approvals[0]!.signature.replace(/==$/, "");
    await writeApproval(h, canonical(envelope));
    expect(await outcome(h)).toEqual({ kind: "unsupported", reason: "invalid-approval" });
  });

  it.each(["duplicate-key", "whitespace", "utf8", "unknown-top", "unknown-nested", "unsafe-number"] as const)("rejects strict format violation %s even with signed fixture material", async (fault) => {
    const { h, data, approvers } = await fixture();
    if (fault === "unknown-top") Object.assign(data.payload, { approved: true });
    if (fault === "unknown-nested") Object.assign(data.payload.node, { trustedBuild: true });
    if (fault === "unsafe-number") data.payload.version = Number.MAX_SAFE_INTEGER + 1;
    let bytes = Buffer.from(canonical(signPayload(data.payload, approvers.privateKeys, approvers.anchors)));
    if (fault === "duplicate-key") bytes = Buffer.from(bytes.toString().replace('"approvalEpoch":', '"approvalEpoch":"shadow","approvalEpoch":'));
    if (fault === "whitespace") bytes = Buffer.concat([bytes, Buffer.from("\n")]);
    if (fault === "utf8") bytes = Buffer.concat([Buffer.from([0xff]), bytes]);
    await writeApproval(h, bytes);
    expect(await outcome(h)).toEqual({ kind: "unsupported", reason: "invalid-approval" });
  });

  it.each(["escape", "link-escape", "duplicate-file", "file-parent", "root-overlap", "root-slash", "inventory-digest"] as const)("rejects signed inconsistent inventory %s", async (fault) => {
    const { h, data } = await fixture();
    const runtime = data.payload.files.find((file) => file.rootId === "runtime")!;
    if (fault === "escape") runtime.path = "../outside";
    else if (fault === "link-escape") data.payload.files[data.payload.files.indexOf(runtime)] = {
      rootId: "runtime", path: runtime.path, kind: "symlink", mode: 0o777, target: "../../outside" };
    else if (fault === "duplicate-file") data.payload.files.push({ ...runtime });
    else if (fault === "file-parent") data.payload.files.push({ rootId: "runtime", path: "package.json/child", kind: "regular", mode: 0o644, size: 0, sha256: sha("") });
    else if (fault === "root-overlap") data.payload.installationRoots[2]!.path = "/opt/bootstrap/dist/nested";
    else if (fault === "root-slash") data.payload.installationRoots[2]!.path = "/";
    data.refreshBindings();
    if (fault === "inventory-digest") data.payload.installationRoots[0]!.inventorySha256 = "0".repeat(64);
    await data.persist(false);
    expect(await outcome(h)).toEqual({ kind: "unsupported", reason: "invalid-approval" });
  });

  it("rejects a coherently signed regular inventory path with an empty trailing component", async () => {
    const { h, data } = await fixture();
    data.payload.files.find((file) => file.rootId === "runtime")!.path = "package.json/";
    await data.persist();
    expect(await outcome(h)).toEqual({ kind: "unsupported", reason: "invalid-approval" });
  });

  it("accepts an ordinary Unicode relative inventory path", async () => {
    const { h, data } = await fixture();
    data.payload.files.find((file) => file.rootId === "runtime")!.path = "依存/dépendance.json";
    await data.persist();
    expect(await outcome(h)).toEqual({ kind: "authenticated" });
  });

  it("accepts a signed bounded relative dependency link whose complete resolution stays inside its root", async () => {
    const { h, data } = await fixture();
    data.payload.files.push({ rootId: "runtime", path: "sub/package-link", kind: "symlink", mode: 0o777, target: "../package.json" });
    await data.persist();
    expect(await outcome(h)).toEqual({ kind: "authenticated" });
  });

  it.each(["source", "startup", "storage", "digest", "body-size"] as const)("rejects exact evidence mismatch %s", async (fault) => {
    const { h, data } = await fixture();
    if (fault === "source") data.artifacts.build.sourceCommit = "2".repeat(40);
    else if (fault === "startup") data.artifacts.build.startupRecipeSha256 = sha("wrong-startup");
    else if (fault === "storage") data.artifacts.storageCrashReboot.storageMeasurementSha256 = sha("another-device");
    else if (fault === "body-size") data.artifacts.independentReview.body = "x".repeat(512 * 1024 + 1);
    await data.persist(false);
    if (fault === "digest") await writeFile(path.join(h.approvalDirectory, "evidence", data.payload.evidence.build + ".json"), "changed");
    expect(await outcome(h)).toEqual({ kind: "unsupported", reason: "invalid-approval" });
  });

  it.each(["symlink", "hardlink", "writable-file", "writable-ancestor", "oversized"] as const)("denies unsupported fixed-file metadata %s", async (fault) => {
    const { h } = await fixture();
    const file = path.join(h.approvalDirectory, "approved-installation.v1.json");
    if (fault === "symlink") { await rename(file, file + ".original"); await symlink(file + ".original", file); }
    else if (fault === "hardlink") await link(file, file + ".second");
    else if (fault === "writable-file") await chmod(file, 0o622);
    else if (fault === "writable-ancestor") await chmod(h.approvalDirectory, 0o777);
    else await writeApproval(h, Buffer.alloc(4 * 1024 * 1024 + 1, 0x20));
    expect(await outcome(h)).toEqual({ kind: "unsupported", reason: "invalid-approval" });
  });

  it("rejects copied fact capabilities and permanently poisons changed active file identity", async () => {
    const { h } = await fixture();
    const result = await h.run<{ forgeries: number; initial: boolean; poisoned: boolean; stayedPoisoned: boolean; factsRejected: boolean }>(`
      import {readFile,rename,writeFile,rm} from "node:fs/promises";
      const p=await import(${moduleImport(h, "upgrade-journal-provenance")}); const r=await p.authenticateFixedApproval();
      if(r.kind!=="authenticated") throw new Error(JSON.stringify(r));
      let forgeries=0; for(const fake of [{},{...r.approval},JSON.parse(JSON.stringify(r.approval)),p.authenticationFacts(r.approval)]) {
        try { p.authenticationFacts(fake); } catch { forgeries++; }
        if(await p.recheckAuthenticatedApproval(fake)!==undefined) throw new Error("forged recheck accepted");
      }
      const initial=!!await p.recheckAuthenticatedApproval(r.approval);
      const file=${JSON.stringify(path.join(h.approvalDirectory, "approved-installation.v1.json"))};
      const bytes=await readFile(file); await rename(file,file+".original"); await writeFile(file,bytes,{mode:0o600});
      const poisoned=await p.recheckAuthenticatedApproval(r.approval)===undefined;
      await rm(file); await rename(file+".original",file);
      const stayedPoisoned=await p.recheckAuthenticatedApproval(r.approval)===undefined;
      let factsRejected=false; try {p.authenticationFacts(r.approval);} catch {factsRejected=true;}
      console.log(JSON.stringify({forgeries,initial,poisoned,stayedPoisoned,factsRejected}));
    `);
    expect(result).toEqual({ forgeries: 4, initial: true, poisoned: true, stayedPoisoned: true, factsRejected: true });
  });

  it("charges a successful recheck to the original owner without creating a fresh budget", async () => {
    const { h } = await fixture();
    const result = await h.run<{ increased: boolean; oneOwner: boolean; sameFact: boolean }>(`
      const p=await import(${moduleImport(h, "upgrade-journal-provenance")}); const a=await import(${moduleImport(h, "upgrade-admission")});
      const r=await p.authenticateFixedApproval(); if(r.kind!=="authenticated") throw new Error(JSON.stringify(r));
      const before=a.admissionProcessSnapshot(); const original=p.authenticationFacts(r.approval);
      const current=await p.recheckAuthenticatedApproval(r.approval); const after=a.admissionProcessSnapshot();
      console.log(JSON.stringify({increased:after.retainedBytes>before.retainedBytes,
        oneOwner:before.invocationCount===1&&after.invocationCount===1,sameFact:current===original}));
    `);
    expect(result).toEqual({ increased: true, oneOwner: true, sameFact: true });
  });

  it("retains failed preflight debt in the same live process pool", async () => {
    const { h } = await fixture();
    const result = await h.run<{ before: number; failedOnce: number; failedTwice: number; count: number; reasons: string[] }>(`
      import {writeFile} from "node:fs/promises";
      const p=await import(${moduleImport(h, "upgrade-journal-provenance")}); const a=await import(${moduleImport(h, "upgrade-admission")});
      await writeFile(${JSON.stringify(path.join(h.approvalDirectory, "approved-installation.v1.json"))},"{",{mode:0o600});
      const before=a.admissionProcessSnapshot().retainedBytes;
      const first=await p.authenticateFixedApproval(); const failedOnce=a.admissionProcessSnapshot().retainedBytes;
      const second=await p.authenticateFixedApproval(); const s=a.admissionProcessSnapshot();
      console.log(JSON.stringify({before,failedOnce,failedTwice:s.retainedBytes,count:s.invocationCount,reasons:[first.reason,second.reason]}));
    `);
    expect(result.failedOnce).toBeGreaterThan(result.before);
    expect(result.failedTwice).toBeGreaterThan(result.failedOnce);
    expect(result.count).toBe(2); expect(result.reasons).toEqual(["invalid-approval", "invalid-approval"]);
  });
});
