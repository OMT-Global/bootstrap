import { copyFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { copyHarness, moduleImport, type CopyHarness } from "./helpers/upgrade-approval-fixture.js";

const harnesses: CopyHarness[] = [];
async function fixture() { const h = await copyHarness(); harnesses.push(h); return h; }
afterEach(async () => { await Promise.all(harnesses.splice(0).map((h) => h.close())); });

describe("process-wide retained admission (accounting only)", () => {
  it("shares one ceiling and retains account and prepaid terminal debt after close", async () => {
    const h = await fixture();
    const result = await h.run<{ retained: boolean; closedWithoutNewDebt: boolean; count: number; distinct: boolean; ceiling: number }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")});
      const before = a.admissionProcessSnapshot();
      const one = a.beginAdmissionInvocation(); const two = a.beginAdmissionInvocation();
      a.reserveAdmission(one, "approval-bytes", 1234); a.reserveAdmission(two, "approval-crypto", 4567);
      const beforeClose = a.admissionProcessSnapshot(); const closed = a.closeAdmissionInvocation(one);
      const other = a.describeAdmission(two); const after = a.admissionProcessSnapshot();
      console.log(JSON.stringify({retained:after.retainedBytes>before.retainedBytes+1234+4567
        &&closed.retainedBytes>1234&&other.retainedBytes>4567,
        closedWithoutNewDebt:closed.closed&&closed.processRetainedBytes===beforeClose.retainedBytes,
        count:after.invocationCount,distinct:closed.invocationId!==other.invocationId,ceiling:after.ceilingBytes}));
    `);
    expect(result).toEqual({ retained: true, closedWithoutNewDebt: true, count: 2, distinct: true, ceiling: 2 * 1024 ** 3 });
  });

  it("rejects copied facts as authority and reuses an unchanged immutable view", async () => {
    const h = await fixture();
    const result = await h.run<{ failures: string[]; same: boolean; frozen: boolean }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")});
      const owner = a.beginAdmissionInvocation(); const facts = a.describeAdmission(owner);
      const failures = [];
      for (const forged of [{}, {...owner}, JSON.parse(JSON.stringify(owner)), facts, {...facts}, null]) {
        try { a.reserveAdmission(forged, "approval-bytes", 1); } catch(e) { failures.push(e.message); }
      }
      console.log(JSON.stringify({failures,same:a.describeAdmission(owner)===facts,
        frozen:Object.isFrozen(owner)&&Object.isFrozen(facts)}));
    `);
    expect(result.failures).toEqual(Array(6).fill("unknown-admission-account"));
    expect(result.same).toBe(true); expect(result.frozen).toBe(true);
  });

  it("preserves historical views and pays for each changed account or process view", async () => {
    const h = await fixture();
    const result = await h.run<{ accountFresh: boolean; processFresh: boolean; unchanged: boolean; historical: boolean; paid: boolean }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")}); const owner=a.beginAdmissionInvocation();
      const old=a.describeAdmission(owner); const oldValues=JSON.stringify(old);
      const processOld=a.admissionProcessSnapshot(); const processValues=JSON.stringify(processOld);
      const cached=a.admissionProcessSnapshot()===processOld;
      a.reserveAdmission(owner,"approval-bytes",37);
      const current=a.describeAdmission(owner); const currentAgain=a.describeAdmission(owner);
      const processCurrent=a.admissionProcessSnapshot();
      console.log(JSON.stringify({accountFresh:current!==old,processFresh:processCurrent!==processOld,
        unchanged:cached&&currentAgain===current&&a.admissionProcessSnapshot()===processCurrent,
        historical:JSON.stringify(old)===oldValues&&JSON.stringify(processOld)===processValues,
        paid:current.retainedBytes>old.retainedBytes+37&&processCurrent.retainedBytes>current.processRetainedBytes}));
    `);
    expect(result).toEqual({ accountFresh: true, processFresh: true, unchanged: true, historical: true, paid: true });
  });

  it("pays changed closed-owner observations without reopening or mutating past facts", async () => {
    const h = await fixture();
    const result = await h.run<{ same: boolean; fresh: boolean; closedDebt: boolean; historical: boolean; rejected: string }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")}); const owner=a.beginAdmissionInvocation();
      const other=a.beginAdmissionInvocation(); const first=a.closeAdmissionInvocation(owner);
      const historical=JSON.stringify(first); const same=a.closeAdmissionInvocation(owner)===first;
      a.reserveAdmission(other,"approval-bytes",19); const next=a.closeAdmissionInvocation(owner);
      let rejected=""; try {a.reserveAdmission(owner,"approval-bytes",1);} catch(e) {rejected=e.message;}
      console.log(JSON.stringify({same,fresh:next!==first&&next.processRetainedBytes>first.processRetainedBytes,
        closedDebt:next.closed&&next.retainedBytes===first.retainedBytes,
        historical:JSON.stringify(first)===historical,rejected}));
    `);
    expect(result).toEqual({ same: true, fresh: true, closedDebt: true, historical: true, rejected: "closed-or-invalid-admission" });
  });

  it("uses fixed denials without new output or credit for repeated malformed and unknown calls", async () => {
    const h = await fixture();
    const result = await h.run<{ invalid: boolean; unknown: boolean; closed: boolean; unchanged: boolean }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")}); const owner=a.beginAdmissionInvocation();
      const before=a.describeAdmission(owner); let invalid,unknown,closed;
      const errors=[];
      for(let n=0;n<32;n++) {
        for (const bytes of [0,-1,0.5,NaN,Infinity,Number.MAX_SAFE_INTEGER]) {
          try {a.reserveAdmission(owner,"approval-bytes",bytes);} catch(e) {invalid??=e;errors.push(e===invalid);}
        }
        try {a.reserveAdmission({},"approval-bytes",1);} catch(e) {unknown??=e;errors.push(e===unknown);}
      }
      const unchanged=a.describeAdmission(owner)===before; a.closeAdmissionInvocation(owner);
      for(let n=0;n<32;n++) {
        try {a.reserveAdmission(owner,"approval-bytes",1);} catch(e) {closed??=e;errors.push(e===closed);}
        try {a.reserveAdmission(owner,"caller-credit",1);} catch(e) {errors.push(e===closed);}
      }
      console.log(JSON.stringify({invalid:invalid.message==="admission-exhausted"&&Object.isFrozen(invalid),
        unknown:unknown.message==="unknown-admission-account"&&Object.isFrozen(unknown),
        closed:closed.message==="closed-or-invalid-admission"&&Object.isFrozen(closed),
        unchanged:unchanged&&errors.every(Boolean)}));
    `);
    expect(result).toEqual({ invalid: true, unknown: true, closed: true, unchanged: true });
  });

  it("closes once from prepaid storage after exact exhaustion and never creates denial copies", async () => {
    const h = await fixture();
    const result = await h.run<{ full: boolean; closed: boolean; same: boolean; fixed: boolean; messages: string[] }>(`
      const a=await import(${moduleImport(h,"upgrade-admission")}); const owner=a.beginAdmissionInvocation();
      const s=a.admissionProcessSnapshot(); a.reserveAdmission(owner,"approval-bytes",s.ceilingBytes-s.retainedBytes);
      let primary; try {a.reserveAdmission(owner,"approval-bytes",1);} catch(e) {primary=e;}
      const terminal=a.closeAdmissionInvocation(owner); const messages=[]; let fixed=true;
      for(let n=0;n<32;n++) {
        for(const operation of [()=>a.beginAdmissionInvocation(),()=>a.admissionProcessSnapshot()]) {
          try {operation();fixed=false;} catch(e) {fixed&&=e===primary; if(n===0)messages.push(e.message);}
        }
      }
      console.log(JSON.stringify({full:terminal.processRetainedBytes===s.ceilingBytes,closed:terminal.closed,
        same:a.closeAdmissionInvocation(owner)===terminal&&a.describeAdmission(owner)===terminal,fixed,messages}));
    `);
    expect(result).toEqual({ full: true, closed: true, same: true, fixed: true,
      messages: ["admission-exhausted", "admission-exhausted"] });
  });

  it("rejects alternate module URLs and copied modules without resetting the live pool", async () => {
    const h = await fixture();
    await copyFile(path.join(h.moduleDirectory, "upgrade-admission.js"), path.join(h.moduleDirectory, "other-admission.js"));
    const result = await h.run<{ failures: string[]; same: boolean; protected: boolean }>(`
      const url=${moduleImport(h, "upgrade-admission")}; const a=await import(url);
      const owner=a.beginAdmissionInvocation(); a.reserveAdmission(owner,"approval-bytes",99); const before=a.admissionProcessSnapshot();
      const failures=[];
      for (const other of [url+"?duplicate",url+"#duplicate",new URL("./other-admission.js",url).href]) {
        try { await import(other); } catch(e) { failures.push(e.message); }
      }
      const d=Object.getOwnPropertyDescriptor(globalThis,Symbol.for("bootstrap.upgradeAdmission.v1"));
      console.log(JSON.stringify({failures,same:a.admissionProcessSnapshot()===before,
        protected:!d.configurable&&!d.writable}));
    `);
    expect(result.failures).toEqual(["unsupported-admission-module", "unsupported-admission-module", "duplicate-admission-producer"]);
    expect(result.same).toBe(true); expect(result.protected).toBe(true);
  });

  it("refuses a preexisting unrecognized producer anchor", async () => {
    const h = await fixture();
    const result = await h.run<{ error: string }>(`
      Object.defineProperty(globalThis,Symbol.for("bootstrap.upgradeAdmission.v1"),{value:{retainedBytes:0}});
      let error=""; try { await import(${moduleImport(h, "upgrade-admission")}); } catch(e) { error=e.message; }
      console.log(JSON.stringify({error}));
    `);
    expect(result.error).toBe("duplicate-admission-producer");
  });
});
