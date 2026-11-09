import { copyFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { copyHarness, moduleImport, type CopyHarness } from "./helpers/upgrade-approval-fixture.js";

const harnesses: CopyHarness[] = [];
async function fixture() { const h = await copyHarness(); harnesses.push(h); return h; }
afterEach(async () => { await Promise.all(harnesses.splice(0).map((h) => h.close())); });

describe("process-wide retained admission (accounting only)", () => {
  it("shares one cumulative ceiling across real owners and retains debt after close", async () => {
    const h = await fixture();
    const result = await h.run<{ before: number; after: number; one: number; two: number; closed: boolean; count: number; ceiling: number }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")});
      const before = a.admissionProcessSnapshot().retainedBytes;
      const one = a.beginAdmissionInvocation(); const two = a.beginAdmissionInvocation();
      a.reserveAdmission(one, "approval-bytes", 1234); a.reserveAdmission(two, "approval-crypto", 4567);
      a.closeAdmissionInvocation(one); const snapshot = a.admissionProcessSnapshot();
      console.log(JSON.stringify({before,after:snapshot.retainedBytes,one:a.describeAdmission(one).retainedBytes,
        two:a.describeAdmission(two).retainedBytes,closed:a.describeAdmission(one).closed,
        count:snapshot.invocationCount,ceiling:snapshot.ceilingBytes}));
    `);
    expect(result).toEqual({ before: 4096, after: 4096 + 1024 + 1234 + 4567,
      one: 512 + 1234, two: 512 + 4567, closed: true, count: 2, ceiling: 2 * 1024 ** 3 });
  });

  it("rejects forged, copied and serialized accounts instead of importing snapshot authority", async () => {
    const h = await fixture();
    const result = await h.run<{ failures: string[]; retained: number; frozen: boolean }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")});
      const owner = a.beginAdmissionInvocation(); const facts = a.describeAdmission(owner);
      const failures = [];
      for (const forged of [{}, {...owner}, JSON.parse(JSON.stringify(owner)), facts, null]) {
        try { a.reserveAdmission(forged, "approval-bytes", 1); } catch(e) { failures.push(e.message); }
      }
      console.log(JSON.stringify({failures,retained:a.describeAdmission(owner).retainedBytes,
        frozen:Object.isFrozen(owner)&&Object.isFrozen(facts)}));
    `);
    expect(result.failures).toEqual(Array(5).fill("unknown-admission-account"));
    expect(result.retained).toBe(512); expect(result.frozen).toBe(true);
  });

  it("denies fractional, negative, overflowing and invalid-kind reservations without credit", async () => {
    const h = await fixture();
    const result = await h.run<{ invalid: number; retained: number; closedError: string }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")}); const owner = a.beginAdmissionInvocation();
      let invalid = 0;
      for (const bytes of [0,-1,0.5,NaN,Infinity,Number.MAX_SAFE_INTEGER]) {
        try { a.reserveAdmission(owner,"approval-bytes",bytes); } catch { invalid++; }
      }
      try { a.reserveAdmission(owner,"caller-credit",1); } catch { invalid++; }
      a.closeAdmissionInvocation(owner); let closedError = "";
      try { a.reserveAdmission(owner,"approval-bytes",1); } catch(e) { closedError=e.message; }
      console.log(JSON.stringify({invalid,retained:a.describeAdmission(owner).retainedBytes,closedError}));
    `);
    expect(result).toEqual({ invalid: 7, retained: 512, closedError: "closed-or-invalid-admission" });
  });

  it("does not create a fresh allowance for a new invocation after exhaustion", async () => {
    const h = await fixture();
    const result = await h.run<{ retained: number; rejected: boolean; reserveRejected: boolean; count: number }>(`
      const a = await import(${moduleImport(h, "upgrade-admission")}); const owner = a.beginAdmissionInvocation();
      const remaining = a.admissionProcessSnapshot().ceilingBytes-a.admissionProcessSnapshot().retainedBytes;
      a.reserveAdmission(owner,"approval-bytes",remaining); a.closeAdmissionInvocation(owner);
      let rejected=false; let reserveRejected=false;
      try { a.beginAdmissionInvocation(); } catch(e) { rejected=e.message==="admission-exhausted"; }
      try { a.reserveAdmission(owner,"approval-bytes",1); } catch { reserveRejected=true; }
      const s=a.admissionProcessSnapshot(); console.log(JSON.stringify({retained:s.retainedBytes,rejected,reserveRejected,count:s.invocationCount}));
    `);
    expect(result).toEqual({ retained: 2 * 1024 ** 3, rejected: true, reserveRejected: true, count: 1 });
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
      console.log(JSON.stringify({failures,same:JSON.stringify(before)===JSON.stringify(a.admissionProcessSnapshot()),
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
