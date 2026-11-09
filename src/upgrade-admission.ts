import { randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Accounting ownership only. This capability never permits execution or publication. */
declare const admissionBrand: unique symbol;
export type AdmissionInvocation = { readonly [admissionBrand]: true };
export type AdmissionKind =
  | "account"
  | "approval-bytes"
  | "approval-decoding"
  | "approval-schema"
  | "approval-crypto"
  | "authentication-fact";
export interface AdmissionFacts {
  readonly invocationId: string;
  readonly closed: boolean;
  readonly retainedBytes: number;
  readonly processRetainedBytes: number;
  readonly processCeilingBytes: number;
}
interface Account {
  id: string;
  closed: boolean;
  retainedBytes: number;
}

const moduleUrl = new URL(import.meta.url);
const canonicalModule = realpathSync(fileURLToPath(moduleUrl));
if (moduleUrl.search || moduleUrl.hash || fileURLToPath(moduleUrl) !== canonicalModule) {
  throw new Error("unsupported-admission-module");
}
const anchorKey = Symbol.for("bootstrap.upgradeAdmission.v1");
if (Object.prototype.hasOwnProperty.call(globalThis, anchorKey)) {
  throw new Error("duplicate-admission-producer");
}
const anchor = Object.freeze({ producer: Object.freeze({}), module: canonicalModule });
Object.defineProperty(globalThis, anchorKey, {
  value: anchor,
  configurable: false,
  enumerable: false,
  writable: false,
});

const CEILING = 2 * 1024 * 1024 * 1024;
const accounts = new Map<object, Account>();
const kinds = new Set<AdmissionKind>([
  "account", "approval-bytes", "approval-decoding", "approval-schema",
  "approval-crypto", "authentication-fact",
]);
// The producer itself exists before any manifest/parser allocation.
let retainedBytes = 4096;

function charge(bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > CEILING - retainedBytes) {
    throw new Error("admission-exhausted");
  }
  retainedBytes += bytes;
}

function accountFor(value: AdmissionInvocation): Account {
  const account = accounts.get(value);
  if (!account) throw new Error("unknown-admission-account");
  return account;
}

/** A real strong ledger owner, with no installation or execution authority. */
export function beginAdmissionInvocation(): AdmissionInvocation {
  charge(512);
  const capability = Object.freeze({}) as AdmissionInvocation;
  accounts.set(capability, {
    id: randomBytes(16).toString("hex"),
    closed: false,
    retainedBytes: 512,
  });
  return capability;
}

/** Call before allocation. There is deliberately no release/reset/import API. */
export function reserveAdmission(
  invocation: AdmissionInvocation,
  kind: AdmissionKind,
  bytes: number,
): void {
  const account = accountFor(invocation);
  if (account.closed || !kinds.has(kind)) throw new Error("closed-or-invalid-admission");
  charge(bytes);
  account.retainedBytes += bytes;
}

export function describeAdmission(invocation: AdmissionInvocation): AdmissionFacts {
  const account = accountFor(invocation);
  return Object.freeze({
    invocationId: account.id,
    closed: account.closed,
    retainedBytes: account.retainedBytes,
    processRetainedBytes: retainedBytes,
    processCeilingBytes: CEILING,
  });
}

export function closeAdmissionInvocation(invocation: AdmissionInvocation): AdmissionFacts {
  accountFor(invocation).closed = true;
  return describeAdmission(invocation);
}

/** Observations cannot reconstruct owners or release retained/uncertain debt. */
export function admissionProcessSnapshot(): Readonly<{
  retainedBytes: number;
  ceilingBytes: number;
  invocationCount: number;
}> {
  return Object.freeze({ retainedBytes, ceilingBytes: CEILING, invocationCount: accounts.size });
}
