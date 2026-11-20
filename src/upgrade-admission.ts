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
type TerminalFacts = { -readonly [Key in keyof AdmissionFacts]: AdmissionFacts[Key] };
interface Account {
  id: string;
  closed: boolean;
  retainedBytes: number;
  terminal: TerminalFacts;
  facts?: AdmissionFacts;
}
type ProcessFacts = Readonly<{ retainedBytes: number; ceilingBytes: number; invocationCount: number }>;

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
// Retained logical allowances; selected-runtime object/framing bounds remain separate.
const FACT_BYTES = 512;
const FAILURE_SETUP_BYTES = 3 * 4096;
let retainedBytes = 4096 + FAILURE_SETUP_BYTES;
// All three objects are paid before creation and reused on every API rejection.
const exhausted = Object.freeze(new Error("admission-exhausted"));
const unknown = Object.freeze(new Error("unknown-admission-account"));
const closedOrInvalid = Object.freeze(new Error("closed-or-invalid-admission"));
let processFacts: ProcessFacts | undefined;

function charge(bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > CEILING - retainedBytes) {
    throw exhausted;
  }
  retainedBytes += bytes;
}

/** Internal fixed authentication-module metadata; no work or capability authority. */
export function reserveAuthenticationBookkeeping(): void {
  charge(65536);
}

function accountFor(value: AdmissionInvocation): Account {
  const account = accounts.get(value);
  if (!account) throw unknown;
  return account;
}

/** A real strong ledger owner, with no installation or execution authority. */
export function beginAdmissionInvocation(): AdmissionInvocation {
  // The private terminal object is allocated now and paid before any later work.
  const initialBytes = 512 + FACT_BYTES;
  charge(initialBytes);
  const capability = Object.freeze({}) as AdmissionInvocation;
  const id = randomBytes(16).toString("hex");
  const terminal: TerminalFacts = {
    invocationId: id, closed: true, retainedBytes: initialBytes,
    processRetainedBytes: retainedBytes, processCeilingBytes: CEILING,
  };
  accounts.set(capability, {
    id,
    closed: false,
    retainedBytes: initialBytes,
    terminal,
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
  if (account.closed || !kinds.has(kind)) throw closedOrInvalid;
  charge(bytes);
  account.retainedBytes += bytes;
}

export function describeAdmission(invocation: AdmissionInvocation): AdmissionFacts {
  const account = accountFor(invocation);
  const previous = account.facts;
  if (previous && previous.closed === account.closed && previous.retainedBytes === account.retainedBytes
    && previous.processRetainedBytes === retainedBytes) return previous;
  // A closed owner's observation is producer metadata, never reopened work.
  charge(FACT_BYTES);
  if (!account.closed) account.retainedBytes += FACT_BYTES;
  account.facts = Object.freeze({
    invocationId: account.id,
    closed: account.closed,
    retainedBytes: account.retainedBytes,
    processRetainedBytes: retainedBytes,
    processCeilingBytes: CEILING,
  });
  return account.facts;
}

export function closeAdmissionInvocation(invocation: AdmissionInvocation): AdmissionFacts {
  const account = accountFor(invocation);
  if (account.closed) return describeAdmission(invocation);
  // Revocation never needs fresh credit; the private first-close object is prepaid.
  account.closed = true;
  account.terminal.retainedBytes = account.retainedBytes;
  account.terminal.processRetainedBytes = retainedBytes;
  account.facts = Object.freeze(account.terminal);
  return account.facts;
}

/** Observations cannot reconstruct owners or release retained/uncertain debt. */
export function admissionProcessSnapshot(): ProcessFacts {
  if (processFacts && processFacts.retainedBytes === retainedBytes
    && processFacts.invocationCount === accounts.size) return processFacts;
  // This code-owned global observation spends only the original process pool.
  charge(FACT_BYTES);
  processFacts = Object.freeze({ retainedBytes, ceilingBytes: CEILING, invocationCount: accounts.size });
  return processFacts;
}
