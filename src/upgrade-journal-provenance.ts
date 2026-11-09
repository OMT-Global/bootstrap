import { createHash, createPublicKey, verify } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import {
  beginAdmissionInvocation, closeAdmissionInvocation, reserveAdmission,
  type AdmissionInvocation,
} from "./upgrade-admission.js";

const APPROVAL_DIRECTORY = "/etc/bootstrap/upgrade-journal";
const TRUSTED_ANCESTOR_ROOT = "/";
const TRUSTED_UID = 0;
const APPROVAL_PATH = `${APPROVAL_DIRECTORY}/approved-installation.v1.json`;
const ROLES = ["installation-approval", "storage-support-approval"] as const;
type Role = (typeof ROLES)[number];
type Data = Record<string, unknown>;
interface ApprovalAnchor {
  readonly role: Role;
  readonly kid: string;
  readonly enabled: boolean;
  readonly jwk: Readonly<{ kty: "OKP"; crv: "Ed25519"; x: string }>;
}
const APPROVAL_ANCHORS: readonly ApprovalAnchor[] = Object.freeze([]);
const H = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const MANIFEST_MAX = 4 * 1024 * 1024;
const EVIDENCE_MAX = 1024 * 1024;

declare const authenticationBrand: unique symbol;
/** Authentication of a statement only: never installation/execution authority. */
export type AuthenticatedApproval = { readonly [authenticationBrand]: true };
export interface AuthenticationFacts {
  readonly kind: "authentication-facts";
  readonly approvalSha256: string;
  readonly approvalEpoch: string;
  readonly installationId: string;
  readonly sourceCommit: string;
  readonly evidenceSha256: Readonly<Record<string, string>>;
}
export type AuthenticationResult =
  | { readonly kind: "authenticated"; readonly approval: AuthenticatedApproval }
  | { readonly kind: "unsupported"; readonly reason: "approval-unavailable" | "invalid-approval" | "admission-exhausted" };
interface AuthenticationRecord {
  account: AdmissionInvocation;
  identity: string;
  digest: string;
  poisoned: boolean;
  facts: AuthenticationFacts;
}
const authenticated = new Map<object, AuthenticationRecord>();
class InvalidApproval extends Error {}
function invalid(): never { throw new InvalidApproval("invalid-approval"); }

function record(value: unknown, keys: readonly string[]): Data {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  const result = value as Data;
  const actual = Object.keys(result);
  if (actual.length !== keys.length || actual.some(key => !keys.includes(key))) invalid();
  return result;
}
function string(value: unknown, maximum = 4096, pattern?: RegExp): string {
  if (typeof value !== "string" || Buffer.byteLength(value) > maximum ||
      /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF])/.test(value) ||
      (pattern && !pattern.test(value))) invalid();
  return value;
}
function hash(value: unknown): string { return string(value, 64, H); }
function id(value: unknown): string { return string(value, 128, ID); }
function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) invalid();
  return value;
}
function list(value: unknown, maximum = 10000): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) invalid();
  return value;
}
function pathname(value: unknown, absolute: boolean): string {
  const result = string(value);
  if (!result || /[\0-\x1f\x7f]/.test(result) || path.posix.isAbsolute(result) !== absolute ||
      path.posix.normalize(result) !== result || result.split("/").length > 32 ||
      (!absolute && result.split("/").some(part => part === "" || part === "." || part === ".."))) invalid();
  return result;
}
function contains(parent: string, child: string): boolean {
  const relative = path.posix.relative(parent, child);
  return relative === "" || (!relative.startsWith("../") && relative !== ".." && !path.posix.isAbsolute(relative));
}
function ordered(values: readonly string[]): void {
  if (values.some((value, index) => index > 0 && value <= values[index - 1]!)) invalid();
}
function canonical(value: unknown, depth = 0): string {
  if (depth > 8) invalid();
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(integer(value));
  if (typeof value === "string") return JSON.stringify(string(value, MANIFEST_MAX));
  if (Array.isArray(value)) return `[${value.map(item => canonical(item, depth + 1)).join(",")}]`;
  if (typeof value !== "object") invalid();
  const object = value as Data;
  return `{${Object.keys(object).sort().map(key => `${canonical(key, depth + 1)}:${canonical(object[key], depth + 1)}`).join(",")}}`;
}
function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}
function parse(bytes: Buffer, account: AdmissionInvocation): unknown {
  // Reserve conservative retained representations before UTF-8, JSON/tree and canonical copies.
  reserveAdmission(account, "approval-decoding", bytes.length * 128 + 65536);
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  const value: unknown = JSON.parse(text);
  if (canonical(value) !== text) invalid();
  return value;
}
function fileIdentity(stat: BigIntStats): string {
  return [stat.dev, stat.ino, stat.mode, stat.uid, stat.gid, stat.nlink,
    stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}
function directoryIdentity(stat: BigIntStats): string {
  return [stat.dev, stat.ino, stat.mode, stat.uid, stat.gid].join(":");
}
function trusted(stat: BigIntStats): void {
  if (stat.uid !== BigInt(TRUSTED_UID) || (stat.mode & 0o22n) !== 0n) invalid();
}
async function readTrusted(
  filename: string,
  maximum: number,
  account: AdmissionInvocation,
): Promise<{ bytes: Buffer; identity: string }> {
  reserveAdmission(account, "approval-schema", 32768);
  const relative = path.posix.relative(TRUSTED_ANCESTOR_ROOT, filename);
  if (relative.startsWith("../") || path.posix.isAbsolute(relative)) invalid();
  const components = relative.split("/");
  const ancestors: { name: string; identity: string }[] = [];
  let name = TRUSTED_ANCESTOR_ROOT;
  for (const component of ["", ...components.slice(0, -1)]) {
    if (component) name = path.posix.join(name, component);
    const stat = await lstat(name, { bigint: true });
    trusted(stat);
    if (!stat.isDirectory() || stat.isSymbolicLink()) invalid();
    ancestors.push({ name, identity: directoryIdentity(stat) });
  }
  const before = await lstat(filename, { bigint: true });
  trusted(before);
  if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum)) invalid();
  reserveAdmission(account, "approval-bytes", Number(before.size) + 1);
  const bytes = Buffer.alloc(Number(before.size) + 1);
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    if (fileIdentity(await file.stat({ bigint: true })) !== fileIdentity(before)) invalid();
    let offset = 0;
    while (offset < bytes.length) {
      const result = await file.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    if (offset !== Number(before.size) || fileIdentity(await file.stat({ bigint: true })) !== fileIdentity(before) ||
        fileIdentity(await lstat(filename, { bigint: true })) !== fileIdentity(before)) invalid();
    for (const ancestor of ancestors) {
      if (directoryIdentity(await lstat(ancestor.name, { bigint: true })) !== ancestor.identity) invalid();
    }
    return { bytes: bytes.subarray(0, offset), identity: fileIdentity(before) };
  } finally {
    await file.close();
  }
}

interface Root { id: string; purpose: string; path: string; inventorySha256: string }
interface Inventory { roots: Root[]; files: Data[]; pythonDigest: string }
function inventory(payload: Data): Inventory {
  const roots = list(payload.installationRoots).map(value => {
    const root = record(value, ["id", "purpose", "path", "inventorySha256"]);
    const purpose = string(root.purpose, 32);
    if (!["distribution", "runtime-dependencies", "python-stdlib"].includes(purpose)) invalid();
    return { id: id(root.id), purpose, path: pathname(root.path, true), inventorySha256: hash(root.inventorySha256) };
  });
  if (!roots.length) invalid();
  ordered(roots.map(root => root.id));
  const byLocation = [...roots].sort((left, right) => {
    const a = left.path === "/" ? "/" : `${left.path}/`;
    const b = right.path === "/" ? "/" : `${right.path}/`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  for (let index = 0; index < byLocation.length; index++) {
    const root = byLocation[index]!;
    if ((index > 0 && contains(byLocation[index - 1]!.path, root.path)) ||
        contains(root.path, APPROVAL_DIRECTORY) || contains(APPROVAL_DIRECTORY, root.path)) invalid();
  }
  const rootMap = new Map(roots.map(root => [root.id, root]));
  const files = list(payload.files).map(value => {
    const raw = value as Data;
    const file = record(value, raw?.kind === "regular"
      ? ["rootId", "path", "kind", "mode", "size", "sha256"]
      : ["rootId", "path", "kind", "mode", "target"]);
    id(file.rootId);
    pathname(file.path, false);
    const mode = integer(file.mode, 4095);
    if (!rootMap.has(file.rootId as string)) invalid();
    if (file.kind === "regular") {
      if ((mode & 0o7022) !== 0) invalid();
      integer(file.size);
      hash(file.sha256);
    } else if (file.kind === "symlink") {
      const target = string(file.target);
      if (!target || path.posix.isAbsolute(target) || /[\0-\x1f\x7f]/.test(target)) invalid();
    } else invalid();
    return file;
  });
  if (roots.length + files.length > 10000) invalid();
  ordered(files.map(file => `${file.rootId}\0${file.path}`));
  const byPath = new Map(files.map(file => [`${file.rootId}\0${file.path}`, file]));
  const directories = new Set(roots.map(root => `${root.id}\0`));
  for (const file of files) {
    const parts = (file.path as string).split("/");
    for (let end = 1; end < parts.length; end++) {
      const key = `${file.rootId}\0${parts.slice(0, end).join("/")}`;
      if (byPath.has(key)) invalid();
      directories.add(key);
    }
  }
  for (const file of files) {
    if (file.kind !== "symlink") continue;
    const parent = (file.path as string).split("/").slice(0, -1);
    let pending = (file.target as string).split("/");
    const seen = new Set<Data>([file]);
    let links = 1;
    let terminal: Data | undefined;
    for (let index = 0; index < pending.length; index++) {
      // Even '.'/'..'/empty separators traverse the current directory first.
      if (!directories.has(`${file.rootId}\0${parent.join("/")}`)) invalid();
      const component = pending[index]!;
      if (component === "" || component === ".") continue;
      if (component === "..") {
        if (!parent.length) invalid();
        parent.pop();
        continue;
      }
      const name = [...parent, component].join("/");
      const key = `${file.rootId}\0${name}`;
      const next = byPath.get(key);
      if (next?.kind === "symlink") {
        if (links >= 8 || seen.has(next)) invalid();
        seen.add(next);
        links++;
        pending = [...(next.target as string).split("/"), ...pending.slice(index + 1)];
        index = -1;
        continue;
      }
      parent.push(component);
      if (next?.kind === "regular") {
        if (index !== pending.length - 1) invalid();
        terminal = next;
      } else if (!directories.has(key)) invalid();
    }
    if (!terminal) invalid();
  }
  const slices = roots.map(root => ({
    root: { id: root.id, purpose: root.purpose, path: root.path },
    files: files.filter(file => file.rootId === root.id),
  }));
  for (let index = 0; index < roots.length; index++) {
    if (digest(slices[index]) !== roots[index]!.inventorySha256) invalid();
  }
  const pythonDigest = digest(slices.filter(slice => slice.root.purpose === "python-stdlib"));
  return { roots, files, pythonDigest };
}

function validatePayload(value: unknown): { payload: Data; inventory: Inventory; startupDigest: string } {
  const payload = record(value, ["domain", "version", "approvalEpoch", "installationId", "sourceBuild", "node",
    "prlimit", "installationRoots", "files", "python", "journalProgram", "storageProfile", "evidence"]);
  if (payload.domain !== "bootstrap-upgrade-journal-installation" || payload.version !== 1) invalid();
  id(payload.approvalEpoch);
  id(payload.installationId);
  const source = record(payload.sourceBuild, ["sourceCommit", "packageSha256", "lockSha256", "buildRecipeSha256",
    "distributionInventorySha256", "buildEvidenceSha256"]);
  string(source.sourceCommit, 40, /^[a-f0-9]{40}$/);
  for (const key of Object.keys(source).filter(key => key !== "sourceCommit")) hash(source[key]);
  const node = record(payload.node, ["executable", "executableSha256", "version", "platform", "architecture",
    "entryRootId", "entryPath", "entrySha256"]);
  pathname(node.executable, true);
  hash(node.executableSha256);
  string(node.version, 128, /^v20\.[0-9]+\.[0-9]+$/);
  if (node.platform !== "linux" || node.architecture !== "x64") invalid();
  id(node.entryRootId);
  pathname(node.entryPath, false);
  hash(node.entrySha256);
  const prlimit = record(payload.prlimit, ["executable", "executableSha256"]);
  pathname(prlimit.executable, true);
  hash(prlimit.executableSha256);
  const python = record(payload.python, ["executable", "executableSha256", "version", "standardLibraryRootIds",
    "standardLibraryInventorySha256"]);
  pathname(python.executable, true);
  hash(python.executableSha256);
  string(python.version, 128, /^[\x20-\x7e]+$/);
  hash(python.standardLibraryInventorySha256);
  const program = record(payload.journalProgram, ["rootId", "path", "mode", "sha256"]);
  id(program.rootId);
  if (program.path !== "scripts/bootstrap/upgrade-journal-linux.py") invalid();
  integer(program.mode, 4095);
  hash(program.sha256);
  const storage = record(payload.storageProfile, ["profile", "measurementProfile", "journalRoot", "machineIdSha256",
    "filesystemUuid", "wwidSha256", "partitionUuid", "kernelRelease", "procVersionSha256", "mountOptionsSha256",
    "measurementSha256", "stackEvidenceSha256"]);
  if (storage.profile !== "linux-local-ext4-journal-v1" || storage.measurementProfile !== "direct-ext4-wwid-v1" ||
      storage.journalRoot !== "/var/lib/bootstrap/upgrade-journal") invalid();
  for (const key of ["machineIdSha256", "wwidSha256", "procVersionSha256", "mountOptionsSha256", "measurementSha256", "stackEvidenceSha256"]) hash(storage[key]);
  string(storage.filesystemUuid, 36, UUID);
  if (storage.partitionUuid !== null) string(storage.partitionUuid, 36, UUID);
  string(storage.kernelRelease, 128, /^[\x20-\x7e]+$/);
  const evidence = record(payload.evidence, ["build", "syscallProfile", "storageCrashReboot", "independentReview"]);
  const evidenceHashes = Object.values(evidence).map(hash);
  if (new Set(evidenceHashes).size !== 4 || source.buildEvidenceSha256 !== evidence.build ||
      storage.stackEvidenceSha256 !== evidence.storageCrashReboot) invalid();
  const tree = inventory(payload);
  const distributionIds = new Set(tree.roots.filter(root => root.purpose !== "python-stdlib").map(root => root.id));
  if (source.distributionInventorySha256 !== digest(tree.files.filter(file => distributionIds.has(file.rootId as string)))) invalid();
  const pythonIds = list(python.standardLibraryRootIds).map(id);
  ordered(pythonIds);
  if (!pythonIds.length || canonical(pythonIds) !== canonical(tree.roots.filter(root => root.purpose === "python-stdlib").map(root => root.id)) ||
      python.standardLibraryInventorySha256 !== tree.pythonDigest) invalid();
  const entry = tree.files.find(file => file.rootId === node.entryRootId && file.path === node.entryPath);
  const script = tree.files.find(file => file.rootId === program.rootId && file.path === program.path);
  const entryRoot = tree.roots.find(root => root.id === node.entryRootId);
  const scriptRoot = tree.roots.find(root => root.id === program.rootId);
  if (!entryRoot || entryRoot.purpose !== "distribution" || entry?.kind !== "regular" || entry.sha256 !== node.entrySha256 ||
      scriptRoot?.purpose !== "distribution" || script?.kind !== "regular" || script.sha256 !== program.sha256 || script.mode !== program.mode) invalid();
  return { payload, inventory: tree, startupDigest: digest([node.executable, "--no-global-search-paths", path.posix.join(entryRoot.path, node.entryPath as string)]) };
}

function verifySignatures(envelope: Data, account: AdmissionInvocation): void {
  reserveAdmission(account, "approval-crypto", MANIFEST_MAX * 4 + 65536);
  const approvals = list(envelope.approvals, 2);
  if (approvals.length !== 2) invalid();
  const keys: string[] = [];
  const message = Buffer.from(`bootstrap-upgrade-journal-approval-v1\0${canonical(envelope.payload)}`, "utf8");
  for (let index = 0; index < ROLES.length; index++) {
    const approval = record(approvals[index], ["role", "kid", "algorithm", "signature"]);
    if (approval.role !== ROLES[index] || approval.algorithm !== "ed25519") invalid();
    const kid = string(approval.kid, 64, /^[A-Za-z0-9._:-]{1,64}$/);
    const anchors = APPROVAL_ANCHORS.filter(anchor => anchor.role === approval.role && anchor.kid === kid && anchor.enabled);
    if (anchors.length !== 1) invalid();
    const jwk = record(anchors[0]!.jwk, ["kty", "crv", "x"]);
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") invalid();
    const x = string(jwk.x, 43, /^[A-Za-z0-9_-]{43}$/);
    if (Buffer.from(x, "base64url").length !== 32 || Buffer.from(x, "base64url").toString("base64url") !== x || keys.includes(x)) invalid();
    keys.push(x);
    const encoded = string(approval.signature, 88, /^[A-Za-z0-9+/]{86}==$/);
    const signature = Buffer.from(encoded, "base64");
    if (signature.length !== 64 || signature.toString("base64") !== encoded) invalid();
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
    if (!verify(null, message, key, signature)) invalid();
  }
}

async function verifyEvidence(
  payload: Data,
  pythonDigest: string,
  startupDigest: string,
  account: AdmissionInvocation,
): Promise<void> {
  const evidence = payload.evidence as Data;
  const source = payload.sourceBuild as Data;
  const storage = payload.storageProfile as Data;
  const kinds = { build: "build", syscallProfile: "syscall-profile", storageCrashReboot: "storage-crash-reboot", independentReview: "independent-review" };
  for (const [slot, kind] of Object.entries(kinds)) {
    const expected = evidence[slot] as string;
    const input = await readTrusted(`${APPROVAL_DIRECTORY}/evidence/${expected}.json`, EVIDENCE_MAX, account);
    if (createHash("sha256").update(input.bytes).digest("hex") !== expected) invalid();
    const report = record(parse(input.bytes, account), ["domain", "version", "kind", "sourceCommit", "distributionInventorySha256",
      "pythonInventorySha256", "startupRecipeSha256", "storageMeasurementSha256", "subjectSha256", "body"]);
    if (report.domain !== "bootstrap-upgrade-journal-evidence" || report.version !== 1 || report.kind !== kind ||
        report.sourceCommit !== source.sourceCommit || report.distributionInventorySha256 !== source.distributionInventorySha256 ||
        report.pythonInventorySha256 !== pythonDigest || report.startupRecipeSha256 !== startupDigest ||
        report.storageMeasurementSha256 !== storage.measurementSha256) invalid();
    hash(report.subjectSha256);
    string(report.body, 512 * 1024);
  }
}

/** Real authentication, with no path/key/profile input or installation-success claim. */
export async function authenticateFixedApproval(): Promise<AuthenticationResult> {
  let account: AdmissionInvocation | undefined;
  try {
    account = beginAdmissionInvocation();
    const input = await readTrusted(APPROVAL_PATH, MANIFEST_MAX, account);
    const envelope = record(parse(input.bytes, account), ["payload", "approvals"]);
    const validated = validatePayload(envelope.payload);
    verifySignatures(envelope, account);
    await verifyEvidence(validated.payload, validated.inventory.pythonDigest, validated.startupDigest, account);
    const selected = await readTrusted(APPROVAL_PATH, MANIFEST_MAX, account);
    if (selected.identity !== input.identity || !selected.bytes.equals(input.bytes)) invalid();
    reserveAdmission(account, "authentication-fact", 65536);
    const payload = validated.payload;
    const source = payload.sourceBuild as Data;
    const evidence = payload.evidence as Record<string, string>;
    const facts: AuthenticationFacts = Object.freeze({
      kind: "authentication-facts",
      approvalSha256: createHash("sha256").update(input.bytes).digest("hex"),
      approvalEpoch: payload.approvalEpoch as string,
      installationId: payload.installationId as string,
      sourceCommit: source.sourceCommit as string,
      evidenceSha256: Object.freeze({ ...evidence }),
    });
    const capability = Object.freeze({}) as AuthenticatedApproval;
    authenticated.set(capability, { account, identity: input.identity, digest: facts.approvalSha256, poisoned: false, facts });
    return Object.freeze({ kind: "authenticated", approval: capability });
  } catch (error) {
    if (account) closeAdmissionInvocation(account);
    const reason = error instanceof Error && error.message === "admission-exhausted" ? "admission-exhausted"
      : error instanceof InvalidApproval || error instanceof SyntaxError || error instanceof TypeError ? "invalid-approval" : "approval-unavailable";
    return Object.freeze({ kind: "unsupported", reason });
  }
}

/** Historical signed-statement facts; neither freshness nor a runnable installation. */
export function authenticationFacts(capability: AuthenticatedApproval): AuthenticationFacts {
  const value = authenticated.get(capability);
  if (!value || value.poisoned) throw new Error("unknown-or-poisoned-authentication");
  return value.facts;
}

/** A real fixed-file recheck. Changed/unknown input permanently poisons this association. */
export async function recheckAuthenticatedApproval(
  capability: AuthenticatedApproval,
): Promise<AuthenticationFacts | undefined> {
  const value = authenticated.get(capability);
  if (!value || value.poisoned) return undefined;
  try {
    const current = await readTrusted(APPROVAL_PATH, MANIFEST_MAX, value.account);
    if (value.poisoned || current.identity !== value.identity ||
        createHash("sha256").update(current.bytes).digest("hex") !== value.digest) invalid();
    return value.facts;
  } catch {
    value.poisoned = true;
    closeAdmissionInvocation(value.account);
    return undefined;
  }
}
