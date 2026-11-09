import { createHash } from "node:crypto";
import https from "node:https";
import path from "node:path";
import { z } from "zod";

export const NODE_ISOLATION_PROFILE = "node-npm-linux-v1";
export const NODE_ISOLATION_IMAGE = "mcr.microsoft.com/devcontainers/javascript-node@sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6";
export const ISOLATION_LIMITS = Object.freeze({ files: 10_000, entries: 10_000, pathDepth: 32, sourceBytes: 512 * 1024 ** 2, bundleBytes: 64 * 1024 ** 2,
  archiveBytes: 64 * 1024 ** 2, downloadBytes: 512 * 1024 ** 2, archives: 1000, outputBytes: 8 * 1024 ** 2,
  phaseMs: 15 * 60_000, operationMs: 60 * 60_000, downloadMs: 30_000, manifestBytes: 1024 ** 2, lockBytes: 16 * 1024 ** 2 });
export interface PlannedGitIdentity { name: string; email: string; date: string }
export interface IsolatedSourceFile { path: string; mode: "100644" | "100755"; bytes: Uint8Array }
interface NodeValidationCommon {
  profile: typeof NODE_ISOLATION_PROFILE; files: readonly IsolatedSourceFile[]; baseBundle: Uint8Array;
  baseCommit: string; branch: string; commitMessage: string; author: PlannedGitIdentity; committer: PlannedGitIdentity; hook: "none" | ".githooks/pre-commit";
}
type ValidationPhase = { phase: "prepared-hook" } | { phase: "final-check"; candidateCommit: string };
export type NodeValidationInput = NodeValidationCommon & ValidationPhase;
export interface ArchiveRequest { url: string; integrity: string }
export type FrozenNodeInput = Omit<NodeValidationCommon, "files" | "baseBundle"> & ValidationPhase & {
  files: Array<{ path: string; mode: "100644" | "100755"; bytes: Buffer; sha256: string }>;
  baseBundle: Buffer; sourceSha256: string; commitPlanSha256: string; archives: ArchiveRequest[];
}
const knownHooks = new Set(["applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
  "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push",
  "pre-receive", "update", "proc-receive", "post-receive", "post-update", "reference-transaction", "push-to-checkout",
  "pre-auto-gc", "post-rewrite", "sendemail-validate", "fsmonitor-watchman", "post-index-change"]);
function demand(value: unknown, message: string): asserts value { if (!value) throw new Error(message); }
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
function safePath(value: string): boolean {
  return value.length > 0 && Buffer.byteLength(value) <= 4096 && Buffer.from(value).toString() === value &&
    !value.includes("\0") && !value.includes("\\") && !path.posix.isAbsolute(value) && path.posix.normalize(value) === value &&
    value.split("/").every((part) => part.length > 0 && part !== "." && part !== ".." && part.toLowerCase() !== ".git") &&
    !["node_modules", "dist"].includes(value.split("/")[0]!);
}
function json(bytes: Uint8Array): unknown { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
export function freezeNodeValidation(input: NodeValidationInput): FrozenNodeInput {
  const text = (maximum: number, forbidden: RegExp) => z.string().min(1).refine((value) => value.trim() === value && Buffer.byteLength(value) <= maximum && Buffer.from(value).toString() === value && !forbidden.test(value));
  const identity = z.object({ name: text(256, /[\x00-\x1f\x7f-\x9f<>]/), email: text(254, /[\s\x00-\x1f\x7f-\x9f<>]/),
    date: z.string().regex(/^(?:0|[1-9][0-9]{0,10}) [+-](?:0[0-9]|1[0-9]|2[0-3])[0-5][0-9]$/) }).strict();
  const common = z.object({ profile: z.literal(NODE_ISOLATION_PROFILE), files: z.array(z.object({ path: z.string(),
    mode: z.enum(["100644", "100755"]), bytes: z.instanceof(Uint8Array) }).strict()).min(1).max(ISOLATION_LIMITS.files),
    baseBundle: z.instanceof(Uint8Array), baseCommit: z.string().regex(/^[a-f0-9]{40}$/), branch: z.string().max(4096).regex(/^codex\/[A-Za-z0-9][A-Za-z0-9._/-]*$/),
    commitMessage: z.string().min(1).refine((value) => Buffer.byteLength(value) <= 16_384 && Buffer.from(value).toString() === value && !value.includes("\0") && /^Signed-off-by: .+ <[^>]+>$/im.test(value)),
    author: identity, committer: identity, hook: z.enum(["none", ".githooks/pre-commit"]) }).strict();
  const parsed = z.discriminatedUnion("phase", [common.extend({ phase: z.literal("prepared-hook") }),
    common.extend({ phase: z.literal("final-check"), candidateCommit: z.string().regex(/^[a-f0-9]{40}$/) })]).parse(input);
  demand(parsed.baseBundle.byteLength > 0 && parsed.baseBundle.byteLength <= ISOLATION_LIMITS.bundleBytes, "Unsupported public base bundle size.");
  demand(!parsed.branch.includes("..") && !parsed.branch.includes("//") && parsed.branch.split("/").every((part) => !part.endsWith(".") && !part.endsWith(".lock")), "Unsupported candidate branch.");
  const seen = new Set<string>(); const directories = new Set<string>(); let size = 0;
  const files = parsed.files.map((file) => {
    demand(safePath(file.path) && !seen.has(file.path), "Unsupported or duplicate prepared source path."); seen.add(file.path);
    size += file.bytes.byteLength; demand(size <= ISOLATION_LIMITS.sourceBytes, "Prepared source exceeds the profile limit.");
    demand(!file.path.endsWith("/.npmrc") && file.path !== ".npmrc" && !file.path.endsWith("/.yarnrc") && file.path !== ".yarnrc", "Repository package-manager configuration is unsupported.");
    if (file.path.endsWith(".gitattributes")) demand(!/\b(?:filter|working-tree-encoding)\s*=/i.test(new TextDecoder().decode(file.bytes)), "External attribute conversion is unsupported.");
    if (file.path.startsWith(".githooks/") && file.mode === "100755" && knownHooks.has(file.path.slice(10))) demand(file.path === parsed.hook, "An effective hook is unsupported or omitted.");
    const bytes = Buffer.from(file.bytes); return { ...file, bytes, sha256: sha256(bytes) };
  }).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  for (const file of files) {
    const parts = file.path.split("/");
    demand(parts.length <= ISOLATION_LIMITS.pathDepth, "Prepared source path exceeds the depth limit.");
    for (let end = 1; end < parts.length; end++) {
      const directory = parts.slice(0, end).join("/");
      demand(!seen.has(directory), "Prepared file/directory collision."); directories.add(directory);
      demand(files.length + directories.size <= ISOLATION_LIMITS.entries, "Prepared source exceeds the materialized entry limit.");
    }
  }
  const get = (name: string) => files.find((file) => file.path === name);
  demand(get("scripts/ci/run-fast-checks.sh"), "The fixed validation entry point is missing.");
  if (parsed.hook !== "none") demand(get(parsed.hook)?.mode === "100755", "The declared pre-commit hook is not executable.");
  demand(!get("npm-shrinkwrap.json"), "Root npm shrinkwrap is unsupported.");
  demand(get("package.json") && get("package-lock.json"), "Root npm manifests are required.");
  demand(get("package.json")!.bytes.length <= ISOLATION_LIMITS.manifestBytes && get("package-lock.json")!.bytes.length <= ISOLATION_LIMITS.lockBytes, "Npm metadata exceeds the profile parser bound.");
  const pkg = z.object({ workspaces: z.never().optional(), packageManager: z.string().regex(/^npm@/).optional() }).passthrough().parse(json(get("package.json")!.bytes));
  void pkg;
  const lock = z.object({ lockfileVersion: z.union([z.literal(2), z.literal(3)]), packages: z.record(z.string(), z.object({
    resolved: z.string().optional(), integrity: z.string().optional(), link: z.boolean().optional(), workspaces: z.never().optional()
  }).passthrough()) }).passthrough().parse(json(get("package-lock.json")!.bytes));
  demand(lock.packages[""], "The npm root lock entry is missing.");
  const requests = new Map<string, string>();
  for (const [name, entry] of Object.entries(lock.packages)) {
    demand(!entry.link, "Linked npm packages are unsupported."); if (name === "") continue;
    demand(name.startsWith("node_modules/") && path.posix.normalize(name) === name && !name.includes("\\") && !name.includes("\0") && entry.resolved && entry.integrity, "Every locked dependency requires a public archive and integrity.");
    const url = new URL(entry.resolved);
    demand(url.protocol === "https:" && url.hostname === "registry.npmjs.org" && !url.port && !url.username && !url.password && !url.search && !url.hash && url.pathname.endsWith(".tgz"), "Only public npm registry tarballs are supported.");
    demand(/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity), "SHA-512 archive integrity is required.");
    demand(!requests.has(url.href) || requests.get(url.href) === entry.integrity, "Conflicting archive integrity."); requests.set(url.href, entry.integrity);
  }
  demand(requests.size <= ISOLATION_LIMITS.archives, "Too many dependency archives.");
  const sourceSha256 = sha256(Buffer.from(JSON.stringify(files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })))));
  const { author, committer, baseCommit, branch, commitMessage, hook } = parsed;
  const commitPlanSha256 = sha256(Buffer.from(JSON.stringify({ author, committer, baseCommit, branch, commitMessage, hook })));
  return { ...parsed, files, baseBundle: Buffer.from(parsed.baseBundle), sourceSha256, commitPlanSha256,
    archives: [...requests].map(([url, integrity]) => ({ url, integrity })) };
}
export function verifyArchive(bytes: Uint8Array, integrity: string): void {
  demand(bytes.byteLength <= ISOLATION_LIMITS.archiveBytes && `sha512-${createHash("sha512").update(bytes).digest("base64")}` === integrity, "Dependency archive size or integrity mismatch.");
}
export async function downloadArchive(request: ArchiveRequest, signal?: AbortSignal): Promise<Buffer> {
  signal?.throwIfAborted();
  const url = new URL(request.url);
  demand(url.protocol === "https:" && url.hostname === "registry.npmjs.org" && !url.port && !url.username && !url.password && !url.search && !url.hash && url.pathname.endsWith(".tgz") && /^sha512-[A-Za-z0-9+/]{86}==$/.test(request.integrity), "Only integrity-bound public npm archives are supported.");
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []; let count = 0; let settled = false; let timer: NodeJS.Timeout | undefined;
    const agent = new https.Agent();
    const finish = () => { clearTimeout(timer); agent.destroy(); };
    const fail = () => { if (!settled) { settled = true; finish(); reject(new Error("Public dependency archive download failed.")); } };
    const connection = https.get(request.url, { agent, ...(signal ? { signal } : {}), headers: { accept: "application/octet-stream" } }, (response) => {
      if (response.statusCode !== 200) { response.destroy(); fail(); return; }
      response.on("data", (chunk: Buffer) => { count += chunk.length; if (count > ISOLATION_LIMITS.archiveBytes) { response.destroy(); fail(); } else chunks.push(chunk); });
      response.on("error", fail); response.on("aborted", fail);
      response.on("end", () => { if (!settled) { try { const bytes = Buffer.concat(chunks); verifyArchive(bytes, request.integrity); settled = true; finish(); resolve(bytes); } catch { fail(); } } });
    });
    timer = setTimeout(() => { connection.destroy(); fail(); }, ISOLATION_LIMITS.downloadMs);
    connection.on("error", fail);
  });
}
