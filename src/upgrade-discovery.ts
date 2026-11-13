import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { parseDocument } from "yaml";

import { normalizeManifest } from "./manifest.js";

export const PUBLIC_DISCOVERY_LIMITS = Object.freeze({
  pages: 10,
  repositories: 500,
  requests: 5000,
  responseBytes: 2 * 1024 * 1024,
  totalBytes: 64 * 1024 * 1024,
  manifestBytes: 256 * 1024,
  treeEntries: 10000,
  manifestNodes: 16384,
  manifestDepth: 32,
  requestMilliseconds: 15000,
  totalMilliseconds: 120000
});

export type PublicDiscoveryFailure =
  | "invalid-input" | "aborted" | "deadline" | "transport" | "http-error" | "rate-limit"
  | "response-limit" | "total-byte-limit" | "request-limit" | "repository-limit"
  | "invalid-response" | "pagination" | "changed-repository" | "changed-organization";

export interface DiscoveredPublicRepository {
  readonly repository: string;
  readonly repositoryId: number;
  readonly defaultBranch: string;
  readonly fork: boolean;
  readonly archived: boolean;
  readonly disabled: boolean;
  readonly outcome: "managed" | "unmanaged" | "unsupported";
  readonly reason?: "repository-disabled" | "manifest-not-regular" | "manifest-too-large" | "invalid-manifest";
  readonly head?: string;
  readonly tree?: string;
  readonly manifest?: Readonly<{
    oid: string;
    bytes: number;
    sha256?: string;
    summary?: Readonly<{
      normalizedClass: string | null;
      flowPolicy: Readonly<{ ref: string | null; sha256: string; refStatus: "observed" | "unrenderable" }> | null;
      exceptionCount: number;
    }>;
  }>;
}

export interface PublicManifestDiscovery {
  readonly organization: string;
  readonly scope: "public-manifest-discovery";
  readonly verification: Readonly<{ policy: "unverified"; drift: "unverified"; exceptions: "unverified"; pilots: "unverified" }>;
  readonly status: "complete" | "incomplete";
  readonly repositories: readonly DiscoveredPublicRepository[];
  readonly requests: number;
  readonly receivedBytes: number;
  readonly failure?: Readonly<{ code: PublicDiscoveryFailure; repository?: string; httpStatus?: number }>;
}

type ObjectValue = Record<string, unknown>;
interface RepositoryMetadata {
  repository: string;
  name: string;
  id: number;
  ownerId: number;
  defaultBranch: string;
  fork: boolean;
  archived: boolean;
  disabled: boolean;
}

class DiscoveryFailure extends Error {
  constructor(readonly code: PublicDiscoveryFailure, readonly httpStatus?: number) {
    super(`Public discovery stopped: ${code}.`);
  }
}

const manifestBodies = new WeakMap<PublicManifestDiscovery, ReadonlyMap<DiscoveredPublicRepository, string>>();
const unverified = Object.freeze({ policy: "unverified", drift: "unverified", exceptions: "unverified", pilots: "unverified" } as const);
const oidPattern = /^[0-9a-f]{40}$/;
const namePattern = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const organizationPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
export const isValidPublicDiscoveryOrganization = (value: unknown): value is string =>
  typeof value === "string" && organizationPattern.test(value);
const object = (value: unknown): ObjectValue => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new DiscoveryFailure("invalid-response");
  return value as ObjectValue;
};
const identity = (value: unknown): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) throw new DiscoveryFailure("invalid-response");
  return value;
};
const oid = (value: unknown): string => {
  if (typeof value !== "string" || !oidPattern.test(value)) throw new DiscoveryFailure("invalid-response");
  return value;
};
const branchName = (value: unknown): string => {
  if (typeof value !== "string" || value.length < 1 || value.length > 255 || /[\x00-\x20\x7f~^:?*[\]\\]/.test(value) ||
    value.includes("..") || value.includes("@{") || value === "@" ||
    value.split("/").some((part) => !part || part.startsWith(".") || part.endsWith(".") || part.endsWith(".lock"))) {
    throw new DiscoveryFailure("invalid-response");
  }
  return value;
};

function metadata(value: unknown, organization: string): RepositoryMetadata {
  const repo = object(value);
  const owner = object(repo.owner);
  if (typeof repo.name !== "string" || !namePattern.test(repo.name) || typeof owner.login !== "string" ||
    owner.login.toLowerCase() !== organization.toLowerCase() || owner.type !== "Organization" ||
    typeof repo.full_name !== "string" || repo.full_name.toLowerCase() !== `${organization}/${repo.name}`.toLowerCase() ||
    repo.private !== false || repo.visibility !== "public" || typeof repo.fork !== "boolean" ||
    typeof repo.archived !== "boolean" || typeof repo.disabled !== "boolean") throw new DiscoveryFailure("invalid-response");
  return {
    repository: repo.full_name,
    name: repo.name,
    id: identity(repo.id),
    ownerId: identity(owner.id),
    defaultBranch: branchName(repo.default_branch),
    fork: repo.fork,
    archived: repo.archived,
    disabled: repo.disabled
  };
}

function sameRepository(left: RepositoryMetadata, right: RepositoryMetadata): boolean {
  return left.repository.toLowerCase() === right.repository.toLowerCase() && left.id === right.id &&
    left.ownerId === right.ownerId && left.defaultBranch === right.defaultBranch && left.fork === right.fork &&
    left.archived === right.archived && left.disabled === right.disabled;
}

class PublicRead {
  readonly controller = new AbortController();
  readonly deadline = performance.now() + PUBLIC_DISCOVERY_LIMITS.totalMilliseconds;
  requests = 0;
  receivedBytes = 0;
  private timedOut = false;
  private readonly onAbort = (): void => this.controller.abort();

  constructor(private readonly parent?: AbortSignal, private readonly publicReadToken?: string) {
    parent?.addEventListener("abort", this.onAbort, { once: true });
  }

  check(): void {
    if (this.parent?.aborted) throw new DiscoveryFailure("aborted");
    if (this.timedOut || performance.now() >= this.deadline) throw new DiscoveryFailure("deadline");
  }

  close(): void {
    this.controller.abort();
    this.parent?.removeEventListener("abort", this.onAbort);
  }

  async json(path: string, paginated = false, anonymous = false): Promise<{ value: unknown; link: string | null }> {
    this.check();
    if (++this.requests > PUBLIC_DISCOVERY_LIMITS.requests) throw new DiscoveryFailure("request-limit");
    const url = new URL(path, "https://api.github.com");
    if (url.origin !== "https://api.github.com" || url.username || url.password || url.hash) throw new DiscoveryFailure("invalid-input");
    const timer = setTimeout(() => { this.timedOut = true; this.controller.abort(); },
      Math.min(PUBLIC_DISCOVERY_LIMITS.requestMilliseconds, this.deadline - performance.now()));
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let consumed = false;
    try {
      const headers: Record<string, string> = {
        Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "Bootstrap-Public-Discovery"
      };
      if (!anonymous && this.publicReadToken) headers.Authorization = `Bearer ${this.publicReadToken}`;
      const response = await fetch(url.href, {
        method: "GET", redirect: "error", credentials: "omit", referrerPolicy: "no-referrer",
        headers,
        signal: this.controller.signal
      });
      this.check();
      if (response.url !== url.href || response.redirected) throw new DiscoveryFailure("invalid-response");
      if (response.status !== 200) {
        throw new DiscoveryFailure(response.status === 429 || response.headers.get("x-ratelimit-remaining") === "0" ? "rate-limit" : "http-error", response.status);
      }
      const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
      if (contentType !== "application/json" && contentType !== "application/vnd.github+json") throw new DiscoveryFailure("invalid-response");
      const length = response.headers.get("content-length");
      if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > PUBLIC_DISCOVERY_LIMITS.responseBytes)) {
        throw new DiscoveryFailure("response-limit");
      }
      const link = response.headers.get("link");
      if ((link?.length ?? 0) > 8192 || (!paginated && link)) throw new DiscoveryFailure("pagination");
      reader = response.body?.getReader();
      if (!reader) throw new DiscoveryFailure("invalid-response");
      const chunks: Buffer[] = [];
      let bytes = 0;
      while (true) {
        const part = await reader.read();
        this.check();
        if (part.done) break;
        bytes += part.value.byteLength;
        this.receivedBytes += part.value.byteLength;
        if (bytes > PUBLIC_DISCOVERY_LIMITS.responseBytes) throw new DiscoveryFailure("response-limit");
        if (this.receivedBytes > PUBLIC_DISCOVERY_LIMITS.totalBytes) throw new DiscoveryFailure("total-byte-limit");
        chunks.push(Buffer.from(part.value));
      }
      consumed = true;
      const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, bytes)));
      this.check();
      return { value, link };
    } catch (error) {
      if (error instanceof DiscoveryFailure) throw error;
      this.check();
      throw new DiscoveryFailure(error instanceof SyntaxError || error instanceof TypeError && consumed ? "invalid-response" : "transport");
    } finally {
      clearTimeout(timer);
      if (!consumed) { this.controller.abort(); void reader?.cancel().catch(() => undefined); }
      reader?.releaseLock();
    }
  }
}

function nextPage(link: string | null, organization: string, ownerId: number | undefined, current: number): number | undefined {
  if (!link) return undefined;
  const seen = new Set<string>();
  let next: number | undefined;
  for (const part of link.split(/,\s*(?=<)/)) {
    const match = /^\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(part);
    if (!match || seen.has(match[2]!)) throw new DiscoveryFailure("pagination");
    seen.add(match[2]!);
    const url = new URL(match[1]!);
    const pathMatches = url.pathname.toLowerCase() === `/orgs/${organization}/repos`.toLowerCase() ||
      ownerId !== undefined && url.pathname === `/organizations/${ownerId}/repos`;
    if (url.origin !== "https://api.github.com" || url.username || url.password || url.hash || !pathMatches ||
      [...url.searchParams.keys()].sort().join() !== "direction,page,per_page,sort,type" ||
      url.searchParams.get("type") !== "public" || url.searchParams.get("sort") !== "full_name" ||
      url.searchParams.get("direction") !== "asc" || url.searchParams.get("per_page") !== "100") throw new DiscoveryFailure("pagination");
    const value = url.searchParams.get("page") ?? "";
    if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) throw new DiscoveryFailure("pagination");
    if (match[2] === "next") {
      next = Number(value);
      if (next !== current + 1) throw new DiscoveryFailure("pagination");
    }
  }
  return next;
}

async function repositories(read: PublicRead, organization: string): Promise<RepositoryMetadata[]> {
  const result: RepositoryMetadata[] = [];
  const ids = new Set<number>();
  const names = new Set<string>();
  let page = 1;
  let ownerId: number | undefined;
  while (true) {
    if (page > PUBLIC_DISCOVERY_LIMITS.pages) throw new DiscoveryFailure("pagination");
    const response = await read.json(`/orgs/${encodeURIComponent(organization)}/repos?type=public&sort=full_name&direction=asc&per_page=100&page=${page}`, true, true);
    if (!Array.isArray(response.value) || response.value.length > 100) throw new DiscoveryFailure("invalid-response");
    for (const value of response.value) {
      const repo = metadata(value, organization);
      ownerId ??= repo.ownerId;
      if (repo.ownerId !== ownerId || ids.has(repo.id) || names.has(repo.repository.toLowerCase())) throw new DiscoveryFailure("invalid-response");
      ids.add(repo.id); names.add(repo.repository.toLowerCase()); result.push(repo);
      if (result.length > PUBLIC_DISCOVERY_LIMITS.repositories) throw new DiscoveryFailure("repository-limit");
    }
    const next = nextPage(response.link, organization, ownerId, page);
    if (next === undefined) return result;
    if (response.value.length === 0) throw new DiscoveryFailure("pagination");
    page = next;
  }
}

async function currentHead(read: PublicRead, prefix: string, branch: string): Promise<string> {
  const ref = object((await read.json(`${prefix}/git/ref/heads/${encodeURIComponent(branch)}`)).value);
  const target = object(ref.object);
  if (ref.ref !== `refs/heads/${branch}` || target.type !== "commit") throw new DiscoveryFailure("invalid-response");
  return oid(target.sha);
}

function manifestSummary(text: string, repo: RepositoryMetadata): NonNullable<NonNullable<DiscoveredPublicRepository["manifest"]>["summary"]> | undefined {
  try {
    const document = parseDocument(text, { strict: true, uniqueKeys: true, prettyErrors: false, customTags: [], schema: "core", version: "1.2" });
    if (document.errors.length || document.warnings.length) return undefined;
    const raw: unknown = document.toJS({ maxAliasCount: 0 });
    const pending: { value: unknown; depth: number }[] = [{ value: raw, depth: 0 }];
    const visited = new Set<object>();
    let nodes = 0;
    while (pending.length) {
      const entry = pending.pop()!;
      if (++nodes > PUBLIC_DISCOVERY_LIMITS.manifestNodes || entry.depth > PUBLIC_DISCOVERY_LIMITS.manifestDepth) return undefined;
      if (entry.value === null || typeof entry.value !== "object") continue;
      if (visited.has(entry.value)) return undefined;
      visited.add(entry.value);
      const keys = Object.keys(entry.value);
      if (keys.some((key) => ["__proto__", "constructor", "prototype"].includes(key))) return undefined;
      for (const value of Object.values(entry.value)) pending.push({ value, depth: entry.depth + 1 });
    }
    const manifest = normalizeManifest(raw as Parameters<typeof normalizeManifest>[0]);
    if (manifest.unknownSettings.length !== 0 || manifest.project.visibility !== "public" ||
      manifest.project.owner.toLowerCase() !== repo.repository.split("/")[0]!.toLowerCase() ||
      manifest.project.name.toLowerCase() !== repo.name.toLowerCase() || manifest.project.defaultBranch !== repo.defaultBranch) return undefined;
    const policy = manifest.policy?.flow;
    const safeRef = policy && /^[A-Za-z0-9._/-]{1,256}$/.test(policy.ref);
    return Object.freeze({
      normalizedClass: manifest.repo.class ?? null,
      flowPolicy: policy ? Object.freeze({ ref: safeRef ? policy.ref : null, sha256: policy.sha256, refStatus: safeRef ? "observed" as const : "unrenderable" as const }) : null,
      exceptionCount: manifest.exceptions.length
    });
  } catch { return undefined; }
}

function readOptions(input: unknown): { signal?: AbortSignal; publicReadToken?: string } | undefined {
  try {
    if (input === null || typeof input !== "object" || Array.isArray(input)) return undefined;
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => key !== "signal" && key !== "publicReadToken")) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => typeof key !== "string" || !("value" in descriptors[key]!))) return undefined;
    const signal: unknown = descriptors.signal?.value;
    const token: unknown = descriptors.publicReadToken?.value;
    if (signal !== undefined && !(signal instanceof AbortSignal)) return undefined;
    if (token !== undefined && (typeof token !== "string" || token.length < 20 || token.length > 4096 ||
      !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(token))) return undefined;
    return { ...(signal ? { signal } : {}), ...(token ? { publicReadToken: token } : {}) };
  } catch {
    return undefined;
  }
}

async function inspectRepository(read: PublicRead, repo: RepositoryMetadata): Promise<{ record: DiscoveredPublicRepository; body?: string }> {
  const common = { repository: repo.repository, repositoryId: repo.id, defaultBranch: repo.defaultBranch, fork: repo.fork, archived: repo.archived, disabled: repo.disabled };
  if (repo.disabled) return { record: Object.freeze({ ...common, outcome: "unsupported", reason: "repository-disabled" }) };
  const prefix = `/repos/${encodeURIComponent(repo.repository.split("/")[0]!)}/${encodeURIComponent(repo.name)}`;
  const head = await currentHead(read, prefix, repo.defaultBranch);
  const commit = object((await read.json(`${prefix}/git/commits/${head}`)).value);
  if (oid(commit.sha) !== head) throw new DiscoveryFailure("invalid-response");
  const tree = oid(object(commit.tree).sha);
  const response = object((await read.json(`${prefix}/git/trees/${tree}`)).value);
  if (oid(response.sha) !== tree || response.truncated !== false || !Array.isArray(response.tree) ||
    response.tree.length > PUBLIC_DISCOVERY_LIMITS.treeEntries) throw new DiscoveryFailure("invalid-response");
  const paths = new Set<string>();
  let entry: ObjectValue | undefined;
  for (const value of response.tree) {
    const item = object(value);
    if (typeof item.path !== "string" || item.path.length === 0 || item.path.length > 1024 || /[\x00/]/.test(item.path) || paths.has(item.path)) throw new DiscoveryFailure("invalid-response");
    paths.add(item.path);
    if (item.path === "project.bootstrap.yaml") entry = item;
  }
  if (!entry) return { record: Object.freeze({ ...common, head, tree, outcome: "unmanaged" }) };
  const fileOid = oid(entry.sha);
  const regular = entry.type === "blob" && (entry.mode === "100644" || entry.mode === "100755");
  const other = entry.type === "blob" && entry.mode === "120000" || entry.type === "tree" && entry.mode === "040000" ||
    entry.type === "commit" && entry.mode === "160000";
  if (!regular && !other) throw new DiscoveryFailure("invalid-response");
  if (!regular) {
    return { record: Object.freeze({ ...common, head, tree, outcome: "unsupported", reason: "manifest-not-regular" }) };
  }
  if (typeof entry.size !== "number" || !Number.isSafeInteger(entry.size) || entry.size < 0) throw new DiscoveryFailure("invalid-response");
  if (entry.size > PUBLIC_DISCOVERY_LIMITS.manifestBytes) {
    return { record: Object.freeze({ ...common, head, tree, outcome: "unsupported", reason: "manifest-too-large", manifest: Object.freeze({ oid: fileOid, bytes: entry.size }) }) };
  }
  const blob = object((await read.json(`${prefix}/git/blobs/${fileOid}`)).value);
  if (oid(blob.sha) !== fileOid || blob.size !== entry.size || blob.encoding !== "base64" || typeof blob.content !== "string" ||
    blob.content.length > 2 * Math.ceil(entry.size / 3) * 4 + 8) throw new DiscoveryFailure("invalid-response");
  const compact = blob.content.replace(/[\r\n]/g, "");
  if (compact.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) throw new DiscoveryFailure("invalid-response");
  const bytes = Buffer.from(compact, "base64");
  if (bytes.length !== entry.size || bytes.toString("base64") !== compact ||
    createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex") !== fileOid) throw new DiscoveryFailure("invalid-response");
  const digest = createHash("sha256").update(bytes).digest("hex");
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { text = ""; }
  const summary = manifestSummary(text, repo);
  const managed = summary !== undefined;
  const bound = Object.freeze({ oid: fileOid, bytes: bytes.length, sha256: digest, ...(summary ? { summary } : {}) });
  const record = Object.freeze({ ...common, head, tree, manifest: bound, outcome: managed ? "managed" as const : "unsupported" as const, ...(!managed ? { reason: "invalid-manifest" as const } : {}) });
  return managed ? { record, body: text } : { record };
}

/** Public observations only: this does not verify token identity, policy bundles, drift, pilots or permission to write. */
export async function discoverPublicManifests(organization: string, options: { signal?: AbortSignal; publicReadToken?: string } = {}): Promise<PublicManifestDiscovery> {
  const selected = readOptions(options);
  const validInput = isValidPublicDiscoveryOrganization(organization) && selected !== undefined;
  const read = new PublicRead(validInput ? selected?.signal : undefined, validInput ? selected?.publicReadToken : undefined);
  const records: DiscoveredPublicRepository[] = [];
  const bodies = new Map<DiscoveredPublicRepository, string>();
  let repository: string | undefined;
  try {
    if (!validInput) throw new DiscoveryFailure("invalid-input");
    const first = await repositories(read, organization);
    for (const repo of first) {
      repository = repo.repository;
      const result = await inspectRepository(read, repo);
      records.push(result.record);
      if (result.body !== undefined) bodies.set(result.record, result.body);
    }
    repository = undefined;
    const second = await repositories(read, organization);
    if (first.length !== second.length || first.some((repo) => !second.some((candidate) => sameRepository(repo, candidate)))) {
      throw new DiscoveryFailure("changed-organization");
    }
    for (let index = 0; index < first.length; index++) {
      const repo = first[index]!;
      repository = repo.repository;
      const prefix = `/repos/${encodeURIComponent(repo.repository.split("/")[0]!)}/${encodeURIComponent(repo.name)}`;
      if (!sameRepository(repo, metadata((await read.json(prefix)).value, organization))) throw new DiscoveryFailure("changed-repository");
      if (!repo.disabled && await currentHead(read, prefix, repo.defaultBranch) !== records[index]!.head) throw new DiscoveryFailure("changed-repository");
    }
    read.check();
    const result: PublicManifestDiscovery = Object.freeze({ organization, scope: "public-manifest-discovery", verification: unverified, status: "complete", repositories: Object.freeze(records), requests: read.requests, receivedBytes: read.receivedBytes });
    manifestBodies.set(result, bodies);
    return result;
  } catch (error) {
    const failure = error instanceof DiscoveryFailure ? error : new DiscoveryFailure("invalid-response");
    return Object.freeze({ organization: validInput ? organization : "", scope: "public-manifest-discovery", verification: unverified, status: "incomplete", repositories: Object.freeze(records), requests: read.requests, receivedBytes: read.receivedBytes,
      failure: Object.freeze({ code: failure.code, ...(repository ? { repository } : {}), ...(failure.httpStatus !== undefined ? { httpStatus: failure.httpStatus } : {}) }) });
  } finally { read.close(); }
}

/** Only an actual complete report and one of its managed records can release the source text. */
export function readDiscoveredManifest(discovery: PublicManifestDiscovery, repository: DiscoveredPublicRepository): string {
  const text = manifestBodies.get(discovery)?.get(repository);
  if (text === undefined) throw new Error("Manifest is not bound to a complete managed discovery.");
  return text;
}
