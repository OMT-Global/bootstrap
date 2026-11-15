import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

export class ObservationFailure extends Error {
  constructor(readonly code: string, readonly httpStatus?: number) { super(`Public observation stopped: ${code}.`); }
}
export const record = (value: unknown): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new ObservationFailure("invalid-response");
  return value as Record<string, unknown>;
};
export const positiveId = (value: unknown): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) throw new ObservationFailure("invalid-response");
  return value;
};
export const objectId = (value: unknown): string => {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) throw new ObservationFailure("invalid-response");
  return value;
};
export function boundedValue(value: unknown): void {
  const pending = [{ value, depth: 0 }]; let nodes = 0;
  while (pending.length) {
    const next = pending.pop()!;
    if (++nodes > 50000 || next.depth > 32) throw new ObservationFailure("invalid-response");
    if (next.value === null || typeof next.value !== "object") continue;
    if (Object.keys(next.value).some((key) => ["__proto__", "constructor", "prototype"].includes(key))) throw new ObservationFailure("invalid-response");
    for (const child of Object.values(next.value)) pending.push({ value: child, depth: next.depth + 1 });
  }
}

/** Fixed GitHub public-object reads. A token is a caller-supplied capability,
 * not proof of its issuer, scope, expiry, or write authority. */
export class PublicObservationRead {
  private readonly controller = new AbortController();
  private readonly began = performance.now();
  private readonly deadline = this.began + 120000;
  private readonly onAbort = (): void => this.controller.abort();
  private requests = 0;
  private receivedBytes = 0;
  private timeout = false;
  private token: string | undefined;
  private readonly tokenScope: string;
  constructor(private readonly parent: AbortSignal | undefined, repository: string, token?: string) {
    if (token !== undefined && (typeof token !== "string" || token.length < 20 || token.length > 4096 || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(token))) throw new ObservationFailure("invalid-input");
    this.tokenScope = repositoryPath(repository).toLowerCase();
    this.token = token; parent?.addEventListener("abort", this.onAbort, { once: true });
  }
  get stats(): Readonly<{ requests: number; receivedBytes: number }> { return Object.freeze({ requests: this.requests, receivedBytes: this.receivedBytes }); }
  get observationWindow(): Readonly<{ beganMonotonic: number; endedMonotonic: number }> {
    return Object.freeze({ beganMonotonic: this.began, endedMonotonic: performance.now() });
  }
  check(): void {
    if (this.parent?.aborted) throw new ObservationFailure("aborted");
    if (this.timeout || performance.now() >= this.deadline) throw new ObservationFailure("deadline");
  }
  async close(): Promise<void> { this.controller.abort(); this.token = undefined; this.parent?.removeEventListener("abort", this.onAbort); }
  async json(path: string, paginated = false): Promise<{ value: unknown; link: string | null }> {
    this.check(); if (++this.requests > 500) throw new ObservationFailure("request-limit");
    const url = new URL(path, "https://api.github.com");
    if (url.origin !== "https://api.github.com" || url.username || url.password || url.hash ||
      !/^\/repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/|$)/.test(url.pathname)) throw new ObservationFailure("invalid-input");
    const timer = setTimeout(() => { this.timeout = true; this.controller.abort(); }, Math.min(15000, this.deadline - performance.now()));
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined; let consumed = false;
    try {
      const headers: Record<string, string> = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "Bootstrap-Public-Observation" };
      if (this.token && (url.pathname.toLowerCase() === this.tokenScope || url.pathname.toLowerCase().startsWith(`${this.tokenScope}/`))) headers.Authorization = `Bearer ${this.token}`;
      const response = await fetch(url.href, { method: "GET", redirect: "error", credentials: "omit", referrerPolicy: "no-referrer", headers, signal: this.controller.signal });
      reader = response.body?.getReader(); this.check();
      if (response.url !== url.href || response.redirected) throw new ObservationFailure("invalid-response");
      if (response.status !== 200) throw new ObservationFailure(response.status === 429 || response.headers.get("x-ratelimit-remaining") === "0" ? "rate-limit" : "http-error", response.status);
      const type = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
      if (!["application/json", "application/vnd.github+json"].includes(type ?? "")) throw new ObservationFailure("invalid-response");
      const length = response.headers.get("content-length");
      if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > 2 * 1024 ** 2)) throw new ObservationFailure("response-limit");
      const link = response.headers.get("link");
      if ((link?.length ?? 0) > 8192 || !paginated && link) throw new ObservationFailure("pagination");
      if (!reader) throw new ObservationFailure("invalid-response");
      const chunks: Buffer[] = []; let size = 0;
      while (true) {
        const part = await reader.read(); this.check(); if (part.done) break;
        size += part.value.byteLength; this.receivedBytes += part.value.byteLength;
        if (size > 2 * 1024 ** 2 || this.receivedBytes > 64 * 1024 ** 2) throw new ObservationFailure("response-limit");
        chunks.push(Buffer.from(part.value));
      }
      consumed = true;
      const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size)));
      boundedValue(value); this.check(); return { value, link };
    } catch (error) {
      if (error instanceof ObservationFailure) throw error;
      this.check(); throw new ObservationFailure(consumed ? "invalid-response" : "transport");
    } finally {
      clearTimeout(timer);
      if (!consumed) { this.controller.abort(); void reader?.cancel().catch(() => undefined); }
      reader?.releaseLock();
    }
  }
}

export function repositoryPath(repository: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/.test(repository)) throw new ObservationFailure("invalid-input");
  return `/repos/${repository.split("/").map(encodeURIComponent).join("/")}`;
}
export async function publicRepository(read: PublicObservationRead, expected: { repository: string; id?: number; defaultBranch?: string }): Promise<{ repository: string; id: number; defaultBranch: string }> {
  const value = record((await read.json(repositoryPath(expected.repository))).value);
  if (typeof value.full_name !== "string" || value.full_name.toLowerCase() !== expected.repository.toLowerCase() || value.private !== false || value.visibility !== "public" ||
    typeof value.default_branch !== "string" || value.default_branch.length < 1 || value.default_branch.length > 255 || /[\x00-\x20\x7f~^:?*[\]\\]/.test(value.default_branch) ||
    value.default_branch.split("/").some((part) => !part || part.startsWith(".") || part.endsWith(".") || part.endsWith(".lock")) || value.default_branch.includes("..") || value.default_branch.includes("@{")) throw new ObservationFailure("invalid-response");
  const id = positiveId(value.id);
  if (expected.id !== undefined && expected.id !== id || expected.defaultBranch !== undefined && expected.defaultBranch !== value.default_branch) throw new ObservationFailure("changed-repository");
  return { repository: value.full_name, id, defaultBranch: value.default_branch };
}
export async function publicHead(read: PublicObservationRead, repository: string, branch: string): Promise<string> {
  const ref = record((await read.json(`${repositoryPath(repository)}/git/ref/heads/${encodeURIComponent(branch)}`)).value);
  const target = record(ref.object);
  if (ref.ref !== `refs/heads/${branch}` || target.type !== "commit") throw new ObservationFailure("invalid-response");
  return objectId(target.sha);
}
export async function resolvePublicCommit(read: PublicObservationRead, repository: string, ref: string): Promise<string> {
  if (/^[0-9a-f]{40}$/.test(ref)) return ref;
  if (!/^refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+$/.test(ref)) throw new ObservationFailure("invalid-input");
  const value = record((await read.json(`${repositoryPath(repository)}/git/ref/tags/${encodeURIComponent(ref.slice(10))}`)).value);
  if (value.ref !== ref) throw new ObservationFailure("invalid-response");
  let target = record(value.object);
  const seen = new Set<string>();
  for (let depth = 0; depth < 4; depth++) {
    const sha = objectId(target.sha);
    if (target.type === "commit") return sha;
    if (target.type !== "tag" || seen.has(sha)) throw new ObservationFailure("invalid-response");
    seen.add(sha);
    const tag = record((await read.json(`${repositoryPath(repository)}/git/tags/${sha}`)).value);
    if (tag.sha !== sha) throw new ObservationFailure("invalid-response");
    target = record(tag.object);
  }
  throw new ObservationFailure("invalid-response");
}

export async function readPublicFile(read: PublicObservationRead, repository: string, commit: string, file: string, expectedTree?: string): Promise<{ bytes: Buffer; text: string; oid: string; sha256: string; mode: "100644" | "100755" }> {
  objectId(commit);
  const parts = file.split("/");
  if (parts.length > 32 || parts.some((part) => !part || part === "." || part === ".." || /[\x00-\x20\x7f\\]/.test(part)) || file.length > 4096) throw new ObservationFailure("invalid-input");
  const prefix = repositoryPath(repository);
  const source = record((await read.json(`${prefix}/git/commits/${commit}`)).value);
  if (source.sha !== commit) throw new ObservationFailure("invalid-response");
  let tree = objectId(record(source.tree).sha);
  if (expectedTree !== undefined && tree !== expectedTree) throw new ObservationFailure("changed-repository");
  for (let depth = 0; depth < parts.length; depth++) {
    const response = record((await read.json(`${prefix}/git/trees/${tree}`)).value);
    if (response.sha !== tree || response.truncated !== false || !Array.isArray(response.tree) || response.tree.length > 10000) throw new ObservationFailure("invalid-response");
    const entries = response.tree.map(record);
    const paths = new Set<string>();
    for (const entry of entries) {
      if (typeof entry.path !== "string" || !entry.path || entry.path.length > 1024 || /[\x00/]/.test(entry.path) || paths.has(entry.path) ||
        !["100644", "100755", "120000", "040000", "160000"].includes(String(entry.mode)) ||
        entry.type !== (entry.mode === "040000" ? "tree" : entry.mode === "160000" ? "commit" : "blob")) throw new ObservationFailure("invalid-response");
      paths.add(entry.path); objectId(entry.sha);
    }
    entries.sort((a, b) => Buffer.compare(Buffer.from(String(a.path) + (a.type === "tree" ? "/" : "")), Buffer.from(String(b.path) + (b.type === "tree" ? "/" : ""))));
    const raw = Buffer.concat(entries.map((entry) => Buffer.concat([Buffer.from(`${String(entry.mode).replace(/^0+/, "")} ${entry.path}\0`), Buffer.from(String(entry.sha), "hex")])));
    if (createHash("sha1").update(`tree ${raw.length}\0`).update(raw).digest("hex") !== tree) throw new ObservationFailure("invalid-response");
    const selected = entries.find((entry) => entry.path === parts[depth]);
    if (!selected) throw new ObservationFailure("missing-source");
    if (depth < parts.length - 1) { if (selected.type !== "tree") throw new ObservationFailure("invalid-response"); tree = objectId(selected.sha); continue; }
    if (selected.type !== "blob" || selected.mode !== "100644" && selected.mode !== "100755" || !Number.isSafeInteger(selected.size) || Number(selected.size) < 0 || Number(selected.size) > 1024 ** 2) throw new ObservationFailure("invalid-response");
    const blob = record((await read.json(`${prefix}/git/blobs/${objectId(selected.sha)}`)).value);
    if (blob.kind === "invalid-source") throw new ObservationFailure("invalid-source");
    if (blob.sha !== selected.sha || blob.size !== selected.size || blob.encoding !== "base64" || typeof blob.content !== "string" || blob.content.length > 2 * 1024 ** 2) throw new ObservationFailure("invalid-response");
    const compact = blob.content.replace(/[\r\n]/g, "");
    const bytes = Buffer.from(compact, "base64");
    if (bytes.length !== selected.size || bytes.toString("base64") !== compact || createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex") !== selected.sha) throw new ObservationFailure("invalid-response");
    return { bytes, text: new TextDecoder("utf-8", { fatal: true }).decode(bytes), oid: String(selected.sha), sha256: createHash("sha256").update(bytes).digest("hex"), mode: selected.mode };
  }
  throw new ObservationFailure("missing-source");
}
