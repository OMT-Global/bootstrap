import { EventEmitter } from "node:events";

export type Resource = "request" | "message" | "socket";
export interface NativePlan {
  status?: number;
  headers?: string[];
  body?: Buffer;
  wire?: Buffer;
  complete?: boolean;
  trailers?: string[];
  httpVersion?: string;
  holdClose?: Resource[];
  holdEnd?: boolean;
  mode?: "ordinary" | "presecure-error" | "post-end-error" | "socket-only" | "information" | "upgrade";
  beforeSecureData?: Buffer;
  headersSentFalse?: boolean;
  authorized?: boolean;
  encrypted?: boolean;
}
class NativeResource extends EventEmitter {
  destroyed = false;
  closed = false;
  constructor(readonly kind: Resource, readonly owner: Exchange) { super(); }
  destroy() {
    if (this.destroyed) return this;
    this.destroyed = true;
    if (this.kind !== "socket") this.owner.socket.destroy();
    this.owner.scheduleClose(this.kind);
    return this;
  }
  resume() { return this; }
}
export class Exchange {
  request = new NativeResource("request", this);
  socket = Object.assign(new NativeResource("socket", this), { encrypted: true, authorized: true, authorizationError: undefined, remoteAddress: "", remoteFamily: "IPv4", connecting: false });
  message: NativeResource & { httpVersion: string; statusCode: number; rawHeaders: string[]; rawTrailers: string[]; headers: Record<string, string>; complete: boolean };
  ended = false;
  secure = false;
  bodyEnded = false;
  endCalls: { body: Buffer; afterSecure: boolean }[] = [];
  writeCalls: unknown[] = [];
  flushCalls = 0;
  pinnedAddress = "";
  constructor(readonly url: URL, readonly options: Record<string, unknown>, readonly plan: NativePlan, callback?: (response: unknown) => void) {
    this.socket.authorized = plan.authorized ?? true; this.socket.encrypted = plan.encrypted ?? true;
    const rawHeaders = plan.headers ?? ["Content-Length", String(plan.body?.length ?? 0), "Connection", "close"];
    const headers: Record<string, string> = {};
    for (let index = 0; index < rawHeaders.length; index += 2) {
      const name = rawHeaders[index]!.toLowerCase(); headers[name] = headers[name] === undefined ? rawHeaders[index + 1]! : `${headers[name]}, ${rawHeaders[index + 1]}`;
    }
    this.message = Object.assign(new NativeResource("message", this), { httpVersion: plan.httpVersion ?? "1.1", statusCode: plan.status ?? 204,
      rawHeaders, headers, rawTrailers: plan.trailers ?? [], complete: plan.complete ?? true });
    Object.assign(this.request, {
      headersSent: false, writableFinished: false, writableEnded: false,
      end: (body?: string | Buffer) => {
        const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(body);
        this.endCalls.push({ body: bytes, afterSecure: this.secure }); this.ended = true;
        Object.assign(this.request, { headersSent: !this.plan.headersSentFalse, writableFinished: true, writableEnded: true });
        if (this.plan.mode !== "presecure-error") queueMicrotask(() => { this.request.emit("finish"); this.respond(); });
        return this.request;
      },
      write: (body: unknown) => { this.writeCalls.push(body); return true; },
      flushHeaders: () => { this.flushCalls++; },
      setTimeout: () => this.request
    });
    if (callback) this.request.once("response", callback);
    const lookup = this.options.lookup as (hostname: string, options: { all: boolean }, callback: (error: unknown, address: unknown, family?: number) => void) => void;
    lookup(this.url.hostname, { all: false }, (error, address, family) => {
      if (error) throw error;
      this.pinnedAddress = String(address); this.socket.remoteAddress = String(address); this.socket.remoteFamily = family === 6 ? "IPv6" : "IPv4";
    });
    const signal = this.options.signal as AbortSignal | undefined;
    signal?.addEventListener("abort", () => this.fail(), { once: true });
    queueMicrotask(() => {
      Object.assign(this.request, { socket: this.socket });
      this.request.emit("socket", this.socket);
      if (this.plan.beforeSecureData) this.socket.emit("data", this.plan.beforeSecureData);
      if (this.plan.mode === "presecure-error") { this.fail(); return; }
      this.secure = true; this.socket.emit("secureConnect");
    });
  }
  scheduleClose(kind: Resource) { if (!this.plan.holdClose?.includes(kind)) queueMicrotask(() => this.close(kind)); }
  close(kind: Resource) {
    const resource = this[kind];
    if (resource.closed) return;
    resource.closed = true;
    resource.emit("close");
  }
  release() { for (const kind of ["request", "message", "socket"] as const) this.close(kind); }
  fail() {
    if (this.request.listenerCount("error")) this.request.emit("error", new Error("fabricated native connection failure"));
    this.request.destroy(); this.message.destroy(); this.socket.destroy();
  }
  headerBytes() {
    return Buffer.from(`HTTP/${this.message.httpVersion} ${this.message.statusCode} fixture\r\n` + this.message.rawHeaders.reduce((all, part, index) => all + (index % 2 ? `: ${part}\r\n` : part), "") + "\r\n");
  }
  respond() {
    if (this.plan.mode === "post-end-error") { this.fail(); return; }
    if (this.plan.mode === "information") this.request.emit("information", { statusCode: 100 });
    if (this.plan.mode === "upgrade") {
      this.request.emit("upgrade", this.message, this.socket, Buffer.alloc(0)); this.fail(); return;
    }
    const body = this.plan.body ?? Buffer.alloc(0);
    const wire = this.plan.wire ?? Buffer.concat([this.headerBytes(), body]);
    if (this.plan.mode === "socket-only") { this.socket.emit("data", wire); this.fail(); return; }
    this.socket.emit("data", wire);
    this.request.emit("response", this.message);
    if (body.length) this.message.emit("data", body);
    if (this.plan.holdEnd) return;
    this.bodyEnded = true; this.message.emit("end");
    for (const kind of ["request", "message", "socket"] as const) this.scheduleClose(kind);
  }
}
export const native = {
  answers: [{ address: "8.8.8.8", family: 4 }] as unknown,
  lookups: [] as { hostname: string; options: unknown }[],
  exchanges: [] as Exchange[],
  plans: [] as NativePlan[],
  holdLookup: false,
  lookupResolve: undefined as undefined | ((value: unknown) => void),
  reset() { this.answers = [{ address: "8.8.8.8", family: 4 }]; this.lookups = []; this.exchanges = []; this.plans = []; this.holdLookup = false; this.lookupResolve = undefined; },
  async lookup(hostname: string, options: unknown) {
    this.lookups.push({ hostname, options });
    return this.holdLookup ? new Promise(resolve => { this.lookupResolve = resolve; }) : this.answers;
  },
  request(input: string | URL | Record<string, unknown>, optionsOrCallback?: Record<string, unknown> | ((response: unknown) => void), callback?: (response: unknown) => void) {
    const isUrl = typeof input === "string" || input instanceof URL;
    const options = (isUrl ? optionsOrCallback : input) as Record<string, unknown>;
    const url = isUrl ? new URL(input as string | URL) : new URL(`https://${String(options.hostname)}${String(options.path ?? "/")}`);
    const cb = typeof optionsOrCallback === "function" ? optionsOrCallback : callback;
    const exchange = new Exchange(url, options, native.plans.shift() ?? {}, cb);
    native.exchanges.push(exchange); return exchange.request;
  },
  release() {
    this.lookupResolve?.(this.answers); this.lookupResolve = undefined;
    for (const exchange of this.exchanges) { exchange.release(); }
  }
};
