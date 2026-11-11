// Synthetic native events through the ACTUAL default sender and default resolver.
// This is source behavior coverage, not native DNS/TLS/process qualification.
import { performance } from "node:perf_hooks";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const networkClosed = vi.hoisted(() => {
  const fetch = vi.fn(() => Promise.reject(new Error("Unexpected fetch in the closed native-event fixture")));
  vi.stubGlobal("fetch", fetch); return { fetch };
});
vi.mock("node:https", async () => { const { native } = await import("./fixtures/webhook-native-events.js"); return { request: native.request, default: { request: native.request } }; });
vi.mock("node:dns/promises", async () => { const { native } = await import("./fixtures/webhook-native-events.js"); const lookup = (hostname: string, options: unknown) => native.lookup(hostname, options); return { lookup, default: { lookup } }; });

import { GitHubClient } from "../src/github/client.js";
import { normalizeManifest } from "../src/manifest.js";
import { deliverMaterialAction, planMaterialAction } from "../src/notifications.js";
import { native, type NativePlan, type Resource } from "./fixtures/webhook-native-events.js";

const controller = () => normalizeManifest({ project: { name: "notifications", owner: "acme" }, archetype: { kind: "generic-empty" }, notifications: { webhookUrlEnv: "FIXTURE_WEBHOOK_URL" } });
const action = (id = "fixture-native-action") => ({ id, action: "repository-settings-change", summary: "Fabricated bounded source test.", governingTarget: "#55" });
const environment = { FIXTURE_WEBHOOK_URL: "https://notifications.example.test/private/fabricated-capability", BOOTSTRAP_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS: "notifications.example.test" };
const client = () => new GitHubClient({ runner: async () => ({ exitCode: 0, stdout: "{}", stderr: "" }) });
const deliver = (id?: string) => deliverMaterialAction(controller(), action(id), { environment, githubClient: client() });
type Report = Awaited<ReturnType<typeof deliver>>;
const webhook = (report: Report) => report.notification.destinations.find(destination => destination.destination === "configured-webhook")!;
const spin = async (predicate: () => boolean) => { for (let index = 0; index < 200; index++) { if (predicate()) return; await Promise.resolve(); } throw new Error("Synthetic native schedule did not reach its expected event"); };
const flush = async () => { for (let index = 0; index < 20; index++) await Promise.resolve(); };
const tracked = (promise: Promise<Report>) => { const result = { settled: false, report: undefined as Report | undefined }; const pending = promise.then(report => { result.settled = true; result.report = report; return report; }); return { result, pending }; };
function timed() {
  vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] }); let now = 0;
  vi.spyOn(performance, "now").mockImplementation(() => now);
  return async (milliseconds: number) => { now += milliseconds; await vi.advanceTimersByTimeAsync(milliseconds); };
}
beforeEach(() => { native.reset(); networkClosed.fetch.mockClear(); });
afterEach(() => { native.release(); expect(networkClosed.fetch).not.toHaveBeenCalled(); vi.restoreAllMocks(); vi.useRealTimers(); });
afterAll(() => vi.unstubAllGlobals());

describe("actual protected default webhook native settlement", () => {
  it.each(["request", "message", "socket"] as const)("does not release a 204 acknowledgement before actual %s close", async (kind: Resource) => {
    native.plans = [{ holdClose: [kind] }]; const delivery = tracked(deliver());
    try {
      await spin(() => native.exchanges[0]?.bodyEnded === true);
      await flush();
      expect(delivery.result.settled).toBe(false);
    } finally { native.exchanges[0]!.close(kind); await delivery.pending; }
    expect(webhook(delivery.result.report!).status).toBe("delivered");
  });

  it("acknowledges a complete opaque binary 200 without a JSON or content-type requirement", async () => {
    native.plans = [{ status: 200, body: Buffer.from([0xff, 0x00, 0x7f]) }];
    const report = await deliver(); const exchange = native.exchanges[0]!;
    expect(webhook(report)).toMatchObject({ status: "delivered", detail: "Webhook returned HTTP 200." });
    expect([exchange.request.closed, exchange.message.closed, exchange.socket.closed]).toEqual([true, true, true]);
    expect(exchange.endCalls).toHaveLength(1); expect(exchange.endCalls[0]!.afterSecure).toBe(true);
    expect(exchange.writeCalls).toEqual([]); expect(exchange.flushCalls).toBe(0);
    expect(exchange.options).toMatchObject({ agent: false, rejectUnauthorized: true, minVersion: "TLSv1.2" });
    const headers = Object.fromEntries(Object.entries(exchange.options.headers as Record<string, unknown>).map(([name, value]) => [name.toLowerCase(), value]));
    expect(headers).toMatchObject({ connection: "close", "accept-encoding": "identity" });
    expect(JSON.stringify(report)).not.toContain("fabricated-capability");
    expect(native.lookups).toEqual([{ hostname: "notifications.example.test", options: { all: true, verbatim: true } }]);
    expect(exchange.pinnedAddress).toBe("8.8.8.8");
  });

  it("accepts exact complete chunked framing and a close-delimited opaque acknowledgement", async () => {
    const headers = ["Transfer-Encoding", "chunked", "Connection", "close"];
    const head = Buffer.from("HTTP/1.1 200 fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    native.plans = [{ status: 200, headers, body: Buffer.from("opaque"), wire: Buffer.concat([head, Buffer.from("6\r\nopaque\r\n0\r\n\r\n")]) }];
    expect(webhook(await deliver()).status).toBe("delivered");
    native.plans = [{ status: 200, headers, body: Buffer.from("0123456789"), wire: Buffer.concat([head, Buffer.from("A\r\n0123456789\r\n0\r\n\r\n")]) }];
    expect(webhook(await deliver()).status).toBe("delivered");
    native.plans = [{ status: 200, headers: ["Connection", "close"], body: Buffer.from("opaque") }];
    expect(webhook(await deliver()).status).toBe("delivered");
  });

  it("denies transfer-encoded 204 even when decoded body bytes are empty", async () => {
    native.plans = [{ status: 204, headers: ["Transfer-Encoding", "chunked", "Connection", "close"],
      wire: Buffer.from("HTTP/1.1 204 fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n") }];
    expect(webhook(await deliver()).status).toBe("failed"); expect(native.exchanges).toHaveLength(1);
  });

  it.each([
    ["nonempty Content-Length", { status: 205, headers: ["Content-Length", "5", "Connection", "close"], body: Buffer.from("reset") }, "failed"],
    ["nonempty chunked", { status: 205, headers: ["Transfer-Encoding", "chunked", "Connection", "close"], body: Buffer.from("reset"),
      wire: Buffer.from("HTTP/1.1 205 fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nreset\r\n0\r\n\r\n") }, "failed"],
    ["nonempty close-delimited", { status: 205, headers: ["Connection", "close"], body: Buffer.from("reset") }, "failed"],
    ["empty Content-Length", { status: 205, headers: ["Content-Length", "0", "Connection", "close"] }, "delivered"],
    ["empty chunked", { status: 205, headers: ["Transfer-Encoding", "chunked", "Connection", "close"],
      wire: Buffer.from("HTTP/1.1 205 fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n") }, "delivered"],
    ["empty close-delimited", { status: 205, headers: ["Connection", "close"] }, "delivered"]
  ] satisfies [string, NativePlan, "delivered" | "failed"][])("enforces HTTP 205 content semantics for %s", async (_label, plan, expected) => {
    native.answers = [{ address: "8.8.8.8", family: 4 }, { address: "1.1.1.1", family: 4 }];
    native.plans = [{ ...plan, holdClose: ["message"] }, {}]; const delivery = tracked(deliver());
    try {
      await spin(() => native.exchanges[0]?.bodyEnded === true); await flush();
      expect(delivery.result.settled).toBe(false); expect(native.exchanges).toHaveLength(1);
    } finally { native.exchanges[0]!.close("message"); await delivery.pending; }
    const report = delivery.result.report!; const exchange = native.exchanges[0]!;
    expect(webhook(report)).toMatchObject({ status: expected, detail: expected === "delivered" ? "Webhook returned HTTP 205." : "Webhook delivery failed." });
    expect([exchange.request.closed, exchange.message.closed, exchange.socket.closed]).toEqual([true, true, true]);
    expect(native.exchanges).toHaveLength(1); expect(exchange.pinnedAddress).toBe("8.8.8.8");
    expect(exchange.endCalls).toHaveLength(1); expect(exchange.endCalls[0]!.afterSecure).toBe(true);
    expect(JSON.stringify(report)).not.toContain("fabricated-capability");
  });

  it("does not treat socket-only HTTP bytes as a response acknowledgement, and drains denial", async () => {
    native.plans = [{ mode: "socket-only", holdClose: ["socket"] }]; const delivery = tracked(deliver());
    try { await spin(() => native.exchanges[0]?.socket.destroyed === true); await flush(); expect(delivery.result.settled).toBe(false); }
    finally { native.exchanges[0]!.close("socket"); await delivery.pending; }
    expect(webhook(delivery.result.report!).status).toBe("failed");
  });

  it.each([
    ["redirect", { status: 302 }], ["Location", { headers: ["Content-Length", "0", "Location", "https://foreign.example.test/"] }],
    ["informational", { mode: "information" }], ["upgrade", { mode: "upgrade" }],
    ["trailers", { trailers: ["x-late", "value"] }], ["declared trailer", { headers: ["Content-Length", "0", "Trailer", "x-late"] }],
    ["duplicate raw header", { headers: ["Content-Length", "0", "content-length", "0"] }],
    ["unsupported framing", { headers: ["Transfer-Encoding", "gzip,chunked"] }],
    ["CL and TE", { headers: ["Content-Length", "0", "Transfer-Encoding", "chunked"] }],
    ["incomplete", { complete: false }], ["HTTP version", { httpVersion: "1.0" }],
    ["wrong length", { headers: ["Content-Length", "1"] }], ["noncanonical length", { headers: ["Content-Length", "00"] }],
    ["body limit", { status: 200, body: Buffer.alloc(1024 ** 2 + 1, 120) }],
    ["header limit", { headers: ["Content-Length", "0", "X-Large", "x".repeat(32768)] }],
    ["wire limit", { wire: Buffer.alloc(1024 ** 2 + 32769, 120) }]
  ] satisfies [string, NativePlan][])("rejects native %s without redirect/retry or routing output", async (_label, plan) => {
    native.plans = [plan];
    const report = await deliver();
    expect(webhook(report).status).toBe("failed"); expect(native.exchanges).toHaveLength(1);
    expect(native.exchanges[0]!.socket.closed).toBe(true);
    expect(JSON.stringify(report)).not.toContain("fabricated-capability");
  });

  it.each([
    ["trailing byte", "0\r\n\r\nx"], ["chunk extension", "0;unsupported=x\r\n\r\n"],
    ["truncated chunk", "2\r\nx\r\n0\r\n\r\n"], ["chunk trailer", "0\r\nx-late: value\r\n\r\n"]
  ])("rejects complete-looking message events with malformed raw chunked %s", async (_label, chunks) => {
    native.plans = [{ status: 200, headers: ["Transfer-Encoding", "chunked"], wire: Buffer.from(`HTTP/1.1 200 fixture\r\nTransfer-Encoding: chunked\r\n\r\n${chunks}`) }];
    expect(webhook(await deliver()).status).toBe("failed");
  });

  it("accepts the exact body/header/wire ceilings without truncating bytes", async () => {
    const body = Buffer.alloc(1024 ** 2, 120);
    const prefix = `HTTP/1.1 200 fixture\r\nContent-Length: ${body.length}\r\nX-Pad: `;
    const suffix = "\r\n\r\n";
    const padding = "x".repeat(32768 - Buffer.byteLength(prefix + suffix));
    const wire = Buffer.concat([Buffer.from(prefix + padding + suffix), body]);
    native.plans = [{ status: 200, headers: ["Content-Length", String(body.length), "X-Pad", padding], body, wire }];
    expect(webhook(await deliver()).status).toBe("delivered"); expect(wire.length).toBe(1024 ** 2 + 32768);
  });

  it("permits exactly 64KiB of actual generated JSON and denies larger payloads before an HTTPS request", async () => {
    const overhead = Buffer.byteLength(JSON.stringify(planMaterialAction(controller(), action("a")).webhookPayload)) - 1;
    expect(webhook(await deliver("a".repeat(65536 - overhead))).status).toBe("delivered");
    expect(native.exchanges[0]!.endCalls[0]!.body.length).toBe(65536);
    const previous = native.exchanges.length;
    expect(webhook(await deliver("a".repeat(65537 - overhead))).status).toBe("failed");
    expect(native.exchanges).toHaveLength(previous);
  });
  it.each([{ authorized: false }, { encrypted: false }])("does not start HTTP from an unqualified secureConnect event: %j", async plan => {
    native.plans = [plan];
    expect(webhook(await deliver()).status).toBe("failed"); expect(native.exchanges).toHaveLength(1); expect(native.exchanges[0]!.endCalls).toEqual([]);
  });
});

describe("actual default DNS complete validation and safe address fallback", () => {
  it("accepts a complete 64-public-answer set and still pins just its first address", async () => {
    native.answers = Array.from({ length: 64 }, () => ({ address: "8.8.8.8", family: 4 }));
    expect(webhook(await deliver()).status).toBe("delivered"); expect(native.exchanges).toHaveLength(1); expect(native.exchanges[0]!.pinnedAddress).toBe("8.8.8.8");
  });
  it("retains a valid public IPv6 DNS answer and its actual native family", async () => {
    native.answers = [{ address: "2606:4700:4700::1111", family: 6 }];
    expect(webhook(await deliver()).status).toBe("delivered"); expect(native.exchanges[0]!.pinnedAddress).toBe("2606:4700:4700::1111");
  });
  it.each([
    ["empty", []], ["65 answers", Array.from({ length: 65 }, () => ({ address: "8.8.8.8", family: 4 }))],
    ["private last", [...Array.from({ length: 63 }, () => ({ address: "8.8.8.8", family: 4 })), { address: "10.0.0.1", family: 4 }]],
    ["wrong IPv4 family", [{ address: "8.8.8.8", family: 6 }]], ["wrong IPv6 family", [{ address: "2606:4700:4700::1111", family: 4 }]],
    ["invalid family", [{ address: "8.8.8.8", family: 7 }]], ["invalid address", [{ address: "not-an-address", family: 4 }]]
  ])("rejects the whole default DNS %s result before connecting", async (_label, answers) => {
    native.answers = answers;
    expect(webhook(await deliver()).status).toBe("failed"); expect(native.exchanges).toEqual([]);
  });

  it("waits for proved no-send presecure failure closure before trying the next validated address", async () => {
    native.answers = [{ address: "8.8.8.8", family: 4 }, { address: "1.1.1.1", family: 4 }];
    native.plans = [{ mode: "presecure-error", holdClose: ["socket"] }, {}]; const delivery = tracked(deliver());
    try {
      await spin(() => native.exchanges[0]?.socket.destroyed === true);
      await flush();
      expect(native.exchanges).toHaveLength(1); expect(native.exchanges[0]!.endCalls).toEqual([]); expect(delivery.result.settled).toBe(false);
    } finally { native.exchanges[0]!.close("socket"); await delivery.pending; }
    expect(webhook(delivery.result.report!).status).toBe("delivered"); expect(native.exchanges).toHaveLength(2);
    expect(native.exchanges[1]!.pinnedAddress).toBe("1.1.1.1");
  });

  it.each(["post-end-error", "presecure-inbound"])("never retries after possible HTTP activity despite an error code or headersSent=false: %s", async mode => {
    native.answers = [{ address: "8.8.8.8", family: 4 }, { address: "1.1.1.1", family: 4 }];
    native.plans = [mode === "post-end-error" ? { mode, headersSentFalse: true } : { mode: "presecure-error", beforeSecureData: Buffer.from("HTTP/") }, {}];
    expect(webhook(await deliver()).status).toBe("failed"); expect(native.exchanges).toHaveLength(1);
    if (mode === "post-end-error") expect(native.exchanges[0]!.endCalls).toHaveLength(1);
    else expect(native.exchanges[0]!.endCalls).toEqual([]);
  });
});

describe("one monotonic default action budget includes lookup, fallback, body and close", () => {
  it("revokes after ten seconds but waits for actual default lookup settlement before returning denial", async () => {
    const advance = timed(); native.holdLookup = true; const delivery = tracked(deliver());
    try {
      await spin(() => native.lookups.length === 1); await advance(10001);
      expect(delivery.result.settled).toBe(false); expect(native.exchanges).toEqual([]);
    } finally { native.lookupResolve?.(native.answers); await delivery.pending; }
    expect(webhook(delivery.result.report!).status).toBe("failed"); expect(native.exchanges).toEqual([]);
  });

  it("does not reset ten seconds after DNS and a safe address fallback", async () => {
    const advance = timed(); native.holdLookup = true; native.answers = [{ address: "8.8.8.8", family: 4 }, { address: "1.1.1.1", family: 4 }];
    native.plans = [{ mode: "presecure-error" }, { status: 200, body: Buffer.from("pending"), holdEnd: true }];
    const delivery = tracked(deliver());
    try {
      await spin(() => native.lookups.length === 1); await advance(6000); native.lookupResolve?.(native.answers);
      await spin(() => native.exchanges.length === 2 && native.exchanges[1]!.ended);
      await advance(4001); await spin(() => delivery.result.settled);
      expect(webhook(delivery.result.report!).status).toBe("failed"); expect(native.exchanges).toHaveLength(2);
    } finally { for (const exchange of native.exchanges) { if (!exchange.request.closed) exchange.fail(); exchange.release(); } await delivery.pending; }
  });

  it("withholds a late close success after the same action permission expired", async () => {
    const advance = timed(); native.plans = [{ holdClose: ["socket"] }]; const delivery = tracked(deliver());
    try {
      await spin(() => native.exchanges[0]?.bodyEnded === true); await advance(10001);
      expect(delivery.result.settled).toBe(false);
    } finally { native.exchanges[0]!.close("socket"); await delivery.pending; }
    expect(webhook(delivery.result.report!).status).toBe("failed");
  });
});
