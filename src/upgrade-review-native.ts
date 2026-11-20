import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { realpath } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import type { Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";
import { z } from "zod";
import { decode, demand, readRegular, trustedExecutable } from "./upgrade-host.js";
import { readRuntimePolicy, type RuntimePolicy } from "./upgrade-runtime-policy.js";

export const NATIVE_HELPER_SHA256 = "fa51b49fb8e835f314a3dc8a94f01c143222386daee9fd10c6609a4fe5d282f3";
const SCRIPT_SHA256 = "3a663d2fae36d4ab995c658bc4bcc15576e3793bbd23db7606c64a3cb69e1e09";
const CLEANUP_NS = 30_000_000_000n;
const unsupported = ["OPENAI_API_KEY", "CODEX_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "OPENAI_BASE_URL", "OPENAI_ORGANIZATION", "OPENAI_PROJECT",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"];
export interface NativeReviewRequest { readonly directory: string; readonly baseCommit: string; readonly candidateCommit: string; readonly signal: AbortSignal }
declare const completionBrand: unique symbol;
export type NativeReviewCompletion = { readonly [completionBrand]: true };
export interface NativeReviewFacts { readonly schemaVersion: 1; readonly helperSha256: string; readonly model: "gpt-6.1-sol";
  readonly thinking: "high"; readonly priority: "P3"; readonly terminal: "complete"; readonly outcome: "clean"; readonly findings: readonly never[];
  readonly baseCommit: string; readonly candidateCommit: string; readonly authorSession: string; readonly executionSession: string;
  readonly configuredPrincipal: string; readonly childPid: number; readonly reportSha256: string; readonly statusSha256: string;
  readonly modelFamilyIndependence: "unproved"; readonly githubApproval: "not-issued" }
type Completion = { facts: NativeReviewFacts; request: NativeReviewRequest; policy: RuntimePolicy; deadline: bigint; pins: ReadonlyMap<string, string>; verified: boolean };
const completions = new WeakMap<NativeReviewCompletion, Completion>();
const consumed = new WeakSet<NativeReviewRequest>();
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
export class NativeReviewCleanupError extends Error { constructor() { super("Native reviewer completion or cleanup is unconfirmed."); } }
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const tokens = z.object({ cached_input_tokens: integer, input_tokens: integer, output_tokens: integer, reasoning_output_tokens: integer }).strict();
const usage = z.object({ attempts: integer, reported_attempts: integer, unknown_attempts: integer, partial_attempts: integer,
  complete: z.boolean(), tokens: tokens.nullable() }).strict();
const reportFields = { findings: z.array(z.never()).length(0), overall_correctness: z.literal("patch is correct"),
  overall_explanation: z.string().max(65536), overall_confidence: z.number().min(0).max(1) };
const passReport = z.object({ ...reportFields, provider_report: z.object(reportFields).strict() }).strict();
const terminalReport = { usage, review_status: z.literal("scoped-clean") };
const aggregateReport = z.object({ ...reportFields, ...terminalReport,
  pass_reports: z.array(z.object({ label: z.string().max(128), report: passReport }).strict()).min(2).max(8192)
}).strict().refine((value) => value.pass_reports.every((pass, index) => pass.label === `chunk ${index + 1}/${value.pass_reports.length}`) &&
  value.overall_confidence === Math.min(...value.pass_reports.map((pass) => pass.report.overall_confidence)));
// This fixed branch profile has no panels, mixed-source mode or allocation manifest.
const reportSchema = z.union([passReport.extend(terminalReport).strict(), aggregateReport]);
const statusSchema = z.object({ schema_version: z.literal(1), status: z.literal("scoped-clean"), exit_code: z.literal(0), engine: z.literal("codex"),
  report_produced: z.literal(true), reason: z.null(), reviewer_exit_code: z.null(), timed_out: z.literal(false), usage }).strict();
function json(bytes: Buffer): unknown {
  demand(bytes.length > 0 && bytes.length <= 131072); const text = decode(bytes);
  const parsed = parseDocument(text, { uniqueKeys: true, customTags: [], schema: "json" });
  demand(!parsed.errors.length && !parsed.warnings.length);
  const value: unknown = JSON.parse(text); const pending = [{ value, depth: 0 }]; let nodes = 0;
  while (pending.length) { const next = pending.pop()!; demand(++nodes <= 8192 && next.depth <= 16);
    if (next.value && typeof next.value === "object") for (const child of Object.values(next.value)) pending.push({ value: child, depth: next.depth + 1 }); }
  return value;
}
async function checkPins(pins: ReadonlyMap<string, string>): Promise<void> {
  for (const [file, expected] of pins) demand(sha(await readRegular(file, 1048576, true)) === expected);
}
/** Fixed fresh native execution; input selectors are not candidate or publication authority. */
export async function runOwnedNativeReview(input: NativeReviewRequest, policy: RuntimePolicy): Promise<NativeReviewCompletion> {
  demand(!consumed.has(input)); consumed.add(input);
  const request = Object.freeze({ directory: input.directory, baseCommit: input.baseCommit, candidateCommit: input.candidateCommit, signal: input.signal });
  const selected = readRuntimePolicy(policy).projection.review; demand(selected?.profile === "fleet-native-sol-high-v1");
  demand(process.platform === "linux" && process.arch === "x64" && process.getuid?.() !== 0 && !request.signal.aborted &&
    !unsupported.some((name) => Object.hasOwn(process.env, name)));
  const configured = process.env.CODEX_HOME?.trim() || path.join(homedir(), ".codex");
  const codexHome = await realpath(configured === "~" ? homedir() : configured.startsWith("~/") ? path.join(homedir(), configured.slice(2)) : configured);
  const python = await trustedExecutable("/usr/bin/python3");
  const script = fileURLToPath(new URL("../src/native/upgrade-review-owner.py", import.meta.url));
  const pins = new Map([[script, SCRIPT_SHA256], [path.join(codexHome, "skills/autoreview/scripts/autoreview"), NATIVE_HELPER_SHA256]]);
  await checkPins(pins); request.signal.throwIfAborted(); readRuntimePolicy(policy);
  const executionSession = randomUUID(); demand(executionSession !== selected.authorSession);
  const home = path.join(request.directory, "runtime/home");
  const environment: NodeJS.ProcessEnv = { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: home, TMPDIR: path.join(request.directory, "runtime/tmp"),
    LANG: "C.UTF-8", LC_ALL: "C.UTF-8", TZ: "UTC", CODEX_HOME: codexHome,
    XDG_CACHE_HOME: path.join(home, ".cache"), XDG_CONFIG_HOME: path.join(home, ".config"), XDG_DATA_HOME: path.join(home, ".local/share"), XDG_STATE_HOME: path.join(home, ".local/state") };
  for (const name of ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"] as const) if (process.env[name] !== undefined) environment[name] = process.env[name];
  // Human/log streams are deliberately discarded; only bounded control frames and output files are evidence.
  const child = spawn(python, ["-I", script], { cwd: "/", env: environment, stdio: ["ignore", "ignore", "ignore", "pipe"] });
  const control = child.stdio[3] as Duplex | null;
  let buffered = Buffer.alloc(0); let received = 0; let sent = 0; let helperPid: number | undefined;
  let drained: number | undefined; let finishAnchor: bigint | undefined; let finalDeadline: bigint | undefined;
  let failed = false; let cancelled = false; let ended = false; let timer: ReturnType<typeof setTimeout>;
  const write = (value: object) => { const bytes = Buffer.from(JSON.stringify(value) + "\n"); demand(control && bytes.length <= 4096 && (sent += bytes.length) <= 131072); control.write(bytes); };
  const withdraw = () => { failed = true; if (!cancelled) { cancelled = true; try { write({ v: 1, type: "cancel" }); } catch { /* No completion is issued. */ }
    clearTimeout(timer); timer = setTimeout(() => { child.kill("SIGKILL"); }, 30_000); } };
  const frame = (line: Buffer) => {
    // Keep the cancellation watchdog in force while the owner exits.
    if (cancelled) return;
    const value = JSON.parse(decode(line)) as Record<string, unknown>;
    demand(Buffer.from(JSON.stringify(value)).equals(line) && value.v === 1);
    if (value.type === "started") { demand(!helperPid && Object.keys(value).join(",") === "v,type,helper" && Number.isSafeInteger(value.helper) && Number(value.helper) > 0);
      helperPid = Number(value.helper); clearTimeout(timer); timer = setTimeout(withdraw, 1_800_000); }
    else if (value.type === "drained") { demand(helperPid && drained === undefined && Object.keys(value).join(",") === "v,type,exit" && Number.isSafeInteger(value.exit));
      drained = Number(value.exit); finishAnchor = process.hrtime.bigint(); clearTimeout(timer); timer = setTimeout(withdraw, 30_000); write({ v: 1, type: "finish" }); }
    else { demand(!failed && drained === 0 && finishAnchor && !finalDeadline && value.type === "complete" &&
      Object.keys(value).join(",") === "v,type,exit,remainingNs" && value.exit === drained && typeof value.remainingNs === "string" && /^[0-9]{1,11}$/.test(value.remainingNs));
      const remaining = BigInt(value.remainingNs); demand(remaining > 0n && remaining <= CLEANUP_NS); finalDeadline = finishAnchor + remaining; demand(finalDeadline > process.hrtime.bigint()); }
  };
  const closed = new Promise<void>((resolve, reject) => {
    child.once("error", withdraw); control?.on("error", withdraw);
    control?.once("end", () => { ended = true; if (!finalDeadline) withdraw(); });
    control?.on("data", (bytes: Buffer) => { try {
      demand((received += bytes.length) <= 131072); buffered = Buffer.concat([buffered, bytes]);
      for (let end = buffered.indexOf(10); end >= 0; end = buffered.indexOf(10)) { demand(end < 4096); frame(buffered.subarray(0, end)); buffered = buffered.subarray(end + 1); }
      demand(buffered.length < 4096);
    } catch { withdraw(); } });
    child.once("close", (code, killed) => { clearTimeout(timer);
      if (code === 0 && killed === null && !failed && ended && !buffered.length && finalDeadline && !request.signal.aborted) resolve();
      else reject(new NativeReviewCleanupError()); });
  });
  timer = setTimeout(withdraw, 5000); request.signal.addEventListener("abort", withdraw, { once: true });
  try {
    demand(control); write({ v: 1, type: "start", directory: request.directory, base: request.baseCommit, candidate: request.candidateCommit });
    if (request.signal.aborted) withdraw(); await closed;
    demand(finalDeadline && finalDeadline > process.hrtime.bigint()); await checkPins(pins); readRuntimePolicy(policy); request.signal.throwIfAborted();
    const reportBytes = await readRegular(path.join(request.directory, "output/review.json"), 131072);
    const statusBytes = await readRegular(path.join(request.directory, "output/status.json"), 131072);
    const report = reportSchema.parse(json(reportBytes)); const status = statusSchema.parse(json(statusBytes));
    demand(JSON.stringify(report.usage) === JSON.stringify(status.usage) && finalDeadline > process.hrtime.bigint());
    request.signal.throwIfAborted(); readRuntimePolicy(policy);
    const facts: NativeReviewFacts = Object.freeze({ schemaVersion: 1, helperSha256: NATIVE_HELPER_SHA256, model: "gpt-6.1-sol", thinking: "high", priority: "P3",
      terminal: "complete", outcome: "clean", findings: Object.freeze([]), baseCommit: request.baseCommit, candidateCommit: request.candidateCommit,
      authorSession: selected.authorSession, executionSession, configuredPrincipal: selected.reviewerPrincipal, childPid: helperPid!, reportSha256: sha(reportBytes), statusSha256: sha(statusBytes),
      modelFamilyIndependence: "unproved", githubApproval: "not-issued" });
    const handle = Object.freeze({}) as NativeReviewCompletion; completions.set(handle, { facts, request, policy, deadline: finalDeadline, pins, verified: false }); return handle;
  } catch (error) { withdraw(); await closed.catch(() => undefined); throw error; }
  finally { clearTimeout(timer); request.signal.removeEventListener("abort", withdraw); }
}
export async function verifyNativeReviewCompletion(handle: NativeReviewCompletion): Promise<NativeReviewFacts> {
  const owned = completions.get(handle); demand(owned && owned.deadline > process.hrtime.bigint());
  owned.request.signal.throwIfAborted(); readRuntimePolicy(owned.policy); await checkPins(owned.pins);
  demand(sha(await readRegular(path.join(owned.request.directory, "output/review.json"), 131072)) === owned.facts.reportSha256 &&
    sha(await readRegular(path.join(owned.request.directory, "output/status.json"), 131072)) === owned.facts.statusSha256 && owned.deadline > process.hrtime.bigint());
  owned.request.signal.throwIfAborted(); owned.verified = true; return owned.facts;
}
/** Called only after the candidate consumer's actual workspace disposal; disposal cancels its workspace signal. */
export function settleNativeReviewCompletion(handle: NativeReviewCompletion): NativeReviewFacts {
  const owned = completions.get(handle); demand(owned?.verified && owned.deadline > process.hrtime.bigint());
  readRuntimePolicy(owned.policy); completions.delete(handle); return owned.facts;
}
