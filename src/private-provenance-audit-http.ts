import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";
import { TLSSocket } from "node:tls";
import {
  createPrivateReadAuditIngress, persistPrivateRoleAuditEvent, PrivateIdentityError,
  signPrivateRoleAuditAck, type PrivateRoleIdentity
} from "./private-provenance-identity.js";
import { controlWire } from "./private-provenance-control.js";

const MAX_BODY = 65_536;
const MAX_PROOF = 4_096;
const MAX_REQUESTS = 16;
const REQUEST_TIMEOUT_MS = 30_000;
const DENIED = controlWire({ error: "Private audit request unavailable or invalid." });

function requireRequest(value: unknown): asserts value {
  if (!value) throw new PrivateIdentityError();
}

function header(request: IncomingMessage, name: string): string | undefined {
  const values = request.headersDistinct[name];
  requireRequest(values === undefined || values.length === 1);
  return values?.[0];
}

function fixedLength(request: IncomingMessage): number {
  const value = header(request, "content-length");
  requireRequest(value !== undefined && /^(?:0|[1-9][0-9]{0,4})$/.test(value));
  const length = Number(value);
  requireRequest(length <= MAX_BODY);
  return length;
}

async function exactBody(request: IncomingMessage, length: number, signal: AbortSignal): Promise<Buffer> {
  const body = Buffer.alloc(length);
  let offset = 0;
  for await (const chunk of request) {
    requireRequest(!signal.aborted && Buffer.isBuffer(chunk) && chunk.byteLength > 0 && offset + chunk.byteLength <= length);
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  requireRequest(!signal.aborted && request.complete && !request.rawTrailers.length && offset === length);
  return body;
}

function credentials(request: IncomingMessage) {
  const bearer = header(request, "authorization");
  const proofValue = header(request, "x-bootstrap-workload-proof");
  requireRequest(bearer && bearer.length <= 16_391 && /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(bearer)
    && proofValue && proofValue.length <= Math.ceil(MAX_PROOF / 3) * 4);
  const proof = Buffer.from(proofValue, "base64");
  requireRequest(proof.byteLength > 0 && proof.byteLength <= MAX_PROOF && proof.toString("base64") === proofValue);
  return { token: bearer.slice("Bearer ".length), proof };
}

function send(response: ServerResponse, status: number, body: Buffer, close: boolean) {
  response.writeHead(status, {
    "content-type": "application/json", "content-length": body.byteLength,
    "cache-control": "no-store", "x-content-type-options": "nosniff",
    ...(close ? { connection: "close" } : {})
  });
  response.end(body);
}

/** Use as the direct Node HTTPS listener of the enrolled audit worker. */
export function createPrivateReadAuditRequestListener(identity: PrivateRoleIdentity): RequestListener {
  const ingress = createPrivateReadAuditIngress(identity);
  const host = new URL(ingress.origin).host;
  const challenged = new WeakSet<TLSSocket>();
  const retired = new WeakSet<TLSSocket>();
  const active = new WeakSet<TLSSocket>();
  let count = 0;

  function deny(response: ServerResponse) {
    if (response.destroyed || response.writableEnded) return;
    if (response.headersSent) { response.destroy(); return; }
    try { send(response, 400, DENIED, true); }
    catch { response.destroy(); }
  }

  async function serve(request: IncomingMessage, response: ServerResponse) {
    const socket = request.socket;
    if (!(socket instanceof TLSSocket) || !socket.encrypted || socket.destroyed) {
      deny(response); return;
    }
    // A pipelined request cannot share the active challenge or receive a second acknowledgment.
    if (active.has(socket)) { retired.add(socket); socket.destroy(); return; }
    if (retired.has(socket)) { deny(response); return; }
    if (count >= MAX_REQUESTS) { retired.add(socket); deny(response); return; }
    active.add(socket);
    count++;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const incomingClose = () => { if (!request.complete) abort(); };
    const outgoingClose = () => { if (!response.writableFinished) abort(); };
    request.once("close", incomingClose);
    request.once("error", abort);
    response.once("close", outgoingClose);
    response.once("error", abort);
    socket.once("close", abort);
    const timer = setTimeout(() => {
      abort(); retired.add(socket); socket.destroy();
    }, REQUEST_TIMEOUT_MS);
    try {
      requireRequest(request.httpVersion === "1.1" && request.method === "POST" && header(request, "host") === host);
      for (const forbidden of ["transfer-encoding", "content-encoding", "trailer", "expect", "upgrade"]) {
        requireRequest(header(request, forbidden) === undefined);
      }
      const length = fixedLength(request);
      if (request.url === "/challenge") {
        requireRequest(length === 0 && !challenged.has(socket) && header(request, "authorization") === undefined
          && header(request, "x-bootstrap-workload-proof") === undefined);
        await exactBody(request, length, controller.signal);
        requireRequest(!socket.destroyed && !response.destroyed && !response.writableEnded);
        const challenge = ingress.challenge(socket);
        challenged.add(socket);
        send(response, 200, controlWire(challenge), false);
        return;
      }
      requireRequest(request.url === "/audit" && challenged.has(socket) && length > 0
        && header(request, "content-type") === "application/json");
      retired.add(socket);
      const { token, proof } = credentials(request);
      const body = await exactBody(request, length, controller.signal);
      const admitted = await ingress.admit(socket, token, proof, body, controller.signal);
      requireRequest(!controller.signal.aborted);
      const evidence = await persistPrivateRoleAuditEvent(identity, admitted, controller.signal);
      const acknowledgment = await signPrivateRoleAuditAck(identity, evidence, controller.signal);
      requireRequest(!controller.signal.aborted && !socket.destroyed && !response.destroyed && !response.writableEnded);
      send(response, 200, acknowledgment, true);
    } catch {
      retired.add(socket);
      if (!controller.signal.aborted) deny(response);
    } finally {
      clearTimeout(timer);
      request.removeListener("close", incomingClose);
      request.removeListener("error", abort);
      response.removeListener("close", outgoingClose);
      response.removeListener("error", abort);
      socket.removeListener("close", abort);
      active.delete(socket);
      count--;
    }
  }
  return (request, response) => { void serve(request, response); };
}
