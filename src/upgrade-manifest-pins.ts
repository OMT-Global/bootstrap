import { isDeepStrictEqual } from "node:util";
import YAML, { isAlias, isMap, isScalar, isSeq } from "yaml";

import { normalizeManifest } from "./manifest.js";
import { isImmutablePolicyRef } from "./policy.js";
import type { BootstrapManifest } from "./types.js";
import { demand, hostFailure } from "./upgrade-host.js";

export const MANIFEST_PIN_LIMITS = Object.freeze({ bytes: 1_048_576, nodes: 10_000, depth: 32 });
interface Span { start: number; end: number; replacement: Buffer }

function document(source: string) {
  const docs = YAML.parseAllDocuments(source, {
    strict: true, uniqueKeys: true, stringKeys: true, keepSourceTokens: true, logLevel: "silent"
  });
  demand(docs.length === 1);
  const doc = docs[0]!;
  demand(doc.errors.length === 0);
  const pending: Array<[unknown, number]> = [[doc.contents, 0]];
  let count = 0;
  while (pending.length) {
    const [node, depth] = pending.pop()!;
    demand(++count <= MANIFEST_PIN_LIMITS.nodes && depth <= MANIFEST_PIN_LIMITS.depth);
    if (isMap(node)) {
      demand(count + pending.length + 2 * node.items.length <= MANIFEST_PIN_LIMITS.nodes);
      for (const pair of node.items) pending.push([pair.key, depth + 1], [pair.value, depth + 1]);
    } else if (isSeq(node)) {
      demand(count + pending.length + node.items.length <= MANIFEST_PIN_LIMITS.nodes);
      for (const item of node.items) pending.push([item, depth + 1]);
    } else demand(node === null || isScalar(node) || isAlias(node));
    demand(pending.length <= MANIFEST_PIN_LIMITS.nodes);
  }
  return doc;
}
function materialize(doc: ReturnType<typeof document>): Parameters<typeof normalizeManifest>[0] {
  // normalizeManifest performs the actual schema validation on this parser output.
  return doc.toJS({ maxAliasCount: 16 });
}

function scalar(node: unknown, source: string, expected: string): { start: number; end: number; quote: string } {
  demand(isScalar(node) && typeof node.value === "string" && node.value === expected &&
    !node.anchor && !node.tag && node.range && node.srcToken);
  const [start, end] = node.range;
  demand(Number.isSafeInteger(start) && Number.isSafeInteger(end) && start >= 0 && end > start && end <= source.length);
  const token = source.slice(start, end);
  const quote = node.type === "QUOTE_SINGLE" ? "'" : node.type === "QUOTE_DOUBLE" ? '"' : "";
  demand((node.type === "PLAIN" || quote !== "") && /^[\x20-\x7e]+$/.test(token) &&
    token === quote + expected + quote && "source" in node.srcToken &&
    node.srcToken.source === token && !token.includes("\\"));
  demand(!quote || !expected.includes(quote));
  return { start, end, quote };
}

function selected(node: unknown, key: string, source: string): unknown {
  demand(isMap(node) && !node.flow && !node.anchor && !node.tag && node.srcToken?.type === "block-map");
  demand(!node.items.some((pair) => isScalar(pair.key) && (pair.key.value === "<<" || pair.key.source === "<<")));
  const matches = node.items.filter((pair) => isScalar(pair.key) && pair.key.value === key);
  demand(matches.length === 1);
  const pair = matches[0]!;
  demand(pair.srcToken && !pair.srcToken.start.some((token) => token.type === "explicit-key-ind"));
  scalar(pair.key, source, key);
  return pair.value;
}

/** Only the two existing project-owned input tokens change; ownership is checked by the caller. */
export function patchManifestPolicyPins(
  raw: Uint8Array, current: BootstrapManifest, target: BootstrapManifest
): Buffer {
  try {
    demand(raw instanceof Uint8Array && raw.byteLength > 0 && raw.byteLength <= MANIFEST_PIN_LIMITS.bytes);
    const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
    demand(Buffer.from(source).equals(Buffer.from(raw)));
    const before = current.policy?.flow;
    const after = target.policy?.flow;
    demand(before && after && before.bundlePath === after.bundlePath &&
      isImmutablePolicyRef(before.ref) && isImmutablePolicyRef(after.ref) &&
      /^[a-f0-9]{64}$/.test(before.sha256) && /^[a-f0-9]{64}$/.test(after.sha256));
    const expected = { ...current, policy: { flow: { ...before, ref: after.ref, sha256: after.sha256 } } };
    demand(isDeepStrictEqual(target, expected));
    const parsed = document(source);
    demand(isDeepStrictEqual(normalizeManifest(materialize(parsed)), current));
    const flow = selected(selected(parsed.contents, "policy", source), "flow", source);
    const spans: Span[] = (["ref", "sha256"] as const).map((key) => {
      const node = selected(flow, key, source);
      demand(isScalar(node) && typeof node.value === "string" &&
        (key === "sha256" ? node.value.toLowerCase() : node.value) === before[key]);
      const token = scalar(node, source, node.value);
      return {
        start: Buffer.byteLength(source.slice(0, token.start)),
        end: Buffer.byteLength(source.slice(0, token.end)),
        replacement: Buffer.from(token.quote + after[key] + token.quote)
      };
    }).sort((left, right) => left.start - right.start);
    demand(spans[0]!.end <= spans[1]!.start);
    const outputBytes = raw.byteLength + spans.reduce((sum, span) => sum + span.replacement.length - (span.end - span.start), 0);
    demand(outputBytes <= MANIFEST_PIN_LIMITS.bytes);
    const bytes = Buffer.from(raw);
    const result = Buffer.concat([
      bytes.subarray(0, spans[0]!.start), spans[0]!.replacement,
      bytes.subarray(spans[0]!.end, spans[1]!.start), spans[1]!.replacement,
      bytes.subarray(spans[1]!.end)
    ], outputBytes);
    const checked = document(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(result));
    demand(isDeepStrictEqual(normalizeManifest(materialize(checked)), target));
    return result;
  } catch { throw hostFailure(); }
}
