import { createHash } from "node:crypto";

import type { BootstrapManifest } from "./types.js";

export interface FlowPolicySource {
  ref: string;
  sha256: string;
}

export interface FlowPolicyBundle {
  standard: "public-repository-standard";
  version: string;
  publisher?: Record<string, unknown>;
  compatibility?: Record<string, Record<string, string>>;
  [key: string]: unknown;
}

export interface ResolvedPolicyContract {
  manifest: BootstrapManifest;
  policy: FlowPolicyBundle;
  source: FlowPolicySource;
  unknownManifestSettings: string[];
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function isImmutablePolicyRef(ref: string): boolean {
  return /^refs\/tags\/v\d+\.\d+\.\d+$/.test(ref) || /^[0-9a-f]{40}$/i.test(ref);
}

export function flowPolicyDigest(bundle: unknown): string {
  return createHash("sha256").update(stableJson(bundle)).digest("hex");
}

export function resolveFlowPolicy(
  manifest: BootstrapManifest,
  bundle: unknown,
  source: FlowPolicySource,
  unknownManifestSettings: string[] = []
): ResolvedPolicyContract {
  if (!isImmutablePolicyRef(source.ref)) {
    throw new Error("Flow policy ref must be an exact release tag or immutable 40-character SHA.");
  }
  if (!/^[0-9a-f]{64}$/i.test(source.sha256)) {
    throw new Error("Flow policy digest must be a SHA-256 hex digest.");
  }
  if (flowPolicyDigest(bundle) !== source.sha256.toLowerCase()) {
    throw new Error("Flow policy digest does not match the verified local bundle.");
  }
  if (!bundle || typeof bundle !== "object") {
    throw new Error("Flow policy bundle must be an object.");
  }
  const policy = bundle as FlowPolicyBundle;
  if (policy.standard !== "public-repository-standard" || !/^1\.\d+\.\d+$/.test(policy.version)) {
    throw new Error("Flow policy bundle is not a compatible Public Repository Standard v1 policy.");
  }

  return { manifest, policy, source: { ...source, sha256: source.sha256.toLowerCase() }, unknownManifestSettings: [...unknownManifestSettings].sort() };
}
