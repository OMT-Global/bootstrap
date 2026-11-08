import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";

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
  license: BootstrapManifest["license"];
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

export function isImmutablePolicyRef(ref: string): boolean {
  return /^refs\/tags\/v\d+\.\d+\.\d+$/.test(ref) || /^[0-9a-f]{40}$/i.test(ref);
}

export function requireImmutableProductionWorkflowRef(ref: string, surface = "Production workflow"): void {
  if (!isImmutablePolicyRef(ref)) {
    throw new Error(`${surface} ref must be an exact vX.Y.Z tag or immutable 40-character SHA; ${JSON.stringify(ref)} is mutable.`);
  }
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

  return { manifest, license: manifest.license, policy, source: { ...source, sha256: source.sha256.toLowerCase() }, unknownManifestSettings: [...unknownManifestSettings].sort() };
}

export const MAX_FLOW_POLICY_BYTES = 1_048_576;

async function readRepositoryPolicyBundle(repositoryRoot: string, bundlePath: string): Promise<unknown> {
  try {
    if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0 ||
        typeof constants.O_NONBLOCK !== "number" || constants.O_NONBLOCK === 0) throw new Error();
    const root = await realpath(repositoryRoot);
    const parent = await realpath(path.dirname(bundlePath));
    const relativeParent = path.relative(root, parent);
    if (relativeParent === ".." || relativeParent.startsWith(`..${path.sep}`) || path.isAbsolute(relativeParent)) throw new Error();
    // The repository root is trusted; concurrent replacement of path components is outside this boundary.
    const handle = await open(bundlePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1) throw new Error();
      const bytes = Buffer.alloc(MAX_FLOW_POLICY_BYTES + 1);
      let used = 0;
      while (used < bytes.length) {
        const { bytesRead } = await handle.read(bytes, used, bytes.length - used, null);
        if (bytesRead === 0) break;
        used += bytesRead;
      }
      if (used > MAX_FLOW_POLICY_BYTES) throw new Error();
      return YAML.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, used)));
    } finally {
      await handle.close();
    }
  } catch {
    throw new Error("Flow policy bundle must be a bounded regular, singly linked UTF-8 file within the repository root.");
  }
}

export async function loadResolvedFlowPolicy(manifest: BootstrapManifest, manifestDir: string): Promise<ResolvedPolicyContract> {
  if (!manifest.policy?.flow) {
    throw new Error("Manifest does not declare a Flow policy bundle.");
  }
  const source = manifest.policy.flow;
  if (path.isAbsolute(source.bundlePath)) {
    throw new Error("Flow policy bundle path must be relative to the manifest directory.");
  }
  const bundlePath = path.resolve(manifestDir, source.bundlePath);
  const relativePath = path.relative(manifestDir, bundlePath);
  if (relativePath === ".." || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) {
    throw new Error("Flow policy bundle path must stay within the manifest directory.");
  }
  const bundle = await readRepositoryPolicyBundle(manifestDir, bundlePath);
  return resolveFlowPolicy(manifest, bundle, source, manifest.unknownSettings);
}
