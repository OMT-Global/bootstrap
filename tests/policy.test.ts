import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { normalizeManifest } from "../src/manifest.js";
import { flowPolicyDigest, loadResolvedFlowPolicy, resolveFlowPolicy } from "../src/policy.js";

const bundle = { standard: "public-repository-standard" as const, version: "1.0.0", publisher: { identitySource: "publisherKey" } };
const manifest = normalizeManifest({ project: { name: "example", owner: "acme" }, archetype: { kind: "generic-empty" } });

describe("resolveFlowPolicy", () => {
  it("resolves a verified local bundle from an exact tag without changing the manifest", () => {
    const resolved = resolveFlowPolicy(manifest, bundle, { ref: "refs/tags/v1.0.0", sha256: flowPolicyDigest(bundle) }, ["future.setting"]);
    expect(resolved.manifest).toBe(manifest);
    expect(resolved.policy.version).toBe("1.0.0");
    expect(resolved.unknownManifestSettings).toEqual(["future.setting"]);
  });

  it("loads a verified manifest-declared bundle without network access", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-policy-"));
    await writeFile(path.join(directory, "flow-policy.yaml"), JSON.stringify(bundle));
    const configured = normalizeManifest({ project: { name: "example", owner: "acme" }, archetype: { kind: "generic-empty" }, policy: { flow: { ref: "refs/tags/v1.0.0", sha256: flowPolicyDigest(bundle), bundlePath: "flow-policy.yaml" } }, futurePolicySetting: true } as never);
    await expect(loadResolvedFlowPolicy(configured, directory)).resolves.toMatchObject({ policy: { version: "1.0.0" }, unknownManifestSettings: ["futurePolicySetting"] });
  });

  it("rejects absolute and traversal bundle paths before reading", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-policy-"));
    for (const bundlePath of [path.join(directory, "flow-policy.yaml"), "../flow-policy.yaml"]) {
      const configured = normalizeManifest({ project: { name: "example", owner: "acme" }, archetype: { kind: "generic-empty" }, policy: { flow: { ref: "refs/tags/v1.0.0", sha256: flowPolicyDigest(bundle), bundlePath } } } as never);
      await expect(loadResolvedFlowPolicy(configured, directory)).rejects.toThrow("manifest directory");
    }
  });

  it("fails closed for floating refs, mismatched digests, and incompatible bundles", () => {
    expect(() => resolveFlowPolicy(manifest, bundle, { ref: "refs/heads/main", sha256: flowPolicyDigest(bundle) })).toThrow("exact release tag");
    expect(() => resolveFlowPolicy(manifest, bundle, { ref: "refs/tags/v1.0.0", sha256: "0".repeat(64) })).toThrow("digest does not match");
    expect(() => resolveFlowPolicy(manifest, { standard: "other", version: "1.0.0" }, { ref: "0123456789012345678901234567890123456789", sha256: flowPolicyDigest({ standard: "other", version: "1.0.0" }) })).toThrow("compatible");
  });
});
