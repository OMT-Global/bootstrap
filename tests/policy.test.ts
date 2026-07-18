import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { normalizeManifest } from "../src/manifest.js";
import { flowPolicyDigest, loadResolvedFlowPolicy, requireImmutableProductionWorkflowRef, resolveFlowPolicy } from "../src/policy.js";

const bundle = { standard: "public-repository-standard" as const, version: "1.0.0", publisher: { identitySource: "publisherKey" } };
const manifest = normalizeManifest({ project: { name: "example", owner: "acme" }, archetype: { kind: "generic-empty" } });

describe("resolveFlowPolicy", () => {
  it("resolves a verified local bundle from an exact tag without changing the manifest", () => {
    const resolved = resolveFlowPolicy(manifest, bundle, { ref: "refs/tags/v1.0.0", sha256: flowPolicyDigest(bundle) }, ["future.setting"]);
    expect(resolved.manifest).toBe(manifest);
    expect(resolved.policy.version).toBe("1.0.0");
    expect(resolved.unknownManifestSettings).toEqual(["future.setting"]);
    expect(resolved.license).toBeUndefined();
  });

  it("exposes the explicit license policy in the resolved contract", () => {
    const licensed = normalizeManifest({
      project: { name: "example", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "legal/proprietary.txt", sha256: "a".repeat(64), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });
    const resolved = resolveFlowPolicy(licensed, bundle, { ref: "refs/tags/v1.0.0", sha256: flowPolicyDigest(bundle) });
    expect(resolved.license).toMatchObject({ mode: "proprietary", template: { approval: "counsel:P-1" } });
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

describe("requireImmutableProductionWorkflowRef", () => {
  it("rejects branch and floating tag references while accepting exact tags and SHAs", () => {
    expect(() => requireImmutableProductionWorkflowRef("refs/heads/main", "Release workflow")).toThrow("mutable");
    expect(() => requireImmutableProductionWorkflowRef("refs/tags/v1", "Release workflow")).toThrow("mutable");
    expect(() => requireImmutableProductionWorkflowRef("refs/tags/v1.2.3", "Release workflow")).not.toThrow();
    expect(() => requireImmutableProductionWorkflowRef("a".repeat(40), "Release workflow")).not.toThrow();
  });
});
