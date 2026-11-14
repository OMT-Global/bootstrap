import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";

import { normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { flowPolicyDigest, loadResolvedFlowPolicy, requireImmutableProductionWorkflowRef, resolveFlowPolicy } from "../src/policy.js";

const bundle = { standard: "public-repository-standard" as const, version: "1.0.0", publisher: { identitySource: "publisherKey" } };
const manifest = normalizeManifest({ project: { name: "example", owner: "acme" }, archetype: { kind: "generic-empty" } });

describe("resolveFlowPolicy", () => {
  it("offers an explicit locale-independent digest without changing legacy pins", () => {
    const program = `import {flowPolicyDigest,resolveFlowPolicy} from './src/policy.ts';
import {normalizeManifest} from './src/manifest.ts';
const bundle={standard:'public-repository-standard',version:'1.0.0','Å':1,Z:2};
const manifest=normalizeManifest({project:{name:'example',owner:'acme'},archetype:{kind:'generic-empty'}});
const legacy=flowPolicyDigest(bundle), stable=flowPolicyDigest(bundle,'sorted-utf16-v1');
resolveFlowPolicy(manifest,bundle,{ref:'refs/tags/v1.0.0',sha256:legacy});
resolveFlowPolicy(manifest,bundle,{ref:'refs/tags/v1.0.0',sha256:stable,canonicalization:'sorted-utf16-v1'});
process.stdout.write(JSON.stringify({legacy,stable}));`;
    const observe = (locale: string) => JSON.parse(execFileSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", program], {
      cwd: process.cwd(), encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: locale, LC_ALL: locale }, timeout: 10000
    })) as { legacy: string; stable: string };
    const en = observe("en_US.UTF-8"), sv = observe("sv_SE.UTF-8");
    const expected = createHash("sha256").update('{"Z":2,"standard":"public-repository-standard","version":"1.0.0","Å":1}').digest("hex");
    expect(en.legacy).not.toBe(sv.legacy);
    expect(en.stable).toBe(expected); expect(sv.stable).toBe(expected);
  });

  it("keeps the released Flow policy digest under both algorithms", () => {
    const released = JSON.parse(readFileSync("policy/flow-public-standard.json", "utf8"));
    const digest = "52877f4225a192c6ac2250a7f289f479be83a923ce15152c517db77ab0d5249d";
    expect(flowPolicyDigest(released)).toBe(digest);
    expect(flowPolicyDigest(released, "sorted-utf16-v1")).toBe(digest);
  });

  it("preserves an explicit canonicalization in the manifest and rejects unsupported values", () => {
    const config = { project: { name: "example", owner: "acme" }, archetype: { kind: "generic-empty" },
      policy: { flow: { ref: "refs/tags/v1.0.0", sha256: "a".repeat(64), bundlePath: "policy.json", canonicalization: "sorted-utf16-v1" } } };
    const parsed = normalizeManifest(config as never);
    expect(parsed.policy?.flow.canonicalization).toBe("sorted-utf16-v1");
    expect(YAML.parse(stringifyManifest(parsed)).policy.flow.canonicalization).toBe("sorted-utf16-v1");
    const { canonicalization: _removed, ...legacy } = config.policy.flow;
    expect(YAML.parse(stringifyManifest(normalizeManifest({ ...config, policy: { flow: legacy } } as never))).policy.flow).not.toHaveProperty("canonicalization");
    expect(() => normalizeManifest({ ...config, policy: { flow: { ...config.policy.flow, canonicalization: "future-version" } } } as never)).toThrow();
  });

  it("does not silently accept a pin from the other canonicalization", () => {
    const policy = { standard: "public-repository-standard", version: "1.0.0", "Å": 1, Z: 2 };
    const legacy = "e88a1aa09c5649429049493ddecb919813f821d1649b8a2b6bde4adb19d8073a";
    const stable = flowPolicyDigest(policy, "sorted-utf16-v1");
    expect(legacy).not.toBe(stable);
    expect(() => resolveFlowPolicy(manifest, policy, { ref: "refs/tags/v1.0.0", sha256: legacy, canonicalization: "sorted-utf16-v1" })).toThrow("digest does not match");
  });
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
