import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { normalizeManifest } from "../src/manifest.js";
import type { BootstrapManifest } from "../src/types.js";
import { MANIFEST_PIN_LIMITS, patchManifestPolicyPins } from "../src/upgrade-manifest-pins.js";

const oldRef = "refs/tags/v1.0.1";
const oldDigest = "a".repeat(64);
const nextRef = "b".repeat(40);
const nextDigest = "c".repeat(64);
const failure = "Governed upgrade host operation is unsupported.";

function fixture(ref = oldRef, digest = oldDigest, quote = "", newline = "\n"): string {
  return [
    "# π 🚀 public comments stay byte-identical",
    "version: 2",
    "project:",
    "  name: fixture",
    "  owner: acme",
    "archetype:",
    "  kind: generic-empty",
    `future-setting: { url: '${oldRef}', digest: '${oldDigest}' }`,
    "policy:",
    "  flow:",
    `    ref: ${quote}${ref}${quote} # release tag is distinct from policy version`,
    `    sha256: ${quote}${digest}${quote} # canonical policy digest`,
    "    bundlePath: policies/public.json",
    ""
  ].join(newline);
}

function manifest(raw: string): BootstrapManifest {
  return normalizeManifest(YAML.parse(raw));
}

function target(current: BootstrapManifest, ref = nextRef, digest = nextDigest): BootstrapManifest {
  return { ...current, policy: { flow: { ...current.policy!.flow, ref, sha256: digest } } };
}

describe("project-owned manifest pin edits", () => {
  for (const quote of ["", "'", '"']) {
    for (const newline of ["\n", "\r\n"]) {
      it(`preserves all unrelated UTF-8 bytes, comments and ${JSON.stringify(quote)} tokens with ${JSON.stringify(newline)}`, () => {
        const raw = fixture(oldRef, oldDigest, quote, newline);
        const current = manifest(raw);
        const output = patchManifestPolicyPins(Buffer.from(raw), current, target(current));
        expect(output.equals(Buffer.from(fixture(nextRef, nextDigest, quote, newline)))).toBe(true);
        expect(output.toString()).toContain(`future-setting: { url: '${oldRef}', digest: '${oldDigest}' }`);
        expect(manifest(output.toString())).toEqual(target(current));
      });
    }
  }

  it("preserves a UTF-8 BOM and unrelated bounded aliases", () => {
    const prefix = "\ufeffunrelated: &public { value: original }\nsecond-unrelated: *public\n";
    const raw = prefix + fixture();
    const current = manifest(raw);
    expect(patchManifestPolicyPins(Buffer.from(raw), current, target(current)).toString()).toBe(prefix + fixture(nextRef, nextDigest));
  });

  it("verifies an existing uppercase digest through the actual normalizer", () => {
    const raw = fixture(oldRef, oldDigest.toUpperCase());
    const current = manifest(raw);
    expect(current.policy!.flow.sha256).toBe(oldDigest);
    expect(patchManifestPolicyPins(Buffer.from(raw), current, target(current)).toString()).toBe(fixture(nextRef, nextDigest));
  });

  it("accepts an unchanged selector without changing any raw byte", () => {
    const raw = fixture();
    const current = manifest(raw);
    expect(patchManifestPolicyPins(Buffer.from(raw), current, current).equals(Buffer.from(raw))).toBe(true);
  });

  it("accepts release refs independently of bundle semantic versions", () => {
    const raw = fixture();
    const current = manifest(raw);
    const output = patchManifestPolicyPins(Buffer.from(raw), current, target(current, "refs/tags/v1.0.2"));
    expect(manifest(output.toString()).policy!.flow.ref).toBe("refs/tags/v1.0.2");
    expect(output.toString()).not.toContain("policyVersion:");
  });

  for (const quote of ["'", '"']) {
    it(`preserves ${quote} while representing a numeric-looking digest as a string`, () => {
      const raw = fixture(oldRef, oldDigest, quote);
      const current = manifest(raw);
      const digest = "1".repeat(64);
      expect(manifest(patchManifestPolicyPins(Buffer.from(raw), current, target(current, nextRef, digest)).toString()).policy!.flow.sha256).toBe(digest);
    });
  }

  it("denies a plain token which cannot preserve its required string type", () => {
    const raw = fixture();
    const current = manifest(raw);
    expect(() => patchManifestPolicyPins(Buffer.from(raw), current, target(current, nextRef, "1".repeat(64)))).toThrow(failure);
  });

  const unsupported: Array<[string, (raw: string) => string]> = [
    ["flow-style policy", (raw) => raw.slice(0, raw.indexOf("policy:\n")) + `policy: { flow: { ref: ${oldRef}, sha256: ${oldDigest}, bundlePath: policies/public.json } }\n`],
    ["flow-style flow", (raw) => raw.slice(0, raw.indexOf("policy:\n")) + `policy:\n  flow: { ref: ${oldRef}, sha256: ${oldDigest}, bundlePath: policies/public.json }\n`],
    ["anchored policy", (raw) => raw.replace("policy:\n", "policy: &policy\n")],
    ["anchored flow", (raw) => raw.replace("  flow:\n", "  flow: &flow\n")],
    ["anchored ref", (raw) => raw.replace(`ref: ${oldRef}`, `ref: &ref ${oldRef}`)],
    ["tagged ref", (raw) => raw.replace(`ref: ${oldRef}`, `ref: !!str ${oldRef}`)],
    ["tagged policy", (raw) => raw.replace("policy:\n", "policy: !!map\n")],
    ["explicit policy key", (raw) => raw.replace("policy:\n", "? policy\n:\n")],
    ["explicit ref key", (raw) => raw.replace(`    ref: ${oldRef}`, `    ? ref\n    : ${oldRef}`)],
    ["escaped ref token", (raw) => raw.replace(`ref: ${oldRef}`, 'ref: "refs/tags/v1.0.\\u0031"')],
    ["folded ref token", (raw) => raw.replace(`ref: ${oldRef} # release tag is distinct from policy version`, `ref: >-\n      ${oldRef}`)],
    ["merge key", (raw) => raw.replace("  flow:\n", "  flow:\n    <<: { future: untouched }\n")],
    ["YAML 1.1 merge key", (raw) => "%YAML 1.1\n---\n" + raw.replace("  flow:\n", "  flow:\n    <<: { future: untouched }\n")],
    ["flow alias", (raw) => raw.slice(0, raw.indexOf("policy:\n")) + `pins: &pins { ref: ${oldRef}, sha256: ${oldDigest}, bundlePath: policies/public.json }\npolicy:\n  flow: *pins\n`]
  ];
  for (const [name, change] of unsupported) {
    it(`denies ${name} without falling back to a normalized rewrite`, () => {
      const raw = change(fixture());
      const current = manifest(raw);
      expect(() => patchManifestPolicyPins(Buffer.from(raw), current, target(current))).toThrow(failure);
    });
  }

  for (const [name, raw] of [
    ["duplicate selected key", fixture().replace(`    ref: ${oldRef}`, `    ref: ${oldRef}\n    ref: ${oldRef}`)],
    ["duplicate root key", fixture() + "policy: {}\n"],
    ["multiple documents", fixture() + "---\nother: document\n"],
    ["malformed YAML", fixture() + "broken: [\n"],
    ["empty input", ""]
  ]) {
    it(`denies ${name}`, () => {
      const current = manifest(fixture());
      expect(() => patchManifestPolicyPins(Buffer.from(raw!), current, target(current))).toThrow(failure);
    });
  }

  it("rejects malformed UTF-8 and input over the fixed byte limit", () => {
    const current = manifest(fixture());
    for (const raw of [Buffer.from([0xc0, 0xaf]), Buffer.alloc(MANIFEST_PIN_LIMITS.bytes + 1, 0x20)]) {
      expect(() => patchManifestPolicyPins(raw, current, target(current))).toThrow(failure);
    }
  });

  it("rejects excessive AST depth and node count before semantic conversion", () => {
    const sources = [fixture() + `deep: ${"[".repeat(34)}0${"]".repeat(34)}\n`, fixture() + `many: [${Array(10_001).fill("0").join(",")}]\n`];
    for (const raw of sources) {
      const current = manifest(raw);
      expect(() => patchManifestPolicyPins(Buffer.from(raw), current, target(current))).toThrow(failure);
    }
  });

  it("rejects alias expansion rather than expanding an unbounded public field", () => {
    const raw = fixture() + "a: &a [x, x, x]\nb: &b [*a, *a, *a]\nc: &c [*b, *b, *b]\nd: [*c, *c, *c]\n";
    const current = manifest(raw);
    expect(() => patchManifestPolicyPins(Buffer.from(raw), current, target(current))).toThrow(failure);
  });

  it("rejects stale current bindings and any target change outside the two pins", () => {
    const raw = fixture();
    const current = manifest(raw);
    const changedProject = { ...target(current), project: { ...current.project, name: "different" } };
    const changedPath = target(current);
    changedPath.policy!.flow.bundlePath = "other.json";
    const stale = { ...current, project: { ...current.project, name: "stale" } };
    for (const [before, after] of [[current, changedProject], [current, changedPath], [stale, target(current)]]) {
      expect(() => patchManifestPolicyPins(Buffer.from(raw), before!, after!)).toThrow(failure);
    }
  });

  it("rejects mutable refs, noncanonical digests and absent policy input", () => {
    const raw = fixture();
    const current = manifest(raw);
    for (const after of [target(current, "main"), target(current, nextRef, "BAD"), { ...current, policy: undefined } as unknown as BootstrapManifest]) {
      expect(() => patchManifestPolicyPins(Buffer.from(raw), current, after)).toThrow(failure);
    }
  });
});
