import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { sha256 } from "../src/lib/hash.js";
import { loadManifest, normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { applyRepo, planRepo } from "../src/render.js";

const authoritativeReviewRule = "- Before opening or updating a PR, use the `autoreview` skill to review the intended PR diff against its actual base. Verify every finding, fix accepted in-scope findings, and rerun affected tests and autoreview after changes. Proceed only when no accepted/actionable findings remain, and record the final command and result in the PR validation evidence. If the skill is unavailable or cannot complete, stop and report the blocker instead of bypassing the gate.";

const privateReviewConsentRule = "- For private repositories, before transmitting a concrete prepared diff to an external autoreviewer, verify required network access and explicit authorization for that diff scope and reviewer provider. Request only missing access or authorization; reuse grants already supplied in the current session.";

describe("Bootstrap ownership migration", () => {
  it("preserves the owner's authoritative autoreview rule verbatim in managed AGENTS", () => {
    const manifest = normalizeManifest({
      project: { name: "instruction-preservation", owner: "acme" },
      archetype: { kind: "generic-empty" }
    });
    const instructions = renderManagedFiles(manifest).find((file) => file.path === "AGENTS.md")!;
    expect(readFileSync("AGENTS.md", "utf8").split("\n")).toContain(authoritativeReviewRule);
    expect(instructions.contents.split("\n")).toContain(authoritativeReviewRule);
    expect(instructions.contents).not.toContain("before implementation:");
  });

  it.each([
    { label: "explicit private visibility", visibility: "private" as const },
    { label: "default private visibility", visibility: undefined }
  ])("requires concrete provider/scope consent before private transmission for $label", ({ visibility }) => {
    const manifest = normalizeManifest({
      project: { name: "private-review-consent", owner: "acme", visibility },
      archetype: { kind: "generic-empty" }
    });
    const instructions = renderManagedFiles(manifest).find((file) => file.path === "AGENTS.md")!.contents;
    expect(instructions.split("\n")).toContain(authoritativeReviewRule);
    expect(instructions.split("\n")).toContain(privateReviewConsentRule);
    expect(instructions).not.toContain("before implementation");
    expect(instructions.indexOf(authoritativeReviewRule)).toBeLessThan(instructions.indexOf(privateReviewConsentRule));
  });

  it("keeps the complete public AGENTS bytes unchanged and omits the private transmission clause", () => {
    const manifest = normalizeManifest({
      project: { name: "public-review-consent", owner: "acme", visibility: "public" },
      archetype: { kind: "generic-empty" },
      ci: { codeqlLanguages: ["javascript-typescript"] }
    });
    const instructions = renderManagedFiles(manifest).find((file) => file.path === "AGENTS.md")!.contents;
    expect(instructions).toBe(readFileSync("AGENTS.md", "utf8"));
    expect(instructions).not.toContain(privateReviewConsentRule);
  });

  it("checks the installed Bootstrap ownership boundary and unchanged current plan", async () => {
    const manifest = await loadManifest(path.resolve("project.bootstrap.yaml"));
    expect(manifest.repo.managedPaths).toHaveLength(47);
    expect(manifest.ci.githubHostedImage).toBe("ubuntu-24.04");
    expect(manifest.release.postpublishRequiresPreflight).toBeUndefined();
    expect(manifest.release.reusableWorkflowRef).toBe("913b298fab0fb008796011d940ee7362a347659d");
    const plan = await planRepo(manifest, process.cwd());
    expect(plan.changes).toHaveLength(50);
    expect(plan.changes.every((change) => change.type === "unchanged")).toBe(true);
    expect(new Set(plan.files.map((file) => file.path))).toEqual(new Set([
      ...manifest.repo.managedPaths, "LICENSE", "THIRD_PARTY_NOTICES.md", ".bootstrap/managed-files.json"
    ]));
    const sidecar = JSON.parse(await readFile(".bootstrap/managed-files.json", "utf8"));
    expect(Object.keys(sidecar.managedFiles)).toHaveLength(49);
    for (const [file, record] of Object.entries(sidecar.managedFiles) as Array<[string, { sha256: string }]>) {
      expect(sha256(await readFile(file, "utf8"))).toBe(record.sha256);
    }
    for (const file of ["README.md", "scripts/release/prep.sh", "scripts/release/build.sh", "scripts/release/postpublish.sh"]) {
      expect(sidecar.managedFiles).not.toHaveProperty(file);
      expect(manifest.repo.managedPaths).not.toContain(file);
    }
    expect(sha256(await readFile("LICENSE", "utf8"))).toBe("e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052");
  });
});


describe("retained repository class migration", () => {
  const identity = { project: { name: "migration-record", owner: "acme" }, archetype: { kind: "generic-empty" as const } };

  it.each([
    { legacy: "application", target: "service" },
    { legacy: "tooling", target: "cli" },
    { legacy: "tooling", target: "infrastructure" }
  ] as const)("retains $legacy to $target through repeated manifest roundtrips", ({ legacy, target }) => {
    const original = normalizeManifest({ ...identity, repo: { class: legacy, classMigration: { target } } });
    const serialized = stringifyManifest(original);
    const second = normalizeManifest(YAML.parse(serialized));
    const third = normalizeManifest(YAML.parse(stringifyManifest(second)));
    expect(second.repo).toEqual(original.repo);
    expect(third.repo).toEqual(original.repo);
    expect(second.repo.classMigration).toEqual({ from: legacy, target });
    expect(stringifyManifest(second)).toBe(serialized);
    expect(stringifyManifest(third)).toBe(serialized);
  });

  it("reaches a fixed point after one genuine fresh apply and reload", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-class-roundtrip-"));
    try {
      const manifest = normalizeManifest({ ...identity, repo: { class: "tooling", classMigration: { target: "cli" }, managedPaths: ["project.bootstrap.yaml"] } });
      await applyRepo(manifest, directory);
      const reloaded = await loadManifest(path.join(directory, "project.bootstrap.yaml"));
      const first = await planRepo(reloaded, directory);
      const second = await planRepo(await loadManifest(path.join(directory, "project.bootstrap.yaml")), directory);
      expect(reloaded.repo.classMigration).toEqual({ from: "tooling", target: "cli" });
      expect(first.changes).toHaveLength(2);
      expect(first.changes.every((change) => change.type === "unchanged")).toBe(true);
      expect(second).toEqual(first);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it.each([
    { label: "canonical record missing legacy source", repo: { class: "cli", classMigration: { target: "cli" } } },
    { label: "canonical target contradiction", repo: { class: "cli", classMigration: { from: "tooling", target: "infrastructure" } } },
    { label: "legacy source contradiction", repo: { class: "tooling", classMigration: { from: "application", target: "cli" } } },
    { label: "record without explicit class", repo: { classMigration: { from: "tooling", target: "cli" } } },
    { label: "nonlegacy source", repo: { class: "cli", classMigration: { from: "service", target: "cli" } } }
  ])("rejects $label", ({ repo }) => {
    expect(() => normalizeManifest({ ...identity, repo } as never)).toThrow();
  });

  it("preserves explicit matching legacy evidence without inventing canonical history", () => {
    const migrated = normalizeManifest({ ...identity, repo: { class: "tooling", classMigration: { from: "tooling", target: "cli" } } });
    expect(migrated.repo.classMigration).toEqual({ from: "tooling", target: "cli" });
    const canonical = normalizeManifest({ ...identity, repo: { class: "cli" } });
    expect(canonical.repo).not.toHaveProperty("classMigration");
  });
});


describe("TAB-bearing manifest scalars", () => {
  it("escapes only TAB-bearing data without changing any parsed manifest or notice value", async () => {
    const raw = await readFile("project.bootstrap.yaml", "utf8");
    const manifest = await loadManifest(path.resolve("project.bootstrap.yaml"));
    const serialized = stringifyManifest(manifest);
    expect(serialized).not.toMatch(/^ +\t/m);
    expect(serialized).toContain("\\t");
    expect(YAML.parse(serialized)).toEqual(YAML.parse(raw));
    expect(normalizeManifest(YAML.parse(serialized))).toEqual(manifest);
    const ordinaryScript = YAML.parseDocument(serialized).getIn(["ci", "customScripts", "fast"], true);
    expect(YAML.isScalar(ordinaryScript) && ordinaryScript.type?.startsWith("BLOCK_")).toBe(true);
  });

  it.each([
    { kind: "nextjs-web", digest: "2857973bd621ff79c796c7ab2f196a1953ae30c5e51473d1d6414bf591fcce25" },
    { kind: "node-ts-service", digest: "7d4640e655e5ccc2be95751609bc23f675cb238b23fd173b44765c26fb8155f1" },
    { kind: "python-service", digest: "f7bfca93753ccb25a6cdf76f28e462dc75c9adb01ca139c02dc65cf612851b3b" },
    { kind: "generic-empty", digest: "5c9b2d54a3da377563e689c4dcbb0ee5656b451e4733ce53b9661d070bedd80b" }
  ] as const)("preserves no-TAB default bytes for $kind", ({ kind, digest }) => {
    const manifest = normalizeManifest({ project: { name: "tab-serializer-default", owner: "acme" }, archetype: { kind } });
    expect(sha256(stringifyManifest(manifest))).toBe(digest);
  });
});
