import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { normalizeManifest } from "../src/manifest.js";
import { resolveLanguageProfiles } from "../src/language-profiles.js";
import { planRepo } from "../src/render.js";

async function fixtureDirectory(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), "bootstrap-language-profiles-"));
}

describe("resolveLanguageProfiles", () => {
  it("selects only profiles supported by repository markers and ignores build output", async () => {
    const directory = await fixtureDirectory();
    await mkdir(path.join(directory, "docs"));
    await mkdir(path.join(directory, "node_modules", "ignored"), { recursive: true });
    await Promise.all([
      writeFile(path.join(directory, "src.ts"), "export {};\n"),
      writeFile(path.join(directory, "main.py"), "print('hello')\n"),
      writeFile(path.join(directory, "docs", "guide.md"), "# Guide\n"),
      writeFile(path.join(directory, "node_modules", "ignored", "package.swift"), "// ignored\n")
    ]);

    const manifest = normalizeManifest({ project: { name: "polyglot", owner: "acme" }, archetype: { kind: "generic-empty" } });
    await expect(resolveLanguageProfiles(manifest, directory)).resolves.toEqual({
      detected: ["typescript", "python", "documentation"],
      selected: ["typescript", "python", "documentation"],
      conflicts: []
    });
  });

  it("reports an archetype mismatch without suppressing detected profiles", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "pyproject.toml"), "[project]\nname = 'service'\n");
    const manifest = normalizeManifest({ project: { name: "mismatch", owner: "acme" }, archetype: { kind: "node-ts-service" } });

    const resolution = await resolveLanguageProfiles(manifest, directory);
    expect(resolution.selected).toEqual(["python"]);
    expect(resolution.conflicts).toEqual([
      {
        profile: "typescript",
        reason: "node-ts-service expects the typescript profile, but the target detects python."
      }
    ]);
  });

  it("includes language-profile evidence in the non-mutating repository plan", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "main.go"), "package main\n");
    const manifest = normalizeManifest({ project: { name: "go-tool", owner: "acme" }, archetype: { kind: "generic-empty" } });

    await expect(planRepo(manifest, directory)).resolves.toMatchObject({
      languageProfiles: { selected: ["go"], conflicts: [] }
    });
  });
});
