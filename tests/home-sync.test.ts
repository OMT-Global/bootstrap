import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { applyHome, planHome } from "../src/home/sync.js";
import { normalizeManifest } from "../src/manifest.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bootstrap-home-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("home sync", () => {
  it("plans and applies portable Codex and Claude assets", async () => {
    const homeDir = await makeTempDir();
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    const initialPlan = await planHome(manifest, homeDir);
    expect(initialPlan.actions.some((action) => action.type === "create")).toBe(true);

    const applied = await applyHome(manifest, homeDir);
    expect(applied.some((action) => action.path === ".codex/AGENTS.md")).toBe(true);
    expect(applied.some((action) => action.path === ".claude/CLAUDE.md")).toBe(true);

    const codexAgents = await readFile(path.join(homeDir, ".codex/AGENTS.md"), "utf8");
    expect(codexAgents).toContain("Codex Home Profile");

    const secondPlan = await planHome(manifest, homeDir);
    expect(secondPlan.actions.every((action) => action.type === "unchanged")).toBe(true);
  });
});
