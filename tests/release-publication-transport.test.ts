import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { immutablePreflightPublisherScript } from "../src/archetypes.js";

const python = process.env.BOOTSTRAP_RELEASE_TEST_PYTHON || "python3";
const fixture = fileURLToPath(new URL("./fixtures/immutable-release-review/transport.py", import.meta.url));
const scenarios = ["distinct-hash-label", "hash-parent", "star-name", "question-name", "class-name", "star-parent", "question-parent", "class-parent", "backslash-parent", "space-name", "unicode-name", "right-bracket-name", "dash-name", "normal-name", "relative-stage", "checksum-mutated-after-hook", "checksum-slot-replaced-after-hook", "checksum-symlink-after-hook", "checksum-flat-collision", "checksum-only"];

describe("strong publication CLI transport", () => {
  it.each(scenarios)("preserves byte selection for %s", async (scenario) => {
    const directory = await mkdtemp(path.join(process.env.BOOTSTRAP_RELEASE_TEST_TMPDIR || os.tmpdir(), "release-transport-"));
    try {
      const program = path.join(directory, "canonical-planner.py");
      const match = immutablePreflightPublisherScript().match(/<<'BOOTSTRAP_PUBLISH_PLAN_PY'\n([\s\S]*?)\nBOOTSTRAP_PUBLISH_PLAN_PY(?:\n|$)/);
      if (!match) throw new Error("Missing canonical publication planner body");
      await writeFile(program, match[1]);
      const result = spawnSync(python, ["-I", "-S", fixture, program, scenario, directory], { encoding: "utf8", timeout: 10_000 });
      expect(result.status, result.stderr || result.stdout).toBe(0);
      const report = JSON.parse(result.stdout);
      expect(report.passed).toBe(true);
      if (!report.expectedSuccess) {
        expect(report.hookRan).toBe(report.failurePhase === "copy");
        expect(report.releaseMutationRan).toBe(false);
        if (report.failurePhase === "copy") expect(report.copyOutputEmpty).toBe(true);
      } else {
        expect(report.uploadedNames).toContain("SHA256SUMS");
        expect(report.checksumBytesMatch).toBe(true);
      }
      if (scenario === "distinct-hash-label") {
        expect(report.parserDemo).toEqual({ literalBytes: "distinct", firstHashBytes: "base", label: "label" });
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});


describe("reserved publication evidence names", () => {
  it.each(["", "nested/"])("includes ordinary suffix names and checksum from %j and excludes exact evidence names", async (prefix) => {
    const directory = await mkdtemp(path.join(process.env.BOOTSTRAP_RELEASE_TEST_TMPDIR || os.tmpdir(), "release-evidence-names-"));
    try {
      const tree = path.join(directory, "package");
      const stage = path.join(directory, "stage");
      await Promise.all([mkdir(tree), mkdir(stage)]);
      const selected = {
        [`${prefix}audit-release-evidence.json`]: "ordinary audit asset",
        [`${prefix}myvalidation-evidence.json`]: "ordinary validation asset"
      };
      const files: Record<string, string> = {
        ...selected,
        "release-evidence.json": "reserved root release",
        "validation-evidence.json": "reserved root validation",
        "internal/release-evidence.json": "reserved nested release",
        "internal/validation-evidence.json": "reserved nested validation"
      };
      const digest = (value: string) => createHash("sha256").update(value).digest("hex");
      files.SHA256SUMS = Object.entries(files).map(([name, value]) => `${digest(value)}  dist/release/${name}\n`).join("");
      files["RELEASE_NOTES.md"] = "release notes";
      for (const [name, value] of Object.entries(files)) {
        await mkdir(path.dirname(path.join(tree, name)), { recursive: true });
        await writeFile(path.join(tree, name), value);
      }
      const match = immutablePreflightPublisherScript().match(/<<'BOOTSTRAP_PUBLISH_PLAN_PY'\n([\s\S]*?)\nBOOTSTRAP_PUBLISH_PLAN_PY(?:\n|$)/);
      if (!match) throw new Error("Missing canonical publication planner body");
      const program = path.join(directory, "planner.py");
      const inventory = path.join(directory, "inventory.json");
      await writeFile(program, match[1]);
      await writeFile(inventory, JSON.stringify(Object.fromEntries(Object.entries(files).map(([name, value]) => [name, digest(value)]))));
      const args = [tree, inventory, "dist/release", "dist/release/RELEASE_NOTES.md", stage, path.join(directory, "plan.json")];
      const planned = spawnSync(python, ["-I", "-S", program, "plan", ...args], { encoding: "utf8", timeout: 10_000 });
      expect(planned.status, planned.stderr).toBe(0);
      const copied = spawnSync(python, ["-I", "-S", program, "copy", ...args], { encoding: "utf8", timeout: 10_000 });
      expect(copied.status, copied.stderr).toBe(0);
      const uploaded = Object.fromEntries(await Promise.all(copied.stdout.split("\0").filter(Boolean).map(async (name) => [path.basename(name), await readFile(name, "utf8")])));
      expect(uploaded).toEqual({ ...Object.fromEntries(Object.entries(selected).map(([name, value]) => [path.basename(name), value])), SHA256SUMS: files.SHA256SUMS });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
