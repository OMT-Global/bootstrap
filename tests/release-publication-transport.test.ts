import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { immutablePreflightPublisherScript } from "../src/archetypes.js";

const python = process.env.BOOTSTRAP_RELEASE_TEST_PYTHON || "python3";
const fixture = fileURLToPath(new URL("./fixtures/immutable-release-review/transport.py", import.meta.url));
const scenarios = ["distinct-hash-label", "hash-parent", "star-name", "question-name", "class-name", "star-parent", "question-parent", "class-parent", "backslash-parent", "space-name", "unicode-name", "right-bracket-name", "dash-name", "normal-name", "relative-stage"];

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
        expect(report.hookRan).toBe(false);
        expect(report.releaseMutationRan).toBe(false);
      }
      if (scenario === "distinct-hash-label") {
        expect(report.parserDemo).toEqual({ literalBytes: "distinct", firstHashBytes: "base", label: "label" });
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
