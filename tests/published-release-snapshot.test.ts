import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { publishedReleaseSnapshotScript } from "../src/published-release-snapshot.js";

describe("published release snapshot prototype", () => {
  it("emits the exact self-contained Python exercised by the synthetic provider scenarios", () => {
    const source = readFileSync(new URL("../src/published-release-snapshot.ts", import.meta.url), "utf8");
    const prefix = "return String.raw`";
    const suffix = "`;\n}";
    const start = source.indexOf(prefix);
    const end = source.lastIndexOf(suffix);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(publishedReleaseSnapshotScript()).toBe(source.slice(start + prefix.length, end));
    const result = spawnSync("python3", ["-I", "-S", "tests/fixtures/published-release-snapshot-prototype.test.py"], {
      cwd: process.cwd(), encoding: "utf8", timeout: 30_000
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("Ran 20 tests");
  });
});
