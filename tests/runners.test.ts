import { describe, expect, it } from "vitest";

import { resolveRunsOn } from "../src/runners.js";

describe("resolveRunsOn", () => {
  it("routes shell-safe jobs to the self-hosted private pool", () => {
    expect(resolveRunsOn("hybrid-safe", "private", ["shell"])).toEqual([
      "self-hosted",
      "linux",
      "shell-only",
      "private"
    ]);
  });

  it("keeps incompatible jobs on GitHub-hosted runners", () => {
    expect(resolveRunsOn("hybrid-safe", "private", ["shell", "docker"])).toBe("ubuntu-latest");
    expect(resolveRunsOn("self-hosted-first", "public", ["browser"])).toBe("ubuntu-latest");
  });
});
