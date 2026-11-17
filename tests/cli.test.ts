import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const tsx = new URL("../node_modules/.bin/tsx", import.meta.url).pathname;
const cli = new URL("../src/cli.ts", import.meta.url).pathname;

describe("CLI help", () => {
  it("exposes a read-only observed inventory with explicit source selectors", async () => {
    const result = await execFileAsync(tsx, [cli, "inventory-public-fleet", "--help"]);
    expect(result.stdout).toContain("--target-ref");
    expect(result.stdout).toContain("--target-sha256");
    expect(result.stdout).toContain("--generator-root");
    expect(result.stdout).toContain("--generator-commit");
    expect(result.stdout).toContain("--json");
    expect(result.stdout).not.toContain("--apply");
    expect(result.stdout).not.toContain("--create-pr");
  });

  it("describes configured webhook delivery", async () => {
    const [deliver, exceptions, conform] = await Promise.all([
      execFileAsync(tsx, [cli, "notifications", "deliver", "--help"]),
      execFileAsync(tsx, [cli, "notifications", "exceptions", "--help"]),
      execFileAsync(tsx, [cli, "conform", "--help"])
    ]);

    expect(deliver.stdout).toContain("configured webhook");
    expect(deliver.stdout).not.toContain("currently disabled");
    expect(exceptions.stdout).toContain("configured webhook");
    expect(exceptions.stdout).not.toContain("currently disabled");
    expect(conform.stdout).toContain("--github-capabilities");
  });
});
