import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const tsx = new URL("../node_modules/.bin/tsx", import.meta.url).pathname;
const cli = new URL("../src/cli.ts", import.meta.url).pathname;

describe("notification CLI help", () => {
  it("does not promise disabled webhook delivery", async () => {
    const [deliver, exceptions] = await Promise.all([
      execFileAsync(tsx, [cli, "notifications", "deliver", "--help"]),
      execFileAsync(tsx, [cli, "notifications", "exceptions", "--help"])
    ]);

    expect(deliver.stdout).toContain("configured webhook delivery is currently disabled");
    expect(exceptions.stdout).toContain("configured webhook delivery is currently disabled");
  });
});
