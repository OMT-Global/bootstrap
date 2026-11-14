import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const valid = { repo: "example/project", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1", pilotOutcome: "passed" };

async function run(input: unknown, json = true) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bootstrap-inventory-test-"));
  const filename = path.join(dir, "inventory.json");
  const data = JSON.stringify(input);
  try {
    await writeFile(filename, data);
    const args = ["--import", "tsx", cli, "upgrade-plan", "--input", filename];
    if (json) args.push("--json");
    const result = await execFileAsync(process.execPath, args)
      .then(({ stdout, stderr }) => ({ code: 0, stdout, stderr }))
      .catch((error: { code: number; stdout: string; stderr: string }) => ({ code: error.code, stdout: error.stdout, stderr: error.stderr }));
    expect(await readFile(filename, "utf8")).toBe(data);
    return result;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe("upgrade-plan inventory input", () => {
  it.each([
    ["object instead of array", valid],
    ["null candidate", [null]],
    ["array candidate", [[]]],
    ["blank repository", [{ ...valid, repo: " " }]],
    ["blank class", [{ ...valid, repoClass: "" }]],
    ["non-string repository", [{ ...valid, repo: 123 }]],
    ["missing version", [{ ...valid, currentPolicy: undefined }]],
    ["non-string target version", [{ ...valid, targetPolicy: 1 }]],
    ["empty exception", [{ ...valid, exceptionId: "" }]],
    ["blank exception", [{ ...valid, exceptionId: "  " }]],
    ["false exception", [{ ...valid, exceptionId: false }]],
    ["null exception", [{ ...valid, exceptionId: null }]],
    ["unrecognized pilot", [{ ...valid, pilotOutcome: "pass" }]],
    ["null pilot", [{ ...valid, pilotOutcome: null }]],
    ["late invalid candidate", [valid, { ...valid, exceptionId: false }]]
  ])("rejects %s without emitting a partial plan", async (_name, input) => {
    const result = await run(input);
    expect(result.code).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Invalid fleet upgrade inventory");
  }, 20000);

  it("keeps valid input and unknown fields, treats missing pilot as pending, and blocks invalid version strings", async () => {
    const result = await run([
      { ...valid, repo: "example/a", extra: "retained" },
      { repo: "example/b", repoClass: "other", currentPolicy: "1.0.0", targetPolicy: "1.0.1" },
      { ...valid, repo: "example/c", repoClass: "third", targetPolicy: "not-semver" }
    ]);
    expect(result.code).toBe(0);
    const rows = JSON.parse(result.stdout);
    expect(rows.find((row: { repo: string }) => row.repo === "example/a")).toMatchObject({ status: "eligible", extra: "retained" });
    expect(rows.find((row: { repo: string }) => row.repo === "example/b")).toMatchObject({ status: "review-required" });
    expect(rows.find((row: { repo: string }) => row.repo === "example/c")).toMatchObject({ status: "blocked", risk: "invalid" });
  }, 20000);

  it("retains exception-bearing review and accepts an empty inventory", async () => {
    const withException = await run([{ ...valid, exceptionId: "EX-1" }]);
    expect(withException.code).toBe(0);
    expect(JSON.parse(withException.stdout)[0]).toMatchObject({ status: "review-required" });
    const empty = await run([]);
    expect(empty.code).toBe(0);
    expect(JSON.parse(empty.stdout)).toEqual([]);
  }, 20000);

  it("blocks an invalid claimed pilot and a different-target batch in the JSON plan", async () => {
    const result = await run([
      { ...valid, repo: "example/a", currentPolicy: "invalid" },
      { ...valid, repo: "example/b" },
      { ...valid, repo: "example/c", repoClass: "other", targetPolicy: "1.0.1" },
      { ...valid, repo: "example/d", repoClass: "other", targetPolicy: "1.0.2" }
    ]);
    expect(result.code).toBe(0);
    const rows = JSON.parse(result.stdout);
    for (const repo of ["example/a", "example/b", "example/d"]) {
      expect(rows.find((row: { repo: string }) => row.repo === repo)).toMatchObject({ status: "blocked" });
    }
    expect(rows.find((row: { repo: string }) => row.repo === "example/d").reason).toContain("different target");
  }, 20000);

  it("reports a failed pilot as blocked in human-readable output", async () => {
    const result = await run([{ ...valid, pilotOutcome: "failed" }], false);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("[blocked] example/project");
    expect(result.stdout).toContain("pilot failed");
  }, 20000);

  it("blocks the entire affected class for conflicting duplicate repository rows", async () => {
    const result = await run([valid, { ...valid, repo: " EXAMPLE/PROJECT ", pilotOutcome: "failed" },
      { ...valid, repo: "example/next" }]);
    expect(result.code).toBe(0);
    const rows = JSON.parse(result.stdout);
    expect(rows).toHaveLength(3);
    expect(rows.every((row: {status: string; reason: string}) => row.status === "blocked" && row.reason.includes("duplicate"))).toBe(true);
  }, 20000);

  it("checks input before human-readable output without echoing rejected values", async () => {
    const marker = "fabricated-invalid-outcome-marker";
    const rejected = await run([{ ...valid, pilotOutcome: marker }], false);
    expect(rejected.code).not.toBe(0);
    expect(rejected.stdout).toBe("");
    expect(rejected.stderr).toContain("pilotOutcome");
    expect(rejected.stderr).not.toContain(marker);
    const accepted = await run([valid], false);
    expect(accepted.code).toBe(0);
    expect(accepted.stdout).toContain("[eligible] example/project");
  }, 20000);
});
