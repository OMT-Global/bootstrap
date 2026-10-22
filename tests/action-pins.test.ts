import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

async function runPinCheck(workflow: string) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-action-pins-"));
  const workflows = path.join(directory, ".github", "workflows");
  await mkdir(workflows, { recursive: true });
  await writeFile(path.join(workflows, "fixture.yml"), workflow);
  return new Promise<{ code: number; output: string }>((resolve, reject) => {
    const child = spawn("bash", [path.resolve("scripts/ci/check-action-pins.sh"), workflows]);
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, output }));
  });
}

describe("check-action-pins", () => {
  it("keeps CodeQL actions in each security job on the same immutable version", async () => {
    for (const file of ["security.yml", "security-pr.yml"]) {
      const workflow: { jobs: Record<string, { steps?: { uses?: string }[] }> } = parse(
        await readFile(path.join(".github", "workflows", file), "utf8"),
      );
      for (const [jobName, job] of Object.entries(workflow.jobs)) {
        const refs = (job.steps ?? [])
          .map((step) => step.uses)
          .filter((uses) => uses?.startsWith("github/codeql-action/"))
          .map((uses) => uses!.split("@")[1]);
        if (refs.length > 0) {
          expect(new Set(refs).size, `${file}:${jobName} has mixed CodeQL versions`).toBe(1);
        }
      }
    }
  });

  it("rejects mutable third-party references and pins without update metadata", async () => {
    const result = await runPinCheck(`jobs:\n  check:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: dorny/paths-filter@7b450fff21473bca461d4b92ce414b9d0420d706\n`);

    expect(result.code).toBe(1);
    expect(result.output).toContain("SA-ACTION-PIN-001");
    expect(result.output).toContain("SA-ACTION-PIN-002");
  });

  it("accepts immutable pins with readable metadata and Bootstrap-owned reusable workflows", async () => {
    const result = await runPinCheck(`jobs:\n  check:\n    steps:\n      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4\n  reuse:\n    uses: OMT-Global/bootstrap/.github/workflows/security-pr.yml@refs/heads/main\n`);

    expect(result.code).toBe(0);
    expect(result.output).toContain("validated 1 third-party action pin");
  });
});
