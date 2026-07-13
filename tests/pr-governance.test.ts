import { spawn } from "node:child_process";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

type Fixture = { files: unknown[]; commits: unknown[]; reviews: unknown[] };

async function runGovernance(fixture: Fixture, overrides: Record<string, string> = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-pr-governance-"));
  const paths = {
    files: path.join(directory, "files.json"),
    commits: path.join(directory, "commits.json"),
    reviews: path.join(directory, "reviews.json")
  };
  await Promise.all([
    writeFile(paths.files, JSON.stringify(fixture.files)),
    writeFile(paths.commits, JSON.stringify(fixture.commits)),
    writeFile(paths.reviews, JSON.stringify(fixture.reviews))
  ]);
  const result = await new Promise<{ code: number; output: string }>((resolve, reject) => {
    const child = spawn("bash", [path.resolve("scripts/ci/check-pr-governance.sh")], {
      cwd: directory,
      env: {
        ...process.env,
        PR_TITLE: "feat: validate fixtures",
        PR_BODY: "Material change: no",
        PR_AUTHOR: "author",
        PR_FILES_FILE: paths.files,
        PR_COMMITS_FILE: paths.commits,
        PR_REVIEWS_FILE: paths.reviews,
        ...overrides
      }
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, output }));
  });
  return { ...result, directory };
}

describe("check-pr-governance", () => {
  it("reports synthetic title, DCO, and changed-line failures with its exclusions", async () => {
    const result = await runGovernance({
      files: [{ filename: "src/large.ts", additions: 801, deletions: 0 }, { filename: "docs/guide.md", additions: 50, deletions: 0 }],
      commits: [{ sha: "1234567890abcdef", author: { login: "human", type: "User" }, commit: { message: "feat: no signoff" } }],
      reviews: []
    }, { PR_TITLE: "missing conventional title" });

    expect(result.code).toBe(1);
    expect(result.output).toContain("PRS-PR-TITLE-001");
    expect(result.output).toContain("PRS-DCO-001");
    expect(result.output).toContain("PRS-PR-SIZE-001");
    expect(result.output).toContain("docs/guide.md");
  });

  it("accepts a material change with an accepted ADR and independent reviewer", async () => {
    const result = await runGovernance({
      files: [{ filename: "src/policy.ts", additions: 10, deletions: 2 }],
      commits: [{ sha: "abcdef1234567890", author: { login: "human", type: "User" }, commit: { message: "feat: policy\n\nSigned-off-by: Human <human@example.com>" } }],
      reviews: [{ state: "APPROVED", user: { login: "reviewer", type: "User" } }]
    }, { PR_BODY: "Material change: yes\nADR: docs/decisions/ADR-0001-test.md" });
    await mkdir(path.join(result.directory, "docs", "decisions"), { recursive: true });
    await writeFile(path.join(result.directory, "docs", "decisions", "ADR-0001-test.md"), "# Decision\n\nStatus: Accepted\n");

    const rerun = await new Promise<{ code: number; output: string }>((resolve, reject) => {
      const child = spawn("bash", [path.resolve("scripts/ci/check-pr-governance.sh")], {
        cwd: result.directory,
        env: {
          ...process.env,
          PR_TITLE: "feat: apply policy",
          PR_BODY: "Material change: yes\nADR: docs/decisions/ADR-0001-test.md",
          PR_AUTHOR: "author",
          PR_FILES_FILE: path.join(result.directory, "files.json"),
          PR_COMMITS_FILE: path.join(result.directory, "commits.json"),
          PR_REVIEWS_FILE: path.join(result.directory, "reviews.json")
        }
      });
      let output = "";
      child.stdout.on("data", (chunk) => (output += chunk));
      child.stderr.on("data", (chunk) => (output += chunk));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code: code ?? 1, output }));
    });

    expect(rerun.code).toBe(0);
    expect(rerun.output).toContain("PASS PRS-PR-GOVERNANCE-001");
  });
});
