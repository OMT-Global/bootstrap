import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { buildIssueHygieneReport, fetchOpenIssues, formatIssueHygieneReport } from "../scripts/ci/report-issue-hygiene.mjs";

const script = path.resolve("scripts/ci/report-issue-hygiene.mjs");

async function runReport(issues: unknown[], asOf = "2026-07-18T12:00:00.000Z") {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-issue-hygiene-"));
  const fixture = path.join(directory, "issues.json");
  const output = path.join(directory, "report.json");
  await writeFile(fixture, JSON.stringify(issues));
  const execution = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(process.execPath, [script, "--fixture", fixture, "--as-of", asOf, "--json-output", output]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
  const report = JSON.parse(await readFile(output, "utf8"));
  return { ...execution, report };
}

function issue(number: number, updatedAt: string, body = "") {
  return {
    number,
    title: `Issue ${number}`,
    html_url: `https://github.com/acme/repo/issues/${number}`,
    updated_at: updatedAt,
    body
  };
}

describe("issue hygiene report", () => {
  it("uses the 30/90-day clocks and never authorizes mutation", async () => {
    const { code, stdout, report } = await runReport([
      issue(3, "2026-04-19T12:00:00.000Z"),
      issue(1, "2026-06-19T12:00:00.000Z"),
      issue(2, "2026-06-18T12:00:00.000Z")
    ]);

    expect(code).toBe(0);
    expect(report).toMatchObject({
      schemaVersion: 1,
      thresholds: { inactiveReviewDays: 30, closeOrRescopeDays: 90 },
      summary: { scanned: 3, current: 1, review: 1, closeOrRescope: 1 }
    });
    expect(report.results.map((entry: any) => entry.issue.number)).toEqual([2, 3]);
    expect(report.results[0]).toMatchObject({ proposedAction: "review", humanDecisionRequired: false, mutationAllowed: false });
    expect(report.results[1]).toMatchObject({ proposedAction: "close-or-rescope", humanDecisionRequired: true, mutationAllowed: false });
    expect(stdout).toContain("never mutates, closes, labels, or reschedules an issue");
  });

  it("preserves a stale issue with a credible evidenced future action", async () => {
    const body = `<!-- prs-next-action {"outcome":"Handle } tokens","dependency":"issue:54","checkpoint":"2026-08-01","evidence":"issue:10"} -->`;
    const { report } = await runReport([issue(9, "2026-01-01T00:00:00.000Z", body)]);

    expect(report.results[0]).toMatchObject({ proposedAction: "review", humanDecisionRequired: false, mutationAllowed: false });
    expect(report.results[0].evidence).toContain("nextActionCheckpoint=2026-08-01");
    expect(JSON.stringify(report)).not.toContain("Handle } tokens");
  });

  it("rejects impossible or non-ISO timestamps instead of normalizing them", () => {
    expect(() => buildIssueHygieneReport([issue(1, "2026-02-31T00:00:00Z")])).toThrow("ISO-8601 timestamp");
    expect(() => buildIssueHygieneReport([issue(1, "2026-01-01T00:00:00Z")], "July 18, 2026")).toThrow(
      "ISO-8601 timestamp"
    );
  });

  it("does not accept malformed or expired action markers and excludes pull requests", async () => {
    const expired = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-07-01","evidence":"issue:10#comment"} -->`;
    const pullRequest = { ...issue(5, "2026-01-01T00:00:00.000Z"), pull_request: { url: "https://api.github.com/repos/acme/repo/pulls/5" } };
    const { report } = await runReport([pullRequest, issue(4, "2026-01-01T00:00:00.000Z", expired)]);

    expect(report.summary.scanned).toBe(1);
    expect(report.results[0]).toMatchObject({ proposedAction: "close-or-rescope", humanDecisionRequired: true, mutationAllowed: false });
  });

  it("rejects nonexistent checkpoint dates and non-HTTPS evidence", async () => {
    const impossibleDate = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-02-31","evidence":"issue:10"} -->`;
    const insecureEvidence = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"http://example.invalid/comment"} -->`;
    const emptyHttpsEvidence = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"https://?"} -->`;
    const malformedTypedEvidence = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"issue:not-an-issue"} -->`;
    const credentialQuery = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"https://example.invalid/report?access_token=secret"} -->`;
    const credentialFragment = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"https://example.invalid/report#secret"} -->`;
    const arbitraryCapabilityPath = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"https://example.invalid/reset/secret"} -->`;
    const githubCapabilityPath = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"https://github.com/password_reset/secret"} -->`;
    const { report } = await runReport([
      issue(7, "2026-01-01T00:00:00.000Z", impossibleDate),
      issue(8, "2026-01-01T00:00:00.000Z", insecureEvidence),
      issue(9, "2026-01-01T00:00:00.000Z", emptyHttpsEvidence),
      issue(10, "2026-01-01T00:00:00.000Z", malformedTypedEvidence),
      issue(11, "2026-01-01T00:00:00.000Z", credentialQuery),
      issue(12, "2026-01-01T00:00:00.000Z", credentialFragment),
      issue(13, "2026-01-01T00:00:00.000Z", arbitraryCapabilityPath),
      issue(14, "2026-01-01T00:00:00.000Z", githubCapabilityPath)
    ]);

    expect(report.results).toHaveLength(8);
    expect(report.results.every((entry: any) => entry.proposedAction === "close-or-rescope")).toBe(true);
  });

  it("accepts a public credential-free HTTPS evidence URL", async () => {
    const body = `<!-- prs-next-action {"outcome":"Later","checkpoint":"2026-08-01","evidence":"https://github.com/acme/repo/issues/10"} -->`;
    const { report } = await runReport([issue(15, "2026-01-01T00:00:00.000Z", body)]);

    expect(report.results[0]).toMatchObject({ proposedAction: "review", humanDecisionRequired: false });
  });

  it("keeps JSON complete while bounding the Markdown workflow summary", () => {
    const issues = Array.from({ length: 2_000 }, (_, index) => ({
      ...issue(index + 1, "2026-01-01T00:00:00.000Z"),
      title: `Issue ${index + 1} ${"x".repeat(1_000)}`
    }));
    const report = buildIssueHygieneReport(issues, "2026-07-18T12:00:00.000Z");
    const markdown = formatIssueHygieneReport(report);

    expect(report.results).toHaveLength(2_000);
    expect(Buffer.byteLength(markdown, "utf8")).toBeLessThanOrEqual(900 * 1024);
    expect(markdown).toContain("additional report entries omitted from Markdown; see the complete JSON artifact");
  });

  it("escapes untrusted issue titles in the Markdown workflow summary", async () => {
    const malicious = {
      ...issue(12, "2026-01-01T00:00:00.000Z"),
      title: "[click](https://evil.invalid) <img src=x>"
    };
    const { stdout, report } = await runReport([malicious]);

    expect(report.results[0].issue.title).toBe(malicious.title);
    expect(stdout).not.toContain(malicious.title);
    expect(stdout).toContain("\\[click\\]\\(https://evil\\.invalid\\) &lt;img src=x&gt;");
  });

  it("follows GitHub pagination without imposing an inventory cap", async () => {
    const firstPage = Array.from({ length: 100 }, (_, index) => issue(index + 1, "2026-07-18T00:00:00.000Z"));
    const secondPage = [issue(101, "2026-07-18T00:00:00.000Z")];
    const requests: string[] = [];
    const fetchImplementation = async (url: string | URL | Request) => {
      requests.push(String(url));
      const body = requests.length === 1 ? firstPage : secondPage;
      const headers = new Headers();
      if (requests.length === 1) {
        headers.set("link", '<https://api.github.com/repositories/123456/issues?state=open&per_page=100&page=2>; rel="next", <https://api.github.com/repositories/123456/issues?state=open&per_page=100&page=2>; rel="last"');
      }
      return new Response(JSON.stringify(body), { status: 200, headers });
    };

    const issues = await fetchOpenIssues("acme/repo", "token", fetchImplementation as typeof fetch);

    expect(requests).toHaveLength(2);
    expect(requests[1]).toContain("/repositories/123456/issues");
    expect(issues).toHaveLength(101);
    expect(issues.at(-1)?.number).toBe(101);
  });

  it("never sends the workflow token to an off-origin pagination link", async () => {
    const fetchImplementation = async () => {
      const headers = new Headers({ link: '<https://evil.invalid/issues?page=2>; rel="next"' });
      return new Response("[]", { status: 200, headers });
    };

    await expect(fetchOpenIssues("acme/repo", "token", fetchImplementation as typeof fetch)).rejects.toThrow(
      "invalid next-page URL"
    );
  });

  it("projects a read-only scheduled workflow with retained report evidence", async () => {
    const workflow = parse(await readFile(path.resolve(".github/workflows/issue-hygiene.yml"), "utf8"));

    expect(workflow.permissions).toEqual({ contents: "read", issues: "read" });
    expect(workflow.on.schedule[0].cron).toBe("17 9 * * 1");
    expect(workflow.jobs.report.steps.find((step: any) => step.name === "Build deterministic issue hygiene report")?.shell).toBe("bash");
    expect(workflow.jobs.report.steps.some((step: any) => step.uses === "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02")).toBe(true);
    expect(JSON.stringify(workflow)).not.toMatch(/issues:\s*write|pull-requests:\s*write/);
  });
});
