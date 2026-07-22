import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { parseDocument } from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest } from "../src/manifest.js";

const tempDirectories: string[] = [];

afterEach(() => {
  for (const directory of tempDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function renderedVerifierScript(): string {
  const manifest = normalizeManifest({
    project: { name: "dependabot-verifier", owner: "acme" },
    archetype: { kind: "generic-empty" }
  });
  const workflow = renderManagedFiles(manifest).find((file) => file.path === ".github/workflows/pr-fast-ci.yml");
  const parsed = parseDocument(workflow?.contents ?? "").toJS() as {
    jobs: { "verify-dependabot-commits": { steps: Array<{ run: string }> } };
  };

  return parsed.jobs["verify-dependabot-commits"].steps[0].run;
}

function runVerifier(
  pages: string[],
  prAuthor = "dependabot[bot]"
): { botOnly: boolean; requests: string[] } {
  const directory = mkdtempSync(join(tmpdir(), "bootstrap-dependabot-verifier-"));
  tempDirectories.push(directory);

  const curlPath = join(directory, "curl");
  const outputPath = join(directory, "github-output");
  const requestLogPath = join(directory, "requests.log");
  writeFileSync(
    curlPath,
    `#!/usr/bin/env bash
set -euo pipefail
url="\${*: -1}"
printf '%s\\n' "$url" >> "$MOCK_CURL_LOG"
page="\${url##*page=}"
key="MOCK_PAGE_$page"
printf '%s' "\${!key:-[]}"
`
  );
  chmodSync(curlPath, 0o755);

  const pageEnvironment = Object.fromEntries(pages.map((page, index) => [`MOCK_PAGE_${index + 1}`, page]));
  execFileSync("bash", ["-c", renderedVerifierScript()], {
    env: {
      ...process.env,
      ...pageEnvironment,
      PATH: `${directory}:${process.env.PATH ?? ""}`,
      PR_AUTHOR: prAuthor,
      PR_COMMITS_URL: "https://api.github.test/repos/acme/demo/pulls/1/commits",
      GITHUB_TOKEN: "",
      GITHUB_OUTPUT: outputPath,
      MOCK_CURL_LOG: requestLogPath
    }
  });

  return {
    botOnly: readFileSync(outputPath, "utf8").trim() === "bot_only=true",
    requests: existsSync(requestLogPath) ? readFileSync(requestLogPath, "utf8").trim().split("\n") : []
  };
}

const dependabotCommit = {
  author: { login: "dependabot[bot]" },
  committer: { login: "web-flow" },
  commit: { verification: { verified: true, reason: "valid" } }
};

describe("Dependabot commit verification", () => {
  it("accepts a non-empty Dependabot-only commit response", () => {
    expect(runVerifier([JSON.stringify([dependabotCommit])]).botOnly).toBe(true);
  });

  it("rejects a non-Dependabot PR even when every commit impersonates Dependabot", () => {
    const result = runVerifier([JSON.stringify([dependabotCommit])], "contributor");

    expect(result.botOnly).toBe(false);
    expect(result.requests).toEqual([]);
  });

  it.each([
    ["unsigned", { ...dependabotCommit, commit: { verification: { verified: false, reason: "unsigned" } } }],
    ["wrong committer", { ...dependabotCommit, committer: { login: "maintainer" } }],
    ["missing committer", { ...dependabotCommit, committer: null }]
  ])("rejects a %s commit that otherwise impersonates Dependabot", (_name, commit) => {
    expect(runVerifier([JSON.stringify([commit])]).botOnly).toBe(false);
  });

  it.each([
    ["empty", []],
    ["mixed author", [dependabotCommit, { ...dependabotCommit, author: { login: "maintainer" } }]],
    ["unlinked author", [dependabotCommit, { ...dependabotCommit, author: null }]]
  ])("fails closed for a %s response", (_name, commits) => {
    expect(runVerifier([JSON.stringify(commits)]).botOnly).toBe(false);
  });

  it("checks later pages before granting the exemption", () => {
    const firstPage = Array.from({ length: 100 }, () => dependabotCommit);
    const result = runVerifier([
      JSON.stringify(firstPage),
      JSON.stringify([{ author: { login: "maintainer" } }])
    ]);

    expect(result.botOnly).toBe(false);
    expect(result.requests).toHaveLength(2);
    expect(result.requests[1]).toContain("page=2");
  });

  it("rejects a non-array API response", () => {
    expect(() => runVerifier([JSON.stringify({ message: "rate limited" })])).toThrow();
  });
});
