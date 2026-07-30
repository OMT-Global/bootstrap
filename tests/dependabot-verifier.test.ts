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
  prAuthor = "dependabot[bot]",
  compareResponses: Record<string, string> = {}
): { botOnly: boolean; requests: string[] } {
  const directory = mkdtempSync(join(tmpdir(), "bootstrap-dependabot-verifier-"));
  tempDirectories.push(directory);

  const curlPath = join(directory, "curl");
  const gitPath = join(directory, "git");
  const outputPath = join(directory, "github-output");
  const requestLogPath = join(directory, "requests.log");
  writeFileSync(
    curlPath,
    `#!/usr/bin/env bash
set -euo pipefail
url="\${*: -1}"
printf '%s\\n' "$url" >> "$MOCK_CURL_LOG"
if [[ "$url" == */compare/* ]]; then
  parent="\${url##*/compare/}"
  parent="\${parent%%...*}"
  key="MOCK_COMPARE_\${parent}"
  printf '%s' "\${!key:-$MOCK_COMPARE_DEFAULT}"
  exit 0
fi
page="\${url##*page=}"
key="MOCK_PAGE_$page"
printf '%s' "\${!key:-[]}"
`
  );
  chmodSync(curlPath, 0o755);
  writeFileSync(
    gitPath,
    `#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *" rev-list "*) printf '%s\\n' base oldbase ;;
  *" merge-tree "*) printf '%s\\n' tree ;;
  *" rev-parse "*) printf '%s\\n' tree ;;
esac
`
  );
  chmodSync(gitPath, 0o755);

  const pageEnvironment = Object.fromEntries(pages.map((page, index) => [`MOCK_PAGE_${index + 1}`, page]));
  execFileSync("bash", ["-c", renderedVerifierScript()], {
    env: {
      ...process.env,
      ...pageEnvironment,
      PATH: `${directory}:${process.env.PATH ?? ""}`,
      PR_AUTHOR: prAuthor,
      PR_COMMITS_URL: "https://api.github.test/repos/acme/demo/pulls/1/commits",
      PR_BASE_REPO: "acme/demo",
      PR_BASE_SHA: "base",
      GITHUB_TOKEN: "",
      GITHUB_OUTPUT: outputPath,
      MOCK_CURL_LOG: requestLogPath,
      MOCK_COMPARE_DEFAULT: JSON.stringify({ status: "identical", behind_by: 0 }),
      ...Object.fromEntries(Object.entries(compareResponses).map(([parent, response]) => [`MOCK_COMPARE_${parent}`, response]))
    }
  });

  return {
    botOnly: readFileSync(outputPath, "utf8").trim() === "bot_only=true",
    requests: existsSync(requestLogPath) ? readFileSync(requestLogPath, "utf8").trim().split("\n") : []
  };
}

const dependabotCommit = {
  sha: "botcommit",
  author: { login: "dependabot[bot]" },
  committer: { login: "web-flow" },
  parents: [{ sha: "base" }],
  commit: { verification: { verified: true, reason: "valid" } }
};

const maintainerMergeCommit = {
  sha: "mergecommit",
  author: { login: "jmcte", type: "User" },
  committer: { login: "web-flow" },
  parents: [{ sha: "botcommit" }, { sha: "base" }],
  commit: {
    message: "Merge branch 'main' into dependabot/example",
    verification: { verified: true, reason: "valid" }
  }
};

describe("Dependabot commit verification", () => {
  it("accepts a non-empty Dependabot-only commit response", () => {
    expect(runVerifier([JSON.stringify([dependabotCommit])]).botOnly).toBe(true);
  });

  it("accepts a verified maintainer merge from main on a Dependabot branch", () => {
    expect(runVerifier([JSON.stringify([dependabotCommit, maintainerMergeCommit])]).botOnly).toBe(true);
  });

  it("accepts successive verified merges when each main parent is an ancestor of the current base", () => {
    const earlierMerge = { ...maintainerMergeCommit, sha: "earliermerge", parents: [{ sha: "botcommit" }, { sha: "oldbase" }] };
    const currentMerge = { ...maintainerMergeCommit, parents: [{ sha: "earliermerge" }, { sha: "base" }] };
    const result = runVerifier([JSON.stringify([dependabotCommit, earlierMerge, currentMerge])]);

    expect(result.botOnly).toBe(true);
  });

  it("rejects a verified merge whose parents are not ancestors of the current base", () => {
    const result = runVerifier([JSON.stringify([{
      ...maintainerMergeCommit,
      parents: [{ sha: "botcommit" }, { sha: "unrelated" }]
    }])], "dependabot[bot]", {
      unrelated: JSON.stringify({ status: "behind", behind_by: 1 })
    });

    expect(result.botOnly).toBe(false);
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
    ["untrusted merge", [dependabotCommit, { ...maintainerMergeCommit, commit: { ...maintainerMergeCommit.commit, message: "Merge branch 'feature' into dependabot/example" } }]],
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
