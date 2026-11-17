import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { parseDocument } from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest } from "../src/manifest.js";

const tempDirectories: string[] = [];
const syntheticToken = "fabricated-governance-token-not-a-credential";

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

  return parsed.jobs["verify-dependabot-commits"].steps[0]!.run;
}

function runVerifier(
  pages: string[],
  prAuthor = "dependabot[bot]",
  compareResponses: Record<string, string> = {}
): { botOnly: boolean; requests: string[]; transport: Array<Record<string, unknown>> } {
  const directory = mkdtempSync(join(tmpdir(), "bootstrap-dependabot-verifier-"));
  tempDirectories.push(directory);

  const curlPath = join(directory, "curl");
  const gitPath = join(directory, "git");
  const outputPath = join(directory, "github-output");
  const requestLogPath = join(directory, "requests.log");
  const transportLogPath = join(directory, "transport.jsonl");
  const realGit = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
  const systemConfig = join(directory, "system.gitconfig");
  const globalConfig = join(directory, "global.gitconfig");
  writeFileSync(systemConfig, "[http]\n\tsslVerify = true\n");
  writeFileSync(globalConfig, "[http]\n\tproxy = http://configured-proxy.invalid:8123\n\tsslCAInfo = /fabricated/corporate-ca.pem\n\tfollowRedirects = initial\n");
  writeFileSync(
    curlPath,
    `#!/usr/bin/env bash
set -euo pipefail
headers=""
if [[ " $* " == *" --header @- "* ]]; then headers="$(cat)"; fi
MOCK_HEADERS="$headers" python3 - "$@" <<'PY'
import json, os, sys
with open(os.environ['MOCK_TRANSPORT_LOG'], 'a') as log:
    log.write(json.dumps({'tool': 'curl', 'args': sys.argv[1:], 'headers': os.environ['MOCK_HEADERS']}) + '\\n')
PY
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
python3 - "$@" <<'PY'
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
repo = pathlib.Path(args[args.index('-C') + 1])
command = next((i for i, arg in enumerate(args) if arg in ('init', 'remote', 'config', 'fetch', 'rev-list', 'merge-tree', 'rev-parse')), len(args))
record = {'tool': 'git', 'args': args}
if 'fetch' in args:
    config = repo / '.git' / 'config'
    record['local_config'] = config.read_text() if config.exists() else ''
    prefix = [os.environ['MOCK_REAL_GIT'], *args[:command], 'config', '--get']
    record['effective'] = {key: subprocess.check_output([*prefix, key], text=True).strip() for key in
        ('http.extraHeader', 'http.proxy', 'http.sslCAInfo', 'http.sslVerify', 'http.followRedirects', 'http.sslVersion')}
with open(os.environ['MOCK_TRANSPORT_LOG'], 'a') as log:
    log.write(json.dumps(record) + '\\n')
PY
case " $* " in
  *" init "*|*" remote "*|*" config "*) "$MOCK_REAL_GIT" "$@" ;;
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
      ...pageEnvironment,
      PATH: `${directory}:${process.env.PATH ?? ""}`,
      ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}),
      PR_AUTHOR: prAuthor,
      PR_COMMITS_URL: "https://api.github.test/repos/acme/demo/pulls/1/commits",
      PR_BASE_REPO: "acme/demo",
      PR_BASE_SHA: "base",
      GITHUB_TOKEN: syntheticToken,
      GIT_CONFIG_SYSTEM: systemConfig,
      GIT_CONFIG_GLOBAL: globalConfig,
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "http.sslVersion",
      GIT_CONFIG_VALUE_0: "tlsv1.2",
      MOCK_REAL_GIT: realGit,
      MOCK_TRANSPORT_LOG: transportLogPath,
      GITHUB_OUTPUT: outputPath,
      MOCK_CURL_LOG: requestLogPath,
      MOCK_COMPARE_DEFAULT: JSON.stringify({ status: "identical", behind_by: 0 }),
      ...Object.fromEntries(Object.entries(compareResponses).map(([parent, response]) => [`MOCK_COMPARE_${parent}`, response]))
    }
  });

  return {
    botOnly: readFileSync(outputPath, "utf8").trim() === "bot_only=true",
    requests: existsSync(requestLogPath) ? readFileSync(requestLogPath, "utf8").trim().split("\n") : [],
    transport: readFileSync(transportLogPath, "utf8").trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>)
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
  it("keeps credentials out of process arguments and temporary Git config while retaining configured transport", () => {
    const result = runVerifier([JSON.stringify([dependabotCommit, maintainerMergeCommit])]);
    const basic = Buffer.from(`x-access-token:${syntheticToken}`).toString("base64");
    const fetches = result.transport.filter((entry) => entry.tool === "git" && (entry.args as string[]).includes("fetch"));
    expect(fetches).toHaveLength(2);
    for (const entry of result.transport) {
      expect(JSON.stringify(entry.args)).not.toContain(syntheticToken);
      expect(JSON.stringify(entry.args)).not.toContain(basic);
    }
    for (const entry of fetches) {
      expect(entry.local_config).not.toContain(basic);
      expect(entry.local_config).not.toContain(syntheticToken);
      expect(entry.effective).toEqual({
        "http.extraHeader": `Authorization: Basic ${basic}`,
        "http.proxy": "http://configured-proxy.invalid:8123",
        "http.sslCAInfo": "/fabricated/corporate-ca.pem",
        "http.sslVerify": "true",
        "http.followRedirects": "initial",
        "http.sslVersion": "tlsv1.2"
      });
    }
    const requests = result.transport.filter((entry) => entry.tool === "curl");
    expect(requests).toHaveLength(1);
    expect(requests[0]!.headers).toBe(`Authorization: Bearer ${syntheticToken}`);
    expect(result.botOnly).toBe(true);
  });

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
    // This 100-commit Bash/jq fixture measured 12.8 seconds in the isolated 2-CPU profile.
    const firstPage = Array.from({ length: 100 }, () => dependabotCommit);
    const result = runVerifier([
      JSON.stringify(firstPage),
      JSON.stringify([{ author: { login: "maintainer" } }])
    ]);

    expect(result.botOnly).toBe(false);
    expect(result.requests).toHaveLength(2);
    expect(result.requests[1]).toContain("page=2");
  }, 30_000);

  it("rejects a non-array API response", () => {
    expect(() => runVerifier([JSON.stringify({ message: "rate limited" })])).toThrow();
  });
});
