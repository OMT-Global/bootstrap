import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest } from "../src/manifest.js";

function publishShell(contents: string): string {
  const workflow = YAML.parse(contents);
  const step = workflow.jobs.publish.steps.find((entry: { name?: string }) => entry.name === "Publish proven release artifact");
  if (!step?.run) throw new Error("Publish shell is missing");
  return step.run;
}

const manifest = normalizeManifest({
  project: { name: "release-fixture", owner: "acme" },
  archetype: { kind: "generic-empty" },
  release: { enabled: true, maturity: "governed" }
});
const generated = renderManagedFiles(manifest).find((file) => file.path === ".github/workflows/release-publish-reusable.yml");
if (!generated) throw new Error("Generated publish reusable is missing");

async function runPublish(shell: string, hook: "missing" | "not-executable" | "directory" | "failed" | "passed", required = true) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-publish-"));
  try {
    const bin = path.join(directory, "bin");
    const packageFixture = path.join(directory, "package");
    const validationFixture = path.join(directory, "validation");
    const runnerTemp = path.join(directory, "runner");
    await Promise.all([bin, packageFixture, validationFixture, runnerTemp].map((entry) => mkdir(entry)));
    const events = path.join(directory, "events");
    await writeFile(events, "");
    const sha = "a".repeat(40);
    await writeFile(path.join(packageFixture, "release-evidence.json"), JSON.stringify({ target_sha: sha, preflight_run_id: "101" }));
    const notes = "Fixture release notes\n";
    await writeFile(path.join(packageFixture, "RELEASE_NOTES.md"), notes);
    await writeFile(path.join(packageFixture, "SHA256SUMS"), `${createHash("sha256").update(notes).digest("hex")}  dist/release/RELEASE_NOTES.md\n`);
    await writeFile(path.join(validationFixture, "validation-evidence.json"), JSON.stringify({ target_sha: sha, validation_run_id: "102", repo: "acme/release-fixture" }));

    const git = path.join(bin, "git");
    await writeFile(git, `#!/bin/bash
set -euo pipefail
case "$1" in
  rev-parse) printf '%s\\n' "$FIXTURE_SHA" ;;
  config) ;;
  tag) printf 'tag:%s\\n' "$3" >> "$EVENT_LOG" ;;
  push) printf 'push:%s\\n' "$4" >> "$EVENT_LOG" ;;
  *) echo "Unexpected git command" >&2; exit 90 ;;
esac
`);
    const gh = path.join(bin, "gh");
    await writeFile(gh, `#!/bin/bash
set -euo pipefail
case "$1 $2" in
  "run download")
    source="$PACKAGE_FIXTURE"
    [[ "$3" != "102" ]] || source="$VALIDATION_FIXTURE"
    destination=""
    while [[ "$#" -gt 0 ]]; do
      if [[ "$1" == "--dir" ]]; then destination="$2"; break; fi
      shift
    done
    [[ -n "$destination" ]] || exit 90
    cp "$source"/* "$destination"/
    ;;
  "run view") printf 'success\\n' ;;
  "release view") exit 0 ;;
  "release create") printf 'release-create\\n' >> "$EVENT_LOG" ;;
  "release upload") printf 'release-upload\\n' >> "$EVENT_LOG" ;;
  *) echo "Unexpected gh command" >&2; exit 90 ;;
esac
`);
    const publishHook = path.join(directory, "publish.sh");
    await writeFile(publishHook, '#!/bin/bash\nprintf "publish-hook\\n" >> "$EVENT_LOG"\n');
    const postpublishHook = path.join(directory, "postpublish.sh");
    if (hook === "directory") {
      await mkdir(postpublishHook);
      await chmod(postpublishHook, 0o755);
    } else if (hook !== "missing") {
      await writeFile(postpublishHook, `#!/bin/bash
printf 'postpublish:%s\\n' "$1" >> "$EVENT_LOG"
exit ${hook === "failed" ? 42 : 0}
`);
      if (hook !== "not-executable") await chmod(postpublishHook, 0o755);
    }
    await Promise.all([git, gh, publishHook].map((entry) => chmod(entry, 0o755)));
    const result = spawnSync("/bin/bash", ["-c", shell], {
      cwd: directory,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        PATH: `${bin}:${path.dirname(process.execPath)}:/usr/bin:/bin`,
        FIXTURE_SHA: sha,
        EVENT_LOG: events,
        PACKAGE_FIXTURE: packageFixture,
        VALIDATION_FIXTURE: validationFixture,
        RUNNER_TEMP: runnerTemp,
        TAG: "v1.2.3",
        TAG_PREFIX: "v",
        CHANNEL: "stable",
        PREFLIGHT_RUN_ID: "101",
        VALIDATION_RUN_ID: "102",
        GITHUB_REPOSITORY: "acme/release-fixture",
        GITHUB_RUN_ID: "103",
        RELEASE_ISSUE: "27",
        REQUIRE_RELEASE_ISSUE: "true",
        REQUIRE_SIGNED_TAG: "false",
        REQUIRE_POSTPUBLISH_VERIFICATION: String(required),
        CREATE_GITHUB_RELEASE: "true",
        UPDATE_MAJOR_TAG: "true",
        UPDATE_MINOR_TAG: "true",
        ARTIFACT_DIR: "dist/release",
        RELEASE_NOTES_FILE: "dist/release/RELEASE_NOTES.md",
        PUBLISH_SCRIPT: publishHook,
        POSTPUBLISH_SCRIPT: postpublishHook
      }
    });
    if (result.error) throw result.error;
    return { status: result.status, stderr: result.stderr, events: (await readFile(events, "utf8")).split("\n").filter(Boolean) };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

for (const [source, shell] of [
  ["checked-in", publishShell(readFileSync(".github/workflows/release-publish-reusable.yml", "utf8"))],
  ["generated", publishShell(generated.contents)]
] as const) {
  describe(`${source} release publish recovery boundaries`, () => {
    it.each(["missing", "not-executable", "directory"] as const)("rejects a %s required postpublish hook before any publication mutation", async (hook) => {
      const result = await runPublish(shell, hook);
      expect(result.status).not.toBe(0);
      expect(result.events).toEqual([]);
      expect(result.stderr).toContain("Postpublish verification script is required but missing or not executable.");
    });

    it("leaves floating aliases untouched when the postpublish hook fails", async () => {
      const result = await runPublish(shell, "failed");
      expect(result.status).toBe(42);
      expect(result.events).toEqual(["publish-hook", "release-upload", "postpublish:v1.2.3"]);
    });

    it("verifies the published release before promoting both floating aliases", async () => {
      const result = await runPublish(shell, "passed");
      expect(result.status).toBe(0);
      expect(result.events).toEqual([
        "publish-hook", "release-upload", "postpublish:v1.2.3",
        "tag:v1.2", "push:refs/tags/v1.2", "tag:v1", "push:refs/tags/v1"
      ]);
    });

    it.each(["missing", "directory"] as const)("continues to allow a %s optional postpublish hook", async (hook) => {
      const result = await runPublish(shell, hook, false);
      expect(result.status).toBe(0);
      expect(result.events).toEqual([
        "publish-hook", "release-upload",
        "tag:v1.2", "push:refs/tags/v1.2", "tag:v1", "push:refs/tags/v1"
      ]);
    });
  });
}
