import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";
import YAML from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { loadManifest } from "../src/manifest.js";
import { loadResolvedFlowPolicy } from "../src/policy.js";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const scriptPath = path.join(repoRoot, "scripts/ci/run-fast-checks.sh");
const tempDirs: string[] = [];
const commands = ["ci --ignore-scripts", "run typecheck", "test -- --maxWorkers=2", "run build"];

async function runChecks(failingCommand?: string): Promise<{ calls: string[]; code: number }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bootstrap-ci-"));
  tempDirs.push(dir);
  const bin = path.join(dir, "bin");
  await mkdir(bin);
  const npm = path.join(bin, "npm");
  await writeFile(npm, '#!/usr/bin/env bash\nset -eu\nprintf "%s\\n" "$*" >> "$CI_COMMAND_LOG"\nif [[ "$*" == "${CI_FAIL_COMMAND:-}" ]]; then exit 42; fi\n');
  await chmod(npm, 0o755);
  const log = path.join(dir, "calls.log");
  let code = 0;
  try {
    await execFileAsync("bash", [scriptPath], {
      cwd: dir,
      env: { PATH: `${bin}:${process.env.PATH}`, CI_COMMAND_LOG: log, ...(failingCommand ? { CI_FAIL_COMMAND: failingCommand } : {}) }
    });
  } catch (error) {
    code = Number((error as { code?: number }).code);
  }
  return { calls: (await readFile(log, "utf8")).trim().split("\n"), code };
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("Bootstrap's own fast CI", () => {
  it("runs locked dependency installation, typecheck, the bounded test suite, and build", async () => {
    expect(await runChecks()).toEqual({ calls: commands, code: 0 });
  });

  it.each(commands)("stops when %s fails instead of reporting a successful check", async (command) => {
    expect(await runChecks(command)).toEqual({ calls: commands.slice(0, commands.indexOf(command) + 1), code: 42 });
  });

  it("projects the script and source/test/package filters from the manifest", async () => {
    const manifest = await loadManifest(path.join(repoRoot, "project.bootstrap.yaml"));
    const rendered = renderManagedFiles(manifest, await loadResolvedFlowPolicy(manifest, repoRoot));
    expect(await readFile(scriptPath, "utf8")).toBe(rendered.find((file) => file.path === "scripts/ci/run-fast-checks.sh")?.contents);
    const live = YAML.parse(await readFile(path.join(repoRoot, ".github/workflows/pr-fast-ci.yml"), "utf8"));
    const projected = YAML.parse(rendered.find((file) => file.path === ".github/workflows/pr-fast-ci.yml")!.contents);
    const filterFor = (workflow: typeof live) => YAML.parse(workflow.jobs.changes.steps[0].with.filters);
    expect(filterFor(live)).toEqual(filterFor(projected));
    expect(filterFor(live).app).toEqual(expect.arrayContaining([
      "src/**", "tests/**", "test/**", "profiles/**", "policy/**", "package*.json", "tsconfig.json", "vitest.config.ts"
    ]));
    expect(live.jobs["fast-checks"].if).toContain("needs.changes.outputs.app == 'true'");
    expect(live.jobs["fast-checks"]["timeout-minutes"]).toBe(15);
    expect(live.permissions).toEqual({ contents: "read", "pull-requests": "read" });
    expect(live.on).toHaveProperty("pull_request");
    expect(live.on).not.toHaveProperty("pull_request_target");
    expect(live.jobs["fast-checks"]["runs-on"]).toBe("ubuntu-24.04");
  });
});
