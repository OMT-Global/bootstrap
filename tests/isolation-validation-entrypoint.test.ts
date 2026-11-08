import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, chmod, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { loadManifest } from "../src/manifest.js";
import { loadResolvedFlowPolicy } from "../src/policy.js";
import { renderManagedFiles } from "../src/archetypes.js";
import { NODE_ISOLATION_IMAGE } from "../src/isolation/node-profile.js";
const execute = promisify(execFile);
const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });
async function fixture(profile: string, failure = "") {
  const target = await mkdtemp(path.join(os.tmpdir(), "bootstrap-full-entrypoint-")); directories.push(target);
  await mkdir(path.join(target, "scripts/ci"), { recursive: true }); await mkdir(path.join(target, "bin"));
  await writeFile(path.join(target, "scripts/ci/run-fast-checks.sh"), '#!/bin/bash\nset -eu\nprintf "fast:%s\\n" "${BOOTSTRAP_REQUIRE_ISOLATION_TESTS:-unset}" >> "$ENTRY_LOG"\n[[ "${ENTRY_FAIL:-}" != fast ]] || exit 13\n');
  for (const name of ["docker", "npm"]) {
    const file = path.join(target, "bin", name);
    await writeFile(file, `#!/bin/bash\nset -eu\nprintf '${name}:%s:%s:%s\\n' "$*" "\${BOOTSTRAP_REQUIRE_ISOLATION_TESTS:-unset}" "\${BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS:-unset}" >> "$ENTRY_LOG"\n[[ "\${ENTRY_FAIL:-}" != ${name} ]] || exit 17\n[[ "\${ENTRY_FAIL:-}" != host || "\${BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS:-}" != 1 ]] || exit 19\n`);
    await chmod(file, 0o755);
  }
  const script = await readFile("scripts/ci/run-extended-validation.sh", "utf8");
  await writeFile(path.join(target, "extended.sh"), script);
  let status = 0; let stdout = "";
  try { stdout = (await execute("/bin/bash", ["extended.sh"], { cwd: target, env: { PATH: `${target}/bin:/usr/bin:/bin`, HOME: target,
    RELEASE_PROFILE: profile, ENTRY_LOG: path.join(target, "events"), ENTRY_FAIL: failure } })).stdout; }
  catch (error) { const result = error as { code: number; stdout: string }; status = result.code; stdout = result.stdout; }
  return { status, stdout, events: (await readFile(path.join(target, "events"), "utf8")).trim().split("\n") };
}
describe("registered full-validation isolation entry point", () => {
  it("matches the supported manifest projection exactly", async () => {
    const manifest = await loadManifest("project.bootstrap.yaml");
    const projection = renderManagedFiles(manifest, await loadResolvedFlowPolicy(manifest, process.cwd())).find((file) => file.path === "scripts/ci/run-extended-validation.sh");
    expect(projection?.contents).toBe(await readFile("scripts/ci/run-extended-validation.sh", "utf8"));
  });
  it.each(["", "smoke", "standard"])("keeps profile %s cheap and explicitly reports Docker tests were not run", async (profile) => {
    const result = await fixture(profile);
    expect(result.status).toBe(0); expect(result.events).toEqual(["fast:unset"]);
    expect(result.stdout).toContain("require the full release-validation profile");
  });
  it("requires actual Docker tests only after normal checks and the immutable image pull", async () => {
    const result = await fixture("full");
    expect(result.status).toBe(0);
    expect(result.events).toEqual(["fast:unset", `docker:pull --platform linux/amd64 ${NODE_ISOLATION_IMAGE}:unset:unset`,
      "npm:test -- tests/isolated-validation-docker.test.ts --maxWorkers=1 --minWorkers=1:1:unset",
      "npm:test -- tests/upgrade-host-linux.test.ts tests/upgrade-transport-linux.test.ts tests/upgrade-brokers-integration-linux.test.ts tests/upgrade-publication.test.ts --maxWorkers=1 --minWorkers=1:unset:1"]);
  });
  it("fails the full route when the mandatory host proof fails after Docker validation", async () => {
    const result = await fixture("full", "host");
    expect(result.status).toBe(19); expect(result.events).toHaveLength(4);
  });
  it.each(["fast", "docker", "npm"])("fails instead of passing a full run when %s fails", async (failure) => {
    const result = await fixture("full", failure);
    expect(result.status).not.toBe(0);
    if (failure === "fast") expect(result.events).toHaveLength(1);
    if (failure === "docker") expect(result.events).toHaveLength(2);
    if (failure === "npm") expect(result.events).toHaveLength(3);
  });
});
