import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { loadManifest, normalizeManifest } from "../src/manifest.js";
import { flowPolicyDigest, loadResolvedFlowPolicy } from "../src/policy.js";
import { selectManagedFiles } from "../src/render.js";

const sourceRef = "refs/tags/v1.0.1";
const sourceDigest = "52877f4225a192c6ac2250a7f289f479be83a923ce15152c517db77ab0d5249d";
const bundlePath = "policy/flow-public-standard.json";

describe("dogfood policy migration", () => {
  it("resolves the Bootstrap manifest against the released Flow policy offline", async () => {
    const manifest = await loadManifest(path.resolve("project.bootstrap.yaml"));
    expect(manifest.policy?.flow).toEqual({ ref: sourceRef, sha256: sourceDigest, bundlePath });
    const resolved = await loadResolvedFlowPolicy(manifest, process.cwd());
    expect(resolved.policy).toMatchObject({
      standard: "public-repository-standard",
      version: "1.0.0",
      humanHardStops: { categories: expect.arrayContaining(["license-change", "public-ownership-change"]) },
      provenance: { literalSecretsProhibited: true, failClosedForRequiredMaterialChanges: true }
    });
    expect(flowPolicyDigest(resolved.policy)).toBe(sourceDigest);
  });

  it.each([
    ["Bootstrap", "project.bootstrap.yaml"],
    ["Flow", "tests/fixtures/dogfood/flow.bootstrap.yaml"]
  ])("binds the %s migration fixture without expanding artifact or legal ownership", async (_name, manifestPath) => {
    const raw = YAML.parse(await readFile(manifestPath, "utf8"));
    const { policy: _existingPolicy, ...unconfigured } = raw;
    const before = normalizeManifest(unconfigured);
    const after = normalizeManifest({
      ...unconfigured,
      policy: { flow: { ref: sourceRef, sha256: sourceDigest, bundlePath } }
    });
    const { policy: _beforePolicy, ...beforeContract } = before;
    const { policy: _afterPolicy, ...afterContract } = after;
    expect(afterContract).toEqual(beforeContract);

    const beforeFiles = selectManagedFiles(before, renderManagedFiles(before));
    const afterFiles = selectManagedFiles(after, renderManagedFiles(after, await loadResolvedFlowPolicy(after, process.cwd())));
    expect(afterFiles.map((file) => file.path)).toEqual(beforeFiles.map((file) => file.path));
    const bindingChanges = _name === "Bootstrap" ? ["project.bootstrap.yaml", "SECURITY.md"] : ["project.bootstrap.yaml"];
    expect(afterFiles.filter((file) => !bindingChanges.includes(file.path)))
      .toEqual(beforeFiles.filter((file) => !bindingChanges.includes(file.path)));
    expect(after.license).toEqual(before.license);
    if (_name === "Flow") {
      expect(after.repo.managedPaths).toEqual([
        ".github/ISSUE_TEMPLATE/implementation.yml",
        ".github/ISSUE_TEMPLATE/flow_blocker.yml"
      ]);
      expect(after.repo.docs.security).toBe(false);
      expect(after.license?.template.approval).toBe("flow-issue-26:maintainer-approval-2026-07-15");
    }
    await expect(loadResolvedFlowPolicy(after, process.cwd()))
      .resolves.toMatchObject({ source: { ref: sourceRef, sha256: sourceDigest } });
  });

  it("rejects a changed snapshot even when its release reference remains unchanged", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-dogfood-"));
    try {
      const manifest = await loadManifest(path.resolve("project.bootstrap.yaml"));
      const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
      bundle.provenance.failClosedForRequiredMaterialChanges = false;
      await writeFile(path.join(directory, "bundle.json"), JSON.stringify(bundle));
      const candidate = {
        ...manifest,
        policy: { flow: { ref: sourceRef, sha256: sourceDigest, bundlePath: "bundle.json" } }
      };
      await expect(loadResolvedFlowPolicy(candidate, directory)).rejects.toThrow("digest does not match");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
