import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { sha256 } from "../src/lib/hash.js";
import { projectLicensePolicy } from "../src/licensing.js";
import { loadManifest } from "../src/manifest.js";

const licenseHash = "e512083a9d1748e3956b62c6d15e9e3e0f882b86c2f92c1e892ea3182287f052";
const templateHash = "0a6aa4a08352ee287faa69276561dc15e1c8a0929c2b2db34a56c7663250271a";
const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function fixture(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-dogfood-license-"));
  tempDirs.push(directory);
  await mkdir(path.join(directory, "legal"));
  await writeFile(path.join(directory, "LICENSE"), await readFile("LICENSE"));
  await writeFile(path.join(directory, "legal/mit-license.txt"), await readFile("legal/mit-license.txt"));
  return directory;
}

describe("approved Bootstrap MIT adoption", () => {
  it("projects the existing license byte-identically with six separate source notices and no writes", async () => {
    const manifest = await loadManifest("project.bootstrap.yaml");
    expect(manifest.license).toBeDefined();
    const directory = await fixture();
    const original = await readFile(path.join(directory, "LICENSE"));
    const projection = await projectLicensePolicy(manifest, directory);
    expect(projection?.summary).toMatchObject({
      beforeMode: "existing-unclassified", afterMode: "spdx:MIT", transitionRequired: true
    });
    const license = projection?.files.find((file) => file.path === "LICENSE");
    const notices = projection?.files.find((file) => file.path === "THIRD_PARTY_NOTICES.md");
    expect(Buffer.from(license!.contents)).toEqual(original);
    expect(sha256(license!.contents)).toBe(licenseHash);
    expect(sha256(await readFile("legal/mit-license.txt"))).toBe(templateHash);
    expect(manifest.license!.thirdPartyNotices).toHaveLength(6);
    expect(manifest.license!.transition?.approvedBy).toContain("jmcte");
    expect(notices!.contents.match(/^## /gm)).toHaveLength(6);
    for (const entry of manifest.license!.thirdPartyNotices) {
      expect(notices!.contents).toContain(entry.name);
      expect(notices!.contents).toContain(entry.notice);
    }
    expect((await readdir(directory)).sort()).toEqual(["LICENSE", "legal"]);
    expect(await readFile(path.join(directory, "LICENSE"))).toEqual(original);
  });

  it("preserves complete installed runtime license texts and current immutable Flow attribution", async () => {
    const manifest = await loadManifest("project.bootstrap.yaml");
    expect(manifest.license).toBeDefined();
    for (const [name, file] of [
      ["commander@14.0.3", "node_modules/commander/LICENSE"],
      ["spdx-license-list@6.12.0", "node_modules/spdx-license-list/license"],
      ["yaml@2.9.1", "node_modules/yaml/LICENSE"],
      ["zod@4.6.7", "node_modules/zod/LICENSE"]
    ]) {
      const text = await readFile(file!, "utf8");
      const entry = manifest.license!.thirdPartyNotices.find((notice) => notice.name === name);
      expect(entry?.notice).toContain(text.trim());
      expect(entry?.notice).toContain(sha256(text));
    }
    const flow = manifest.license!.thirdPartyNotices.filter((entry) => entry.kind === "incorporated-source");
    expect(flow).toHaveLength(2);
    for (const entry of flow) {
      expect(entry.source).toContain("669d095891a2fa2c9772735edf3e9cdf44c1214f");
      expect(entry.notice).toContain((await readFile("LICENSE", "utf8")).trim());
    }
    const policy = flow.find((entry) => entry.source.endsWith("policies/public-repository-standard-v1.json"));
    expect(policy?.notice).toContain("504c79e59689f906a234e7145ee5752588b438b3");
    expect(policy?.notice).toContain("0867c061fba5e689394030821e898abf9db7edcc");
  });

  it("requires adoption evidence even when LICENSE is unchanged", async () => {
    const manifest = await loadManifest("project.bootstrap.yaml");
    expect(manifest.license).toBeDefined();
    const directory = await fixture();
    delete manifest.license!.transition;
    await expect(projectLicensePolicy(manifest, directory)).rejects.toThrow("legal hard stop");
  });

  it("rejects modified license or template bytes against the exact approved hashes", async () => {
    const manifest = await loadManifest("project.bootstrap.yaml");
    expect(manifest.license).toBeDefined();
    const licenseDirectory = await fixture();
    await writeFile(path.join(licenseDirectory, "LICENSE"), "Changed legal terms\n");
    await expect(projectLicensePolicy(manifest, licenseDirectory)).rejects.toThrow("transition evidence does not match");
    const templateDirectory = await fixture();
    await writeFile(path.join(templateDirectory, "legal/mit-license.txt"), "Changed template\n");
    await expect(projectLicensePolicy(manifest, templateDirectory)).rejects.toThrow("template digest does not match");
  });
});
