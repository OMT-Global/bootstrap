import { execFile } from "node:child_process";
import { link, mkdir, mkdtemp, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { normalizeManifest } from "../src/manifest.js";
import { sha256 } from "../src/lib/hash.js";
import { applyRepo, planRepo } from "../src/render.js";
import type { LicensePolicy, LicenseTransitionEvidence } from "../src/types.js";

const proprietaryTemplate = "Copyright {{copyright_years}} {{copyright_holder}}\nAll rights reserved under the approved proprietary terms.\n";
const mitTemplate = "SPDX-License-Identifier: {{spdx_identifier}}\nCopyright {{copyright_years}} {{copyright_holder}}\nMIT license terms from the approved template.\n";
const sharedTemplate = "Copyright {{copyright_years}} {{copyright_holder}}\nTerms supplied by the approved template.\n";
const proprietaryTemplateWithSpdxTag = "SPDX-License-Identifier: MIT\nCopyright {{copyright_years}} {{copyright_holder}}\nAll rights reserved.\n";
const execFileAsync = promisify(execFile);

async function fixture(name: string): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), `bootstrap-${name}-`));
  await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
  await writeFile(path.join(directory, "mit.txt"), mitTemplate);
  await writeFile(path.join(directory, "shared.txt"), sharedTemplate);
  await writeFile(path.join(directory, "proprietary-with-spdx.txt"), proprietaryTemplateWithSpdxTag);
  return directory;
}

function proprietary(overrides: Partial<LicensePolicy> = {}): LicensePolicy {
  return {
    mode: "proprietary",
    holder: "OMT Global LLC",
    holderVerification: "legal-entity:OMT-Global-LLC",
    years: "2026",
    template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "legal-template:P-1" },
    thirdPartyNotices: [],
    ...overrides
  } as LicensePolicy;
}

function manifest(license?: LicensePolicy) {
  return normalizeManifest({
    version: 2,
    project: { name: "licensed-product", owner: "OMT-Global", visibility: "private", maturity: "stable" },
    repo: { class: "service", managedPaths: ["project.bootstrap.yaml"] },
    archetype: { kind: "generic-empty" },
    ...(license ? { license } : {})
  });
}

function renderedTemplate(template: string, holder = "OMT Global LLC", years = "2026", identifier = ""): string {
  return `${template
    .replaceAll("{{copyright_holder}}", () => holder)
    .replaceAll("{{copyright_years}}", () => years)
    .replaceAll("{{spdx_identifier}}", () => identifier)
    .trimEnd()}\n`;
}

function transitionEvidence(
  fromMode: string,
  fromContents: string,
  toMode: string,
  toContents: string
): LicenseTransitionEvidence {
  return {
    approvedBy: "legal-reviewer",
    issue: "LEGAL-42",
    ownership: "Ownership verified",
    contributors: "Contributor rights verified",
    distributionHistory: "Historical grants and distributions recorded",
    fromMode,
    fromContentSha256: sha256(fromContents),
    toMode,
    toContentSha256: sha256(toContents)
  };
}

describe("license policy projection", () => {
  it("does not infer an open-source license from private visibility", async () => {
    const directory = await fixture("unlicensed-private");
    const plan = await planRepo(manifest(), directory);

    expect(plan.license).toBeUndefined();
    expect(plan.changes.map((change) => change.path)).not.toContain("LICENSE");
  });

  it("projects Button King-style proprietary licensing and a separate notice inventory deterministically", async () => {
    const directory = await fixture("button-king");
    const configured = manifest(proprietary({
      thirdPartyNotices: [
        { name: "Pixel Font", kind: "font", license: "OFL-1.1", source: "assets/fonts/pixel-font" },
        { name: "Game SDK", kind: "dependency", license: "Apache-2.0", source: "https://example.invalid/sdk", notice: "Copyright its contributors." },
        { name: "Álpha Asset", kind: "asset", license: "CC0-1.0", source: "assets/alpha" },
        { name: "Zulu Asset", kind: "asset", license: "CC0-1.0", source: "assets/zulu" }
      ]
    }));

    const plan = await planRepo(configured, directory);
    expect(plan.license).toEqual({
      beforeMode: "none",
      afterMode: "proprietary",
      transitionRequired: false,
      templateApproval: "legal-template:P-1"
    });
    expect(plan.changes).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "LICENSE", type: "create" }),
      expect.objectContaining({ path: "THIRD_PARTY_NOTICES.md", type: "create" })
    ]));

    await applyRepo(configured, directory);
    expect(await readFile(path.join(directory, "LICENSE"), "utf8")).toContain("Copyright 2026 OMT Global LLC");
    const notices = await readFile(path.join(directory, "THIRD_PARTY_NOTICES.md"), "utf8");
    expect(notices.indexOf("## Game SDK")).toBeLessThan(notices.indexOf("## Pixel Font"));
    expect(notices.indexOf("## Zulu Asset")).toBeLessThan(notices.indexOf("## Álpha Asset"));
    expect((await planRepo(configured, directory)).changes.every((change) => change.type === "unchanged")).toBe(true);
  });

  it("hard-stops a Pocket Parade-style existing MIT replacement until all legal evidence is supplied", async () => {
    const directory = await fixture("pocket-parade");
    const existingMit = "MIT License\n\nCopyright 2024 Prior Holder\n";
    await writeFile(path.join(directory, "LICENSE"), existingMit);

    await expect(planRepo(manifest(proprietary()), directory)).rejects.toThrow("PRS-LICENSE-TRANSITION-001");

    const approved = manifest(proprietary({
      transition: transitionEvidence(
        "existing-unclassified",
        existingMit,
        "proprietary",
        renderedTemplate(proprietaryTemplate)
      )
    }));
    const plan = await planRepo(approved, directory);
    expect(plan.license).toMatchObject({ beforeMode: "existing-unclassified", afterMode: "proprietary", transitionRequired: true });
  });

  it("does not expose control characters from an unrecognized existing license marker", async () => {
    const directory = await fixture("unsafe-existing-marker");
    await writeFile(path.join(directory, "LICENSE"), "SPDX-License-Identifier: \u001b[2JMIT\n");

    await expect(planRepo(manifest(proprietary()), directory)).rejects.toThrow(
      "adopting or replacing existing-unclassified as proprietary"
    );
  });

  it("requires explicit adoption evidence for a byte-identical unmanaged license", async () => {
    const directory = await fixture("stateless-identical-adoption");
    const renderedLicense = renderedTemplate(sharedTemplate);
    await writeFile(path.join(directory, "LICENSE"), renderedLicense);
    const configured = manifest(proprietary({
      template: { path: "shared.txt", sha256: sha256(sharedTemplate), approval: "legal-template:shared" }
    }));

    await expect(planRepo(configured, directory)).rejects.toThrow("PRS-LICENSE-TRANSITION-001");

    const approved = manifest(proprietary({
      template: { path: "shared.txt", sha256: sha256(sharedTemplate), approval: "legal-template:shared" },
      transition: transitionEvidence(
        "existing-unclassified",
        renderedLicense,
        "proprietary",
        renderedLicense
      )
    }));
    const plan = await planRepo(approved, directory);
    expect(plan.license).toMatchObject({
      beforeMode: "existing-unclassified",
      afterMode: "proprietary",
      transitionRequired: true
    });
  });

  it("recovers managed license ownership without trusting sidecar legal classification", async () => {
    const directory = await fixture("clone-durable-state");
    const configured = manifest(proprietary());
    await applyRepo(configured, directory);
    const localStatePath = path.join(directory, ".bootstrap", "bootstrap-state.json");
    const staleLocalState = JSON.parse(await readFile(localStatePath, "utf8")) as {
      manifestHash: string;
      managedFiles: Record<string, string>;
      license: { contentSha256: string };
    };
    staleLocalState.manifestHash = "stale-checkout";
    staleLocalState.managedFiles.LICENSE = "0".repeat(64);
    staleLocalState.managedFiles[".bootstrap/managed-files.json"] = "0".repeat(64);
    staleLocalState.license.contentSha256 = "0".repeat(64);
    await writeFile(localStatePath, `${JSON.stringify(staleLocalState, null, 2)}\n`);
    await expect(planRepo(configured, directory)).rejects.toThrow("managed LICENSE was directly modified");
    await unlink(localStatePath);
    await execFileAsync("git", ["init", "-q"], { cwd: directory });
    await execFileAsync("git", ["config", "user.name", "Bootstrap Tests"], { cwd: directory });
    await execFileAsync("git", ["config", "user.email", "bootstrap-tests@example.invalid"], { cwd: directory });
    await execFileAsync("git", ["add", "-A"], { cwd: directory });
    await execFileAsync("git", ["-c", "commit.gpgsign=false", "commit", "-qm", "test: track generated projection"], { cwd: directory });

    await expect(planRepo(configured, directory)).rejects.toThrow("PRS-LICENSE-TRANSITION-001");
    const renderedLicense = renderedTemplate(proprietaryTemplate);
    const cloneApproved = manifest(proprietary({
      transition: transitionEvidence("existing-unclassified", renderedLicense, "proprietary", renderedLicense)
    }));
    const plan = await planRepo(cloneApproved, directory);
    expect(plan.changes.find((change) => change.path === "LICENSE")?.type).toBe("unchanged");
    expect(plan.license).toMatchObject({
      beforeMode: "existing-unclassified",
      afterMode: "proprietary",
      transitionRequired: true
    });
    const changedNotices = manifest(proprietary({
      transition: transitionEvidence("existing-unclassified", renderedLicense, "proprietary", renderedLicense),
      thirdPartyNotices: [
        { name: "New SDK", kind: "dependency", license: "MIT", source: "https://example.invalid/sdk" }
      ]
    }));
    await expect(planRepo(changedNotices, directory)).rejects.toThrow("existing third-party notices are unmanaged");
    await expect(planRepo(manifest(), directory)).rejects.toThrow("removing an existing managed license policy is forbidden");
  });

  it("does not trust an untracked ownership sidecar when local state is absent", async () => {
    const directory = await fixture("untrusted-sidecar");
    const configured = manifest(proprietary());
    await applyRepo(configured, directory);
    await unlink(path.join(directory, ".bootstrap", "bootstrap-state.json"));
    await expect(planRepo(manifest(), directory)).rejects.toThrow("removing an existing managed license policy is forbidden");

    const victimContents = "product-owned content\n";
    await writeFile(path.join(directory, "victim.txt"), victimContents);
    const sidecarPath = path.join(directory, ".bootstrap", "managed-files.json");
    const sidecar = JSON.parse(await readFile(sidecarPath, "utf8")) as {
      managedFiles: Record<string, { sha256: string; source: string }>;
    };
    sidecar.managedFiles["victim.txt"] = { sha256: sha256(victimContents), source: "bootstrap" };
    await writeFile(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`);

    const renderedLicense = renderedTemplate(proprietaryTemplate);
    const approvedAdoption = manifest(proprietary({
      transition: transitionEvidence("existing-unclassified", renderedLicense, "proprietary", renderedLicense)
    }));
    await expect(planRepo(approvedAdoption, directory)).rejects.toThrow(
      "victim.txt cannot be removed from mutable sidecar ownership alone"
    );
    expect(await readFile(path.join(directory, "victim.txt"), "utf8")).toBe(victimContents);
  });

  it("supports license planning from a linked-worktree gitdir file", async () => {
    const directory = await fixture("linked-worktree");
    const gitDirectory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-linked-gitdir-"));
    await mkdir(path.join(gitDirectory, "info"));
    await writeFile(path.join(directory, ".git"), `gitdir: ${gitDirectory}\n`);

    const plan = await planRepo(manifest(proprietary()), directory);
    expect(plan.license).toMatchObject({ beforeMode: "none", afterMode: "proprietary" });
  });

  it("hard-stops alternate existing license filenames", async () => {
    for (const fileName of [
      "LICENSE.md",
      "LICENSE.txt",
      "LICENSE-MIT",
      "LICENSE_APACHE",
      "LICENCE",
      "COPYING",
      "COPYING.LESSER",
      "UNLICENSE"
    ]) {
      const directory = await fixture(`alternate-${fileName.toLowerCase().replaceAll(".", "-")}`);
      await writeFile(path.join(directory, fileName), "Prior license terms\n");
      await expect(planRepo(manifest(proprietary()), directory)).rejects.toThrow(
        `alternate license file(s) ${JSON.stringify(fileName)} must be reconciled into LICENSE`
      );
    }
  });

  it("detects line terminators and escapes controls in alternate license filenames", async () => {
    for (const fileName of ["LICENSE-\nMIT", "LICENSE-\u001b[2J"]) {
      const directory = await fixture("control-alternate-license");
      await writeFile(path.join(directory, fileName), "Prior license terms\n");

      let message = "";
      try {
        await planRepo(manifest(proprietary()), directory);
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("alternate license file(s)");
      expect(message).not.toContain("\n");
      expect(message).not.toContain("\u001b");
      expect(message).toMatch(/LICENSE-(?:\\n|\\u001b\[2J)/);
    }
  });

  it("rejects traversal paths recovered from the tracked ownership sidecar", async () => {
    const directory = await fixture("unsafe-sidecar-path");
    const configured = manifest(proprietary());
    await applyRepo(configured, directory);
    await unlink(path.join(directory, ".bootstrap", "bootstrap-state.json"));
    const victimPath = path.join(path.dirname(directory), `${path.basename(directory)}-victim.txt`);
    await writeFile(victimPath, "preserve me\n");
    const sidecarPath = path.join(directory, ".bootstrap", "managed-files.json");
    const sidecar = JSON.parse(await readFile(sidecarPath, "utf8")) as {
      managedFiles: Record<string, { sha256: string; source: string }>;
    };
    sidecar.managedFiles[`../${path.basename(victimPath)}`] = {
      sha256: sha256("preserve me\n"),
      source: "bootstrap"
    };
    await writeFile(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`);

    await expect(planRepo(configured, directory)).rejects.toThrow("Bootstrap ownership sidecar is invalid or incomplete");
    expect(await readFile(victimPath, "utf8")).toBe("preserve me\n");
  });

  it("rejects control and format characters in ownership-sidecar paths", async () => {
    for (const unsafePath of ["victim\nfile", "victim\u001b[2J", "victim\u202efile"]) {
      const directory = await fixture("unsafe-sidecar-control-path");
      const configured = manifest(proprietary());
      await applyRepo(configured, directory);
      await unlink(path.join(directory, ".bootstrap", "bootstrap-state.json"));
      const sidecarPath = path.join(directory, ".bootstrap", "managed-files.json");
      const sidecar = JSON.parse(await readFile(sidecarPath, "utf8")) as {
        managedFiles: Record<string, { sha256: string; source: string }>;
      };
      sidecar.managedFiles[unsafePath] = { sha256: sha256("untrusted\n"), source: "bootstrap" };
      await writeFile(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`);

      await expect(planRepo(configured, directory)).rejects.toThrow(
        "Bootstrap ownership sidecar is invalid or incomplete"
      );
    }
  });

  it("uses current-manifest local state to detect coordinated sidecar tampering", async () => {
    const directory = await fixture("sidecar-tamper-cross-check");
    const configured = manifest(proprietary());
    await applyRepo(configured, directory);
    const changedLicense = "tampered license\n";
    await writeFile(path.join(directory, "LICENSE"), changedLicense);
    const sidecarPath = path.join(directory, ".bootstrap", "managed-files.json");
    const sidecar = JSON.parse(await readFile(sidecarPath, "utf8")) as {
      managedFiles: Record<string, { sha256: string }>;
      license: { contentSha256: string };
    };
    sidecar.managedFiles.LICENSE!.sha256 = sha256(changedLicense);
    sidecar.license.contentSha256 = sha256(changedLicense);
    await writeFile(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`);

    await expect(planRepo(configured, directory)).rejects.toThrow("PRS-OWNERSHIP-001: managed LICENSE was directly modified");
  });

  it("blocks direct edits and requires evidence for an explicit proprietary-to-SPDX rollback", async () => {
    const directory = await fixture("rollback");
    const proprietaryManifest = manifest(proprietary());
    await applyRepo(proprietaryManifest, directory);
    await writeFile(path.join(directory, "LICENSE"), "direct edit\n");
    await expect(planRepo(proprietaryManifest, directory)).rejects.toThrow("PRS-OWNERSHIP-001");

    const deletedDirectory = await fixture("deleted-license");
    await applyRepo(proprietaryManifest, deletedDirectory);
    await unlink(path.join(deletedDirectory, "LICENSE"));
    await expect(planRepo(proprietaryManifest, deletedDirectory)).rejects.toThrow("managed LICENSE was deleted");

    const cleanDirectory = await fixture("spdx-rollback");
    await applyRepo(proprietaryManifest, cleanDirectory);
    const spdx = manifest({
      mode: "spdx",
      identifier: "MIT",
      holder: "OMT Global LLC",
      holderVerification: "legal-entity:OMT-Global-LLC",
      years: "2026",
      template: { path: "mit.txt", sha256: sha256(mitTemplate), approval: "SPDX:MIT", spdxIdentifier: "MIT" },
      thirdPartyNotices: [],
      transition: transitionEvidence(
        "proprietary",
        renderedTemplate(proprietaryTemplate),
        "spdx:MIT",
        renderedTemplate(mitTemplate, "OMT Global LLC", "2026", "MIT")
      )
    });
    const rollback = await planRepo(spdx, cleanDirectory);
    expect(rollback.license).toMatchObject({ beforeMode: "proprietary", afterMode: "spdx:MIT", transitionRequired: true });
  });

  it("requires transition evidence when the legal mode changes but rendered bytes do not", async () => {
    const directory = await fixture("same-bytes-transition");
    const proprietaryManifest = manifest(proprietary({
      template: { path: "shared.txt", sha256: sha256(sharedTemplate), approval: "legal-template:shared" }
    }));
    await applyRepo(proprietaryManifest, directory);

    const spdxPolicy: LicensePolicy = {
      mode: "spdx",
      identifier: "MIT",
      holder: "OMT Global LLC",
      holderVerification: "legal-entity:OMT-Global-LLC",
      years: "2026",
      template: { path: "shared.txt", sha256: sha256(sharedTemplate), approval: "SPDX:MIT", spdxIdentifier: "MIT" },
      thirdPartyNotices: []
    };
    const spdxWithoutEvidence = manifest(spdxPolicy);
    await expect(planRepo(spdxWithoutEvidence, directory)).rejects.toThrow("PRS-LICENSE-TRANSITION-001");

    const spdxPolicyWithEvidence: LicensePolicy = {
      ...spdxPolicy,
      transition: transitionEvidence(
        "proprietary",
        renderedTemplate(sharedTemplate),
        "spdx:MIT",
        renderedTemplate(sharedTemplate)
      )
    };
    const spdxWithEvidence = manifest(spdxPolicyWithEvidence);
    const plan = await planRepo(spdxWithEvidence, directory);
    expect(plan.license).toMatchObject({ beforeMode: "proprietary", afterMode: "spdx:MIT", transitionRequired: true });

    await applyRepo(spdxWithEvidence, directory);
    const staleEvidence = manifest({ ...spdxPolicyWithEvidence, holder: "Changed Holder" });
    await expect(planRepo(staleEvidence, directory)).rejects.toThrow("transition evidence does not match");
  });

  it("rejects literal SPDX tags in proprietary templates", async () => {
    const directory = await fixture("proprietary-literal-spdx");
    const configured = manifest(proprietary({
      template: {
        path: "proprietary-with-spdx.txt",
        sha256: sha256(proprietaryTemplateWithSpdxTag),
        approval: "legal-template:invalid"
      }
    }));

    await expect(planRepo(configured, directory)).rejects.toThrow("proprietary templates cannot declare an SPDX identifier");
  });

  it("rejects SPDX declarations that contradict the selected identifier", async () => {
    const directory = await fixture("mismatched-literal-spdx");
    const apacheTemplate = "SPDX-License-Identifier: Apache-2.0\nCopyright {{copyright_years}} {{copyright_holder}}\n";
    await writeFile(path.join(directory, "apache-literal.txt"), apacheTemplate);
    const configured = manifest({
      mode: "spdx",
      identifier: "MIT",
      holder: "OMT Global LLC",
      holderVerification: "legal-entity:OMT-Global-LLC",
      years: "2026",
      template: {
        path: "apache-literal.txt",
        sha256: sha256(apacheTemplate),
        approval: "SPDX:MIT",
        spdxIdentifier: "MIT"
      },
      thirdPartyNotices: []
    });

    await expect(planRepo(configured, directory)).rejects.toThrow(
      "rendered SPDX declaration does not match the selected identifier"
    );
  });

  it("rejects license templates that escape through symlinks", async () => {
    const directory = await fixture("symlink-template");
    const outsideDirectory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-outside-template-"));
    const outsideTemplate = path.join(outsideDirectory, "proprietary.txt");
    await writeFile(outsideTemplate, proprietaryTemplate);

    await symlink(outsideTemplate, path.join(directory, "linked-template.txt"));
    await expect(planRepo(manifest(proprietary({
      template: {
        path: "linked-template.txt",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:outside"
      }
    })), directory)).rejects.toThrow("path components cannot be symlinks");

    await mkdir(path.join(directory, "legal"));
    await symlink(outsideDirectory, path.join(directory, "legal", "external"));
    await expect(planRepo(manifest(proprietary({
      template: {
        path: "legal/external/proprietary.txt",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:outside-directory"
      }
    })), directory)).rejects.toThrow("path components cannot be symlinks");

    await writeFile(path.join(directory, "LICENSE"), proprietaryTemplate);
    await symlink(directory, path.join(directory, "alias"));
    await expect(planRepo(manifest(proprietary({
      template: {
        path: "alias/LICENSE",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:aliased-output"
      }
    })), directory)).rejects.toThrow("path components cannot be symlinks");

    const hardlinkDirectory = await fixture("hardlink-template-alias");
    await writeFile(path.join(hardlinkDirectory, "LICENSE"), proprietaryTemplate);
    await link(path.join(hardlinkDirectory, "LICENSE"), path.join(hardlinkDirectory, "hardlinked-template.txt"));
    await expect(planRepo(manifest(proprietary({
      template: {
        path: "hardlinked-template.txt",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:hardlinked-output"
      }
    })), hardlinkDirectory)).rejects.toThrow("regular, singly linked file");

    const nonDirectory = await fixture("template-intermediate-file");
    await writeFile(path.join(nonDirectory, "legal"), "not a directory\n");
    await expect(planRepo(manifest(proprietary({
      template: {
        path: "legal/license.txt",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:invalid-intermediate"
      }
    })), nonDirectory)).rejects.toThrow(
      "PRS-LICENSE-TEMPLATE-001: approved license template was not found at legal/license.txt"
    );
  });

  it("hashes exact bytes and rejects non-UTF-8 legal files", async () => {
    const directory = await fixture("invalid-utf8-template");
    const invalidTemplate = Buffer.concat([Buffer.from(proprietaryTemplate), Buffer.from([0xff])]);
    await writeFile(path.join(directory, "invalid-utf8.txt"), invalidTemplate);

    await expect(planRepo(manifest(proprietary({
      template: {
        path: "invalid-utf8.txt",
        sha256: sha256(invalidTemplate),
        approval: "legal-template:invalid-utf8"
      }
    })), directory)).rejects.toThrow("PRS-LICENSE-ENCODING-001: approved license template must be valid UTF-8");

    const existingDirectory = await fixture("invalid-utf8-existing-license");
    await writeFile(path.join(existingDirectory, "LICENSE"), Buffer.from([0xff]));
    await expect(planRepo(manifest(proprietary()), existingDirectory)).rejects.toThrow(
      "PRS-LICENSE-ENCODING-001: existing LICENSE must be valid UTF-8"
    );

    const bomDirectory = await fixture("bom-existing-license");
    const projectedLicense = renderedTemplate(proprietaryTemplate);
    await writeFile(
      path.join(bomDirectory, "LICENSE"),
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(projectedLicense)])
    );
    await expect(planRepo(manifest(proprietary()), bomDirectory)).rejects.toThrow("PRS-LICENSE-TRANSITION-001");
  });

  it("rejects linked managed legal output paths", async () => {
    const directory = await fixture("linked-license-output");
    const outsideDirectory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-outside-output-"));
    const outsideLicense = path.join(outsideDirectory, "LICENSE");
    await writeFile(outsideLicense, renderedTemplate(proprietaryTemplate));
    await symlink(outsideLicense, path.join(directory, "LICENSE"));
    await expect(planRepo(manifest(proprietary()), directory)).rejects.toThrow(
      "PRS-OWNERSHIP-001: LICENSE must be a regular, non-linked repository file"
    );

    const danglingDirectory = await fixture("dangling-license-output");
    await symlink(path.join(outsideDirectory, "missing"), path.join(danglingDirectory, "LICENSE"));
    await expect(planRepo(manifest(proprietary()), danglingDirectory)).rejects.toThrow(
      "PRS-OWNERSHIP-001: LICENSE must be a regular, non-linked repository file"
    );

    const noticesDirectory = await fixture("linked-notices-output");
    const outsideNotices = path.join(outsideDirectory, "THIRD_PARTY_NOTICES.md");
    await writeFile(outsideNotices, "External notices\n");
    await symlink(outsideNotices, path.join(noticesDirectory, "THIRD_PARTY_NOTICES.md"));
    await expect(planRepo(manifest(proprietary()), noticesDirectory)).rejects.toThrow(
      "PRS-OWNERSHIP-001: THIRD_PARTY_NOTICES.md must be a regular, non-linked repository file"
    );

    const hardlinkDirectory = await fixture("hardlinked-license-output");
    await link(outsideLicense, path.join(hardlinkDirectory, "LICENSE"));
    await expect(planRepo(manifest(proprietary()), hardlinkDirectory)).rejects.toThrow(
      "PRS-OWNERSHIP-001: LICENSE must be a regular, non-linked repository file"
    );
  });

  it("rejects case-insensitive aliases of projected notice files", async () => {
    const directory = await fixture("reserved-template-name");
    await writeFile(path.join(directory, "license"), proprietaryTemplate);

    await expect(planRepo(manifest(proprietary({
      template: {
        path: "license",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:reserved-name"
      }
    })), directory)).rejects.toThrow(
      /separate from Bootstrap-managed output files|alternate license file\(s\) "license" must be reconciled/
    );
  });

  it("rejects case-insensitive aliases of other selected managed outputs", async () => {
    const directory = await fixture("managed-output-template-name");
    await writeFile(path.join(directory, "PROJECT.BOOTSTRAP.YAML"), proprietaryTemplate);

    await expect(planRepo(manifest(proprietary({
      template: {
        path: "PROJECT.BOOTSTRAP.YAML",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:managed-output"
      }
    })), directory)).rejects.toThrow("separate from Bootstrap-managed output files");

    await mkdir(path.join(directory, ".BOOTSTRAP"));
    await writeFile(path.join(directory, ".BOOTSTRAP", "MANAGED-FILES.JSON"), proprietaryTemplate);
    await expect(planRepo(manifest(proprietary({
      template: {
        path: ".BOOTSTRAP/MANAGED-FILES.JSON",
        sha256: sha256(proprietaryTemplate),
        approval: "legal-template:ownership-sidecar"
      }
    })), directory)).rejects.toThrow(
      /separate from Bootstrap-managed output files|Bootstrap ownership sidecar is invalid or incomplete/
    );
  });

  it("renders legal metadata literally when it contains replacement tokens", async () => {
    const directory = await fixture("literal-holder");
    const configured = manifest(proprietary({ holder: "Cash $$ {{copyright_years}} Holdings" }));

    await applyRepo(configured, directory);
    expect(await readFile(path.join(directory, "LICENSE"), "utf8")).toContain("Cash $$ {{copyright_years}} Holdings");
  });

  it("preserves approved template bytes outside declared substitutions", async () => {
    const directory = await fixture("template-trailing-bytes");
    const template = "Copyright {{copyright_years}} {{copyright_holder}}  \n\n";
    await writeFile(path.join(directory, "trailing-bytes.txt"), template);
    const configured = manifest(proprietary({
      template: {
        path: "trailing-bytes.txt",
        sha256: sha256(template),
        approval: "legal-template:trailing-bytes"
      }
    }));

    await applyRepo(configured, directory);
    expect(await readFile(path.join(directory, "LICENSE"), "utf8")).toBe(
      "Copyright 2026 OMT Global LLC  \n\n"
    );
  });

  it("preserves unmanaged third-party notice files instead of overwriting them", async () => {
    const directory = await fixture("third-party-preserve");
    await writeFile(path.join(directory, "THIRD_PARTY_NOTICES.md"), "Existing obligations\n");
    await expect(planRepo(manifest(proprietary()), directory)).rejects.toThrow("PRS-LICENSE-NOTICES-001");
  });
});
