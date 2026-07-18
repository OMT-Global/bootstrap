import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import { conformanceReportSchema, formatConformanceReport, githubCapabilitySnapshotSchema, runConformance } from "../src/conformance.js";
import { normalizeManifest } from "../src/manifest.js";
import { applyRepo } from "../src/render.js";
import { sha256 } from "../src/lib/hash.js";

const proprietaryTemplate = "Copyright {{copyright_years}} {{copyright_holder}}\nApproved proprietary terms.\n";

async function fixtureDirectory(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), "bootstrap-conformance-"));
}

describe("runConformance", () => {
  it("returns deterministic machine-validated blocking results for missing contract fields", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({ project: { name: "missing-contract", owner: "acme" }, archetype: { kind: "generic-empty" } });

    const report = await runConformance(manifest, directory);

    expect(conformanceReportSchema.parse(report)).toEqual(report);
    expect(report.exitCode).toBe(1);
    expect(report.results.map((entry) => entry.ruleId)).toEqual([
      "PRS-ACTION-PIN-001",
      "PRS-CLASS-001",
      "PRS-LICENSE-001",
      "PRS-MATURITY-001",
      "PRS-OWNERSHIP-001",
      "PRS-PROFILE-001",
      "PRS-REQUIRED-FILE-001"
    ]);
    expect(report.results.every((entry) => entry.classification.length > 0)).toBe(true);
  });

  it("passes the core for an applied canonical contract", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "pyproject.toml"), "[project]\nname = 'service'\n");
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const manifest = normalizeManifest({
      project: { name: "canonical-contract", owner: "acme", maturity: "stable" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);

    const report = await runConformance(manifest, directory);

    expect(report.exitCode).toBe(0);
    expect(report.summary.warning).toBe(0);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-PROFILE-001", severity: "pass" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-RECOGNITION-001", severity: "pass" }));
    expect(formatConformanceReport(report)).toContain("Conformance: 0 blocking, 0 warning");
  });

  it("distinguishes supported, unsupported, misconfigured, and waived controls", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "capabilities", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "generic-empty" },
      exceptions: [{
        id: "temporary-pages-waiver",
        policy: "github-pages",
        scope: "github.pages",
        rationale: "The current plan does not provide the required control.",
        approvedBy: "alice",
        issue: "#58",
        expiresAt: "2099-01-01"
      }, {
        id: "temporary-branch-waiver",
        policy: "github-capability",
        scope: "github.branch-protection",
        rationale: "The migration cannot apply required checks yet.",
        approvedBy: "alice",
        issue: "#58",
        expiresAt: "2099-01-01"
      }]
    });

    const report = await runConformance(manifest, directory, {
      githubCapabilities: { schemaVersion: 1, observations: [
        { control: "secret-scanning", status: "supported", evidence: "enabled", remediation: "Keep enabled." },
        { control: "push-protection", status: "unsupported", evidence: "plan does not expose control", remediation: "Upgrade the plan or retain an approved waiver." },
        { control: "branch-protection", status: "misconfigured", evidence: "required checks absent", remediation: "Apply the required branch protection." }
      ] }
    });

    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-GITHUB-CAPABILITY-001", classification: "conformant", severity: "pass" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-GITHUB-CAPABILITY-001", classification: "unsupported", severity: "warning" }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-GITHUB-CAPABILITY-001",
      classification: "waived",
      severity: "pass",
      evidence: expect.arrayContaining(["approved exception temporary-branch-waiver"])
    }));
    expect(report.results.filter((entry) => entry.ruleId === "PRS-EXCEPTION-001").every((entry) => entry.classification === "conformant")).toBe(true);
  });

  it("applies valid waivers only to their canonical conformance targets", async () => {
    const directory = await fixtureDirectory();
    await import("node:fs/promises").then(({ mkdir }) => mkdir(path.join(directory, ".github/workflows"), { recursive: true }));
    await writeFile(path.join(directory, ".github/workflows/unsafe.yml"), "jobs:\n  test:\n    uses: owner/workflow/.github/workflows/test.yml@main\n");
    const manifest = normalizeManifest({
      project: { name: "waivers", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "generic-empty" },
      exceptions: [
        { id: "files", policy: "repository-files", scope: "repo.managed-artifacts", rationale: "migration", approvedBy: "alice", issue: "#58", expiresAt: "2099-01-01" },
        { id: "pins", policy: "supply-chain", scope: "github.workflows.actions", rationale: "migration", approvedBy: "alice", issue: "#58", expiresAt: "2099-01-01" }
      ]
    });

    const report = await runConformance(manifest, directory);

    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-REQUIRED-FILE-001", severity: "pass", classification: "waived" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-ACTION-PIN-001", severity: "pass", classification: "waived" }));
  });

  it("rejects unsafe or multiline capability evidence", () => {
    const base = { schemaVersion: 1, observations: [{ control: "secret-scanning", status: "supported", evidence: "enabled", remediation: "Keep enabled." }] };
    expect(githubCapabilitySnapshotSchema.safeParse(base).success).toBe(true);
    expect(githubCapabilitySnapshotSchema.safeParse({
      ...base,
      observations: [{ ...base.observations[0], evidence: ["access", "token"].join("_") + String.fromCharCode(61) + "fixture" }]
    }).success).toBe(false);
    expect(githubCapabilitySnapshotSchema.safeParse({
      ...base,
      observations: [{ ...base.observations[0], evidence: "enabled\nprivate state" }]
    }).success).toBe(false);
    expect(githubCapabilitySnapshotSchema.safeParse({
      ...base,
      observations: [{ ...base.observations[0], evidence: "enabled\u0008changed" }]
    }).success).toBe(false);
    expect(githubCapabilitySnapshotSchema.safeParse({
      ...base,
      observations: [...base.observations, { ...base.observations[0], status: "misconfigured" }]
    }).success).toBe(false);
    expect(githubCapabilitySnapshotSchema.safeParse({
      ...base,
      observations: [{ ...base.observations[0], evidence: "   ", remediation: "\t" }]
    }).success).toBe(false);
  });

  it("parses actual YAML uses fields and blocks mutable or undocumented references", async () => {
    const directory = await fixtureDirectory();
    await import("node:fs/promises").then(({ mkdir }) => mkdir(path.join(directory, ".github/workflows/fixtures"), { recursive: true }));
    await writeFile(path.join(directory, ".github/workflows/unsafe.yml"), [
      "jobs:",
      "  test:",
      "    steps:",
      "      - { uses: 'actions/checkout@v4' }",
      "      - uses: > # v4",
      "          actions/cache@v4",
      "      - &mutable { uses: actions/upload-artifact@v4 }",
      "      - *mutable",
      `      - uses: actions/setup-node@${"a".repeat(40)} #   `,
      `      - uses: actions/cache@${"d".repeat(40)} # TODO`,
      "      - uses: actions/checkout",
      "      - uses: docker://alpine:latest",
      `      - uses: docker://alpine@sha256:${"b".repeat(64)}`,
      `      - uses: docker://alpine@sha256:${"c".repeat(64)} # 3.20`,
      `      - uses: docker://debian@sha256:${"e".repeat(64)} # bookworm`,
      `      - uses: actions/checkout@${"f".repeat(40)} # release/2026-07`,
      "      - name: &uses-key uses",
      "      - ? *uses-key",
      "        : actions/download-artifact@v4",
      "      - uses: null",
      "      - run: |",
      "          uses: ignored/example@v1"
    ].join("\n"));
    await writeFile(path.join(directory, ".github/workflows/fixtures/not-a-workflow.yml"), "jobs:\n  ignored:\n    uses: ignored/example@v1\n");
    const manifest = normalizeManifest({ project: { name: "pins", owner: "acme", maturity: "stable" }, repo: { class: "service" }, archetype: { kind: "generic-empty" } });

    const report = await runConformance(manifest, directory);
    const pinFailures = report.results.filter((entry) => entry.ruleId === "PRS-ACTION-PIN-001");

    expect(pinFailures).toHaveLength(11);
    expect(pinFailures.every((entry) => entry.severity === "blocking")).toBe(true);
    expect(pinFailures.map((entry) => entry.evidence[0])).toEqual(expect.arrayContaining([
      expect.stringContaining("actions/checkout@v4 is not pinned"),
      expect.stringContaining("actions/cache@v4 is not pinned"),
      expect.stringContaining("actions/upload-artifact@v4 is not pinned"),
      expect.stringContaining("actions/setup-node@" + "a".repeat(40) + " lacks readable release metadata"),
      expect.stringContaining("actions/cache@" + "d".repeat(40) + " lacks readable release metadata"),
      expect.stringContaining("actions/checkout lacks an immutable action reference"),
      expect.stringContaining("actions/download-artifact@v4 is not pinned"),
      expect.stringContaining("uses must be a string action reference"),
      expect.stringContaining("docker://alpine:latest is not pinned"),
      expect.stringContaining("docker://alpine@sha256:" + "b".repeat(64) + " lacks readable release metadata")
    ]));
    expect(pinFailures.map((entry) => entry.evidence.join(" ")).join(" ")).not.toContain("sha256:" + "c".repeat(64));
    expect(pinFailures.map((entry) => entry.evidence.join(" ")).join(" ")).not.toContain("sha256:" + "e".repeat(64));
    expect(pinFailures.map((entry) => entry.evidence.join(" ")).join(" ")).not.toContain("actions/checkout@" + "f".repeat(40));
    expect(pinFailures.map((entry) => entry.evidence.join(" ")).join(" ")).not.toContain("ignored/example");
    expect(pinFailures.find((entry) => entry.evidence[0]?.includes("docker://alpine:latest"))?.remediation).toContain("64-character sha256 digest");
    expect(pinFailures.find((entry) => entry.evidence[0]?.includes("uses must be a string"))?.remediation).toContain("malformed uses value");
  });

  it("rejects a symlinked workflow root without reading outside the repository", async () => {
    const directory = await fixtureDirectory();
    const external = await fixtureDirectory();
    await writeFile(path.join(external, "outside.yml"), "jobs:\n  test:\n    uses: outside/action@v1\n");
    await symlink(external, path.join(directory, ".github"));
    const manifest = normalizeManifest({ project: { name: "root-link", owner: "acme", maturity: "stable" }, repo: { class: "service" }, archetype: { kind: "generic-empty" } });

    const report = await runConformance(manifest, directory);
    const pinFailures = report.results.filter((entry) => entry.ruleId === "PRS-ACTION-PIN-001");

    expect(pinFailures).toHaveLength(1);
    expect(pinFailures[0]).toMatchObject({
      severity: "blocking",
      evidence: [expect.stringContaining(".github: workflow root component")],
      remediation: expect.stringContaining("regular directories and files")
    });
    expect(pinFailures[0]?.evidence.join(" ")).not.toContain("outside/action");
  });

  it("accepts a missing canonical class with a valid scoped exception that is nearing expiry", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-16T12:00:00.000Z"));
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "class-exception", owner: "acme", maturity: "maintenance" },
      archetype: { kind: "generic-empty" },
      exceptions: [
        {
          id: "legacy-class",
          policy: "repository-classification",
          scope: "repo.class",
          rationale: "Class selection is pending owner review.",
          approvedBy: "alice",
          issue: "#56",
          expiresAt: "2026-07-20"
        }
      ]
    });

    try {
      const report = await runConformance(manifest, directory);

      expect(report.results).toContainEqual(
        expect.objectContaining({
          ruleId: "PRS-CLASS-001",
          severity: "pass",
          classification: "waived",
          evidence: ["approved exception legacy-class"]
        })
      );
      expect(report.results).toContainEqual(
        expect.objectContaining({ ruleId: "PRS-EXCEPTION-001", severity: "warning" })
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("reports an existing-license replacement as a stable legal hard stop", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    await writeFile(path.join(directory, "LICENSE"), "MIT License\nCopyright prior holder\n");
    const manifest = normalizeManifest({
      project: { name: "license-transition", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });

    const report = await runConformance(manifest, directory);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-TRANSITION-001", severity: "blocking" }));
    expect(report.results).not.toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: [expect.stringContaining("PRS-LICENSE-TRANSITION-001")]
    }));
  });

  it("fails closed with a stable template rule when approved content does not match its pin", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const manifest = normalizeManifest({
      project: { name: "template-drift", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: "0".repeat(64), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });

    const report = await runConformance(manifest, directory);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-TEMPLATE-001", severity: "blocking" }));
  });

  it("reports independent ownership drift alongside a license-policy failure", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const configured = normalizeManifest({
      project: { name: "combined-failures", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });
    await applyRepo(configured, directory);
    await writeFile(path.join(directory, "AGENTS.md"), "direct edit\n");
    await writeFile(path.join(directory, "LICENSE"), "direct edit\n");
    await rm(path.join(directory, "README.md"));
    await rm(path.join(directory, "THIRD_PARTY_NOTICES.md"));

    const invalidTemplate = normalizeManifest({
      ...configured,
      license: {
        ...configured.license!,
        template: { ...configured.license!.template, sha256: "0".repeat(64) }
      }
    });
    const report = await runConformance(invalidTemplate, directory);

    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-LICENSE-TEMPLATE-001",
      severity: "blocking"
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file AGENTS.md was directly modified."]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file README.md was deleted."]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file LICENSE was directly modified."]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file THIRD_PARTY_NOTICES.md was deleted."]
    }));
  });

  it("preserves the ownership rule when a managed license is edited or deleted", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const manifest = normalizeManifest({
      project: { name: "managed-license-drift", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });
    await applyRepo(manifest, directory);

    await writeFile(path.join(directory, "LICENSE"), "direct edit\n");
    const editedReport = await runConformance(manifest, directory);
    expect(editedReport.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file LICENSE was directly modified."]
    }));
    expect(editedReport.results.filter((entry) =>
      entry.ruleId === "PRS-OWNERSHIP-001" && entry.evidence.some((item) => /managed(?: file)? LICENSE was directly modified/i.test(item))
    ).length).toBe(1);

    await rm(path.join(directory, "LICENSE"));
    const deletedReport = await runConformance(manifest, directory);
    expect(deletedReport.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file LICENSE was deleted."]
    }));
  });

  it("validates LICENSE path safety before reading it without a declared policy", async () => {
    const directory = await fixtureDirectory();
    await symlink(path.join(directory, "missing-license-target"), path.join(directory, "LICENSE"));
    const manifest = normalizeManifest({
      project: { name: "unsafe-unlicensed-output", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "generic-empty" }
    });

    const report = await runConformance(manifest, directory);
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: [expect.stringContaining("LICENSE must be a regular, non-linked repository file")]
    }));
  });
});
