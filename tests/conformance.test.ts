import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
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
      "PRS-FORK-SAFETY-001",
      "PRS-LICENSE-001",
      "PRS-MATURITY-001",
      "PRS-OWNERSHIP-001",
      "PRS-PROFILE-001",
      "PRS-REQUIRED-FILE-001",
      "PRS-SECURITY-BASELINE-001"
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

  it("validates the complete public security baseline and authorized capability observations", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const controls = [
      "code-scanning",
      "dependabot-alerts",
      "dependabot-security-updates",
      "dependency-graph",
      "private-vulnerability-reporting",
      "push-protection",
      "secret-scanning"
    ];

    const report = await runConformance(manifest, directory, {
      githubCapabilities: {
        schemaVersion: 1,
        observations: controls.map((control) => ({
          control,
          status: "supported",
          evidence: "enabled",
          remediation: "Keep enabled.",
          ...(control === "dependency-graph" ? { dependencyReviewEnabled: true } : {})
        }))
      }
    });

    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-SECURITY-BASELINE-001", severity: "pass", classification: "conformant" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "pass", classification: "conformant" }));
    expect(report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-CAPABILITY-001")).toEqual([]);
    expect(report.results.filter((entry) => entry.ruleId === "PRS-GITHUB-CAPABILITY-001")).toHaveLength(controls.length);
  });

  it("requires typed activation evidence for a supported dependency graph", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const observation = {
      control: "dependency-graph",
      status: "supported" as const,
      evidence: "enabled",
      remediation: "Keep enabled."
    };

    const unverified = await runConformance(manifest, directory, {
      githubCapabilities: { schemaVersion: 1, observations: [observation] }
    });
    expect(unverified.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-GITHUB-CAPABILITY-001",
      severity: "warning",
      classification: "unverified",
      evidence: expect.arrayContaining(["dependency review activation: no authorized observation provided"])
    }));

    const disabled = await runConformance(manifest, directory, {
      githubCapabilities: { schemaVersion: 1, observations: [{ ...observation, dependencyReviewEnabled: false }] }
    });
    expect(disabled.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-GITHUB-CAPABILITY-001",
      severity: "blocking",
      classification: "misconfigured",
      evidence: expect.arrayContaining(["dependency review activation: disabled"])
    }));

    const enabled = await runConformance(manifest, directory, {
      githubCapabilities: { schemaVersion: 1, observations: [{ ...observation, dependencyReviewEnabled: true }] }
    });
    expect(enabled.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-GITHUB-CAPABILITY-001",
      severity: "pass",
      classification: "conformant",
      evidence: expect.arrayContaining(["dependency review activation: enabled"])
    }));
  });

  it("accepts equivalent unfiltered event syntax and stable versioned GitHub-hosted runners", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const workflowPath = path.join(directory, ".github/workflows/security.yml");
    const workflow = await readFile(workflowPath, "utf8");
    await writeFile(
      workflowPath,
      workflow
        .replace("  pull_request:\n", "  pull_request: {}\n")
        .replaceAll("runs-on: ubuntu-latest", "runs-on: ubuntu-24.04")
        .replace("    - cron: '23 6 * * 1'", "    - cron: '23 6 * JAN 7'")
        .replace("permissions:\n  contents: read", "permissions: read-all")
    );

    const report = await runConformance(manifest, directory);

    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-SECURITY-BASELINE-001", severity: "pass" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "pass" }));
  });

  it("rejects reusable workflow secret inheritance on trusted security events", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const workflowPath = path.join(directory, ".github/workflows/security.yml");
    const workflow = await readFile(workflowPath, "utf8");
    await writeFile(workflowPath, `${workflow}\n  secret-forwarder:\n    if: github.event_name == 'push' || github.event_name == 'schedule'\n    uses: acme/security/.github/workflows/scan.yml@${"b".repeat(40)} # v1\n    secrets: inherit\n  fork-self-hosted:\n    runs-on: self-hosted\n    permissions:\n      contents: read\n    steps:\n      - run: echo unsafe\n`);

    const report = await runConformance(manifest, directory);

    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-FORK-SAFETY-001",
      severity: "blocking",
      evidence: [".github/workflows/security.yml references GitHub Actions secrets"]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-FORK-SAFETY-001",
      severity: "blocking",
      evidence: ["fork-self-hosted does not use GitHub-hosted isolation"]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-SECURITY-BASELINE-001",
      severity: "blocking",
      evidence: [".github/workflows/security.yml includes unmanaged job fork-self-hosted"]
    }));
  });

  it("rejects CodeQL analysis with result upload disabled", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const workflowPath = path.join(directory, ".github/workflows/security.yml");
    const workflow = await readFile(workflowPath, "utf8");
    await writeFile(
      workflowPath,
      workflow.replace(
        '          category: "/language:${{ matrix.language }}"',
        '          category: "/language:${{ matrix.language }}"\n          upload: false'
      )
    );

    const report = await runConformance(manifest, directory);

    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-SECURITY-BASELINE-001",
      severity: "blocking",
      evidence: [".github/workflows/security.yml CodeQL analysis upload is disabled"]
    }));
  });

  it("rejects fail-open security action inputs and unsupported cron cadence", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const workflowPath = path.join(directory, ".github/workflows/security.yml");
    const workflow = await readFile(workflowPath, "utf8");
    await writeFile(
      workflowPath,
      workflow
        .replace("  dependency-review:\n", "  dependency-review:\n    continue-on-error: true\n")
        .replace("  codeql:\n", "  codeql:\n    continue-on-error: true\n")
        .replace("  sbom:\n", "  sbom:\n    continue-on-error: true\n")
        .replace(
          "          fail-on-severity: high",
          "          fail-on-severity: high\n          vulnerability-check: false\n          warn-only: true"
        )
        .replace(
          "          upload-release-assets: false",
          "          upload-release-assets: false\n          upload-artifact: false"
        )
        .replace("    - cron: '23 6 * * 1'", "    - cron: '23 6 * * 1'\n      timezone: Not/AZone")
    );

    const report = await runConformance(manifest, directory);
    const evidence = report.results
      .filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001")
      .flatMap((entry) => entry.evidence)
      .join(" ");

    expect(evidence).toContain("dependency review inputs do not enforce blocking vulnerability checks");
    expect(evidence).toContain("SBOM inputs do not preserve the managed SPDX JSON artifact contract");
    expect(evidence).toContain("job dependency-review can ignore security failures");
    expect(evidence).toContain("job codeql can ignore security failures");
    expect(evidence).toContain("job sbom can ignore security failures");
    expect(evidence).toContain("has no runnable scheduled security scan");

    await writeFile(workflowPath, workflow.replace("    - cron: '23 6 * * 1'", "    - cron: '23 6 * * 1'\n    - cron: '*/1 * * * *'"));
    const unsupportedCadence = await runConformance(manifest, directory);
    expect(unsupportedCadence.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-SECURITY-BASELINE-001",
      severity: "blocking",
      evidence: [".github/workflows/security.yml has no runnable scheduled security scan"]
    }));
  });

  it("rejects unreachable managed actions and checkout source overrides", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const workflowPath = path.join(directory, ".github/workflows/security.yml");
    const workflow = await readFile(workflowPath, "utf8");
    await writeFile(
      workflowPath,
      workflow
        .replace(
          "    steps:\n      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4\n      - uses: github/codeql-action/init@",
          "    steps:\n      - run: exit 1\n      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4\n      - uses: github/codeql-action/init@"
        )
        .replace(
          "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4\n      - uses: anchore/sbom-action@",
          "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4\n        with:\n          repository: attacker/decoy\n      - uses: anchore/sbom-action@"
        )
    );

    const report = await runConformance(manifest, directory);
    const evidence = report.results
      .filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001")
      .flatMap((entry) => entry.evidence)
      .join(" ");

    expect(evidence).toContain("job codeql does not preserve its required action sequence");
    expect(evidence).toContain("job sbom does not preserve its required action sequence");
  });

  it("rejects dependency, matrix, trigger, and schedule suppression paths", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "public-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const workflowPath = path.join(directory, ".github/workflows/security.yml");
    const workflow = await readFile(workflowPath, "utf8");
    await writeFile(
      workflowPath,
      workflow
        .replace('    branches: ["main"]', '    branches: ["main", "!main"]\n    paths-ignore: ["**"]')
        .replace("    - cron: '23 6 * * 1'", "    - cron: '0 0 31 2 *'")
        .replace("  codeql:\n", "  codeql:\n    needs: dependency-review\n")
        .replace(
          '        language: ["javascript-typescript"]',
          '        language: ["javascript-typescript"]\n        exclude:\n          - language: javascript-typescript'
        )
        .replace("  sbom:\n", "  sbom:\n    needs: dependency-review\n")
    );

    const report = await runConformance(manifest, directory);
    const evidence = report.results
      .filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001")
      .flatMap((entry) => entry.evidence)
      .join(" ");

    expect(evidence).toContain("job codeql declares a dependency");
    expect(evidence).toContain("job sbom declares a dependency");
    expect(evidence).toContain("CodeQL languages do not match ci.codeqlLanguages");
    expect(evidence).toContain("does not scan every trusted push to main");
    expect(evidence).toContain("has no runnable scheduled security scan");
  });

  it("rejects invalid or disabled GitHub Actions Dependabot updaters", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "dependabot-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const updater = (version: number, limit?: unknown, directory = "/") => [
      `version: ${version}`,
      "updates:",
      "  - package-ecosystem: github-actions",
      `    directory: ${directory}`,
      "    schedule:",
      "      interval: weekly",
      ...(limit === undefined ? [] : [`    open-pull-requests-limit: ${typeof limit === "string" ? JSON.stringify(limit) : String(limit)}`])
    ].join("\n");

    await writeFile(path.join(directory, ".github/dependabot.yml"), updater(1));
    const invalidVersion = await runConformance(manifest, directory);
    expect(invalidVersion.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-SECURITY-BASELINE-001",
      severity: "blocking",
      evidence: ["Dependabot security updates and GitHub Actions pin updates are not fully projected"]
    }));

    await writeFile(path.join(directory, ".github/dependabot.yml"), updater(2, 0));
    const disabledUpdates = await runConformance(manifest, directory);
    expect(disabledUpdates.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-SECURITY-BASELINE-001",
      severity: "blocking",
      evidence: ["Dependabot security updates and GitHub Actions pin updates are not fully projected"]
    }));

    for (const invalidLimit of [false, -1, 1.5, "5", "not-a-number"]) {
      await writeFile(path.join(directory, ".github/dependabot.yml"), updater(2, invalidLimit));
      const invalidLimitReport = await runConformance(manifest, directory);
      expect(invalidLimitReport.results).toContainEqual(expect.objectContaining({
        ruleId: "PRS-SECURITY-BASELINE-001",
        severity: "blocking",
        evidence: ["Dependabot security updates and GitHub Actions pin updates are not fully projected"]
      }));
    }

    await writeFile(path.join(directory, ".github/dependabot.yml"), updater(2, 11));
    const largeValidLimit = await runConformance(manifest, directory);
    expect(largeValidLimit.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-SECURITY-BASELINE-001",
      severity: "pass"
    }));

    await writeFile(path.join(directory, ".github/dependabot.yml"), updater(2, undefined, "/not-workflows"));
    const wrongDirectory = await runConformance(manifest, directory);
    expect(wrongDirectory.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-SECURITY-BASELINE-001",
      severity: "blocking",
      evidence: ["Dependabot security updates and GitHub Actions pin updates are not fully projected"]
    }));
  });

  it("blocks incomplete public security projection and fork-unsafe workflow fixtures", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "unsafe-security", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service", docs: { security: false } },
      archetype: { kind: "node-ts-service" },
      ci: { dependabot: { enabled: false, securityUpdates: false, versionUpdates: false } },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const unsafeReference = ["$", "{{", "toJSON", "(", "sec", "rets", ")", "}}"].join("");
    await writeFile(path.join(directory, ".github/workflows/security.yml"), [
      "on:",
      "  pull_request_target:",
      "permissions:",
      "  contents: write",
      "jobs:",
      "  dependency-review:",
      "    if: github.event_name == 'pull_request'",
      "    steps:",
      "      - uses: actions/dependency-review-action@v5",
      "        env:",
      `          FIXTURE: ${unsafeReference}`,
      "  codeql:",
      "    if: github.event_name == 'pull_request'",
      "    steps: []",
      "  sbom:",
      "    if: github.event_name == 'pull_request'",
      "    steps: []"
    ].join("\n"));

    const report = await runConformance(manifest, directory);
    const baseline = report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001");
    const forkSafety = report.results.filter((entry) => entry.ruleId === "PRS-FORK-SAFETY-001");
    const capabilities = report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-CAPABILITY-001");

    expect(baseline.every((entry) => entry.severity === "blocking")).toBe(true);
    expect(baseline.map((entry) => entry.evidence.join(" ")).join(" ")).toContain("SECURITY.md");
    expect(baseline.map((entry) => entry.evidence.join(" ")).join(" ")).toContain("Dependabot");
    expect(forkSafety.every((entry) => entry.severity === "blocking")).toBe(true);
    expect(forkSafety.map((entry) => entry.evidence.join(" ")).join(" ")).toContain("pull_request_target");
    expect(forkSafety.map((entry) => entry.evidence.join(" ")).join(" ")).toContain("references GitHub Actions secrets");
    expect(capabilities).toHaveLength(7);
    expect(capabilities.every((entry) => entry.severity === "warning" && entry.classification === "unverified")).toBe(true);
  });

  it("rejects dead trusted scans, wrong advisory routing, decoy actions, and writable pull-request jobs", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "security-target", owner: "acme", visibility: "public", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" },
      release: { reusableWorkflowRef: "a".repeat(40) }
    });
    await applyRepo(manifest, directory);
    const trustedSecretReference = ["$", "{{", " sec", "rets", ".SBOM_TOKEN ", "}}"].join("");
    await writeFile(path.join(directory, "SECURITY.md"), [
      "https://github.com/wrong/repository/security/advisories/new",
      "Acknowledge within 3 business days and update within 10 business days."
    ].join("\n"));
    await writeFile(path.join(directory, ".github/dependabot.yml"), [
      "version: 2",
      "updates:",
      "  - package-ecosystem: github-actions",
      "    directory: /",
      "    schedule:",
      "      interval: weekly",
      "    open-pull-requests-limit: 0"
    ].join("\n"));
    await writeFile(path.join(directory, ".github/workflows/security.yml"), [
      "on:",
      "  pull_request:",
      "    types: [closed]",
      "  push:",
      "    branches: [main]",
      "  schedule:",
      "    - cron: '99 99 99 99 99'",
      "  merge_group:",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  dependency-review:",
      "    if: github.event_name == 'pull_request'",
      "    runs-on: ubuntu-persistent",
      "    permissions:",
      "      contents: write",
      "    steps:",
      "      - if: false",
      "        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4",
      "      - if: false",
      "        uses: actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294 # v5.0.0",
      "  codeql:",
      "    if: github.event_name == 'push' || github.event_name == 'schedule'",
      "    permissions:",
      "      contents: read",
      "    steps:",
      "      - if: false",
      "        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4",
      "      - if: false",
      "        uses: github/codeql-action/init@7188fc363630916deb702c7fdcf4e481b751f97a # v4",
      "        with:",
      "          languages: javascript-typescript",
      "      - if: false",
      "        uses: github/codeql-action/analyze@7188fc363630916deb702c7fdcf4e481b751f97a # v4",
      "  sbom:",
      "    if: github.event_name == 'push' || github.event_name == 'schedule'",
      "    steps:",
      "      - if: false",
      "        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4",
      "      - if: false",
      "        uses: anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0",
      "        env:",
      `          TOKEN: ${trustedSecretReference}`,
      "  decoy:",
      "    if: false",
      "    permissions:",
      "      contents: read",
      "    steps:",
      "      - uses: actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294 # v5.0.0",
      "      - uses: github/codeql-action/init@7188fc363630916deb702c7fdcf4e481b751f97a # v4",
      "      - uses: github/codeql-action/analyze@7188fc363630916deb702c7fdcf4e481b751f97a # v4",
      "      - uses: anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0"
    ].join("\n"));

    const report = await runConformance(manifest, directory);
    const baselineEvidence = report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001").flatMap((entry) => entry.evidence).join(" ");
    const forkEvidence = report.results.filter((entry) => entry.ruleId === "PRS-FORK-SAFETY-001").flatMap((entry) => entry.evidence).join(" ");

    expect(baselineEvidence).toContain("private vulnerability reporting route");
    expect(baselineEvidence).toContain("detail-free fallback contact request");
    expect(baselineEvidence).toContain("all severity remediation and coordinated-disclosure targets");
    expect(baselineEvidence).toContain("Dependabot security updates and GitHub Actions pin updates are not fully projected");
    expect(baselineEvidence).toContain("has no runnable scheduled security scan");
    expect(baselineEvidence).toContain("job dependency-review does not preserve its required action sequence");
    expect(baselineEvidence).toContain("job codeql does not preserve its required action sequence");
    expect(baselineEvidence).toContain("job sbom does not preserve its required action sequence");
    expect(baselineEvidence).toContain("CodeQL languages do not match ci.codeqlLanguages");
    expect(baselineEvidence).toContain("CodeQL analysis category does not preserve per-language evidence");
    expect(baselineEvidence).toContain("SBOM inputs do not preserve the managed SPDX JSON artifact contract");
    expect(baselineEvidence).toContain("codeql lacks contents: read or security-events: write");
    expect(baselineEvidence).toContain("sbom lacks contents: write");
    expect(baselineEvidence).toContain("codeql has no approved security executor boundary");
    expect(baselineEvidence).toContain("sbom has no approved security executor boundary");
    expect(forkEvidence).toContain("does not use GitHub-hosted isolation");
    expect(forkEvidence).toContain("references GitHub Actions secrets");
    expect(forkEvidence).toContain("dependency-review job permissions are not read-only");
    expect(forkEvidence).toContain("decoy may run on pull_request");
    expect(forkEvidence).toContain("includes unapproved event merge_group");
    expect(forkEvidence).toContain("does not use an unfiltered fork-safe pull_request event");
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
    expect(githubCapabilitySnapshotSchema.safeParse({
      ...base,
      observations: [{ ...base.observations[0], dependencyReviewEnabled: true }]
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
