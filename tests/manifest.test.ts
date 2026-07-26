import { describe, expect, it } from "vitest";

import { DEFAULT_ISSUE_LABELS, normalizeManifest, stringifyManifest } from "../src/manifest.js";

const templateDigest = "a".repeat(64);

describe("normalizeManifest", () => {
  it("requires explicit typed licensing and never derives it from repository visibility", () => {
    const privateManifest = normalizeManifest({
      project: { name: "private-product", owner: "acme", visibility: "private" },
      archetype: { kind: "generic-empty" }
    });
    expect(privateManifest.license).toBeUndefined();

    const proprietary = normalizeManifest({
      project: { name: "private-product", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2024-2026",
        template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });
    expect(proprietary.license).toMatchObject({ mode: "proprietary", holder: "Acme LLC", holderVerification: "legal-entity:acme-llc", years: "2024-2026" });

    expect(() => normalizeManifest({
      project: { name: "invalid-license", owner: "acme" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        years: "2026-2024",
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    } as never)).toThrow();
  });

  it("rejects blank legal evidence and nonexistent SPDX identifiers", () => {
    const transition = {
      approvedBy: "legal-reviewer",
      issue: "LEGAL-42",
      ownership: "Ownership verified",
      contributors: "Contributor rights verified",
      distributionHistory: "Distribution history recorded",
      fromMode: "existing-unclassified",
      fromContentSha256: "b".repeat(64),
      toMode: "proprietary",
      toContentSha256: "c".repeat(64)
    };

    for (const field of Object.keys(transition) as Array<keyof typeof transition>) {
      expect(() => normalizeManifest({
        project: { name: "blank-transition", owner: "acme", visibility: "private" },
        license: {
          mode: "proprietary",
          holder: "Acme LLC",
          holderVerification: "legal-entity:acme-llc",
          years: "2026",
          template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:P-1" },
          thirdPartyNotices: [],
          transition: { ...transition, [field]: "   " }
        },
        archetype: { kind: "generic-empty" }
      })).toThrow();
    }

    expect(() => normalizeManifest({
      project: { name: "invalid-spdx", owner: "acme", visibility: "public" },
      license: {
        mode: "spdx",
        identifier: "Definitely-Not-A-License",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: {
          path: "legal/license.txt",
          sha256: templateDigest,
          approval: "maintainer-approved",
          spdxIdentifier: "Definitely-Not-A-License"
        },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    })).toThrow("Use a recognized SPDX license identifier");

    expect(() => normalizeManifest({
      project: { name: "mismatched-spdx-template", owner: "acme", visibility: "public" },
      license: {
        mode: "spdx",
        identifier: "Apache-2.0",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: {
          path: "legal/mit.txt",
          sha256: templateDigest,
          approval: "maintainer-approved",
          spdxIdentifier: "MIT"
        },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    })).toThrow("SPDX templates must be approved for the selected license identifier");

    expect(() => normalizeManifest({
      project: { name: "unbound-spdx-template", owner: "acme", visibility: "public" },
      license: {
        mode: "spdx", identifier: "MIT", holder: "Acme LLC", holderVerification: "legal-entity:acme-llc", years: "2026",
        template: { path: "legal/mit.txt", sha256: templateDigest, approval: "maintainer-approved" }, thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    })).toThrow("SPDX templates must be approved for the selected license identifier");

    const fullRegistryPolicy = normalizeManifest({
      project: { name: "full-spdx-registry", owner: "acme", visibility: "public" },
      license: { mode: "spdx", identifier: "0BSD", holder: "Acme LLC", holderVerification: "legal-entity:acme-llc", years: "2026", template: { path: "legal/0bsd.txt", sha256: templateDigest, approval: "maintainer-approved", spdxIdentifier: "0BSD" }, thirdPartyNotices: [] },
      archetype: { kind: "generic-empty" }
    });
    expect(fullRegistryPolicy.license).toMatchObject({ mode: "spdx", identifier: "0BSD" });

    const legacyTransition = normalizeManifest({
      project: { name: "legacy-transition", owner: "acme", visibility: "private" },
      license: { mode: "proprietary", holder: "Acme LLC", holderVerification: "legal-entity:acme-llc", years: "2026", template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:P-1" }, thirdPartyNotices: [], transition },
      archetype: { kind: "generic-empty" }
    });
    expect(legacyTransition.license?.transition).toMatchObject({ from: { mode: "existing-unclassified", licenseSha256: "b".repeat(64) }, to: { mode: "proprietary", licenseSha256: "c".repeat(64) } });

    const currentTransition = normalizeManifest({
      project: { name: "current-transition", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary", holder: "Acme LLC", holderVerification: "legal-entity:acme-llc", years: "2026",
        template: { path: "legal/proprietary.txt", sha256: templateDigest.toUpperCase(), approval: "counsel:P-1" }, thirdPartyNotices: [],
        transition: {
          from: { mode: "existing-unclassified", licenseSha256: "B".repeat(64) },
          to: { mode: "proprietary", licenseSha256: "C".repeat(64) },
          approvedBy: "legal-reviewer", issue: "LEGAL-42", ownership: "Ownership verified",
          contributors: "Contributor rights verified", distributionHistory: "Distribution history recorded",
          reconciles: [{ path: "COPYING", licenseSha256: "D".repeat(64) }]
        },
        thirdPartyNoticesTransition: {
          fromSha256: "E".repeat(64), toSha256: "F".repeat(64), approvedBy: "legal-reviewer",
          issue: "LEGAL-42", reconciliation: "Every third-party obligation was reviewed"
        }
      },
      archetype: { kind: "generic-empty" }
    });
    expect(currentTransition.license).toMatchObject({
      template: { sha256: templateDigest },
      transition: {
        from: { licenseSha256: "b".repeat(64) },
        to: { licenseSha256: "c".repeat(64) },
        reconciles: [{ path: "COPYING", licenseSha256: "d".repeat(64) }]
      },
      thirdPartyNoticesTransition: { fromSha256: "e".repeat(64), toSha256: "f".repeat(64) }
    });

    expect(() => normalizeManifest({
      project: { name: "injected-holder", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC\nAdditional terms",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    })).toThrow("Use one line without control, format, or separator characters");

    expect(() => normalizeManifest({
      project: { name: "spoofed-approval", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:\u001b[2Jspoofed" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    })).toThrow("Use one line without control, format, or separator characters");

    expect(() => normalizeManifest({
      project: { name: "unicode-spoofed-approval", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:\u202Espoofed" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    })).toThrow("Use one line without control, format, or separator characters");

    expect(normalizeManifest({
      project: { name: "multiline-notice", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:P-1" },
        thirdPartyNotices: [{
          name: "SDK",
          kind: "dependency",
          license: "Apache-2.0",
          source: "https://example.invalid/sdk",
          notice: "\nCopyright contributors.\nSee bundled NOTICE.\n"
        }]
      },
      archetype: { kind: "generic-empty" }
    }).license?.thirdPartyNotices[0]?.notice).toBe("Copyright contributors.\nSee bundled NOTICE.");

    expect(() => normalizeManifest({
      project: { name: "unsafe-notice-boundary", owner: "acme", visibility: "private" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "legal/proprietary.txt", sha256: templateDigest, approval: "counsel:P-1" },
        thirdPartyNotices: [{
          name: "SDK",
          kind: "dependency",
          license: "Apache-2.0",
          source: "https://example.invalid/sdk",
          notice: "\ufeffCopyright contributors."
        }]
      },
      archetype: { kind: "generic-empty" }
    })).toThrow("Do not use control, format, or Unicode separator characters in legal text.");
  });

  it("accepts version 2 manifests as compatibility input", () => {
    const manifest = normalizeManifest({
      version: 2,
      project: {
        name: "apw-cli",
        owner: "OMT-Global",
        visibility: "public",
        defaultBranch: "main"
      },
      repo: {
        managedPaths: ["project.bootstrap.yaml", ".github/workflows/pr-fast-ci.yml"],
        class: "library"
      },
      archetype: {
        kind: "generic-empty",
        packageManager: "npm",
        moduleName: "apw"
      },
      github: {
        createRepo: false,
        reviewers: ["jmcte"],
        requiredStatusChecks: ["CI Gate"],
        security: { dependabot: false }
      },
      ci: {
        policy: "standard-public",
        runnerPolicy: "hybrid-safe",
        workflows: { prFastCi: true }
      }
    } as never);

    expect(manifest.version).toBe(2);
    expect(manifest.project.name).toBe("apw-cli");
    expect(manifest.repo.managedPaths).toContain(".github/workflows/pr-fast-ci.yml");
    expect(manifest.ci.runnerPolicy).toBe("hybrid-safe");
    expect(manifest.github.requiredStatusChecks).toEqual(["CI Gate"]);
  });

  it("preserves unknown top-level settings for resolver reporting", () => {
    const manifest = normalizeManifest({
      project: { name: "future-compatible", owner: "acme" },
      archetype: { kind: "generic-empty" },
      futurePolicySetting: { enabled: true }
    } as never);

    expect(manifest.unknownSettings).toEqual(["futurePolicySetting"]);
  });

  it("requires an explicit canonical target before migrating legacy repository classes", () => {
    expect(() =>
      normalizeManifest({
        project: { name: "legacy-tool", owner: "acme" },
        repo: { class: "tooling" },
        archetype: { kind: "generic-empty" }
      } as never)
    ).toThrow("repo.classMigration.target");

    const manifest = normalizeManifest({
      project: { name: "legacy-tool", owner: "acme" },
      repo: { class: "tooling", classMigration: { target: "cli" } },
      archetype: { kind: "generic-empty" }
    } as never);

    expect(manifest.repo).toMatchObject({ class: "cli", classMigration: { from: "tooling", target: "cli" } });
    expect(stringifyManifest(manifest)).toContain("classMigration:");
    expect(stringifyManifest(manifest)).toContain("from: tooling");
  });

  it("keeps product maturity distinct from release automation maturity", () => {
    const manifest = normalizeManifest({
      project: { name: "stable-library", owner: "acme", maturity: "stable" },
      archetype: { kind: "generic-empty" },
      release: { maturity: "regulated" }
    } as never);

    expect(manifest.project.maturity).toBe("stable");
    expect(manifest.release.maturity).toBe("regulated");
  });

  it("resolves publisher identity without inventing a spending threshold", () => {
    const defaultPublisher = normalizeManifest({
      project: { name: "publisher-default", owner: "acme" },
      archetype: { kind: "generic-empty" }
    });

    expect(defaultPublisher.publisher).toEqual({ key: "acme" });
    expect(stringifyManifest(defaultPublisher)).not.toContain("publisher:");

    const configuredPublisher = normalizeManifest({
      project: { name: "publisher-configured", owner: "acme" },
      publisher: {
        key: "acme-public",
        spendingApprovalThreshold: { amount: 500, currency: "USD" }
      },
      archetype: { kind: "generic-empty" }
    });

    expect(configuredPublisher.publisher).toEqual({
      key: "acme-public",
      spendingApprovalThreshold: { amount: 500, currency: "USD" }
    });
    expect(stringifyManifest(configuredPublisher)).toContain("spendingApprovalThreshold:");
    expect(() =>
      normalizeManifest({
        project: { name: "invalid-currency", owner: "acme" },
        publisher: { spendingApprovalThreshold: { amount: 500, currency: "ZZZ" } },
        archetype: { kind: "generic-empty" }
      })
    ).toThrow();
  });

  it("applies defaults and reviewer-derived governance", () => {
    const manifest = normalizeManifest({
      project: {
        name: "hello-world",
        owner: "acme"
      },
      archetype: {
        kind: "node-ts-service"
      },
      github: {
        reviewers: ["alice", "@acme/platform"]
      }
    });

    expect(manifest.project.defaultBranch).toBe("main");
    expect(manifest.project.displayName).toBeUndefined();
    expect(manifest.repo.managedPaths).toEqual([]);
    expect(manifest.github.codeowners).toEqual([
      {
        pattern: "*",
        owners: ["@alice", "@acme/platform"]
      }
    ]);
    expect(manifest.github.requiredStatusChecks).toEqual(["CI Gate"]);
    expect(manifest.github.issueLabels).toEqual(DEFAULT_ISSUE_LABELS);
    expect(manifest.ci.aiAttestation).toEqual({
      enabled: false,
      artifactName: "ai-attestation",
      retentionDays: 90,
      provider: "unknown",
      model: "unknown",
      promptHash: "unknown",
      reusableWorkflowRepo: "acme/bootstrap",
      reusableWorkflowRef: "refs/heads/main"
    });
    expect(manifest.release).toEqual({
      enabled: true,
      maturity: "simple",
      tagPrefix: "v",
      createGitHubRelease: true,
      updateMajorTag: true,
      updateMinorTag: true,
      reusableWorkflowRepo: "acme/bootstrap",
      reusableWorkflowRef: "refs/heads/main",
      changelog: {
        enabled: true,
        mode: "github-generated-notes",
        categories: [
          { title: "Features", labels: ["type:feature"] },
          { title: "Fixes", labels: ["type:bug"] },
          { title: "Operations", labels: ["area:infra", "area:qa"] },
          { title: "Documentation", labels: ["kind:docs", "documentation"] }
        ]
      },
      versions: [],
      artifacts: {
        directory: "dist/release",
        checksum: "sha256",
        sbom: "optional"
      },
      publish: {
        githubReleaseAssets: true,
        packages: [],
        containers: []
      }
    });
    expect(manifest.environments.stage.reviewers).toEqual(["alice", "acme/platform"]);
    expect(manifest.environments.prod.branches).toEqual(["main"]);
  });

  it("preserves explicit environment reviewers and branches", () => {
    const manifest = normalizeManifest({
      project: {
        name: "py-service",
        owner: "acme"
      },
      archetype: {
        kind: "python-service"
      },
      environments: {
        stage: {
          reviewers: ["release-team"],
          requireApproval: true,
          preventSelfReview: true,
          branches: []
        },
        prod: {
          reviewers: ["release-team"],
          requireApproval: true,
          preventSelfReview: true,
          branches: ["main"]
        }
      }
    });

    expect(manifest.environments.stage.reviewers).toEqual(["release-team"]);
    expect(manifest.environments.prod.branches).toEqual(["main"]);
  });

  it("preserves explicit required checks and managed path selection", () => {
    const manifest = normalizeManifest({
      project: {
        name: "runner-repo",
        owner: "acme"
      },
      repo: {
        managedPaths: ["project.bootstrap.yaml", "docs/bootstrap/**"]
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        requiredStatusChecks: ["test"]
      }
    });

    expect(manifest.repo.managedPaths).toEqual(["project.bootstrap.yaml", "docs/bootstrap/**"]);
    expect(manifest.github.requiredStatusChecks).toEqual(["test"]);
  });

  it("normalizes explicit issue label colors", () => {
    const manifest = normalizeManifest({
      project: {
        name: "labeled-repo",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        issueLabels: [
          {
            name: "area:frontend",
            color: "#1F77B4",
            description: "Frontend work."
          }
        ]
      }
    });

    expect(manifest.github.issueLabels).toEqual([
      {
        name: "area:frontend",
        color: "1f77b4",
        description: "Frontend work."
      }
    ]);
  });

  it("normalizes declared repo-specific workflow lanes", () => {
    const manifest = normalizeManifest({
      project: {
        name: "ops-repo",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      ci: {
        additionalWorkflows: [
          {
            path: ".github\\workflows\\deploy.yml",
            purpose: "Runs deploy orchestration after the standard CI lanes pass."
          }
        ]
      }
    });

    expect(manifest.ci.additionalWorkflows).toEqual([
      {
        path: ".github/workflows/deploy.yml",
        purpose: "Runs deploy orchestration after the standard CI lanes pass."
      }
    ]);
  });

  it("normalizes AI attestation defaults and explicit overrides", () => {
    const manifest = normalizeManifest({
      project: {
        name: "attested-repo",
        owner: "OMT-Global"
      },
      archetype: {
        kind: "generic-empty"
      },
      ci: {
        aiAttestation: {
          enabled: true,
          provider: "OpenAI",
          model: "gpt-5.4",
          promptHash: "sha256:abc123",
          artifactName: "repo-attestation",
          retentionDays: 30,
          reusableWorkflowRef: "refs/tags/bootstrap-v1"
        }
      }
    });

    expect(manifest.ci.aiAttestation).toEqual({
      enabled: true,
      artifactName: "repo-attestation",
      retentionDays: 30,
      provider: "OpenAI",
      model: "gpt-5.4",
      promptHash: "sha256:abc123",
      reusableWorkflowRepo: "OMT-Global/bootstrap",
      reusableWorkflowRef: "refs/tags/bootstrap-v1"
    });
  });

  it("normalizes release defaults and explicit overrides", () => {
    const manifest = normalizeManifest({
      project: {
        name: "release-repo",
        owner: "OMT-Global"
      },
      archetype: {
        kind: "generic-empty"
      },
      release: {
        enabled: true,
        maturity: "governed",
        tagPrefix: "bootstrap-v",
        createGitHubRelease: false,
        updateMajorTag: true,
        updateMinorTag: false,
        reusableWorkflowRef: "refs/tags/v1",
        changelog: {
          enabled: false,
          categories: [{ title: "Infrastructure", labels: ["area:infra"] }]
        },
        versions: [
          { type: "npm", path: "package.json" },
          { type: "python", path: "pyproject.toml" }
        ],
        artifacts: {
          directory: "build/release",
          checksum: "none",
          sbom: "disabled"
        },
        publish: {
          githubReleaseAssets: false,
          packages: ["npm"],
          containers: [
            {
              image: "ghcr.io/omt-global/release-repo",
              updateLatestTag: true
            }
          ]
        }
      }
    });

    expect(manifest.release).toEqual({
      enabled: true,
      maturity: "governed",
      tagPrefix: "bootstrap-v",
      createGitHubRelease: false,
      updateMajorTag: true,
      updateMinorTag: false,
      reusableWorkflowRepo: "OMT-Global/bootstrap",
      reusableWorkflowRef: "refs/tags/v1",
      changelog: {
        enabled: false,
        mode: "github-generated-notes",
        categories: [{ title: "Infrastructure", labels: ["area:infra"] }]
      },
      versions: [
        { type: "npm", path: "package.json" },
        { type: "python", path: "pyproject.toml" }
      ],
      artifacts: {
        directory: "build/release",
        checksum: "none",
        sbom: "disabled"
      },
      publish: {
        githubReleaseAssets: false,
        packages: ["npm"],
        containers: [
          {
            image: "ghcr.io/omt-global/release-repo",
            updateMajorTag: true,
            updateMinorTag: true,
            updateLatestTag: true
          }
        ]
      }
    });
  });

  it("normalizes release automation extension defaults", () => {
    const manifest = normalizeManifest({
      project: {
        name: "release-repo",
        owner: "OMT-Global"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    expect(manifest.release.changelog).toEqual({
      enabled: true,
      mode: "github-generated-notes",
      categories: [
        { title: "Features", labels: ["type:feature"] },
        { title: "Fixes", labels: ["type:bug"] },
        { title: "Operations", labels: ["area:infra", "area:qa"] },
        { title: "Documentation", labels: ["kind:docs", "documentation"] }
      ]
    });
    expect(manifest.release.versions).toEqual([]);
    expect(manifest.release.artifacts).toEqual({
      directory: "dist/release",
      checksum: "sha256",
      sbom: "optional"
    });
    expect(manifest.release.publish).toEqual({
      githubReleaseAssets: true,
      packages: [],
      containers: []
    });
  });

  it("preserves an explicit docs-facing display name", () => {
    const manifest = normalizeManifest({
      project: {
        name: "bootstrap",
        displayName: "Bootstrap",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    expect(manifest.project.name).toBe("bootstrap");
    expect(manifest.project.displayName).toBe("Bootstrap");
  });

  it("drops explicit legacy Claude agent settings", () => {
    const manifest = normalizeManifest({
      project: {
        name: "legacy-claude-repo",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      agents: {
        manageClaudeHome: true,
        enableClaudeWebEnvironment: true,
        enableClaudeDevcontainer: true,
        enableClaudeGitHubAction: true
      }
    });

    expect(manifest.agents).toEqual({
      manageCodexHome: true,
      codexProfile: "default",
      sharedSkills: []
    });
  });


  it("normalizes representative version 2 manifests with rich repo, CI, agent, and capability fields", () => {
    const manifest = normalizeManifest({
      version: 2,
      project: {
        name: "mailplus-intelligence",
        displayName: "MailPlus Intelligence",
        description: "Intelligence and automation workspace for MailPlus-related tooling.",
        visibility: "public",
        owner: "OMT-Global",
        defaultBranch: "main"
      },
      repo: {
        class: "library",
        managedPaths: ["project.bootstrap.yaml", ".github/workflows/claude.yml"],
        docs: {
          readme: true,
          contributing: true,
          security: true
        },
        templates: {
          pullRequest: "standard",
          issueTemplates: ["bug", "feature"]
        },
        env: {
          exampleFile: false,
          strategy: "optional"
        },
        hooks: {
          preCommit: "standard",
          prePush: "none"
        }
      },
      archetype: {
        kind: "generic-empty",
        packageManager: "python",
        moduleName: "mailplus_intelligence"
      },
      github: {
        createRepo: false,
        reviewers: ["jmcte"],
        codeowners: [{ pattern: "*", owners: ["@jmcte"] }],
        allowRebaseMerge: true,
        security: {
          dependabot: false,
          secretScanningHints: true
        }
      },
      ci: {
        policy: "experimental",
        fastChecks: ["secrets", "unit-tests"],
        extendedChecks: ["template-review", "fixture-regression"],
        workflows: {
          prFastCi: true,
          extendedValidation: true,
          claude: true,
          pagesDeploy: false,
          ci: false,
          extras: [
            {
              path: ".github\\workflows\\deploy.yml",
              purpose: "Deploys documentation after CI passes."
            }
          ]
        },
        additionalWorkflows: []
      },
      agents: {
        manageCodexHome: true,
        manageClaudeHome: true,
        codexProfile: "default",
        claudeProfile: "default",
        enableClaudeWebEnvironment: true,
        enableClaudeDevcontainer: true,
        enableClaudeGitHubAction: true,
        sharedSkills: []
      },
      capabilities: {
        pages: {
          enabled: false,
          provider: "cloudflare-pages",
          outputDir: "dist"
        },
        release: {
          enabled: true,
          kind: "github-release"
        },
        docsPublish: {
          enabled: false
        },
        containers: {
          enabled: false
        }
      }
    });

    expect(manifest.version).toBe(2);
    expect(manifest.repo).toMatchObject({
      class: "library",
      docs: { readme: true, contributing: true, security: true },
      env: { exampleFile: false, strategy: "optional" },
      hooks: { preCommit: "standard", prePush: "none" }
    });
    expect(manifest.archetype.packageManager).toBe("python");
    expect(manifest.github.security).toEqual({ dependabot: false, secretScanningHints: true });
    expect(manifest.ci.policy).toBe("experimental");
    expect(manifest.ci.workflows).toMatchObject({
      prFastCi: true,
      extendedValidation: true,
      claude: true,
      pagesDeploy: false,
      ci: false
    });
    expect(manifest.ci.additionalWorkflows).toEqual([
      {
        path: ".github/workflows/deploy.yml",
        purpose: "Deploys documentation after CI passes."
      }
    ]);
    expect(manifest.agents).toMatchObject({
      manageClaudeHome: true,
      claudeProfile: "default",
      enableClaudeWebEnvironment: true,
      enableClaudeDevcontainer: true,
      enableClaudeGitHubAction: true
    });
    expect(manifest.capabilities?.release).toEqual({ enabled: true, kind: "github-release" });
    expect(manifest.release.enabled).toBe(true);
  });

  it("normalizes optional organization governance settings", () => {
    const manifest = normalizeManifest({
      project: {
        name: "bootstrap",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        organization: {
          defaultRepositoryPermission: "read",
          membersCanCreateRepositories: false,
          membersCanCreatePublicRepositories: false,
          membersCanCreatePrivateRepositories: false,
          newRepositorySecurity: {
            dependencyGraph: true,
            dependabotAlerts: true,
            dependabotSecurityUpdates: true,
            secretScanning: true,
            secretScanningPushProtection: true
          }
        }
      }
    });

    expect(manifest.github.organization).toEqual({
      defaultRepositoryPermission: "read",
      membersCanCreateRepositories: false,
      membersCanCreatePublicRepositories: false,
      membersCanCreatePrivateRepositories: false,
      newRepositorySecurity: {
        dependencyGraph: true,
        dependabotAlerts: true,
        dependabotSecurityUpdates: true,
        secretScanning: true,
        secretScanningPushProtection: true
      }
    });
  });

  it("rejects CodeQL languages that require a compiled build contract", () => {
    expect(() => normalizeManifest({
      project: { name: "go-service", owner: "acme", visibility: "public" },
      archetype: { kind: "generic-empty" },
      ci: { codeqlLanguages: ["go"] }
    } as never)).toThrow();
  });

  it("accepts compiled CodeQL languages supported by no-build analysis", () => {
    const manifest = normalizeManifest({
      project: { name: "compiled-service", owner: "acme", visibility: "public" },
      archetype: { kind: "generic-empty" },
      ci: { codeqlLanguages: ["c-cpp", "csharp", "rust"] }
    });

    expect(manifest.ci.codeqlLanguages).toEqual(["c-cpp", "csharp", "rust"]);
  });
});
