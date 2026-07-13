import { describe, expect, it } from "vitest";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest } from "../src/manifest.js";

const autoMergeEvidencePattern =
  /auto-merge (is )?(enabled|armed)|enabled auto-merge|gh pr merge --auto|auto_merge|auto merge enabled|auto-merge (is )?(unavailable|unsafe|not available|not safe)|plan-limit|fallback merge-readiness/i;

function autoMergeEvidenceLines(body: string): string {
  return body
    .split(/\r?\n/)
    .filter((line) => !/^\s*-\s+\[\s\]\s/.test(line))
    .join("\n");
}

describe("renderManagedFiles", () => {
  const archetypes = ["nextjs-web", "node-ts-service", "python-service", "generic-empty"] as const;

  for (const kind of archetypes) {
    it(`renders a stable managed file set for ${kind}`, () => {
      const manifest = normalizeManifest({
        project: {
          name: `${kind}-demo`,
          owner: "acme"
        },
        archetype: {
          kind
        },
        github: {
          reviewers: ["alice"]
        }
      });

      const files = renderManagedFiles(manifest);
      expect(
        files.map((file) => ({
          path: file.path,
          executable: file.executable ?? false
        }))
      ).toMatchSnapshot();

      const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");
      const extendedValidationWorkflow = files.find((file) => file.path === ".github/workflows/extended-validation.yml");
      expect(prWorkflow?.contents).toContain("name: CI Gate");
      expect(prWorkflow?.contents).toContain("dorny/paths-filter@v4");
      expect(prWorkflow?.contents).not.toContain("dorny/paths-filter@v3");
      expect(extendedValidationWorkflow?.contents).toContain("dorny/paths-filter@v4");
      expect(extendedValidationWorkflow?.contents).not.toContain("dorny/paths-filter@v3");
      expect(prWorkflow?.contents).toContain("types: [opened, edited, synchronize, reopened, ready_for_review]");
      expect(prWorkflow?.contents).toContain("['self-hosted', 'linux'");
      expect(prWorkflow?.contents).toContain("validate-pr-description:");
      expect(prWorkflow?.contents).toContain("PR body must close/link an issue");
      expect(prWorkflow?.contents).toContain("refs?|part[[:space:]]+of");
      expect(prWorkflow?.contents).toContain("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#");
      expect(prWorkflow?.contents).toContain("https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/");
      expect(prWorkflow?.contents).toContain("auto_merge_evidence=");
      expect(prWorkflow?.contents).toContain('<<<"$auto_merge_evidence"');

      const prTemplate = files.find((file) => file.path === ".github/PULL_REQUEST_TEMPLATE.md");
      const dependabot = files.find((file) => file.path === ".github/dependabot.yml");
      expect(prTemplate?.contents).toContain("## Summary");
      expect(prTemplate?.contents).toContain("## Governing Issue");
      expect(prTemplate?.contents).toContain("## Validation");
      expect(prTemplate?.contents).toContain("## Bootstrap Governance");
      expect(prTemplate?.contents).toContain("fallback merge-readiness policy applies");
      expect(prTemplate?.contents).toContain("## Notes");
      expect(dependabot?.contents).toContain('package-ecosystem: "npm"');
      expect(dependabot?.contents).toContain('package-ecosystem: "github-actions"');
      expect(dependabot?.contents).toContain("npm-minor-patch");
      expect(dependabot?.contents).toContain("version-update:semver-major");

      expect(files.some((file) => file.path === "CLAUDE.md")).toBe(false);
      expect(files.some((file) => file.path === ".github/workflows/claude.yml")).toBe(false);
      expect(files.some((file) => file.path === ".devcontainer/devcontainer.json")).toBe(false);
      expect(files.some((file) => file.path === "scripts/claude-cloud/setup.sh")).toBe(false);

      const contributing = files.find((file) => file.path === "CONTRIBUTING.md");
      expect(contributing?.contents).toContain("Use `.github/PULL_REQUEST_TEMPLATE.md`");

      expect(prTemplate?.contents).toContain("Refs #<issue-number>");
    });
  }

  it("can disable Dependabot version update rendering", () => {
    const manifest = normalizeManifest({
      project: {
        name: "quiet-deps",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      ci: {
        dependabot: {
          versionUpdates: false
        }
      }
    });

    const files = renderManagedFiles(manifest);
    expect(files.some((file) => file.path === ".github/dependabot.yml")).toBe(false);
    expect(manifest.ci.dependabot.securityUpdates).toBe(true);
  });

  it("uses the primary required status check name in the generated PR workflow", () => {
    const manifest = normalizeManifest({
      project: {
        name: "runner-adoption",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        requiredStatusChecks: ["test"]
      }
    });

    const files = renderManagedFiles(manifest);
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");
    expect(prWorkflow?.contents).toContain("name: test");
    expect(prWorkflow?.contents).not.toContain("name: CI Gate");
  });

  it("does not accept untouched auto-merge checklist text as merge automation evidence", () => {
    const manifest = normalizeManifest({
      project: {
        name: "merge-gated-repo",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    const files = renderManagedFiles(manifest);
    const prTemplate = files.find((file) => file.path === ".github/PULL_REQUEST_TEMPLATE.md");
    const templateBody = prTemplate?.contents ?? "";

    expect(autoMergeEvidencePattern.test(templateBody)).toBe(true);
    expect(autoMergeEvidencePattern.test(autoMergeEvidenceLines(templateBody))).toBe(false);

    const bodyWithAuthorStatement = `${templateBody}\nAuto-merge is unavailable because review is pending.`;
    expect(autoMergeEvidencePattern.test(autoMergeEvidenceLines(bodyWithAuthorStatement))).toBe(true);

    const bodyWithCheckedChecklist = templateBody.replace(
      "- [ ] PR author enabled auto-merge with",
      "- [x] PR author enabled auto-merge with"
    );
    expect(autoMergeEvidencePattern.test(autoMergeEvidenceLines(bodyWithCheckedChecklist))).toBe(true);
  });

  it("uses the display name in docs while keeping the repository slug visible", () => {
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

    const files = renderManagedFiles(manifest);
    const readme = files.find((file) => file.path === "README.md");
    const onboarding = files.find((file) => file.path === "docs/bootstrap/onboarding.md");

    expect(readme?.contents).toContain("# Bootstrap");
    expect(readme?.contents).toContain("- Repository: `acme/bootstrap`");
    expect(readme?.contents).toContain("require approval from someone other than the most recent pusher");
    expect(readme?.contents).toContain("fallback merge-readiness policy");
    expect(onboarding?.contents).toContain("- Product name: `Bootstrap`");
    expect(onboarding?.contents).toContain("- Repository: `acme/bootstrap`");
    expect(onboarding?.contents).toContain(
      "require one approval, code owner review, and approval from someone other than the most recent pusher"
    );
    expect(onboarding?.contents).toContain("PR Fast CI validates the required PR description sections");
    expect(onboarding?.contents).toContain("allow auto-merge` are enabled when the GitHub plan supports them");
    expect(onboarding?.contents).toContain("Fallback merge readiness requires");
  });


  it("renders version 2 docs, templates, environment, and workflow switches", () => {
    const manifest = normalizeManifest({
      version: 2,
      project: {
        name: "mailplus-intelligence",
        displayName: "MailPlus Intelligence",
        description: "Intelligence and automation workspace for MailPlus-related tooling.",
        visibility: "public",
        owner: "OMT-Global"
      },
      repo: {
        class: "library",
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
        security: {
          dependabot: false,
          secretScanningHints: true
        }
      },
      ci: {
        policy: "experimental",
        workflows: {
          prFastCi: true,
          extendedValidation: false,
          claude: true,
          pagesDeploy: false,
          ci: false,
          extras: []
        }
      },
      agents: {
        manageClaudeHome: true,
        enableClaudeWebEnvironment: true,
        enableClaudeDevcontainer: true,
        enableClaudeGitHubAction: true
      },
      capabilities: {
        release: {
          enabled: true,
          kind: "github-release"
        }
      }
    });

    const files = renderManagedFiles(manifest);
    const paths = files.map((file) => file.path);
    const renderedManifest = files.find((file) => file.path === "project.bootstrap.yaml");
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");
    const claudeWorkflow = files.find((file) => file.path === ".github/workflows/claude.yml");

    expect(paths).toContain("SECURITY.md");
    expect(paths).toContain("CLAUDE.md");
    expect(paths).toContain(".github/ISSUE_TEMPLATE/bug.yml");
    expect(paths).toContain(".github/ISSUE_TEMPLATE/feature.yml");
    expect(paths).toContain(".github/workflows/pr-fast-ci.yml");
    expect(paths).toContain(".github/workflows/claude.yml");
    expect(paths).toContain(".devcontainer/devcontainer.json");
    expect(paths).toContain("scripts/claude-cloud/setup.sh");
    expect(paths).toContain("docs/bootstrap/claude-environment.md");
    expect(paths).not.toContain(".env.example");
    expect(paths).not.toContain(".github/workflows/extended-validation.yml");
    expect(renderedManifest?.contents).toContain("version: 2");
    expect(renderedManifest?.contents).toContain("capabilities:");
    expect(renderedManifest?.contents).not.toContain("\nrelease:\n");
    expect(prWorkflow?.contents).toContain("dorny/paths-filter@v4");
    expect(prWorkflow?.contents).not.toContain("dorny/paths-filter@v3");
    expect(claudeWorkflow?.contents).toContain("name: Claude Code");
    expect(claudeWorkflow?.contents).toContain("anthropics/claude-code-action@v1");
  });

  it("documents required PR template enforcement in generated agent instructions", () => {
    const manifest = normalizeManifest({
      project: {
        name: "template-required",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    const files = renderManagedFiles(manifest);
    const agents = files.find((file) => file.path === "AGENTS.md");
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");

    expect(agents?.contents).toContain("PRs must use the generated pull request template");
    expect(prWorkflow?.contents).toContain("- validate-pr-description");
    expect(prWorkflow?.contents).toContain("validate-pr-description=${{ needs.validate-pr-description.result }}");
  });

  it("renders an AI attestation caller workflow when enabled", () => {
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
          reusableWorkflowRef: "refs/tags/bootstrap-v1"
        }
      }
    });

    const files = renderManagedFiles(manifest);
    const attestationWorkflow = files.find((file) => file.path === ".github/workflows/ai-attestation.yml");
    const readme = files.find((file) => file.path === "README.md");
    const onboarding = files.find((file) => file.path === "docs/bootstrap/onboarding.md");

    expect(attestationWorkflow?.contents).toContain("name: AI Attestation");
    expect(attestationWorkflow?.contents).toContain(
      "uses: OMT-Global/bootstrap/.github/workflows/ai-attestation-reusable.yml@refs/tags/bootstrap-v1"
    );
    expect(attestationWorkflow?.contents).toContain(
      "ai_provider: ${{ vars.AI_ATTESTATION_PROVIDER || 'OpenAI' }}"
    );
    expect(readme?.contents).toContain("Optional signed AI attestation workflow");
    expect(onboarding?.contents).toContain("AI attestation workflows");
    expect(onboarding?.contents).toContain("AI_ATTESTATION_PROVIDER");
  });

  it("renders release automation when enabled", () => {
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
        tagPrefix: "v",
        reusableWorkflowRef: "refs/tags/v1"
      }
    });

    const files = renderManagedFiles(manifest);
    const releaseWorkflow = files.find((file) => file.path === ".github/workflows/release-tag.yml");
    const verifyScript = files.find((file) => file.path === "scripts/ci/run-release-verification.sh");
    const versionScript = files.find((file) => file.path === "scripts/ci/run-release-version.sh");
    const buildScript = files.find((file) => file.path === "scripts/ci/run-release-build.sh");
    const publishScript = files.find((file) => file.path === "scripts/ci/run-release-publish.sh");
    const changelogConfig = files.find((file) => file.path === ".github/release.yml");
    const versioningDoc = files.find((file) => file.path === "docs/bootstrap/versioning.md");

    expect(releaseWorkflow?.contents).toContain("name: Release");
    expect(releaseWorkflow?.contents).toContain(
      "uses: OMT-Global/bootstrap/.github/workflows/release.yml@refs/tags/v1"
    );
    expect(releaseWorkflow?.contents).toContain("tag-prefix: 'v'");
    expect(releaseWorkflow?.contents).toContain("version-script: scripts/ci/run-release-version.sh");
    expect(releaseWorkflow?.contents).toContain("build-script: scripts/ci/run-release-build.sh");
    expect(releaseWorkflow?.contents).toContain("artifact-dir: dist/release");
    expect(verifyScript?.contents).toContain("bash scripts/ci/run-fast-checks.sh");
    expect(versionScript?.contents).toContain("No release version surfaces are configured");
    expect(versionScript?.contents).toContain('version="${tag#"${prefix}"}"');
    expect(buildScript?.contents).toContain('artifact_dir="dist/release"');
    expect(buildScript?.contents).toContain("SHA256SUMS");
    expect(buildScript?.contents).toContain("! -name release-evidence.json ! -name validation-evidence.json");
    expect(buildScript?.contents).toContain("No release artifacts were produced");
    expect(publishScript?.contents).toContain("Create exact release tags such as v1.2.3");
    expect(changelogConfig?.contents).toContain("changelog:");
    expect(changelogConfig?.contents).toContain("- title: Features");
    expect(changelogConfig?.contents).toContain('- "*"');
    expect(versioningDoc?.contents).toContain("Semantic Versioning");
    expect(versioningDoc?.contents).toContain("release/X.Y");
    expect(versioningDoc?.contents).toContain("Version Validation");
    expect(versioningDoc?.contents).toContain("Release Artifacts");
    expect(versioningDoc?.contents).toContain("Release Notes");
  });

  it("renders governed release automation when requested", () => {
    const manifest = normalizeManifest({
      project: {
        name: "governed-release-repo",
        owner: "OMT-Global"
      },
      archetype: {
        kind: "generic-empty"
      },
      release: {
        enabled: true,
        maturity: "governed",
        reusableWorkflowRef: "refs/tags/bootstrap-v1"
      }
    });

    const files = renderManagedFiles(manifest);
    const paths = files.map((file) => file.path);
    const preflight = files.find((file) => file.path === ".github/workflows/release-preflight.yml");
    const publish = files.find((file) => file.path === ".github/workflows/release-publish.yml");
    const reusablePublish = files.find(
      (file) => file.path === ".github/workflows/release-publish-reusable.yml"
    );
    const releaseTrain = files.find((file) => file.path === "docs/release-train.md");
    const issueTemplate = files.find((file) => file.path === ".github/ISSUE_TEMPLATE/release_train.yml");

    expect(paths).not.toContain(".github/workflows/release-tag.yml");
    expect(paths).toContain(".github/workflows/release-preflight-reusable.yml");
    expect(paths).toContain(".github/workflows/full-release-validation-reusable.yml");
    expect(paths).toContain(".github/workflows/release-publish-reusable.yml");
    expect(paths).toContain(".github/workflows/release-postpublish-reusable.yml");
    expect(paths).toContain("scripts/release/preflight.sh");
    expect(paths).toContain("scripts/release/postpublish.sh");
    expect(paths).toContain("docs/bootstrap/release-evidence-schema.md");
    expect(preflight?.contents).toContain(
      "uses: OMT-Global/bootstrap/.github/workflows/release-preflight-reusable.yml@refs/tags/bootstrap-v1"
    );
    expect(publish?.contents).toContain("require_release_issue: true");
    expect(publish?.contents).toContain("require_signed_tag: false");
    expect(reusablePublish?.contents).toContain("gh run download");
    expect(reusablePublish?.contents).toContain("PREFLIGHT_ARTIFACT_DIR");
    expect(reusablePublish?.contents).toContain("VALIDATION_ARTIFACT_DIR");
    expect(reusablePublish?.contents).toContain("SHA256SUMS");
    expect(reusablePublish?.contents).toContain("RELEASE_ASSET_DIR");
    expect(reusablePublish?.contents).toContain("while read -r asset_sha asset_path; do");
    expect(reusablePublish?.contents).toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS" ]] || { echo "Missing preflight SHA256SUMS manifest." >&2; exit 1; }');
    expect(reusablePublish?.contents).toContain("resolve_preflight_asset()");
    expect(reusablePublish?.contents).toContain('if ! release_notes_source="$(resolve_preflight_asset "$RELEASE_NOTES_FILE")"; then');
    expect(reusablePublish?.contents).toContain('cp -p -- "$release_notes_source" "$RELEASE_NOTES_FILE"');
    expect(reusablePublish?.contents).toContain('[[ "$asset_path" != *"release-evidence.json" && "$asset_path" != *"validation-evidence.json" ]] || continue');
    expect(reusablePublish?.contents).not.toContain('find "$ARTIFACT_DIR" -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 >>"$ARTIFACT_DIR/SHA256SUMS"');
    expect(reusablePublish?.contents).toContain('if ! asset_source="$(resolve_preflight_asset "$asset_path")"; then');
    expect(reusablePublish?.contents).toContain('cp -p -- "$asset_source" "$RELEASE_ASSET_DIR/$asset_name"');
    expect(reusablePublish?.contents).toContain('release_assets+=("$RELEASE_ASSET_DIR/$asset_name")');
    expect(reusablePublish?.contents).not.toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/$asset_path" ]] ||');
    expect(reusablePublish?.contents).not.toContain('gh release upload "$TAG" "$ARTIFACT_DIR"/*');
    expect(reusablePublish?.contents).not.toContain('gh release upload "$TAG" "${release_assets[@]}" "$ARTIFACT_DIR"/*');
    expect(reusablePublish?.contents).not.toContain('find "$ARTIFACT_DIR" -maxdepth 1 -type f');
    expect(reusablePublish?.contents).toContain('done < "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS"');
    expect(reusablePublish?.contents).toContain("UPDATE_MAJOR_TAG");
    expect(reusablePublish?.contents).toContain(
      "Preflight evidence run ID does not match the requested preflight run."
    );
    expect(reusablePublish?.contents).toContain("Preflight evidence target SHA does not match tag SHA.");
    expect(reusablePublish?.contents).toContain("Validation evidence target SHA does not match tag SHA.");
    expect(reusablePublish?.contents).toContain("Validation evidence run ID does not match the requested validation run.");
    expect(reusablePublish?.contents).toContain("release-evidence-validation");
    const reusableValidation = files.find((file) => file.path === ".github/workflows/full-release-validation-reusable.yml");
    expect(reusableValidation?.contents).toContain("name: ${{ inputs.evidence_artifact_name }}-validation");
    expect(reusableValidation?.contents).not.toContain("inputs.release_package_artifact_name");
    expect(reusablePublish?.contents).not.toContain("|| true");
    expect(reusablePublish?.contents).toContain("Postpublish verification script is required but missing or not executable.");
    expect(releaseTrain?.contents).toContain("Publish must consume the artifact bundle proven by preflight");
    expect(issueTemplate?.contents).toContain("preflight_run_id recorded");
  });

  it("renders npm and python version validation in the release version hook", () => {
    const manifest = normalizeManifest({
      project: {
        name: "versioned-repo",
        owner: "acme"
      },
      archetype: {
        kind: "node-ts-service"
      },
      release: {
        enabled: true,
        versions: [
          { type: "npm", path: "package.json" },
          { type: "python", path: "pyproject.toml" }
        ]
      }
    });

    const files = renderManagedFiles(manifest);
    const versionScript = files.find((file) => file.path === "scripts/ci/run-release-version.sh");

    expect(versionScript?.contents).toContain('npm_file="package.json"');
    expect(versionScript?.contents).toContain('py_file="pyproject.toml"');
    expect(versionScript?.contents).toContain("does not match release tag");
    expect(versionScript?.contents).not.toContain("No release version surfaces are configured");
  });

  it("documents repo-specific workflow lanes without replacing the standard CI frame", () => {
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
            path: ".github/workflows/deploy.yml",
            purpose: "Runs deploy orchestration after the standard CI lanes pass."
          }
        ]
      }
    });

    const files = renderManagedFiles(manifest);
    const readme = files.find((file) => file.path === "README.md");
    const onboarding = files.find((file) => file.path === "docs/bootstrap/onboarding.md");
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");

    expect(readme?.contents).toContain("Repo-Specific Workflow Lanes");
    expect(readme?.contents).toContain("`.github/workflows/deploy.yml`");
    expect(onboarding?.contents).toContain("Do not repurpose them as the required PR gate");
    expect(prWorkflow?.contents).toContain("name: CI Gate");
  });

  it("renders flow governance labels and templates when enabled", () => {
    const manifest = normalizeManifest({
      project: {
        name: "flow-enabled-repo",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        flowGovernance: true
      }
    });

    const files = renderManagedFiles(manifest);
    const prTemplate = files.find((file) => file.path === ".github/PULL_REQUEST_TEMPLATE.md");
    const implementation = files.find((file) => file.path === ".github/ISSUE_TEMPLATE/implementation.yml");
    const blocker = files.find((file) => file.path === ".github/ISSUE_TEMPLATE/flow_blocker.yml");

    expect(manifest.github.issueLabels.some((label) => label.name === "state:needs-repair")).toBe(true);
    expect(manifest.github.issueLabels.some((label) => label.name === "state:implementing")).toBe(true);
    expect(manifest.github.issueLabels.some((label) => label.name === "lane:daedalus")).toBe(true);
    expect(manifest.github.issueLabels.some((label) => label.name === "kind:governance")).toBe(true);
    expect(manifest.github.issueLabels.some((label) => label.name === "priority:p2")).toBe(true);
    expect(prTemplate?.contents).toContain("\n## Flow Contract\n");
    expect(prTemplate?.contents).toContain("\n- [ ] PR author enabled auto-merge where GitHub allows it");
    expect(prTemplate?.contents).toMatch(/^## Summary/m);
    expect(prTemplate?.contents).toMatch(/^## Merge Automation/m);
    expect(prTemplate?.contents).not.toContain("    ## Flow Contract");
    expect(prTemplate?.contents).not.toContain("    ## Summary");
    expect(implementation?.contents).toContain("Autonomy class");
    expect(implementation?.contents).toContain("Recommended lane");
    expect(blocker?.contents).toContain("Required unblock action");
  });

});
