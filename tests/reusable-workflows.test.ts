import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";

function loadWorkflow(relativePath: string) {
  const workflowPath = path.resolve(relativePath);
  return YAML.parse(readFileSync(workflowPath, "utf8")) as Record<string, unknown>;
}

describe("reusable workflows", () => {
  it("defines the security PR reusable workflow contract", () => {
    const workflow = loadWorkflow(".github/workflows/security-pr.yml");
    expect(workflow.name).toBe("Security PR");
    expect((workflow.on as any).workflow_call.inputs["dependency-review"].default).toBe(true);
    expect((workflow.jobs as any)["dependency-review"]).toBeTruthy();
    expect((workflow.jobs as any).codeql).toBeTruthy();
  });

  it("defines the reusable release workflow contract", () => {
    const workflow = loadWorkflow(".github/workflows/release.yml");
    expect(workflow.name).toBe("Reusable Release");
    expect((workflow.on as any).workflow_call.inputs["runs-on"].default).toBe('["ubuntu-latest"]');
    expect((workflow.on as any).workflow_call.inputs["verify-script"].default).toContain("run-release-verification");
    expect((workflow.on as any).workflow_call.inputs["version-script"].default).toContain("run-release-version");
    expect((workflow.on as any).workflow_call.inputs["build-script"].default).toContain("run-release-build");
    expect((workflow.on as any).workflow_call.inputs["release-notes-file"].default).toBe(
      "dist/release/RELEASE_NOTES.md"
    );
    expect((workflow.on as any).workflow_call.inputs["artifact-dir"].default).toBe("dist/release");
    expect((workflow.on as any).workflow_call.inputs["tag-prefix"].default).toBe("v");
    expect((workflow.on as any).workflow_call.inputs["update-major-tag"].default).toBe(true);
    const releaseJob = (workflow.jobs as any).release;
    expect(releaseJob).toBeTruthy();
    const stepNames = releaseJob.steps.map((step: any) => step.name).filter(Boolean);
    expect(stepNames).toEqual([
      "Derive release metadata",
      "Verify release contract",
      "Run release version hook",
      "Build release artifacts",
      "Publish release artifacts",
      "Generate release notes",
      "Create GitHub release",
      "Promote floating SemVer tags"
    ]);
    const deriveMetadata = releaseJob.steps.find((step: any) => step.name === "Derive release metadata");
    const createRelease = releaseJob.steps.find((step: any) => step.name === "Create GitHub release");
    const promoteTags = releaseJob.steps.find((step: any) => step.name === "Promote floating SemVer tags");
    expect(deriveMetadata.run).toContain("semver_component='(0|[1-9][0-9]*)'");
    expect(deriveMetadata.run).toContain("prerelease_identifier=");
    expect(deriveMetadata.run).toContain("is_prerelease=${is_prerelease}");
    expect(createRelease.run).toContain("release_create_args=(--prerelease --latest=false)");
    expect(createRelease.run).toContain("release_edit_args=(--prerelease)");
    expect(createRelease.env.IS_PRERELEASE).toBe("${{ steps.release_meta.outputs.is_prerelease }}");
    expect(promoteTags.env.IS_PRERELEASE).toBe("${{ steps.release_meta.outputs.is_prerelease }}");
    expect(promoteTags.run).toContain("Skipping floating SemVer tag promotion for prerelease");
    expect(promoteTags.run).toContain("semver_component='(0|[1-9][0-9]*)'");
    expect(deriveMetadata.run).toContain(
      "^${escaped_prefix}${semver_component}\\.${semver_component}\\.${semver_component}${prerelease_pattern}$"
    );
    expect(promoteTags.run).toContain(
      "^${escaped_prefix}${semver_component}\\.${semver_component}\\.${semver_component}$"
    );
  });

  it("defines the reusable AI attestation workflow contract", () => {
    const workflow = loadWorkflow(".github/workflows/ai-attestation-reusable.yml");
    expect(workflow.name).toBe("Reusable AI Attestation");
    expect((workflow.on as any).workflow_call.inputs["artifact_name"].default).toBe("ai-attestation");
    expect((workflow.on as any).workflow_call.inputs["retention_days"].default).toBe(90);
    expect((workflow.jobs as any).attest).toBeTruthy();
    expect((workflow.jobs as any).verify).toBeTruthy();
  });
});
