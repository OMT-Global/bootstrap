import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";

function loadWorkflow(relativePath: string) {
  const workflowPath = path.resolve(relativePath);
  return YAML.parse(readFileSync(workflowPath, "utf8")) as Record<string, unknown>;
}

describe("reusable workflows", () => {
  const shellSafePublicRunner = '["self-hosted","linux","shell-only","public"]';

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
    expect((workflow.on as any).workflow_call.inputs["runs-on"].default).toBe(shellSafePublicRunner);
    expect((workflow.on as any).workflow_call.inputs["verify-script"].default).toContain("run-release-verification");
    expect((workflow.on as any).workflow_call.inputs["version-script"].default).toContain("run-release-version");
    expect((workflow.on as any).workflow_call.inputs["build-script"].default).toContain("run-release-build");
    expect((workflow.on as any).workflow_call.inputs["release-notes-file"].default).toBe(
      "dist/release/RELEASE_NOTES.md"
    );
    expect((workflow.on as any).workflow_call.inputs["artifact-dir"].default).toBe("dist/release");
    expect((workflow.on as any).workflow_call.inputs["tag-prefix"].default).toBe("v");
    expect((workflow.on as any).workflow_call.inputs["update-major-tag"].default).toBe(true);
    const releaseSecrets = (workflow.on as any).workflow_call.secrets;
    expect(releaseSecrets.DOCKYARD_DEVELOPER_ID_APPLICATION.required).toBe(false);
    expect(releaseSecrets.DOCKYARD_KEYCHAIN_ACCESS_GROUP.required).toBe(false);
    expect(releaseSecrets.DOCKYARD_NOTARY_KEYCHAIN_PROFILE.required).toBe(false);
    const releaseJob = (workflow.jobs as any).release;
    expect(releaseJob).toBeTruthy();
    expect(releaseJob.env.DOCKYARD_DEVELOPER_ID_APPLICATION).toBe(
      "${{ secrets.DOCKYARD_DEVELOPER_ID_APPLICATION }}"
    );
    expect(releaseJob.env.DOCKYARD_KEYCHAIN_ACCESS_GROUP).toBe("${{ secrets.DOCKYARD_KEYCHAIN_ACCESS_GROUP }}");
    expect(releaseJob.env.DOCKYARD_NOTARY_KEYCHAIN_PROFILE).toBe(
      "${{ secrets.DOCKYARD_NOTARY_KEYCHAIN_PROFILE }}"
    );
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
    const publishArtifacts = releaseJob.steps.find((step: any) => step.name === "Publish release artifacts");
    const createRelease = releaseJob.steps.find((step: any) => step.name === "Create GitHub release");
    const promoteTags = releaseJob.steps.find((step: any) => step.name === "Promote floating SemVer tags");
    expect(deriveMetadata.run).toContain("semver_component='(0|[1-9][0-9]*)'");
    expect(publishArtifacts.env.GH_TOKEN).toBe("${{ github.token }}");
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
    expect((workflow.jobs as any).attest["runs-on"]).toBe("ubuntu-latest");
    expect((workflow.jobs as any).verify["runs-on"]).toBe("ubuntu-latest");
  });

  it("defines governed release train reusable workflow contracts", () => {
    const preflight = loadWorkflow(".github/workflows/release-preflight-reusable.yml");
    const validation = loadWorkflow(".github/workflows/full-release-validation-reusable.yml");
    const publish = loadWorkflow(".github/workflows/release-publish-reusable.yml");
    const postpublish = loadWorkflow(".github/workflows/release-postpublish-reusable.yml");

    expect(preflight.name).toBe("Reusable Release Preflight");
    expect((preflight.on as any).workflow_call.inputs.version.required).toBe(true);
    expect((validation.on as any).workflow_call.inputs.evidence_artifact_name.default).toBe("release-evidence");
    expect((validation.on as any).workflow_call.inputs.release_package_artifact_name).toBeUndefined();
    expect((validation.jobs as any).validate.steps.some((step: any) => step.uses === "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" && step.with?.name === "${{ inputs.evidence_artifact_name }}-validation")).toBe(true);
    expect((preflight.jobs as any).preflight).toBeTruthy();
    expect(validation.name).toBe("Reusable Full Release Validation");
    expect((validation.jobs as any).validate).toBeTruthy();
    expect(publish.name).toBe("Reusable Release Publish");
    expect(JSON.stringify(publish)).not.toContain("|| true");
    expect((publish.on as any).workflow_call.inputs.require_release_issue.default).toBe(true);
    expect((publish.on as any).workflow_call.inputs.default_branch.default).toBe("main");
    expect((publish.jobs as any).publish.environment).toBe(
      "${{ inputs.publish_environment || 'release-publish' }}"
    );
    expect((publish.jobs as any).publish.steps[1].run).toContain("PREFLIGHT_ARTIFACT_DIR");
    expect((publish.jobs as any).publish.steps[1].run).toContain("SHA256SUMS");
    expect((publish.jobs as any).publish.steps[1].run).toContain("RELEASE_ASSET_DIR");
    expect((publish.jobs as any).publish.steps[1].run).toContain("while read -r asset_sha asset_path; do");
    expect((publish.jobs as any).publish.steps[1].run).toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS" ]] || { echo "Missing preflight SHA256SUMS manifest." >&2; exit 1; }');
    expect((publish.jobs as any).publish.steps[1].run).toContain("resolve_preflight_asset()");
    expect((publish.jobs as any).publish.steps[1].run).toContain('if ! release_notes_source="$(resolve_preflight_asset "$RELEASE_NOTES_FILE")"; then');
    expect((publish.jobs as any).publish.steps[1].run).toContain('cp -p -- "$release_notes_source" "$RELEASE_NOTES_FILE"');
    expect((publish.jobs as any).publish.steps[1].run).toContain('[[ "$asset_path" != *"release-evidence.json" && "$asset_path" != *"validation-evidence.json" ]] || continue');
    expect((publish.jobs as any).publish.steps[1].run).toContain('if ! asset_source="$(resolve_preflight_asset "$asset_path")"; then');
    expect((publish.jobs as any).publish.steps[1].run).toContain('cp -p -- "$asset_source" "$RELEASE_ASSET_DIR/$asset_name"');
    expect((publish.jobs as any).publish.steps[1].run).toContain('release_assets+=("$RELEASE_ASSET_DIR/$asset_name")');
    expect((publish.jobs as any).publish.steps[1].run).toContain('[[ ${#release_assets[@]} -gt 0 ]] || { echo "No release assets were staged for upload." >&2; exit 1; }');
    expect((publish.jobs as any).publish.steps[1].run).not.toContain('gh release upload "$TAG" "$ARTIFACT_DIR"/*');
    expect((publish.jobs as any).publish.steps[1].run).toContain(
      'Preflight evidence run ID does not match the requested preflight run.'
    );
    expect((publish.jobs as any).publish.steps[1].run).toContain("Preflight evidence target SHA does not match tag SHA.");
    expect((publish.jobs as any).publish.steps[1].run).toContain("Validation evidence target SHA does not match tag SHA.");
    expect((publish.jobs as any).publish.steps[1].run).toContain("release-evidence-validation");
    expect((publish.jobs as any).publish.steps[1].run).toContain("release-evidence.json");
    expect((publish.jobs as any).publish.steps[1].run).toContain("SHA256SUMS");
    expect((publish.jobs as any).publish.steps[1].run).toContain("while read -r asset_sha asset_path; do");
    expect((publish.jobs as any).publish.steps[1].run).not.toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/$asset_path" ]] ||');
    expect((publish.jobs as any).publish.steps[1].run).toContain("Validation evidence run ID does not match the requested validation run.");
    expect((publish.jobs as any).publish.steps[1].run).toContain("Validation evidence repo does not match the current repository.");
    expect(postpublish.name).toBe("Reusable Release Postpublish");
    expect((postpublish.jobs as any).postpublish).toBeTruthy();
    expect(JSON.stringify(postpublish)).not.toContain("|| true");
    expect(JSON.stringify(postpublish)).toContain("Postpublish verification hook is missing or not executable");
  });
});
