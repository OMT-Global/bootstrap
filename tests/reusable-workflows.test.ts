import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest } from "../src/manifest.js";

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
    const publishSteps = (publish.jobs as any).publish.steps;
    const publishMatches = publishSteps.filter((step: any) => step.name === "Publish proven release artifact");
    expect(publishMatches).toHaveLength(1);
    const publishStep = publishMatches[0];
    expect(publishStep.run).toContain("PREFLIGHT_ARTIFACT_DIR");
    expect(publishStep.run).toContain("SHA256SUMS");
    expect(publishStep.run).toContain("RELEASE_ASSET_DIR");
    expect(publishStep.run).toContain("while read -r asset_sha asset_path; do");
    expect(publishStep.run).toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS" ]] || { echo "Missing preflight SHA256SUMS manifest." >&2; exit 1; }');
    expect(publishStep.run).toContain("resolve_preflight_asset()");
    expect(publishStep.run).toContain('if ! release_notes_source="$(resolve_preflight_asset "$RELEASE_NOTES_FILE")"; then');
    expect(publishStep.run).toContain('cp -p -- "$release_notes_source" "$RELEASE_NOTES_FILE"');
    expect(publishStep.run).toContain('[[ "$asset_path" != *"release-evidence.json" && "$asset_path" != *"validation-evidence.json" ]] || continue');
    expect(publishStep.run).toContain('if ! asset_source="$(resolve_preflight_asset "$asset_path")"; then');
    expect(publishStep.run).toContain('cp -p -- "$asset_source" "$RELEASE_ASSET_DIR/$asset_name"');
    expect(publishStep.run).toContain('release_assets+=("$RELEASE_ASSET_DIR/$asset_name")');
    expect(publishStep.run).toContain('[[ ${#release_assets[@]} -gt 0 ]] || { echo "No release assets were staged for upload." >&2; exit 1; }');
    expect(publishStep.run).not.toContain('gh release upload "$TAG" "$ARTIFACT_DIR"/*');
    expect(publishStep.run).toContain(
      'Preflight evidence run ID does not match the requested preflight run.'
    );
    expect(publishStep.run).toContain("Preflight evidence target SHA does not match tag SHA.");
    expect(publishStep.run).toContain("Validation evidence target SHA does not match tag SHA.");
    expect(publishStep.run).toContain("release-evidence-validation");
    expect(publishStep.run).toContain("release-evidence.json");
    expect(publishStep.run).toContain("SHA256SUMS");
    expect(publishStep.run).toContain("while read -r asset_sha asset_path; do");
    expect(publishStep.run).not.toContain('[[ -f "$PREFLIGHT_ARTIFACT_DIR/$asset_path" ]] ||');
    expect(publishStep.run).toContain("Validation evidence run ID does not match the requested validation run.");
    expect(publishStep.run).toContain("Validation evidence repo does not match the current repository.");
    expect((publish.on as any).workflow_call.inputs.verify_existing_release.default).toBe(false);
    expect((publish.on as any).workflow_call.inputs.publish_new_source_release.default).toBe(false);
    expect((publish.on as any).workflow_call.inputs.promote_release_aliases.default).toBe(false);
    expect(publishStep.env).toMatchObject({
      TAG: "${{ inputs.tag }}", PREFLIGHT_RUN_ID: "${{ inputs.preflight_run_id }}",
      VALIDATION_RUN_ID: "${{ inputs.validation_run_id }}", VERIFY_EXISTING_RELEASE: "${{ inputs.verify_existing_release }}",
      PUBLISH_NEW_SOURCE_RELEASE: "${{ inputs.publish_new_source_release }}",
      PROMOTE_RELEASE_ALIASES: "${{ inputs.promote_release_aliases }}",
      APPROVAL_PULL_NUMBER: "${{ inputs.approval_pull_number }}", RELEASE_RUNTIME_COMMIT: "${{ vars.RELEASE_RUNTIME_COMMIT }}",
      APPROVED_RUNTIME_ROOT: "${{ github.workspace }}/.bootstrap-release-runtime",
      RELEASE_APP_PRIVATE_KEY: "${{ (inputs.verify_existing_release || inputs.publish_new_source_release || inputs.promote_release_aliases) && secrets.RELEASE_APP_PRIVATE_KEY || '' }}"
    });
    const targetCheckout = publishSteps.find((step: any) => step.with?.ref === "${{ inputs.tag }}");
    expect(targetCheckout.with).toMatchObject({ path: "${{ (inputs.verify_existing_release || inputs.publish_new_source_release || inputs.promote_release_aliases) && 'release-target' || '.' }}",
      "persist-credentials": "${{ !(inputs.verify_existing_release || inputs.publish_new_source_release || inputs.promote_release_aliases) }}" });
    for (const name of ["Validate approved retry runtime selection", "Checkout approved retry runtime", "Build approved retry runtime before exposing App key"]) {
      const matches = publishSteps.filter((step: any) => step.name === name);
      expect(matches).toHaveLength(1);
      expect(matches[0].if).toBe("inputs.verify_existing_release || inputs.publish_new_source_release || inputs.promote_release_aliases");
      expect(publishSteps.indexOf(matches[0])).toBeLessThan(publishSteps.indexOf(publishStep));
      expect(matches[0].env ?? {}).not.toHaveProperty("RELEASE_APP_PRIVATE_KEY");
    }
    expect(publishSteps.find((step: any) => step.name === "Checkout approved retry runtime").with).toMatchObject({
      repository: "OMT-Global/bootstrap", ref: "${{ vars.RELEASE_RUNTIME_COMMIT }}", path: ".bootstrap-release-runtime", "persist-credentials": false
    });
    expect(publishSteps.find((step: any) => step.name === "Build approved retry runtime before exposing App key").run)
      .toContain('[[ "$(git rev-parse HEAD)" == "$RELEASE_RUNTIME_COMMIT" ]] || exit 1');
    expect(publishSteps.find((step: any) => step.with?.name === "${{ inputs.evidence_artifact_name }}-publish").with.path)
      .toBe("${{ (inputs.verify_existing_release || inputs.publish_new_source_release || inputs.promote_release_aliases) && format('{0}/approved-retry-evidence.json', runner.temp) || format('{0}/postpublish-evidence.json', inputs.artifact_dir) }}");
    expect(postpublish.name).toBe("Reusable Release Postpublish");
    expect((postpublish.jobs as any).postpublish).toBeTruthy();
    expect(JSON.stringify(postpublish)).not.toContain("|| true");
    expect(JSON.stringify(postpublish)).toContain("Postpublish verification hook is missing or not executable");
  });
});

// Permission contracts verified from the pinned 7bb026d and b064ddb reusables.
// A reusable workflow cannot elevate permissions delegated by its caller.
const governedCallers = [
  { name: "release-preflight", job: "preflight", permissions: { contents: "read", actions: "read", "id-token": "write" } },
  { name: "full-release-validation", job: "validate", permissions: { contents: "read", actions: "read" } },
  { name: "release-publish", job: "publish", permissions: { contents: "write", actions: "read", packages: "write", "id-token": "write", attestations: "write" } },
  { name: "release-postpublish", job: "postpublish", permissions: { contents: "read", actions: "read" } }
];

function generatedReleaseWorkflows(visibility: "public" | "private") {
  const manifest = normalizeManifest({
    project: { name: "release-pilot", owner: "acme", visibility },
    archetype: { kind: "generic-empty" },
    ci: { codeqlLanguages: ["javascript-typescript"] },
    release: { enabled: true, maturity: "governed" }
  });
  return new Map(renderManagedFiles(manifest)
    .filter((file) => file.path.startsWith(".github/workflows/"))
    .map((file) => [file.path, YAML.parse(file.contents)]));
}

describe("governed release callers", () => {
  for (const { name, job, permissions } of governedCallers) {
    it(`${name} delegates the pinned reusable's permissions in the checked-in caller`, () => {
      const caller = loadWorkflow(`.github/workflows/${name}.yml`);
      const reusable = loadWorkflow(`.github/workflows/${name}-reusable.yml`);
      const call = (caller.jobs as any)[job];
      expect(call.uses).toMatch(new RegExp(`${name}-reusable\\.yml@[0-9a-f]{40}$`));
      expect(reusable.permissions).toEqual(permissions);
      expect(call.permissions).toEqual(reusable.permissions);
    });

    it.each(["public", "private"] as const)(`${name} delegates the reusable's exact permissions for %s repositories`, (visibility) => {
      const files = generatedReleaseWorkflows(visibility);
      const caller = files.get(`.github/workflows/${name}.yml`);
      const reusable = files.get(`.github/workflows/${name}-reusable.yml`);
      expect(reusable.permissions).toEqual(permissions);
      expect(caller.jobs[job].permissions).toEqual(reusable.permissions);
    });
  }

  it("requests public-compatible evidence retention in both checked-in non-publishing callers", () => {
    for (const [name, job] of [["release-preflight", "preflight"], ["full-release-validation", "validate"]]) {
      const workflow = loadWorkflow(`.github/workflows/${name}.yml`);
      expect((workflow.jobs as any)[job!].with.evidence_retention_days).toBe(90);
    }
  });

  it.each([["public", 90], ["private", 365]] as const)("requests %s-compatible evidence retention", (visibility, retention) => {
    const files = generatedReleaseWorkflows(visibility);
    expect(files.get(".github/workflows/release-preflight.yml").jobs.preflight.with.evidence_retention_days).toBe(retention);
    expect(files.get(".github/workflows/full-release-validation.yml").jobs.validate.with.evidence_retention_days).toBe(retention);
  });
});
