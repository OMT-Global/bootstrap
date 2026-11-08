import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest, stringifyManifest } from "../src/manifest.js";

const approvedLegacyPin = "913b298fab0fb008796011d940ee7362a347659d";
// Exact public caller from 9b77eaaa3ed9ad2da35ec1af9fe13d1563c7cce4, with the old pin and no opt-in.
// Exact old reusable ABI from 913b298fab0fb008796011d940ee7362a347659d; never read moving generated files.
const legacyCaller = readFileSync(new URL("./fixtures/release-postpublish-legacy.yml", import.meta.url), "utf8");
const legacyReusableBytes = readFileSync(new URL("./fixtures/release-postpublish-legacy-reusable.yml", import.meta.url), "utf8");
const legacyReusable = YAML.parse(legacyReusableBytes);

function manifest(release: Record<string, unknown> = {}) {
  return normalizeManifest({
    project: { name: "example", owner: "octo-org" },
    archetype: { kind: "generic-empty" },
    release: {
      enabled: true,
      maturity: "governed",
      reusableWorkflowRepo: "OMT-Global/bootstrap",
      reusableWorkflowRef: approvedLegacyPin,
      ...release
    }
  } as never);
}

function workflows(release: Record<string, unknown> = {}) {
  return new Map(renderManagedFiles(manifest(release)).map((file) => [file.path, file.contents]));
}

describe("standalone postpublish preflight contract", () => {
  it("retains the immutable captured legacy caller and reusable ABI", () => {
    expect(createHash("sha256").update(legacyCaller).digest("hex")).toBe("2a201994f59a50f525dae65e42b77f6b580a8a0bc916f57d95510c95b41523c9");
    expect(createHash("sha256").update(legacyReusableBytes).digest("hex")).toBe("64d7c1c62bcea23cd1d2652199d15ef9cbadd4e99522d850d246ec0b20fdede5");
    expect(legacyReusable.on.workflow_call.inputs.preflight_run_id).toBeUndefined();
  });

  it.each([undefined, false])("preserves exact legacy caller bytes when the selector is %s", (selected) => {
    const release = selected === undefined ? {} : { postpublishRequiresPreflight: selected };
    const caller = workflows(release).get(".github/workflows/release-postpublish.yml")!;
    expect(caller).toBe(legacyCaller);
    const parsed = YAML.parse(caller);
    expect(parsed.on.workflow_dispatch.inputs.preflight_run_id).toBeUndefined();
    expect(parsed.jobs.postpublish.with.preflight_run_id).toBeUndefined();
    expect(Object.keys(parsed.jobs.postpublish.with).every((key) => key in legacyReusable.on.workflow_call.inputs)).toBe(true);
  });

  it("preserves absent-field manifest bytes and explicit boolean values", () => {
    expect(manifest().release.postpublishRequiresPreflight).toBeUndefined();
    expect(stringifyManifest(manifest())).not.toContain("postpublishRequiresPreflight:");
    for (const selected of [false, true]) {
      const normalized = manifest({ postpublishRequiresPreflight: selected });
      expect(normalized.release.postpublishRequiresPreflight).toBe(selected);
      expect(stringifyManifest(normalized)).toContain(`postpublishRequiresPreflight: ${selected}`);
    }
  });

  it.each(["true", "false", 0, 1, null, {}, []])("rejects the non-boolean selector %j", (selected) => {
    expect(() => manifest({ postpublishRequiresPreflight: selected })).toThrow();
  });

  it("requires an explicit run ID and forwards it to the selected new immutable reusable pin", () => {
    const newPin = "a".repeat(40);
    const files = workflows({ postpublishRequiresPreflight: true, reusableWorkflowRef: newPin });
    const caller = YAML.parse(files.get(".github/workflows/release-postpublish.yml")!);
    const reusable = YAML.parse(files.get(".github/workflows/release-postpublish-reusable.yml")!);
    expect(caller.on.workflow_dispatch.inputs.preflight_run_id).toEqual({
      description: "Exact approved release preflight run ID", required: true, type: "string"
    });
    expect(caller.jobs.postpublish.uses).toBe(`OMT-Global/bootstrap/.github/workflows/release-postpublish-reusable.yml@${newPin}`);
    expect(caller.jobs.postpublish.with.preflight_run_id).toBe("${{ inputs.preflight_run_id }}");
    expect(Object.keys(caller.jobs.postpublish.with).every((key) => key in reusable.on.workflow_call.inputs)).toBe(true);
    expect(caller.jobs.postpublish.permissions).toEqual({ contents: "read", actions: "read" });
  });

  it("adds a default-empty reusable input that accepts old callers and reaches the hook environment", () => {
    const files = workflows();
    const reusable = YAML.parse(files.get(".github/workflows/release-postpublish-reusable.yml")!);
    const caller = YAML.parse(legacyCaller);
    expect(reusable.on.workflow_call.inputs.preflight_run_id).toEqual({ required: false, type: "string", default: "" });
    expect(Object.keys(caller.jobs.postpublish.with).every((key) => key in reusable.on.workflow_call.inputs)).toBe(true);
    const verify = reusable.jobs.postpublish.steps.find((step: { name?: string }) => step.name === "Verify published release");
    expect(verify.env.PREFLIGHT_RUN_ID).toBe("${{ inputs.preflight_run_id }}");
    expect(spawnSync("bash", ["-n"], { input: verify.run }).status).toBe(0);
    const publish = YAML.parse(files.get(".github/workflows/release-publish-reusable.yml")!);
    expect(publish.jobs.publish.steps[1].env.PREFLIGHT_RUN_ID).toBe("${{ inputs.preflight_run_id }}");
  });
});
