import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

import { loadManifest } from "../src/manifest.js";
import { loadResolvedFlowPolicy } from "../src/policy.js";
import { renderManagedFiles } from "../src/archetypes.js";

const workflowPath = ".github/workflows/node20-compatibility.yml";
const workflow = parse(readFileSync(workflowPath, "utf8"));

describe("project-owned Node 20 compatibility proof", () => {
  it("runs the actual minimum-major application and regression checks on hosted pull requests", () => {
    expect(workflow.on).toHaveProperty("pull_request");
    expect(workflow.on).not.toHaveProperty("pull_request_target");
    expect(workflow.permissions).toEqual({ contents: "read" });
    const job = workflow.jobs["security-response"];
    expect(job["runs-on"]).toBe("ubuntu-24.04");
    expect(job.steps[0]).toEqual({
      uses: "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
      with: { "persist-credentials": false }
    });
    expect(job.steps[1]).toMatchObject({
      uses: "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
      with: { "node-version": "20.20.2" }
    });
    const commands = job.steps.flatMap((step: { run?: string }) => step.run ? [step.run] : []);
    expect(commands).toEqual(expect.arrayContaining([
      expect.stringContaining('process.versions.node.split(".")[0] !== "20"'),
      "npm ci --ignore-scripts", "npm run typecheck", "npm run build",
      expect.stringContaining("tests/security-response-markdown.test.ts tests/security-response-policy.test.ts tests/conformance.test.ts tests/policy.test.ts tests/managed-security-policy.test.ts"),
      expect.stringContaining("node dist/cli.js --help")
    ]));
    expect(readFileSync(workflowPath, "utf8")).not.toContain("secrets.");
  });

  it("keeps the new workflow outside the generated asset projection", async () => {
    const manifest = await loadManifest("project.bootstrap.yaml");
    expect(renderManagedFiles(manifest, await loadResolvedFlowPolicy(manifest, process.cwd())).some((file) => file.path === workflowPath)).toBe(false);
  });
});
