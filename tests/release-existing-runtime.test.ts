import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import YAML from "yaml";
import { promoteApprovedBootstrapReleaseAliases, publishNewBootstrapSourceRelease, releaseAppJwt, runExistingReleaseRuntime } from "../src/release-existing-runtime.js";
import { normalizeManifest } from "../src/manifest.js";
import { renderManagedFiles } from "../src/archetypes.js";
import * as preparation from "../src/release-github-package-preparation.js";
import * as validation from "../src/release-validation-evidence.js";
import { approvedReleasePackageMetadata, prepareApprovedReleasePackage } from "../src/release-approved-package.js";
import { publicationQualificationFixture } from "./helpers/publication-qualification-fixture.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

describe("approved retry executable boundary", () => {
  it("signs a short-lived dedicated App JWT using only a fabricated RSA key", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const token = releaseAppJwt(privateKey.export({ type: "pkcs8", format: "pem" }).toString(), 123, 1_800_000_000_000);
    const [header, payload, signature] = token.split(".");
    expect(JSON.parse(Buffer.from(header!, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    expect(JSON.parse(Buffer.from(payload!, "base64url").toString())).toEqual({ iat: 1_799_999_940, exp: 1_800_000_540, iss: "123" });
    expect(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature!, "base64url"))).toBe(true);
  });
  it("rejects invalid configuration before any provider or key use", async () => {
    const provider = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("must not call provider"); });
    try {
      await expect(runExistingReleaseRuntime({ RELEASE_RETRY_CONFIG: "{}", RELEASE_APP_PRIVATE_KEY: "fabricated-invalid-key" })).rejects.toThrow();
      expect(provider).not.toHaveBeenCalled();
    } finally { provider.mockRestore(); }
  });
  it.each(["retry", "publication", "aliases"])("runs the concrete App-token and workflow consumer: %s", async (mode) => {
    const publish = mode === "publication", aliases = mode === "aliases";
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "retry-runtime-")));
    await mkdir(path.join(root, "release-target"));
    const source = packageFixture();
    const manifest = JSON.parse(Buffer.from(source.observation.manifestBytes).toString());
    manifest.repository.full_name = "OMT-Global/bootstrap";
    function canonical(value: any): any { return Array.isArray(value) ? value.map(canonical) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k])])) : value; }
    source.observation.manifestBytes = Buffer.from(`${JSON.stringify(canonical(manifest))}\n`);
    source.observation.actual.repository.full_name = manifest.repository.full_name;
    const digest = createHash("sha256").update(source.observation.manifestBytes).digest("hex");
    source.observation.reviews[0]!.body = `APPROVE-RELEASE-SHA256 ${digest}`;
    const pkg = prepareApprovedReleasePackage(source);
    const m = approvedReleasePackageMetadata(pkg);
    const blobSha = createHash("sha1").update(`blob ${source.observation.manifestBytes.length}\0`).update(source.observation.manifestBytes).digest("hex");
    const key = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const qualification = publicationQualificationFixture(m);
    const { json, sha256, qualifierId } = qualification.qualification;
    const aliasRecord = { schema_version: 1, action: "promote_release_aliases", authorized_by: "111", authorized_at: qualification.record.qualified_at, expires_at: qualification.record.expires_at,
      repository: m.repository, repository_id: m.repositoryId, app_id: 10, installation_id: 20, tag: m.tag, commit: m.commit, tag_object: "9".repeat(40), approval_sha256: m.approvalSha256, release_id: "400",
      operation_run_id: "130", operation_attempt: "3", operation_workflow_commit: "c".repeat(40), updates: [{ name: "refs/tags/v1", beforeOid: "b".repeat(40), afterOid: m.commit }, { name: "refs/tags/v1.2", beforeOid: "b".repeat(40), afterOid: m.commit }] };
    const aliasJson = JSON.stringify(aliasRecord);
    const config = { appId: 10, installationId: 20, repositoryId: "100", runtimeCommit: "c".repeat(40), reviewerId: "111", manifestPath: source.policy.manifest_path,
      maxValiditySeconds: 3600, ...(aliases ? { aliasAuthorization: { json: aliasJson, sha256: createHash("sha256").update(aliasJson).digest("hex"), authorizerId: "111" } } : {}), ...(publish ? { publicationQualification: { json, sha256, qualifierId } } : {}), publication: { id: "131", path: ".github/workflows/release-publish.yml", commit: "c".repeat(40) },
      preflight: { id: "122", path: ".github/workflows/preflight.yml", commit: "c".repeat(40) },
      validation: { id: "141", path: ".github/workflows/full-release-validation.yml", commit: "c".repeat(40) }, latest: true,
      pythonPath: "/fabricated/python", pythonSha256: "0".repeat(64), ghPath: "/fabricated/gh", ghSha256: "1".repeat(64),
      maxAssetBytes: 10000, maxArchiveBytes: 10000, maxExpandedBytes: 10000, maxMembers: 100 };
    const environment = { RELEASE_RETRY_CONFIG: JSON.stringify(config), RELEASE_APP_PRIVATE_KEY: key, GITHUB_REPOSITORY: manifest.repository.full_name,
      GITHUB_REPOSITORY_ID: "100", RELEASE_RUNTIME_COMMIT: config.runtimeCommit, GITHUB_SHA: config.publication.commit, GITHUB_RUN_ID: "130",
      GITHUB_RUN_ATTEMPT: "3", PREFLIGHT_RUN_ID: "120", VALIDATION_RUN_ID: "140", APPROVAL_PULL_NUMBER: "4", RELEASE_ISSUE: "27",
      TAG: m.tag, CHANNEL: "stable", GITHUB_WORKSPACE: root, RUNNER_TEMP: root, CREATE_GITHUB_RELEASE: "true" };
    const operation = aliases ? promoteApprovedBootstrapReleaseAliases : publish ? publishNewBootstrapSourceRelease : runExistingReleaseRuntime;
    Object.assign(environment, publish ? { PUBLISH_SCRIPT: "scripts/release/publish.sh" } : aliases ? { UPDATE_MAJOR_TAG: "true", UPDATE_MINOR_TAG: "true" } : {});
    const aliasRefs = new Map<string, any>([[m.tag,{__typename:"Tag",oid:"9".repeat(40),target:{__typename:"Commit",oid:m.commit}}],["v1.2.2",{__typename:"Commit",oid:"b".repeat(40)}],["v1",{__typename:"Commit",oid:"b".repeat(40)}],["v1.2",{__typename:"Commit",oid:"b".repeat(40)}]]);
    let aliasMutations=0;
    let created = false; let published = false; const uploaded: any[] = [];
    const requests: { path: string; method: string }[] = [];
    const validationCheck = vi.fn(async () => {});
    const validationReader = vi.spyOn(validation, "verifyGitHubValidation").mockImplementation(async (input) => {
      expect(input.targetCommit).toBe(m.commit); expect(input.runId).toBe("140"); expect(input.workflowId).toBe("141");
      return validationCheck;
    });
    let revoked = false;
    let targetChanged = false;
    const producer = vi.spyOn(preparation, "prepareGitHubReleasePackageFromCheckout").mockImplementation(async (input) => {
      expect(input.sourceRoot).toBe(path.join(root, "release-target"));
      expect(input.requireSignedTag).toBe(true);
      expect(input.publishScript).toBe(publish ? "scripts/release/publish.sh" : undefined);
      expect(input.ghSha256).toBe(config.ghSha256);
      expect(input.approval.token).toBe("fabricated-installation-token");
      await input.assertTarget(m.tag, m.commit);
      return pkg;
    });
    const provider = vi.spyOn(globalThis, "fetch").mockImplementation(async (request, init) => {
      const url = new URL(String(request)); const method = init?.method ?? "GET";
      requests.push({ path: url.pathname, method });
      let value: any; let status = 200;
      const release = { id: 400, tag_name: m.tag, draft: publish && !published, name: m.tag, upload_url: `https://uploads.github.com/repos/${m.repository}/releases/400/assets{?name,label}`, body: m.notes, prerelease: false, author: { id: 999 } };
      if (url.pathname === "/graphql") {
        const body = JSON.parse(String(init?.body));
        if(body.query.startsWith("mutation")){aliasMutations++;for(const u of body.variables.input.refUpdates){expect(aliasRefs.get(u.name.slice(10)).oid).toBe(u.beforeOid);}for(const u of body.variables.input.refUpdates)aliasRefs.set(u.name.slice(10),{__typename:"Commit",oid:u.afterOid});value={data:{updateRefs:{clientMutationId:body.variables.input.clientMutationId}}};}
        else value={data:{node:{id:"R_100",nameWithOwner:m.repository,isPrivate:false,refs:{totalCount:aliasRefs.size,nodes:[...aliasRefs].map(([name,target])=>({name,prefix:"refs/tags/",target})),pageInfo:{hasNextPage:false,endCursor:"end"}}}}};
      }
      else if (url.pathname.endsWith("/rulesets/42")) value = qualification.record.projection;
      else if (publish && url.pathname.endsWith("/releases") && method === "POST") { created = true; status = 201; value = release; }
      else if (publish && url.pathname.endsWith("/releases/400") && method === "PATCH") { published = true; value = { ...release, draft: false }; }
      else if (publish && url.pathname.endsWith("/releases/400/assets") && method === "POST") {
        const item = m.assets.find((a) => a.name === url.searchParams.get("name"))!;
        value = { id: 500 + uploaded.length, name: item.name, size: item.size, state: "uploaded", digest: `sha256:${item.sha256}` }; uploaded.push(value); status = 201;
      }
      else if (url.pathname === "/app") value = { id: 10 };
      else if (url.pathname === "/app/installations/20/access_tokens") {
        expect(method).toBe("POST");
        expect(JSON.parse(String(init?.body))).toEqual({ repository_ids: [100], permissions: { contents: "write", actions: "read", pull_requests: "read" } });
        status = 201;
        value = { token: "fabricated-installation-token", expires_at: new Date(Date.now() + 600000).toISOString().replace(/\.\d{3}Z$/, "Z"),
          permissions: { contents: "write", actions: "read", pull_requests: "read" }, repository_selection: "selected", repositories: [{ id: 100 }] };
      } else if (url.pathname === "/installation/repositories") value = { total_count: 1, repositories: [{ id: 100, full_name: m.repository, private: false }] };
      else if (url.pathname === "/users/jmcte") value = { id: 111, login: "jmcte", type: "User" };
      else if (url.pathname.endsWith("/actions/runs/140")) value = { id: 140, run_attempt: 1, workflow_id: 141, path: config.validation.path, head_sha: config.validation.commit,
        status: "completed", conclusion: "success", event: "workflow_dispatch", repository: { id: 100 }, head_repository: { id: 100 } };
      else if (url.pathname.endsWith("/actions/runs/130/attempts/3")) value = { id: 130, run_attempt: 3, workflow_id: 131, path: config.publication.path,
        head_sha: config.publication.commit, status: "in_progress", event: "workflow_dispatch", repository: { id: 100 }, head_repository: { id: 100 }, actor: { id: 113, type: "User" }, triggering_actor: { id: 115, type: "User" } };
      else if (url.pathname.endsWith("/pulls/4/files")) value = [{ filename: source.policy.manifest_path, status: "added", sha: blobSha }];
      else if (url.pathname.includes("/git/blobs/")) value = { sha: blobSha, encoding: "base64", content: Buffer.from(source.observation.manifestBytes).toString("base64"), size: source.observation.manifestBytes.length };
      else if (url.pathname.endsWith("/pulls/4/reviews")) value = [{ id: 200, user: { id: 111 }, state: revoked ? "DISMISSED" : "APPROVED", commit_id: source.observation.pull.head, submitted_at: source.observation.reviews[0]!.submitted_at, body: source.observation.reviews[0]!.body }];
      else if (url.pathname.endsWith("/pulls/4")) value = { number: 4, state: "open", changed_files: 1, head: { sha: source.observation.pull.head, repo: { id: 100 } }, base: { sha: "e".repeat(40), repo: { id: 100 } }, user: { id: 112 } };
      else if (url.pathname.endsWith(`/git/ref/tags/${m.tag}`)) value = { ref: `refs/tags/${m.tag}`, object: { type: "tag", sha: "9".repeat(40) } };
      else if (url.pathname.includes("/git/tags/")) value = { sha: "9".repeat(40), tag: m.tag, object: { type: "commit", sha: targetChanged ? "0".repeat(40) : m.commit }, verification: { verified: true, reason: "valid", signature: "fabricated", payload: "fabricated" } };
      else if (url.pathname.endsWith("/releases")) value = publish && !created ? [] : [release];
      else if (url.pathname.endsWith("/releases/400") || url.pathname.endsWith("/releases/latest")) value = release;
      else if (url.pathname.endsWith("/releases/400/assets")) value = m.assets.map((a, i) => ({ id: 500 + i, name: a.name, size: a.size, state: "uploaded", digest: `sha256:${a.sha256}` }));
      else if (url.pathname === "/repos/OMT-Global/bootstrap") value = { id: 100, node_id: "R_100", full_name: m.repository, private: false, permissions: { push: true } };
      else throw new Error("Unexpected fabricated request");
      const response = new Response(JSON.stringify(value), { status });
      Object.defineProperty(response, "url", { value: String(request) });
      return response;
    });
    try {
      expect(await operation(environment)).toMatchObject({ kind: aliases ? "promoted-aliases" : publish ? "verified-created" : "verified-existing", releaseId: "400" });
      expect(producer).toHaveBeenCalledTimes(1);
      expect(validationReader).toHaveBeenCalledTimes(1); expect(validationCheck.mock.calls.length).toBeGreaterThanOrEqual(6);
      revoked = true;
      await expect(operation(environment)).rejects.toThrow();
      revoked = false; targetChanged = true;
      await expect(operation(environment)).rejects.toThrow();
      expect(requests.filter((r) => r.method !== "GET" && r.path !== "/app/installations/20/access_tokens" && r.path !== "/graphql")).toHaveLength(publish ? m.assets.length + 2 : 0);
      expect(aliasMutations).toBe(aliases ? 1 : 0);
    } finally { producer.mockRestore(); provider.mockRestore(); validationReader.mockRestore(); await rm(root, { recursive: true, force: true }); }
  });
  it("keeps old pinned callers compatible until the manifest selects the new input contract", () => {
    const manifest = (approvedRetry?: boolean) => normalizeManifest({ project: { name: "release-fixture", owner: "acme" }, archetype: { kind: "generic-empty" },
      release: { enabled: true, maturity: "governed", ...(approvedRetry === undefined ? {} : { approvedRetry }) } });
    const caller = (enabled?: boolean) => YAML.parse(renderManagedFiles(manifest(enabled)).find((f) => f.path === ".github/workflows/release-publish.yml")!.contents);
    expect(caller().jobs.publish.with).not.toHaveProperty("verify_existing_release");
    const enabled = caller(true);
    expect(enabled.on.workflow_dispatch.inputs.verify_existing_release.default).toBe(false);
    expect(enabled.jobs.publish.with.verify_existing_release).toBe("${{ inputs.verify_existing_release }}");
    const publication = normalizeManifest({ project: { name: "release-fixture", owner: "acme" }, archetype: { kind: "generic-empty" }, release: { enabled: true, maturity: "governed", approvedPublication: true } });
    const publicationCaller = YAML.parse(renderManagedFiles(publication).find((f) => f.path === ".github/workflows/release-publish.yml")!.contents);
    expect(caller().jobs.publish.with).not.toHaveProperty("publish_new_source_release");
    expect(caller(true).jobs.publish.with).not.toHaveProperty("publish_new_source_release");
    expect(publicationCaller.on.workflow_dispatch.inputs.publish_new_source_release.default).toBe(false);
    expect(publicationCaller.jobs.publish.with.publish_new_source_release).toBe("${{ inputs.publish_new_source_release }}");
    const aliasManifest = normalizeManifest({ project: { name: "release-fixture", owner: "acme" }, archetype: { kind: "generic-empty" }, release: { enabled: true, maturity: "governed", approvedAliases: true } });
    const aliasCaller = YAML.parse(renderManagedFiles(aliasManifest).find((f)=>f.path===".github/workflows/release-publish.yml")!.contents);
    expect(caller().jobs.publish.with).not.toHaveProperty("promote_release_aliases");
    expect(publicationCaller.jobs.publish.with).not.toHaveProperty("promote_release_aliases");
    expect(aliasCaller.on.workflow_dispatch.inputs.promote_release_aliases.default).toBe(false);
    expect(aliasCaller.jobs.publish.with.promote_release_aliases).toBe("${{ inputs.promote_release_aliases }}");
    const reusable = YAML.parse(renderManagedFiles(manifest()).find((f) => f.path === ".github/workflows/release-publish-reusable.yml")!.contents);
    const steps = reusable.jobs.publish.steps;
    expect(steps.find((s: any) => s.name === "Checkout approved retry runtime").with).toMatchObject({ repository: "OMT-Global/bootstrap", ref: "${{ vars.RELEASE_RUNTIME_COMMIT }}", "persist-credentials": false });
    expect(steps.findIndex((s: any) => s.name === "Build approved retry runtime before exposing App key")).toBeLessThan(steps.findIndex((s: any) => s.name === "Publish proven release artifact"));
  });
});
