import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { verifyGitHubValidation } from "../src/release-validation-evidence.js";

const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const zipProgram = `import io,json,sys,zipfile,stat\ns=json.load(sys.stdin); b=io.BytesIO()\nwith zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:\n for e in s:\n  i=zipfile.ZipInfo(e['name']); i.create_system=3; i.external_attr=((stat.S_IFLNK if e.get('symlink') else stat.S_IFREG)|0o600)<<16; i.compress_type=zipfile.ZIP_STORED if e.get('stored') else zipfile.ZIP_DEFLATED\n  z.writestr(i,e['data'])\nsys.stdout.buffer.write(b.getvalue())\n`;
type Entry = { name: string; data: string; symlink?: boolean; stored?: boolean };
async function fixture(change?: (evidence: any, entries: Entry[]) => void) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "validation-evidence-")));
  const pythonPath = await realpath(execFileSync("which", [process.env.BOOTSTRAP_RELEASE_TEST_PYTHON ?? "python3"], { encoding: "utf8" }).trim());
  const evidence = { schema_version: 1, repo: "Example/repo", target_sha: "b".repeat(40), validation_run_id: "140", run_attempt: "2",
    checks: { validate_script: "passed", standard_checks: "passed" } };
  const entries: Entry[] = []; change?.(evidence, entries);
  if (!entries.length) entries.push({ name: "validation-evidence.json", data: JSON.stringify(evidence) });
  const zip = execFileSync(pythonPath, ["-I", "-S", "-c", zipProgram], { input: JSON.stringify(entries), maxBuffer: 3 * 1024 * 1024 });
  const artifact = { id: 142, name: "release-evidence-validation", expired: false, digest: `sha256:${sha(zip)}`,
    workflow_run: { id: 140, repository_id: 100, head_repository_id: 100, head_sha: "c".repeat(40) } };
  const run = { id: 140, run_attempt: 2, workflow_id: 141, path: ".github/workflows/full-release-validation.yml", head_sha: "c".repeat(40),
    event: "workflow_dispatch", status: "completed", conclusion: "success", repository: { id: 100, full_name: "Example/repo" }, head_repository: { id: 100 } };
  await writeFile(path.join(root, "artifact.zip"), zip);
  await writeFile(path.join(root, "artifact.json"), JSON.stringify(artifact));
  await writeFile(path.join(root, "attempt.json"), JSON.stringify(run));
  const ghPath = path.join(root, "gh");
  const quote = (v: string) => "'" + v.replace(/'/g, "'\\''") + "'";
  await writeFile(ghPath, `#!/bin/sh\nset -eu\n[ "$1" = api ]\ncase "$2" in\nrepos/Example/repo/actions/artifacts/142) /bin/cat ${quote(path.join(root,"artifact.json"))} ;;\nrepos/Example/repo/actions/artifacts/142/zip) /bin/cat ${quote(path.join(root,"artifact.zip"))} ;;\nrepos/Example/repo/actions/runs/140/attempts/2) /bin/cat ${quote(path.join(root,"attempt.json"))} ;;\n*) exit 90 ;;\nesac\n`);
  await chmod(ghPath, 0o700);
  let altered = (_url: URL, value: any) => value;
  const requests: string[] = [];
  const fetchImpl: typeof fetch = async (request, init) => {
    expect(init?.method).toBe("GET");
    const url = new URL(String(request)); requests.push(url.pathname);
    let value: any;
    if (url.pathname.endsWith("/actions/runs/140") || url.pathname.endsWith("/attempts/2")) value = run;
    else if (url.pathname.endsWith("/actions/runs/140/artifacts")) value = { total_count: 1, artifacts: [artifact] };
    else if (url.pathname.endsWith("/actions/artifacts/142")) value = artifact;
    else throw new Error("Unexpected provider call");
    const response = new Response(JSON.stringify(altered(url, structuredClone(value))));
    Object.defineProperty(response, "url", { value: String(request) }); return response;
  };
  const input = { repository: "Example/repo", repositoryId: "100", runId: "140", workflowId: "141", workflowPath: run.path,
    workflowCommit: run.head_sha, targetCommit: evidence.target_sha === "b".repeat(40) ? evidence.target_sha : "b".repeat(40), token: "fabricated-token",
    pythonPath, pythonSha256: sha(await readFile(pythonPath)), ghPath, ghSha256: sha(await readFile(ghPath)), runtimeDir: root, fetchImpl };
  return { input, requests, setProvider(fn: typeof altered) { altered = fn; }, cleanup: () => rm(root, { recursive: true, force: true }) };
}
describe("bounded authenticated full-validation evidence", () => {
  it("verifies real ZIP bytes and rechecks the selected run and artifact before later boundaries", async () => {
    const f = await fixture();
    try {
      const check = await verifyGitHubValidation(f.input); await check();
      expect(f.requests.filter((p) => p.endsWith("/actions/artifacts/142"))).toHaveLength(3);
      f.setProvider((u, v) => { if (u.pathname.endsWith("/actions/artifacts/142")) v.digest = `sha256:${"0".repeat(64)}`; return v; });
      await expect(check()).rejects.toThrow();
    } finally { await f.cleanup(); }
  });
  it.each([
    ["target", (e: any) => { e.target_sha = "0".repeat(40); }],
    ["run", (e: any) => { e.validation_run_id = "999"; }],
    ["attempt", (e: any) => { e.run_attempt = "1"; }],
    ["missing attempt", (e: any) => { delete e.run_attempt; }],
    ["repository", (e: any) => { e.repo = "Other/repo"; }],
    ["skipped checks", (e: any) => { e.checks.standard_checks = "skipped"; }],
    ["boolean schema", (e: any) => { e.schema_version = true; }],
    ["expanded bound", (e: any) => { e.padding = "x".repeat(65536); }],
    ["archive bound", (e: any, list: Entry[]) => { e.padding = "x".repeat(1048576); list.push({ name: "validation-evidence.json", data: JSON.stringify(e), stored: true }); }],
    ["traversal", (e: any, list: Entry[]) => { list.push({ name: "../validation-evidence.json", data: JSON.stringify(e) }); }],
    ["symlink", (e: any, list: Entry[]) => { list.push({ name: "validation-evidence.json", data: JSON.stringify(e), symlink: true }); }],
    ["extra member", (e: any, list: Entry[]) => { list.push({ name: "validation-evidence.json", data: JSON.stringify(e) }, { name: "extra", data: "x" }); }],
    ["duplicate member", (e: any, list: Entry[]) => { const x = { name: "validation-evidence.json", data: JSON.stringify(e) }; list.push(x,x); }],
    ["duplicate JSON key", (e: any, list: Entry[]) => { list.push({ name: "validation-evidence.json", data: JSON.stringify(e).replace('"schema_version":1', '"schema_version":1,"schema_version":1') }); }]
  ] as const)("rejects %s before returning a validation capability", async (_name, change) => {
    const f = await fixture(change); try { await expect(verifyGitHubValidation(f.input)).rejects.toThrow(); } finally { await f.cleanup(); }
  });
  it.each(["workflow", "failure", "inventory", "attempt"])("rejects authenticated %s mismatch", async (mode) => {
    const f = await fixture();
    try {
      f.setProvider((u,v) => {
        if (mode === "workflow" && v.workflow_id) v.workflow_id = 999;
        if (mode === "failure" && v.conclusion) v.conclusion = "failure";
        if (mode === "inventory" && v.artifacts) v.total_count = 2;
        if (mode === "attempt" && u.pathname.endsWith("/attempts/2")) v.run_attempt = 3;
        return v;
      });
      await expect(verifyGitHubValidation(f.input)).rejects.toThrow();
    } finally { await f.cleanup(); }
  });
});
