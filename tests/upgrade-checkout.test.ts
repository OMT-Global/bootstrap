import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, readlink, rm, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { IsolatedSourceFile } from "../src/isolation/node-profile.js";
import { auditCheckout } from "../src/upgrade-checkout.js";
import { verifyGitSnapshot } from "../src/upgrade-git.js";

const directories: string[] = [];
const origin = "https://github.com/example/public.git";
const blockedMessage = "Checkout is not eligible for a governed upgrade.";
const file = (name: string, text: string, executable = false): IsolatedSourceFile => ({
  path: name, mode: executable ? "100755" : "100644", bytes: Buffer.from(text)
});

async function fixture(extra: IsolatedSourceFile[] = []) {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "bootstrap-checkout-test-")); directories.push(workspace);
  const root = path.join(workspace, "original"); const scratch = path.join(workspace, "scratch");
  const template = path.join(workspace, "empty-template"); await Promise.all([root, scratch, template].map((dir) => mkdir(dir)));
  const env = { PATH: "/usr/bin:/bin:/usr/local/bin", HOME: workspace, TMPDIR: scratch, GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0",
    GIT_AUTHOR_NAME: "Public Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000",
    GIT_COMMITTER_NAME: "Public Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null",
    "-c", "commit.gpgsign=false", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null", ...args],
  { cwd: root, env, ...(input === undefined ? {} : { input }), maxBuffer: 8 * 1024 ** 2 });
  git(["init", "-q", "--initial-branch=main", `--template=${template}`]);
  git(["config", "remote.origin.url", origin]);
  await mkdir(path.join(root, ".git/info"), { recursive: true }); await mkdir(path.join(root, ".git/hooks"), { recursive: true });
  const files = [file("README.md", "approved public source\n"), file("src/source.txt", "tracked public text\n"),
    file(".gitignore", "ignored/\n*.log\n"), ...extra];
  const records: Buffer[] = [];
  for (const entry of files) {
    await mkdir(path.dirname(path.join(root, entry.path)), { recursive: true });
    await writeFile(path.join(root, entry.path), entry.bytes, { mode: entry.mode === "100755" ? 0o755 : 0o644 });
    const oid = git(["hash-object", "--stdin", "--no-filters", "-w"], entry.bytes).toString().trim();
    records.push(Buffer.from(`${entry.mode} ${oid}\t${entry.path}\0`));
  }
  git(["update-index", "-z", "--index-info"], Buffer.concat(records));
  const tree = git(["write-tree"]).toString().trim();
  const baseCommit = git(["commit-tree", tree], "test: synthetic public checkout\n").toString().trim();
  git(["update-ref", "refs/heads/main", baseCommit]);
  const commitBytes = git(["cat-file", "commit", baseCommit]);
  const snapshot = verifyGitSnapshot({ baseCommit, commitBytes, files });
  await mkdir(path.join(root, "ignored")); await writeFile(path.join(root, "ignored/private-sentinel"), "private fixture contents\n");
  return { workspace, root, scratch, env, files, baseCommit, tree, commitBytes, snapshot, git };
}

async function inventory(root: string, prefix = ""): Promise<unknown[]> {
  const rows: unknown[] = [];
  for (const name of (await readdir(path.join(root, prefix))).sort()) {
    const relative = prefix ? `${prefix}/${name}` : name;
    const stat = await lstat(path.join(root, relative));
    if (stat.isDirectory()) rows.push([relative, "directory", stat.mode], ...await inventory(root, relative));
    else if (stat.isSymbolicLink()) rows.push([relative, "link", await readlink(path.join(root, relative))]);
    else if (stat.isFile()) rows.push([relative, "file", stat.mode, createHash("sha256").update(await readFile(path.join(root, relative))).digest("hex")]);
    else rows.push([relative, "special", stat.mode]);
  }
  return rows;
}

async function blocked(data: Awaited<ReturnType<typeof fixture>>) {
  const before = await inventory(data.root);
  const error = await auditCheckout(data.root, data.snapshot, origin).then(() => undefined, (value: unknown) => value);
  expect(error).toBeInstanceOf(Error);
  expect((error as Error).message).toBe(blockedMessage);
  expect((error as Error).message).not.toContain(data.workspace);
  expect(await inventory(data.root)).toEqual(before);
}

function auditInChild(data: Awaited<ReturnType<typeof fixture>>, payload: string) {
  const script = `import {readFileSync} from 'node:fs';
import {verifyGitSnapshot} from ${JSON.stringify(new URL("../src/upgrade-git.ts", import.meta.url).href)};
import {auditCheckout} from ${JSON.stringify(new URL("../src/upgrade-checkout.ts", import.meta.url).href)};
const p=JSON.parse(readFileSync(process.argv[1],'utf8'));
const s=verifyGitSnapshot({baseCommit:p.baseCommit,commitBytes:Buffer.from(p.commit,'base64'),files:p.files.map(f=>({...f,bytes:Buffer.from(f.bytes,'base64')}))});
try {await auditCheckout(p.root,s,p.origin);console.log(JSON.stringify({ok:true}));}
catch(error){console.log(JSON.stringify({ok:false,message:error.message}));}`;
  const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script, payload], {
    cwd: path.resolve(path.dirname(new URL(import.meta.url).pathname), ".."), env: data.env, encoding: "utf8",
    timeout: 5_000, killSignal: "SIGKILL", maxBuffer: 16 * 1024
  });
  expect(result.error, "The metadata audit must reject a FIFO before a blocking read.").toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout.trim()) as { ok: boolean; message?: string };
}

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(directories.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("original checkout eligibility is a read-only data audit", () => {
  it("accepts a clean raw public base and preserves refs, index, files and ignored sentinel bytes", async () => {
    const data = await fixture(); const before = await inventory(data.root);
    const first = await auditCheckout(data.root, data.snapshot, origin);
    const second = await auditCheckout(data.root, data.snapshot, origin);
    expect(first).toMatchObject({ baseCommit: data.baseCommit, tree: data.tree, sourceSha256: data.snapshot.sourceSha256 });
    expect(first.originalStateSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(second).toEqual(first);
    expect(await inventory(data.root)).toEqual(before);
    expect(JSON.stringify(first)).not.toContain(data.workspace);
    expect(JSON.stringify(first)).not.toContain("private-sentinel");
  });

  it.each(["raw", "staged", "assume-unchanged", "skip-worktree", "executable"])("blocks %s dirt without trusting porcelain state", async (kind) => {
    const data = await fixture(); const name = "src/source.txt";
    if (kind === "assume-unchanged" || kind === "skip-worktree") data.git(["update-index", `--${kind}`, name]);
    if (kind === "executable") await chmod(path.join(data.root, name), 0o755);
    else await writeFile(path.join(data.root, name), "changed private working bytes\n");
    if (kind === "staged") data.git(["add", "--", name]);
    if (kind === "assume-unchanged" || kind === "skip-worktree") expect(data.git(["diff", "--", name]).toString()).toBe("");
    await blocked(data);
  });

  it("blocks an untracked private file without exposing its name or contents", async () => {
    const data = await fixture(); await writeFile(path.join(data.root, "sensitive-user-draft"), "private sentinel must not appear in output\n");
    await blocked(data);
  });

  it("blocks staging under an original public-ignored TMPDIR before any temporary checkout mutation", async () => {
    const data = await fixture();
    vi.stubEnv("TMPDIR", path.join(data.root, "ignored"));
    await blocked(data);
    expect((await readdir(path.join(data.root, "ignored"))).sort()).toEqual(["private-sentinel"]);
  });

  it.each(["origin", "push-origin", "include", "local-exclude", "worktree", "alternate", "split-index", "sparse"])
    ("blocks unsupported %s authority or layout without changing it", async (kind) => {
      const data = await fixture();
      if (kind === "origin") data.git(["config", "remote.origin.url", "https://github.com/private-sentinel/other.git"]);
      if (kind === "push-origin") data.git(["config", "remote.origin.pushurl", "https://github.com/private-sentinel/other.git"]);
      if (kind === "include") data.git(["config", "include.path", path.join(data.workspace, "private-config")]);
      if (kind === "local-exclude") await writeFile(path.join(data.root, ".git/info/exclude"), "sensitive-user-draft\n");
      if (kind === "worktree") data.git(["config", "core.worktree", data.root]);
      if (kind === "alternate") await writeFile(path.join(data.root, ".git/objects/info/alternates"), path.join(data.workspace, "private-objects") + "\n");
      if (kind === "split-index") data.git(["update-index", "--split-index"]);
      if (kind === "sparse") data.git(["config", "core.sparseCheckout", "true"]);
      await blocked(data);
    });

  it.each(["fsmonitor", "filter", "textconv", "helper", "ssh", "rewrite"])("never executes an original %s command canary", async (kind) => {
    const attributes = kind === "filter" ? [file(".gitattributes", "*.txt filter=canary\n")] :
      kind === "textconv" ? [file(".gitattributes", "*.txt diff=canary\n")] : [];
    const data = await fixture(attributes); const marker = path.join(data.workspace, "host-command-executed");
    const command = `sh -c ': > "${marker}"'`;
    const key = { fsmonitor: "core.fsmonitor", filter: "filter.canary.clean", textconv: "diff.canary.textconv",
      helper: "credential.helper", ssh: "core.sshCommand", rewrite: "url.https://private-sentinel.invalid/.insteadOf" }[kind]!;
    data.git(["config", key, kind === "rewrite" ? "https://github.com/" : command]);
    const before = await inventory(data.root);
    try { await auditCheckout(data.root, data.snapshot, origin); }
    catch (error) { expect((error as Error).message).toBe(blockedMessage); }
    await expect(lstat(marker)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await inventory(data.root)).toEqual(before);
  });

  it("blocks an effective local hook rather than silently skipping its authority", async () => {
    const data = await fixture(); const marker = path.join(data.workspace, "local-hook-executed");
    await writeFile(path.join(data.root, ".git/hooks/post-checkout"), `#!/bin/sh\n: > '${marker}'\n`, { mode: 0o755 });
    await blocked(data);
    await expect(lstat(marker)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["tracked-leaf", "tracked-parent", "metadata"])("rejects an outside-file symlink at %s", async (kind) => {
    const data = await fixture(); const outside = path.join(data.workspace, "outside"); await mkdir(outside);
    await writeFile(path.join(outside, "source.txt"), "private sentinel outside source\n");
    if (kind === "tracked-parent") { await rm(path.join(data.root, "src"), { recursive: true }); await symlink(outside, path.join(data.root, "src")); }
    else {
      const target = path.join(data.root, kind === "metadata" ? ".git/config" : "src/source.txt");
      await unlink(target); await symlink(path.join(outside, "source.txt"), target);
    }
    await blocked(data);
    expect((await readFile(path.join(outside, "source.txt"))).toString()).toBe("private sentinel outside source\n");
  });

  it.each([".git/hooks", ".git/objects/info"])("rejects an outside metadata directory at %s before enumeration", async (name) => {
    const data = await fixture(); const outside = path.join(data.workspace, "outside-empty-metadata"); await mkdir(outside);
    await rm(path.join(data.root, name), { recursive: true }); await symlink(outside, path.join(data.root, name));
    await blocked(data);
    expect(await readdir(outside)).toEqual([]);
  });

  it.each(["src/source.txt", ".git/config"])("rejects a multiply-linked %s", async (name) => {
    const data = await fixture(); await link(path.join(data.root, name), path.join(data.workspace, "outside-hardlink"));
    await blocked(data);
  });

  it.each(["src/source.txt", ".git/HEAD", ".git/index", ".git/config"])("rejects FIFO %s in a deadline-bounded child", async (name) => {
    const data = await fixture(); const target = path.join(data.root, name); await unlink(target);
    execFileSync("/usr/bin/mkfifo", [target], { env: data.env });
    const payload = path.join(data.workspace, "audit-input.json");
    await writeFile(payload, JSON.stringify({ root: data.root, origin, baseCommit: data.baseCommit,
      commit: data.commitBytes.toString("base64"), files: data.files.map((entry) => ({ ...entry, bytes: Buffer.from(entry.bytes).toString("base64") })) }));
    const before = await inventory(data.root); const result = auditInChild(data, payload);
    expect(result).toEqual({ ok: false, message: blockedMessage });
    expect(await inventory(data.root)).toEqual(before);
  }, 8_000);

  it.skipIf(process.platform !== "linux")("rejects unsupported raw UTF-8 names without replacement aliases", async () => {
    const data = await fixture();
    await writeFile(Buffer.concat([Buffer.from(data.root + "/"), Buffer.from([0xff])]), "private sentinel\n");
    const error = await auditCheckout(data.root, data.snapshot, origin).then(() => undefined, (value: unknown) => value);
    expect((error as Error).message).toBe(blockedMessage);
  });
});
