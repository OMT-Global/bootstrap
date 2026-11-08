import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import https from "node:https";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  downloadArchive, freezeNodeValidation, ISOLATION_LIMITS, NODE_ISOLATION_PROFILE, verifyArchive,
  type IsolatedSourceFile, type NodeValidationInput
} from "../src/isolation/node-profile.js";

const archive = Buffer.from("fabricated public package archive");
const integrity = `sha512-${createHash("sha512").update(archive).digest("base64")}`;
const archiveUrl = "https://registry.npmjs.org/example/-/example-1.0.0.tgz";
const file = (name: string, text: string, executable = false): IsolatedSourceFile => ({
  path: name, mode: executable ? "100755" : "100644", bytes: Buffer.from(text)
});
function fixture(): NodeValidationInput {
  return {
    profile: NODE_ISOLATION_PROFILE, phase: "prepared-hook",
    files: [file("package.json", JSON.stringify({ name: "isolation-fixture", version: "1.0.0", private: true })),
      file("package-lock.json", JSON.stringify({ name: "isolation-fixture", version: "1.0.0", lockfileVersion: 3,
        packages: { "": { name: "isolation-fixture", version: "1.0.0" } } })),
      file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\nprintf 'fixture checks\\n'\n", true)],
    baseBundle: Buffer.from("fabricated public bundle bytes"), baseCommit: "a".repeat(40),
    branch: "codex/isolation-fixture", commitMessage: "test: validate fixture\n\nSigned-off-by: Fixture <fixture@example.com>\n", hook: "none"
  };
}
function contents(input: NodeValidationInput, name: string): any {
  return JSON.parse(Buffer.from(input.files.find((entry) => entry.path === name)!.bytes).toString());
}
function replace(input: NodeValidationInput, name: string, value: unknown): void {
  (input.files as IsolatedSourceFile[])[input.files.findIndex((entry) => entry.path === name)] = file(name, JSON.stringify(value));
}
function dependency(input: NodeValidationInput, changes: Record<string, unknown> = {}): void {
  const lock = contents(input, "package-lock.json");
  lock.packages["node_modules/example"] = { version: "1.0.0", resolved: archiveUrl, integrity, ...changes };
  replace(input, "package-lock.json", lock);
}
function extra(input: NodeValidationInput, entry: IsolatedSourceFile): void { (input.files as IsolatedSourceFile[]).push(entry); }

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.useRealTimers(); });

describe("frozen Node isolation profile", () => {
  it("distinguishes prepared-hook and final-check evidence requests", () => {
    const prepared = fixture();
    expect(freezeNodeValidation(prepared)).toMatchObject({ phase: "prepared-hook" });
    expect(freezeNodeValidation({ ...prepared, phase: "final-check", candidateCommit: "b".repeat(40) }))
      .toMatchObject({ phase: "final-check", candidateCommit: "b".repeat(40) });
  });

  it("requires an exact candidate commit only for final-check and rejects ambiguous phases", () => {
    const prepared = fixture();
    expect(() => freezeNodeValidation({ ...prepared, phase: "final-check" } as NodeValidationInput)).toThrow();
    expect(() => freezeNodeValidation({ ...prepared, candidateCommit: "b".repeat(40) } as NodeValidationInput)).toThrow();
    for (const candidateCommit of ["HEAD", "B".repeat(40), "b".repeat(39), ""]) {
      expect(() => freezeNodeValidation({ ...prepared, phase: "final-check", candidateCommit } as NodeValidationInput)).toThrow();
    }
    const { phase: _phase, ...missing } = prepared;
    expect(() => freezeNodeValidation(missing as NodeValidationInput)).toThrow();
    for (const phase of ["check", "hook", "", null]) {
      expect(() => freezeNodeValidation({ ...prepared, phase } as NodeValidationInput)).toThrow();
    }
  });

  it.each([2, 3])("accepts a public root npm lockfile v%s and copies caller-owned bytes", (lockfileVersion) => {
    const input = fixture(); dependency(input);
    const lock = contents(input, "package-lock.json"); lock.lockfileVersion = lockfileVersion; replace(input, "package-lock.json", lock);
    extra(input, file("資料/a file\nwith newline.txt", "published content"));
    const original = Buffer.from(input.files[0]!.bytes);
    const frozen = freezeNodeValidation(input);
    expect(frozen.archives).toEqual([{ url: archiveUrl, integrity }]);
    expect(frozen.sourceSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(frozen.files.find((entry) => entry.path === "資料/a file\nwith newline.txt")?.bytes.toString()).toBe("published content");
    input.files[0]!.bytes.fill(0); input.baseBundle.fill(0);
    expect(frozen.files.find((entry) => entry.path === "package.json")!.bytes).toEqual(original);
    expect(frozen.baseBundle.toString()).toBe("fabricated public bundle bytes");
  });

  it("binds raw bytes, executable modes, and paths while ignoring caller inventory ordering", () => {
    const input = fixture();
    const expected = freezeNodeValidation(input).sourceSha256;
    expect(freezeNodeValidation({ ...input, files: [...input.files].reverse() }).sourceSha256).toBe(expected);
    // Mutate a non-JSON file so input remains parseable and the digest must change.
    const body = fixture(); body.files[2]!.bytes[body.files[2]!.bytes.length - 1] = 32;
    expect(freezeNodeValidation(body).sourceSha256).not.toBe(expected);
    const mode = fixture(); (mode.files[2] as IsolatedSourceFile).mode = "100644";
    expect(freezeNodeValidation(mode).sourceSha256).not.toBe(expected);
    const name = fixture(); extra(name, file("extra", ""));
    expect(freezeNodeValidation(name).sourceSha256).not.toBe(expected);
  });

  it.each(["../outside", "a/../outside", "/absolute", "a//b", "a\\b", "a\0b", ".git/config", ".GiT/index", "a/.git/config",
    "node_modules/package/index.js", "dist/output.js", "a\ud800b", "a/", ""])('rejects unsafe or reserved source path %j', (name) => {
    const input = fixture(); extra(input, file(name, "not executable"));
    expect(() => freezeNodeValidation(input)).toThrow();
  });

  it.each([".npmrc", "nested/.npmrc", ".yarnrc", "nested/.yarnrc"])("rejects repository package-manager configuration %s", (name) => {
    const input = fixture(); extra(input, file(name, "registry=https://registry.npmjs.org\n"));
    expect(() => freezeNodeValidation(input)).toThrow(/configuration is unsupported/);
  });

  it.each(["* filter=outside", "* working-tree-encoding=UTF-16", "* FILTER = executable"])("rejects external attribute conversion %s", (text) => {
    const input = fixture(); extra(input, file(".gitattributes", text));
    expect(() => freezeNodeValidation(input)).toThrow(/attribute conversion/);
  });

  it("rejects duplicate paths and either ordering of a file/directory collision", () => {
    const duplicate = fixture(); extra(duplicate, { ...duplicate.files[0]! });
    expect(() => freezeNodeValidation(duplicate)).toThrow(/duplicate/);
    for (const entries of [[file("docs", "file"), file("docs/nested", "child")], [file("docs/nested", "child"), file("docs", "file")]]) {
      const input = fixture(); entries.forEach((entry) => extra(input, entry));
      expect(() => freezeNodeValidation(input)).toThrow(/collision/);
    }
  });

  it("rejects absent manifests or the fixed check entry point", () => {
    for (const name of ["package.json", "package-lock.json", "scripts/ci/run-fast-checks.sh"]) {
      const input = fixture(); input.files = input.files.filter((entry) => entry.path !== name);
      expect(() => freezeNodeValidation(input)).toThrow(/required|missing/);
    }
  });

  it("requires the declared executable pre-commit hook and blocks other effective hooks", () => {
    const input = fixture(); input.hook = ".githooks/pre-commit";
    expect(() => freezeNodeValidation(input)).toThrow(/not executable/);
    extra(input, file(".githooks/pre-commit", "#!/bin/bash\nexit 0\n", true));
    expect(freezeNodeValidation(input).hook).toBe(".githooks/pre-commit");
    expect(() => freezeNodeValidation({ ...input, hook: "none" })).toThrow(/unsupported or omitted/);
    for (const name of ["pre-push", "post-checkout", "commit-msg", "fsmonitor-watchman", "post-index-change"]) {
      const other = fixture(); extra(other, file(`.githooks/${name}`, "#!/bin/bash\nexit 0\n", true));
      expect(() => freezeNodeValidation(other)).toThrow(/unsupported or omitted/);
    }
    const inactive = fixture(); extra(inactive, file(".githooks/pre-push", "not executable"));
    expect(freezeNodeValidation(inactive).hook).toBe("none");
  });

  it.each(["main", "codex/a..b", "codex/a//b", "codex/a.lock", "codex/a.", "codex/a@{b", "codex/a\nother"])("rejects unsupported branch %j", (branch) => {
    expect(() => freezeNodeValidation({ ...fixture(), branch })).toThrow();
  });

  it("requires a valid public base and bounded DCO message", () => {
    for (const change of [{ profile: "arbitrary" }, { baseCommit: "HEAD" }, { baseBundle: Buffer.alloc(0) },
      { commitMessage: "missing DCO" }, { commitMessage: `Signed-off-by: Fixture <fixture@example.com>\n${"x".repeat(16_384)}` },
      { commitMessage: "Signed-off-by: Fixture <fixture@example.com>\0" }]) {
      expect(() => freezeNodeValidation({ ...fixture(), ...change } as NodeValidationInput)).toThrow();
    }
  });

  it("bounds source and bundle bytes before retaining copies, and rejects oversized inventories", () => {
    const bundle = fixture(); bundle.baseBundle = new Uint8Array(ISOLATION_LIMITS.bundleBytes + 1);
    expect(() => freezeNodeValidation(bundle)).toThrow(/bundle size/);
    const source = fixture(); extra(source, { path: "large", mode: "100644", bytes: new Uint8Array(ISOLATION_LIMITS.sourceBytes + 1) });
    expect(() => freezeNodeValidation(source)).toThrow(/source exceeds/);
    const files = fixture(); files.files = Array.from({ length: ISOLATION_LIMITS.files + 1 }, (_, index) => file(`entry-${index}`, ""));
    expect(() => freezeNodeValidation(files)).toThrow();
  });

  it.each([
    ["package.json", ISOLATION_LIMITS.manifestBytes],
    ["package-lock.json", ISOLATION_LIMITS.lockBytes]
  ] as const)("bounds %s bytes before JSON parsing while accepting the exact limit", (name, maximum) => {
    const input = fixture();
    const index = input.files.findIndex((entry) => entry.path === name);
    const original = Buffer.from(input.files[index]!.bytes);
    const setBytes = (bytes: Uint8Array) => {
      (input.files as IsolatedSourceFile[])[index] = { ...input.files[index]!, bytes };
    };
    setBytes(Buffer.concat([original, Buffer.alloc(maximum - original.length, 32)]));
    expect(() => freezeNodeValidation(input)).not.toThrow();
    setBytes(Buffer.concat([original, Buffer.alloc(maximum + 1 - original.length, 32)]));
    expect(() => freezeNodeValidation(input)).toThrow(/metadata exceeds the profile parser bound/);
    setBytes(Buffer.alloc(maximum + 1, 0xff));
    expect(() => freezeNodeValidation(input)).toThrow(/metadata exceeds the profile parser bound/);
  });

  it("rejects a commit message that cannot survive exact UTF-8 byte binding", () => {
    expect(() => freezeNodeValidation({ ...fixture(),
      commitMessage: "test: malformed message\n\nSigned-off-by: Fixture <fixture@example.com>\n\ud800" })).toThrow();
  });

  it.each([{ workspaces: [] }, { workspaces: ["packages/*"] }, { packageManager: "pnpm@9.0.0" }, { packageManager: "yarn@1.0.0" }])("blocks unsupported root package settings %j", (changes) => {
    const input = fixture(); replace(input, "package.json", { ...contents(input, "package.json"), ...changes });
    expect(() => freezeNodeValidation(input)).toThrow();
  });

  it.each([1, 4, "3"])("rejects unsupported lockfile version %j", (lockfileVersion) => {
    const input = fixture(); const lock = contents(input, "package-lock.json"); lock.lockfileVersion = lockfileVersion; replace(input, "package-lock.json", lock);
    expect(() => freezeNodeValidation(input)).toThrow();
  });

  it("requires a root lock entry and no workspace links", () => {
    const absent = fixture(); replace(absent, "package-lock.json", { lockfileVersion: 3, packages: {} });
    expect(() => freezeNodeValidation(absent)).toThrow(/root lock/);
    const linked = fixture(); dependency(linked, { link: true });
    expect(() => freezeNodeValidation(linked)).toThrow(/Linked/);
    const workspace = fixture(); const lock = contents(workspace, "package-lock.json"); lock.packages[""].workspaces = ["packages/*"]; replace(workspace, "package-lock.json", lock);
    expect(() => freezeNodeValidation(workspace)).toThrow();
  });

  it.each(["file:../local.tgz", "git+https://github.com/example/project.git", "http://registry.npmjs.org/example.tgz",
    "https://private.example.com/example.tgz", "https://registry.npmjs.org.example.com/example.tgz",
    "https://fixture:example@registry.npmjs.org/example.tgz", "https://registry.npmjs.org/example.tgz?authorization=example",
    "https://registry.npmjs.org/example.tgz#fragment", "https://registry.npmjs.org/example.json", "https://registry.npmjs.org:8443/example.tgz"])("rejects unsupported archive source %s", (resolved) => {
    const input = fixture(); dependency(input, { resolved }); expect(() => freezeNodeValidation(input)).toThrow();
  });

  it.each([undefined, "sha1-example", "sha512-invalid", `sha512-${"A".repeat(88)}`])("requires complete SHA-512 archive integrity %j", (value) => {
    const input = fixture(); dependency(input, { integrity: value }); expect(() => freezeNodeValidation(input)).toThrow();
  });

  it("deduplicates identical archive requests but rejects conflicting integrity for one URL", () => {
    const input = fixture(); dependency(input); const lock = contents(input, "package-lock.json");
    lock.packages["node_modules/second"] = { ...lock.packages["node_modules/example"] }; replace(input, "package-lock.json", lock);
    expect(freezeNodeValidation(input).archives).toHaveLength(1);
    lock.packages["node_modules/second"].integrity = `sha512-${createHash("sha512").update("other").digest("base64")}`; replace(input, "package-lock.json", lock);
    expect(() => freezeNodeValidation(input)).toThrow(/Conflicting/);
  });

  it("bounds the distinct locked archive inventory", () => {
    const input = fixture(); const lock = contents(input, "package-lock.json");
    for (let index = 0; index <= ISOLATION_LIMITS.archives; index++) lock.packages[`node_modules/package-${index}`] = { resolved: `https://registry.npmjs.org/example/-/example-${index}.tgz`, integrity };
    replace(input, "package-lock.json", lock); expect(() => freezeNodeValidation(input)).toThrow(/Too many/);
  });

  it("rejects invalid UTF-8 or non-object package data", () => {
    for (const bytes of [Buffer.from([0xff]), Buffer.from("[]")]) {
      const input = fixture(); (input.files as IsolatedSourceFile[])[0] = { ...input.files[0]!, bytes };
      expect(() => freezeNodeValidation(input)).toThrow();
    }
  });
});

function networkFixture(statusCode = 200) {
  const response = Object.assign(new EventEmitter(), { statusCode, destroy: vi.fn() });
  const connection = Object.assign(new EventEmitter(), { destroy: vi.fn() });
  const get = vi.spyOn(https, "get").mockImplementation((...args: any[]) => {
    queueMicrotask(() => args[2](response));
    return connection as any;
  });
  return { response, connection, get, open: async () => { await Promise.resolve(); } };
}

describe("bounded integrity-bound public archive data", () => {
  it("verifies the complete archive bytes and rejects tampering or excess bytes", () => {
    expect(() => verifyArchive(archive, integrity)).not.toThrow();
    expect(() => verifyArchive(Buffer.concat([archive, Buffer.from("changed")]), integrity)).toThrow(/integrity/);
    expect(() => verifyArchive(new Uint8Array(ISOLATION_LIMITS.archiveBytes + 1), integrity)).toThrow(/size/);
  });

  it("downloads bytes with no caller authentication or proxy headers", async () => {
    vi.stubEnv("GH_TOKEN", `fabricated-${createHash("sha256").update("fixture").digest("hex")}`);
    const network = networkFixture();
    const result = downloadArchive({ url: archiveUrl, integrity }); await network.open();
    network.response.emit("data", archive.subarray(0, 5)); network.response.emit("data", archive.subarray(5)); network.response.emit("end");
    expect(await result).toEqual(archive);
    const options = network.get.mock.calls[0]![1] as { headers: Record<string, string> };
    expect(options.headers).toEqual({ accept: "application/octet-stream" });
    expect(network.get.mock.calls[0]![0]).toBe(archiveUrl);
  });

  it.each([301, 302, 307, 308, 401, 403, 404, 500])("does not follow a redirect or accept HTTP status %s", async (status) => {
    const network = networkFixture(status); const result = downloadArchive({ url: archiveUrl, integrity });
    await expect(result).rejects.toThrow(/download failed/);
    expect(network.get).toHaveBeenCalledTimes(1); expect(network.response.destroy).toHaveBeenCalled();
  });

  it("rejects a complete response whose actual digest differs", async () => {
    const network = networkFixture(); const result = downloadArchive({ url: archiveUrl, integrity });
    const rejected = expect(result).rejects.toThrow(/download failed/); await network.open();
    network.response.emit("data", Buffer.from("tampered")); network.response.emit("end"); await rejected;
  });

  it("cuts off a response as soon as its byte bound is exceeded", async () => {
    const network = networkFixture(); const result = downloadArchive({ url: archiveUrl, integrity });
    const rejected = expect(result).rejects.toThrow(/download failed/); await network.open();
    network.response.emit("data", Buffer.alloc(ISOLATION_LIMITS.archiveBytes + 1)); await rejected;
    expect(network.response.destroy).toHaveBeenCalled();
  });

  it.each(["error", "aborted"])("rejects a response %s without accepting partial bytes", async (event) => {
    const network = networkFixture(); const result = downloadArchive({ url: archiveUrl, integrity });
    const rejected = expect(result).rejects.toThrow(/download failed/); await network.open();
    network.response.emit("data", archive.subarray(0, 4)); network.response.emit(event, new Error("fabricated transport failure")); await rejected;
  });

  it("uses an absolute download deadline even while response data continues", async () => {
    vi.useFakeTimers(); const network = networkFixture(); const result = downloadArchive({ url: archiveUrl, integrity });
    const rejected = expect(result).rejects.toThrow(/download failed/); await network.open();
    for (let index = 0; index < 2; index++) { await vi.advanceTimersByTimeAsync(10_000); network.response.emit("data", archive.subarray(0, 1)); }
    await vi.advanceTimersByTimeAsync(ISOLATION_LIMITS.downloadMs - 20_000); await rejected;
    expect(network.connection.destroy).toHaveBeenCalled();
  });

  it("rejects connection errors", async () => {
    const network = networkFixture(); const result = downloadArchive({ url: archiveUrl, integrity });
    const rejected = expect(result).rejects.toThrow(/download failed/);
    network.connection.emit("error", new Error("fabricated connection failure")); await rejected;
  });

  it("does not open a public archive request after cancellation", async () => {
    const controller = new AbortController(); controller.abort();
    const get = vi.spyOn(https, "get");
    await expect(downloadArchive({ url: archiveUrl, integrity }, controller.signal)).rejects.toThrow();
    expect(get).not.toHaveBeenCalled();
  });

  it.each(["https://private.example.com/archive.tgz", "file:/archive.tgz", "https://user:password@registry.npmjs.org/archive.tgz"])("rejects unsupported direct downloader input %s before opening a connection", async (url) => {
    const get = vi.spyOn(https, "get");
    await expect(downloadArchive({ url, integrity })).rejects.toThrow(); expect(get).not.toHaveBeenCalled();
  });
});
