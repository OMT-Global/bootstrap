import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, symlink, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";

const harness = vi.hoisted(() => ({ resolve: vi.fn(), missingSafeInputFlags: false }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, constants: {
    ...actual.constants,
    get O_NOFOLLOW() { return harness.missingSafeInputFlags ? undefined : actual.constants.O_NOFOLLOW; }
  } };
});
vi.mock("../src/provenance-github.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/provenance-github.js")>();
  return { ...actual, resolvePublicGitHubReviewers: harness.resolve };
});

import { registerSignedProvenanceCommands } from "../src/provenance-cli.js";
import { createPublicProvenance, generateProvenanceSigningKeyPair, signPublicProvenance, verifySignedPublicProvenance } from "../src/provenance.js";

const subject = { repository: "acme/widget", commitSha: "a".repeat(40), ref: "refs/heads/topic" };
const context = { repository: subject.repository, commitSha: subject.commitSha, pullRequest: 7 };
const live = [{ login: "reviewer", state: "approved" as const }];
const key = generateProvenanceSigningKeyPair();
const other = generateProvenanceSigningKeyPair();
function manifest() {
  return createPublicProvenance({
    runId: "123.1", subject,
    execution: { workflow: "Public provenance", createdAt: "2026-11-09T00:00:00Z" },
    reviewers: [{ login: "claimed-reviewer", state: "approved" }],
    metadata: { policy: "public-standard-v1" }
  });
}
let root: string;
let stdout: MockInstance<typeof process.stdout.write>;
function program() {
  const command = new Command().exitOverride();
  command.configureOutput({ writeErr: () => undefined, writeOut: () => undefined });
  registerSignedProvenanceCommands(command.command("provenance"));
  return command;
}
const expectedArgs = ["--repository", subject.repository, "--commit", subject.commitSha, "--pr", "7"];
function parse(args: string[]) {
  return program().parseAsync(["node", "bootstrap", "provenance", ...args]);
}
function signArgs(extra: string[] = []) {
  return ["sign", "--input", path.join(root, "manifest.json"), "--private-key", path.join(root, "selected.jwk.json"),
    "--output", path.join(root, "signed.json"), ...expectedArgs, ...extra];
}
function verifyArgs(extra: string[] = []) {
  return ["verify", "--input", path.join(root, "signed.json"), "--keyring", path.join(root, "trusted.json"), ...expectedArgs, ...extra];
}
async function writeJson(name: string, value: unknown) {
  await writeFile(path.join(root, name), JSON.stringify(value), { mode: 0o600 });
}

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), "public-provenance-cli-"));
  await writeJson("manifest.json", manifest());
  await writeJson("selected.jwk.json", key.privateKey);
  await writeJson("trusted.json", [key.publicKey]);
  harness.resolve.mockReset().mockResolvedValue(structuredClone(live));
  harness.missingSafeInputFlags = false;
  stdout = vi.spyOn(process.stdout, "write").mockReturnValue(true);
});
afterEach(async () => {
  stdout.mockRestore();
  await rm(root, { recursive: true, force: true });
});

describe("signed public provenance commands", () => {
  it("round-trips through real Commander handlers, local files and the existing trusted codec", async () => {
    await parse(signArgs());
    const serialized = await readFile(path.join(root, "signed.json"), "utf8");
    const envelope: unknown = JSON.parse(serialized);
    const parsed = verifySignedPublicProvenance(envelope, { trustedPublicKeys: [key.publicKey], expectedSubject: subject });
    expect(parsed.reviewers).toEqual(live);
    expect(parsed.redaction).toEqual(manifest().redaction);
    expect(serialized).not.toContain(String(key.privateKey.d));
    expect(serialized).not.toContain("claimed-reviewer");
    await parse(verifyArgs());
    expect(harness.resolve).toHaveBeenCalledTimes(3);
    for (const [actualContext] of harness.resolve.mock.calls) expect(actualContext).toEqual(context);
    const output = stdout.mock.calls.map(([value]) => String(value)).join("");
    expect(output).toContain("Verified public signature");
    expect(output).not.toContain(String(key.privateKey.d));
    expect(await readdir(root)).toEqual(["manifest.json", "selected.jwk.json", "signed.json", "trusted.json"]);
  });

  it("rechecks actual lineage before output and preserves unrelated files when it changes", async () => {
    harness.resolve.mockResolvedValueOnce(live).mockResolvedValueOnce([{ login: "replacement", state: "approved" }]);
    await expect(parse(signArgs())).rejects.toThrow(/^Public provenance signing failed;/);
    await expect(readFile(path.join(root, "signed.json"))).rejects.toThrow();
    expect(JSON.parse(await readFile(path.join(root, "manifest.json"), "utf8"))).toEqual(manifest());
    expect((await readdir(root)).some((name) => name.startsWith(".bootstrap-provenance-"))).toBe(false);
  });

  it("never overwrites an existing output, including a symlink", async () => {
    await writeFile(path.join(root, "signed.json"), "existing artifact");
    await expect(parse(signArgs())).rejects.toThrow("signing failed");
    expect(await readFile(path.join(root, "signed.json"), "utf8")).toBe("existing artifact");
    await rm(path.join(root, "signed.json"));
    await writeFile(path.join(root, "unrelated.txt"), "preserve this target");
    await symlink(path.join(root, "unrelated.txt"), path.join(root, "signed.json"));
    await expect(parse(signArgs())).rejects.toThrow("signing failed");
    expect(await readFile(path.join(root, "unrelated.txt"), "utf8")).toBe("preserve this target");
    expect((await readdir(root)).some((name) => name.startsWith(".bootstrap-provenance-"))).toBe(false);
  });

  it("does not create missing output directories or change the selected key file", async () => {
    const before = await readFile(path.join(root, "selected.jwk.json"));
    await expect(parse(signArgs(["--output", path.join(root, "absent", "signed.json")]))).rejects.toThrow("signing failed");
    await expect(readdir(path.join(root, "absent"))).rejects.toThrow();
    expect(await readFile(path.join(root, "selected.jwk.json"))).toEqual(before);
  });

  it.each([
    ["repository", ["--repository", "acme/other"]],
    ["commit", ["--commit", "b".repeat(40)]],
    ["noncanonical PR", ["--pr", "07"]],
    ["oversized PR", ["--pr", "2147483648"]]
  ])("rejects mismatched or invalid expected %s before lookup", async (_name, args) => {
    await expect(parse(signArgs(args))).rejects.toThrow("signing failed");
    expect(harness.resolve).not.toHaveBeenCalled();
  });

  it("bounds local JSON, selected private key and public keyring input", async () => {
    await writeFile(path.join(root, "manifest.json"), " ".repeat(1_048_577));
    await expect(parse(signArgs())).rejects.toThrow("signing failed");
    await writeJson("manifest.json", manifest());
    await writeFile(path.join(root, "selected.jwk.json"), " ".repeat(4_097));
    await expect(parse(signArgs())).rejects.toThrow("signing failed");
    await writeFile(path.join(root, "trusted.json"), " ".repeat(65_537));
    await expect(parse(verifyArgs())).rejects.toThrow("verification failed");
    expect(harness.resolve).not.toHaveBeenCalled();
  });

  it("rejects nonregular or symlink inputs before lookup", async () => {
    await expect(parse(signArgs(["--input", root]))).rejects.toThrow("signing failed");
    await symlink(path.join(root, "selected.jwk.json"), path.join(root, "key-link.json"));
    await expect(parse(signArgs(["--private-key", path.join(root, "key-link.json")]))).rejects.toThrow("signing failed");
    expect(harness.resolve).not.toHaveBeenCalled();
  });

  it("fails before input or network when the platform lacks safe local input capabilities", async () => {
    harness.missingSafeInputFlags = true;
    await expect(parse(signArgs())).rejects.toThrow("signing failed");
    await expect(parse(verifyArgs())).rejects.toThrow("verification failed");
    expect(harness.resolve).not.toHaveBeenCalled();
    await expect(readFile(path.join(root, "signed.json"))).rejects.toThrow();
  });

  it.each([
    ["missing private component", { ...key.publicKey }],
    ["unknown private fields", { ...key.privateKey, unapproved: true }],
    ["wrong curve", { ...key.privateKey, crv: "X25519" }],
    ["noncanonical key bytes", { ...key.privateKey, x: String(key.privateKey.x) + "=" }]
  ])("rejects %s without exposing local key details", async (_label, malformed) => {
    await writeJson("selected.jwk.json", malformed);
    await expect(parse(signArgs())).rejects.toThrow(/^Public provenance signing failed; no key or lookup details are included\.$/);
    expect(harness.resolve).not.toHaveBeenCalled();
    expect(stdout.mock.calls.flat().join("")).not.toContain(String(key.privateKey.d));
  });

  it("rejects an inconsistent private/public key pair without publishing a bad envelope", async () => {
    await writeJson("selected.jwk.json", { ...key.privateKey, x: other.publicKey.x });
    await expect(parse(signArgs())).rejects.toThrow("signing failed");
    await expect(readFile(path.join(root, "signed.json"))).rejects.toThrow();
  });

  const invalidEnvelope: Array<[string, (envelope: ReturnType<typeof signPublicProvenance>) => unknown]> = [
    ["unsigned manifest", () => manifest()],
    ["tampered metadata", (value) => ({ ...value, manifest: { ...value.manifest, metadata: { policy: "changed" } } })],
    ["old schema", (value) => ({ ...value, manifest: { ...value.manifest, schemaVersion: 1 } })],
    ["unknown envelope fields", (value) => ({ ...value, extra: true })],
    ["private embedded key", (value) => ({ ...value, signature: { ...value.signature, publicKey: key.privateKey } })],
    ["wrong immutable subject", () => signPublicProvenance({ ...manifest(), subject: { ...subject, commitSha: "b".repeat(40) } }, { privateKey: key.privateKey })]
  ];
  it.each(invalidEnvelope)("rejects %s before any GitHub lookup", async (_name, mutate) => {
    const envelope = signPublicProvenance({ ...manifest(), reviewers: live }, { privateKey: key.privateKey });
    await writeJson("signed.json", mutate(envelope));
    await expect(parse(verifyArgs())).rejects.toThrow("verification failed");
    expect(harness.resolve).not.toHaveBeenCalled();
  });

  it.each([
    ["empty trust", []], ["different key", [other.publicKey]],
    ["private fields", [key.privateKey]], ["duplicate trust", [key.publicKey, key.publicKey]],
    ["unknown public fields", [{ ...key.publicKey, approved: true }]]
  ])("rejects %s before any GitHub lookup", async (_name, keyring) => {
    await writeJson("signed.json", signPublicProvenance({ ...manifest(), reviewers: live }, { privateKey: key.privateKey }));
    await writeJson("trusted.json", keyring);
    await expect(parse(verifyArgs())).rejects.toThrow("verification failed");
    expect(harness.resolve).not.toHaveBeenCalled();
  });

  it("rejects correctly signed fabricated reviewer claims and later stale lineage", async () => {
    await writeJson("signed.json", signPublicProvenance(manifest(), { privateKey: key.privateKey }));
    await expect(parse(verifyArgs())).rejects.toThrow("verification failed");
    expect(harness.resolve).toHaveBeenCalledWith(context);
    await writeJson("signed.json", signPublicProvenance({ ...manifest(), reviewers: live }, { privateKey: key.privateKey }));
    harness.resolve.mockResolvedValue([{ login: "other-reviewer", state: "approved" }]);
    await expect(parse(verifyArgs())).rejects.toThrow("verification failed");
  });

  it("sanitizes all failed remote lookup details", async () => {
    harness.resolve.mockRejectedValue(new Error("UNTRUSTED_DIAGNOSTIC " + String(key.privateKey.d)));
    await expect(parse(signArgs())).rejects.toThrow(/^Public provenance signing failed; no key or lookup details are included\.$/);
    expect(stdout.mock.calls.flat().join("")).not.toContain(String(key.privateKey.d));
  });

  it("requires independent context options", async () => {
    await expect(parse(["verify", "--input", path.join(root, "signed.json"), "--keyring", path.join(root, "trusted.json")])).rejects.toThrow("required option");
    expect(harness.resolve).not.toHaveBeenCalled();
  });

  it.skipIf(process.platform === "win32")("runs the shipped CLI and concrete gh adapter end to end with an owned public HTTP-response fixture", async () => {
    const bin = path.join(root, "bin");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(bin);
    const reply = {
      data: { repository: {
        id: "REPO1", nameWithOwner: subject.repository, isPrivate: false,
        pullRequest: {
          id: "PR1", number: 7, headRefOid: subject.commitSha,
          headRepository: { id: "HEAD1", nameWithOwner: "contributor/widget", isPrivate: false },
          author: { id: "AUTHOR1", login: "author" }, reviewDecision: "APPROVED",
          latestOpinionatedReviews: {
            totalCount: 1,
            nodes: [{ id: "REVIEW1", state: "APPROVED", submittedAt: "2026-11-09T00:00:00Z", commit: { oid: subject.commitSha }, author: { id: "REVIEWER1", login: "reviewer" } }],
            pageInfo: { hasNextPage: false, endCursor: null }
          }
        }
      } }
    };
    await writeJson("response.json", reply);
    const gh = `#!${process.execPath}\nconst fs = require("node:fs");\nconst args = process.argv.slice(2);\nfs.appendFileSync(process.env.PUBLIC_PROVENANCE_CALLS, JSON.stringify(args) + "\\n");\nif (args[0] !== "api" || args[1] !== "--hostname" || args[2] !== "github.com" || args[3] !== "graphql" || !args.some(x => x.startsWith("query=query PublicProvenanceReviews") && x.includes("latestOpinionatedReviews"))) process.exit(2);\nprocess.stdout.write(fs.readFileSync(process.env.PUBLIC_PROVENANCE_RESPONSE));\n`;
    await writeFile(path.join(bin, "gh"), gh, { mode: 0o755 });
    const env = {
      PATH: `${bin}:/usr/bin:/bin`, HOME: root, LANG: "C",
      PUBLIC_PROVENANCE_RESPONSE: path.join(root, "response.json"), PUBLIC_PROVENANCE_CALLS: path.join(root, "calls.jsonl")
    };
    const run = promisify(execFile);
    const tsx = new URL("../node_modules/tsx/dist/cli.mjs", import.meta.url).pathname;
    const cli = new URL("../src/cli.ts", import.meta.url).pathname;
    const signed = await run(process.execPath, [tsx, cli, "provenance", ...signArgs()], { env, maxBuffer: 65_536, timeout: 15_000 });
    expect(signed.stdout).toContain("Wrote signed public provenance");
    const verified = await run(process.execPath, [tsx, cli, "provenance", ...verifyArgs()], { env, maxBuffer: 65_536, timeout: 15_000 });
    expect(verified.stdout).toContain("Verified public signature");
    const calls = await readFile(path.join(root, "calls.jsonl"), "utf8");
    expect(calls.trim().split("\n")).toHaveLength(6);
    expect(calls).not.toContain(String(key.privateKey.d));
    expect(calls).not.toContain("selected.jwk.json");
    expect(calls).not.toContain("--private-key");
    const envelope: unknown = JSON.parse(await readFile(path.join(root, "signed.json"), "utf8"));
    expect(verifySignedPublicProvenance(envelope, { trustedPublicKeys: [key.publicKey], expectedSubject: subject }).reviewers).toEqual(live);
    expect(harness.resolve).not.toHaveBeenCalled();
  });

  it("wires new commands into the actual existing CLI while retaining unsigned commands", async () => {
    const run = promisify(execFile);
    const tsx = new URL("../node_modules/tsx/dist/cli.mjs", import.meta.url).pathname;
    const cli = new URL("../src/cli.ts", import.meta.url).pathname;
    const help = await run(process.execPath, [tsx, cli, "provenance", "--help"], { maxBuffer: 65_536, timeout: 15_000 });
    expect(help.stdout).toContain("validate");
    expect(help.stdout).toContain("create");
    expect(help.stdout).toContain("sign");
    expect(help.stdout).toContain("verify");
    const verify = await run(process.execPath, [tsx, cli, "provenance", "verify", "--help"], { maxBuffer: 65_536, timeout: 15_000 });
    expect(verify.stdout).toContain("--keyring");
    expect(verify.stdout).toContain("--repository");
    expect(verify.stdout).toContain("--commit");
    expect(verify.stdout).toContain("--pr");
  });
});
