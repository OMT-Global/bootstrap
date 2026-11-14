import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import ts from "typescript";

export const projectRoot = fileURLToPath(new URL("../../", import.meta.url));
export const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return "{" + Object.keys(record).sort().map((key) => JSON.stringify(key) + ":" + canonical(record[key])).join(",") + "}";
  }
  return JSON.stringify(value);
}

export interface CopyHarness {
  readonly root: string;
  readonly moduleDirectory: string;
  readonly approvalDirectory: string;
  run<T>(body: string): Promise<T>;
  close(): Promise<void>;
}
export interface FixtureAnchor {
  role: string;
  kid: string;
  enabled: boolean;
  jwk: { kty: string; crv: string; x: string };
}
export function testApprovers(): { anchors: FixtureAnchor[]; privateKeys: KeyObject[] } {
  const pairs = [generateKeyPairSync("ed25519"), generateKeyPairSync("ed25519")];
  return {
    anchors: pairs.map((pair, i) => {
      const jwk = pair.publicKey.export({ format: "jwk" });
      return { role: i ? "storage-support-approval" : "installation-approval", kid: "fixture-" + i,
        enabled: true, jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x! } };
    }),
    privateKeys: pairs.map((pair) => pair.privateKey),
  };
}

/** Separate disposable code copies only. Production has no runtime fixture selector. */
export async function copyHarness(anchors?: readonly FixtureAnchor[]): Promise<CopyHarness> {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "bootstrap-approval-copy-")));
  const moduleDirectory = path.join(root, "modules");
  const approvalDirectory = path.join(root, "approval");
  await mkdir(moduleDirectory); await mkdir(approvalDirectory, { mode: 0o700 });
  await mkdir(path.join(approvalDirectory, "evidence"), { mode: 0o700 });
  await writeFile(path.join(moduleDirectory, "package.json"), '{"type":"module"}');
  for (const name of ["upgrade-admission", "upgrade-journal-provenance"]) {
    let source: string;
    try { source = await readFile(path.join(projectRoot, "src", name + ".ts"), "utf8"); }
    catch (error) { if (name === "upgrade-admission") throw error; else continue; }
    if (name === "upgrade-journal-provenance" && anchors !== undefined) {
      const substitutions = [
        ['const APPROVAL_DIRECTORY = "/etc/bootstrap/upgrade-journal";', "const APPROVAL_DIRECTORY = " + JSON.stringify(approvalDirectory) + ";"],
        ['const TRUSTED_ANCESTOR_ROOT = "/";', "const TRUSTED_ANCESTOR_ROOT = " + JSON.stringify(root) + ";"],
        ["const TRUSTED_UID = 0;", "const TRUSTED_UID = " + String(process.getuid!()) + ";"],
        ["const APPROVAL_ANCHORS: readonly ApprovalAnchor[] = Object.freeze([]);", "const APPROVAL_ANCHORS: readonly ApprovalAnchor[] = Object.freeze(" + JSON.stringify(anchors) + ");"],
      ];
      for (const [from, to] of substitutions) {
        if (source.split(from!).length !== 2) throw new Error("fixture substitution must match exactly once: " + from);
        source = source.replace(from!, to!);
      }
    }
    const built = ts.transpileModule(source, { compilerOptions: {
      target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022, strict: true,
    } });
    await writeFile(path.join(moduleDirectory, name + ".js"), built.outputText);
  }
  let invocation = 0;
  return { root, moduleDirectory, approvalDirectory,
    async run<T>(body: string): Promise<T> {
      const script = path.join(moduleDirectory, "scenario-" + invocation++ + ".mjs");
      await writeFile(script, body);
      const output = execFileSync(process.execPath, [script], { cwd: root,
        env: { LANG: "C", LC_ALL: "C", TZ: "UTC" }, timeout: 20_000, maxBuffer: 1024 * 1024 });
      return JSON.parse(output.toString("utf8")) as T;
    },
    close: () => rm(root, { recursive: true, force: true }),
  };
}

export async function writeApproval(harness: CopyHarness, bytes: Uint8Array | string): Promise<void> {
  const file = path.join(harness.approvalDirectory, "approved-installation.v1.json");
  await writeFile(file, bytes, { mode: 0o600 }); await chmod(file, 0o600);
}
export const moduleImport = (harness: CopyHarness, name: string) => JSON.stringify(pathToFileURL(path.join(harness.moduleDirectory, name + ".js")).href);
export function signPayload(payload: unknown, keys: readonly KeyObject[], anchors: readonly FixtureAnchor[]) {
  const message = Buffer.from("bootstrap-upgrade-journal-approval-v1\0" + canonical(payload));
  return { payload, approvals: keys.map((key, i) => ({ role: anchors[i]!.role, kid: anchors[i]!.kid,
    algorithm: "ed25519", signature: sign(null, message, key).toString("base64") })) };
}

export type FixtureFile =
  | { rootId: string; path: string; kind: "regular"; mode: number; size: number; sha256: string }
  | { rootId: string; path: string; kind: "symlink"; mode: number; target: string };

/** Fabricated approval statements: no live installation, device or hardware proof. */
export async function approvalFixture(harness: CopyHarness, approvers: ReturnType<typeof testApprovers>) {
  const files: FixtureFile[] = [
    { rootId: "dist", path: "scripts/bootstrap/upgrade-journal-linux.py", kind: "regular", mode: 0o644, size: 7, sha256: sha("program") },
    { rootId: "dist", path: "upgrade-journal-entry.js", kind: "regular", mode: 0o644, size: 5, sha256: sha("entry") },
    { rootId: "python", path: "os.py", kind: "regular", mode: 0o644, size: 6, sha256: sha("python") },
    { rootId: "runtime", path: "package.json", kind: "regular", mode: 0o644, size: 7, sha256: sha("package") },
  ];
  const roots = [
    { id: "dist", purpose: "distribution", path: "/opt/bootstrap/dist", inventorySha256: "" },
    { id: "python", purpose: "python-stdlib", path: "/usr/lib/python3.11", inventorySha256: "" },
    { id: "runtime", purpose: "runtime-dependencies", path: "/opt/bootstrap/runtime", inventorySha256: "" },
  ];
  const payload = {
    domain: "bootstrap-upgrade-journal-installation", version: 1,
    approvalEpoch: "fixture-epoch-1", installationId: "fabricated-installation",
    sourceBuild: { sourceCommit: "1".repeat(40), packageSha256: sha("package"), lockSha256: sha("lock"),
      buildRecipeSha256: sha("recipe"), distributionInventorySha256: "", buildEvidenceSha256: "" },
    node: { executable: "/opt/bootstrap/bin/node", executableSha256: sha("node"), version: "v20.20.2",
      platform: "linux", architecture: "x64", entryRootId: "dist", entryPath: "upgrade-journal-entry.js", entrySha256: sha("entry") },
    prlimit: { executable: "/usr/bin/prlimit", executableSha256: sha("prlimit") },
    installationRoots: roots, files,
    python: { executable: "/usr/bin/python3.11", executableSha256: sha("python-binary"), version: "3.11.0",
      standardLibraryRootIds: ["python"], standardLibraryInventorySha256: "" },
    journalProgram: { rootId: "dist", path: "scripts/bootstrap/upgrade-journal-linux.py", mode: 0o644, sha256: sha("program") },
    storageProfile: { profile: "linux-local-ext4-journal-v1", measurementProfile: "direct-ext4-wwid-v1",
      journalRoot: "/var/lib/bootstrap/upgrade-journal", machineIdSha256: sha("machine"),
      filesystemUuid: "12345678-1234-1234-1234-123456789abc", wwidSha256: sha("wwid"), partitionUuid: null,
      kernelRelease: "6.1.0-fixture", procVersionSha256: sha("kernel"), mountOptionsSha256: sha("rw,data=ordered"),
      measurementSha256: sha("fabricated-storage-measurement"), stackEvidenceSha256: "" },
    evidence: { build: "", syscallProfile: "", storageCrashReboot: "", independentReview: "" },
  };
  const kinds = { build: "build", syscallProfile: "syscall-profile", storageCrashReboot: "storage-crash-reboot", independentReview: "independent-review" };
  const artifact = (kind: string) => ({ domain: "bootstrap-upgrade-journal-evidence", version: 1, kind,
    sourceCommit: payload.sourceBuild.sourceCommit, distributionInventorySha256: "", pythonInventorySha256: "",
    startupRecipeSha256: "", storageMeasurementSha256: payload.storageProfile.measurementSha256,
    subjectSha256: sha("fabricated-subject-" + kind), body: "Fabricated " + kind + " report; no native or hardware proof." });
  const artifacts = { build: artifact(kinds.build), syscallProfile: artifact(kinds.syscallProfile),
    storageCrashReboot: artifact(kinds.storageCrashReboot), independentReview: artifact(kinds.independentReview) };
  function refreshBindings() {
    const slice = (root: typeof roots[number]) => ({ root: { id: root.id, purpose: root.purpose, path: root.path },
      files: payload.files.filter((file) => file.rootId === root.id) });
    for (const root of roots) root.inventorySha256 = sha(canonical(slice(root)));
    payload.sourceBuild.distributionInventorySha256 = sha(canonical(payload.files.filter((file) => roots.find((root) => root.id === file.rootId)?.purpose !== "python-stdlib")));
    payload.python.standardLibraryInventorySha256 = sha(canonical(roots.filter((root) => root.purpose === "python-stdlib").map(slice)));
    const recipe = sha(canonical([payload.node.executable, "--no-global-search-paths", path.posix.join(roots.find((root) => root.id === payload.node.entryRootId)!.path, payload.node.entryPath)]));
    for (const item of Object.values(artifacts)) {
      item.sourceCommit = payload.sourceBuild.sourceCommit;
      item.distributionInventorySha256 = payload.sourceBuild.distributionInventorySha256;
      item.pythonInventorySha256 = payload.python.standardLibraryInventorySha256;
      item.startupRecipeSha256 = recipe; item.storageMeasurementSha256 = payload.storageProfile.measurementSha256;
    }
  }
  async function persist(refresh = true) {
    if (refresh) refreshBindings();
    for (const slot of Object.keys(artifacts) as (keyof typeof artifacts)[]) {
      const bytes = canonical(artifacts[slot]); const digest = sha(bytes); payload.evidence[slot] = digest;
      const target = path.join(harness.approvalDirectory, "evidence", digest + ".json");
      await writeFile(target, bytes, { mode: 0o600 }); await chmod(target, 0o600);
    }
    payload.sourceBuild.buildEvidenceSha256 = payload.evidence.build;
    payload.storageProfile.stackEvidenceSha256 = payload.evidence.storageCrashReboot;
    const envelope = signPayload(payload, approvers.privateKeys, approvers.anchors);
    await writeApproval(harness, canonical(envelope)); return envelope;
  }
  await persist(); return { payload, artifacts, refreshBindings, persist };
}
