import { execFileSync, spawnSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { verifyGitSnapshot } from "../src/upgrade-git.js";
import { immutablePreflightVerifierScript } from "../src/archetypes.js";
import { type ReviewedReleaseManifest, reviewReleaseManifest, reviewedReleaseSelectors } from "../src/release-approval.js";
import { approvedReleasePackageMetadata } from "../src/release-approved-package.js";
import { acquireReviewedArtifact, acquireReviewedPreflight } from "../src/release-artifact-acquisition.js";
import { prepareReleaseForPublication } from "../src/release-prepare-publication.js";
import { prepareGitHubReleasePackage } from "../src/release-github-package-preparation.js";
import { reviewedPreflightEnvironment } from "../src/release-reviewed-preflight.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

const python = process.env.BOOTSTRAP_RELEASE_TEST_PYTHON || "python3";
const targetSha = "a".repeat(40);
const platformHeadSha = "b".repeat(40);

function verifierProgram(): string {
  return immutablePreflightVerifierScript();
}

// stdlib ZIP writers produce the ordinary formats; deliberate corruptions change
// the original wire names/headers so the decoder, not a sanitized fixture, is tested.
const zipFixtureProgram = String.raw`
import base64, binascii, io, json, stat, struct, sys, zipfile, zlib

spec = json.load(sys.stdin)
class StreamingBuffer(io.BytesIO):
    def seekable(self):
        return False
    def seek(self, *args):
        raise io.UnsupportedOperation("fixture is not seekable")

buffer = StreamingBuffer() if spec.get("descriptor") else io.BytesIO()
with zipfile.ZipFile(buffer, "w", allowZip64=True) as archive:
    for entry in spec["entries"]:
        info = zipfile.ZipInfo(entry["name"])
        info.create_system = entry.get("system", 3)
        info.compress_type = zipfile.ZIP_DEFLATED if entry.get("deflate") else zipfile.ZIP_STORED
        kind = entry.get("kind", "file")
        types = {"file": stat.S_IFREG, "directory": stat.S_IFDIR,
                 "symlink": stat.S_IFLNK, "fifo": stat.S_IFIFO,
                 "socket": stat.S_IFSOCK, "character": stat.S_IFCHR,
                 "block": stat.S_IFBLK}
        info.external_attr = (types[kind] | 0o644) << 16
        if kind == "directory":
            info.external_attr |= 0x10
        if info.create_system == 0:
            info.external_attr = 0x10 if kind == "directory" else 0x20
        if entry.get("dosDirectory"):
            info.external_attr |= 0x10
        payload = base64.b64decode(entry["dataBase64"], validate=True) if "dataBase64" in entry else entry.get("data", "fixture payload").encode("utf-8")
        with archive.open(info, "w", force_zip64=bool(spec.get("zip64"))) as member:
            member.write(payload)

def directory_records(data):
    eocd = data.rfind(b"PK\x05\x06")
    central_start = struct.unpack_from("<I", data, eocd + 16)[0]
    cursor = central_start
    records = []
    while data[cursor:cursor + 4] == b"PK\x01\x02":
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", data, cursor + 28)
        local = struct.unpack_from("<I", data, cursor + 42)[0]
        records.append((cursor, local, name_size))
        cursor += 46 + name_size + extra_size + comment_size
    return eocd, central_start, records

data = bytearray(buffer.getvalue())
variant = spec.get("descriptorVariant")
if variant:
    assert spec.get("descriptor"), "descriptor variants need a streamed archive"
    eocd, central_start, records = directory_records(data)
    central, local, name_size = records[-1]
    local_name_size, local_extra_size = struct.unpack_from("<HH", data, local + 26)
    crc, compressed_size, file_size = struct.unpack_from("<III", data, central + 16)
    descriptor_start = local + 30 + local_name_size + local_extra_size + compressed_size
    assert data[descriptor_start:descriptor_start + 4] == b"PK\x07\x08"
    assert descriptor_start + (24 if spec.get("zip64") else 16) == central_start
    wide = bool(spec.get("zip64")) or variant == "central-sizes"
    descriptor = struct.pack("<IQQ" if wide else "<III", crc, compressed_size, file_size)
    if spec.get("descriptorMutation") == "mismatch":
        descriptor = struct.pack("<IQQ" if wide else "<III", crc, compressed_size + 1, file_size)
    if not spec.get("unsignedDescriptor"):
        descriptor = b"PK\x07\x08" + descriptor
    if spec.get("descriptorMutation") == "truncated":
        descriptor = descriptor[:-1]
    delta = len(descriptor) - (central_start - descriptor_start)
    data[descriptor_start:central_start] = descriptor
    central_start += delta
    central += delta
    eocd += delta
    struct.pack_into("<I", data, eocd + 16, central_start)
    if variant in ("offset-only", "central-sizes"):
        extra_size = struct.unpack_from("<H", data, central + 30)[0]
        if variant == "offset-only":
            extra = struct.pack("<HHQ", 1, 8, local)
            struct.pack_into("<I", data, central + 42, 0xffffffff)
        else:
            extra = struct.pack("<HHQQ", 1, 16, file_size, compressed_size)
            struct.pack_into("<II", data, central + 20, 0xffffffff, 0xffffffff)
            data[local + 4] = 45
        data[central + 4] = data[central + 6] = 45
        struct.pack_into("<H", data, central + 30, extra_size + len(extra))
        extra_end = central + 46 + name_size + extra_size
        data[extra_end:extra_end] = extra
        eocd += len(extra)
        directory_size = struct.unpack_from("<I", data, eocd + 12)[0]
        struct.pack_into("<I", data, eocd + 12, directory_size + len(extra))
    if not spec.get("descriptorMutation"):
        with zipfile.ZipFile(io.BytesIO(data)) as readable:
            assert readable.testzip() is None
            for entry in spec["entries"]:
                assert readable.read(entry["name"]) == entry.get("data", "fixture payload").encode("utf-8")
        print(json.dumps({"stdlibReadSucceeded": True, "archiveBytes": len(data), "descriptorWidth": 8 if wide else 4, "signed": not spec.get("unsignedDescriptor", False), "centralSizeSentinels": variant == "central-sizes", "centralOffsetSentinel": variant == "offset-only", "localSizeSentinels": bool(spec.get("zip64"))}))
mutation = spec.get("mutation")
if mutation:
    eocd, central_start, records = directory_records(data)
    central, local, name_size = records[-1]
    local_name_size, local_extra_size = struct.unpack_from("<HH", data, local + 26)
    payload_start = local + 30 + local_name_size + local_extra_size
    compressed_size = struct.unpack_from("<I", data, central + 20)[0]
    if mutation == "nul-name":
        replacement = b"bad\x00name"
        assert name_size == len(replacement)
        data[central + 46:central + 46 + name_size] = replacement
        data[local + 30:local + 30 + name_size] = replacement
    elif mutation == "local-name":
        data[local + 30] ^= 1
    elif mutation == "invalid-utf8":
        data[central + 46] = 255
        data[local + 30] = 255
        for offset, flag_offset in [(local, 6), (central, 8)]:
            flags = struct.unpack_from("<H", data, offset + flag_offset)[0]
            struct.pack_into("<H", data, offset + flag_offset, flags | 0x800)
    elif mutation == "crc":
        for offset, crc_offset in [(local, 14), (central, 16)]:
            crc = struct.unpack_from("<I", data, offset + crc_offset)[0]
            struct.pack_into("<I", data, offset + crc_offset, crc ^ 1)
    elif mutation == "size-prefix":
        prefix_crc = binascii.crc32(spec["entries"][-1].get("data", "fixture payload").encode("utf-8")[:1])
        for offset, crc_offset, size_offset in [(local, 14, 22), (central, 16, 24)]:
            struct.pack_into("<I", data, offset + crc_offset, prefix_crc)
            struct.pack_into("<I", data, offset + size_offset, 1)
    elif mutation in ("deflate-no-eof", "deflate-trailing"):
        compressed = bytes(data[payload_start:payload_start + compressed_size])
        if mutation == "deflate-no-eof":
            expected = spec["entries"][-1]["data"].encode("utf-8")
            replacement = None
            for cut in range(1, min(8, len(compressed))):
                decoder = zlib.decompressobj(-15)
                candidate = compressed[:-cut]
                try:
                    expanded = decoder.decompress(candidate) + decoder.flush()
                except zlib.error:
                    continue
                if expanded == expected and not decoder.eof:
                    replacement = candidate
                    break
            assert replacement is not None, "missing-EOF fixture must retain the complete decoded content"
        else:
            replacement = compressed + b"\x00"
        delta = len(replacement) - compressed_size
        struct.pack_into("<I", data, local + 18, len(replacement))
        struct.pack_into("<I", data, central + 20, len(replacement))
        data[payload_start:payload_start + compressed_size] = replacement
        struct.pack_into("<I", data, eocd + delta + 16, central_start + delta)
    elif mutation in ("encrypted", "compression"):
        for offset, field in [(local, 6 if mutation == "encrypted" else 8), (central, 8 if mutation == "encrypted" else 10)]:
            value = struct.unpack_from("<H", data, offset + field)[0]
            struct.pack_into("<H", data, offset + field, value | 1 if mutation == "encrypted" else 99)
    elif mutation == "truncated":
        del data[-12:]
    else:
        raise ValueError("unknown fixture mutation")
open(sys.argv[1], "wb").write(data)
`;

type Entry = {
  name: string;
  data?: string;
  dataBase64?: string;
  kind?: "file" | "directory" | "symlink" | "fifo" | "socket" | "character" | "block";
  system?: number;
  deflate?: boolean;
  dosDirectory?: boolean;
};

type FixtureOptions = {
  entries?: Entry[];
  mutation?: string;
  descriptor?: boolean;
  zip64?: boolean;
  descriptorVariant?: "ordinary" | "offset-only" | "central-sizes";
  unsignedDescriptor?: boolean;
  descriptorMutation?: "mismatch" | "truncated";
  evidence?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  attempt?: Record<string, unknown>;
  env?: Record<string, string>;
  runId?: string;
  artifactId?: string;
  apiArtifactId?: string;
  apiRunId?: string;
  attemptRoute?: string;
  apiAttempt?: string;
  metadataFailure?: boolean;
  downloadFailure?: boolean;
  attemptFailure?: boolean;
  metadataText?: string;
  attemptText?: string;
  wrongDownloadedBytes?: boolean;
  reviewEnvironment?: (digest: string) => Record<string, string>;
  fixtureRepository?: string;
  fixtureRepositoryId?: number;
  archiveBytes?: Buffer;
  sourceBytes?: Buffer;
  sourceName?: string;
  targetCommit?: string;
};

async function runVerifier(options: FixtureOptions = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-immutable-preflight-"));
  try {
    const bin = path.join(directory, "bin");
    const runnerTemp = path.join(directory, "runner");
    await Promise.all([mkdir(bin), mkdir(runnerTemp)]);
    const fixtureRepository = options.fixtureRepository || "fake/repo";
    const fixtureRepositoryId = options.fixtureRepositoryId || 42;
    const fixtureTarget = options.targetCommit || targetSha;
    const runId = options.runId || "101";
    const artifactId = options.artifactId || "202";
    const attemptRoute = options.attemptRoute || "1";
    const archive = path.join(directory, "approved-A.zip");
    const evidence = { schema_version: 1, repo: fixtureRepository, version: "v1.2.3", channel: "stable", target_ref: "independent-target", target_sha: fixtureTarget, preflight_run_id: runId, run_attempt: "1", checks: { prep: "passed", preflight: "passed", build: "passed" }, ...options.evidence };
    const entries: Entry[] = [
      { name: "release-evidence.json", data: JSON.stringify(evidence) },
      { name: "RELEASE_NOTES.md", data: "independently approved A\n" },
      options.sourceBytes ? { name: options.sourceName || "source.tar.gz", dataBase64: options.sourceBytes.toString("base64") } :
        { name: "source.tar.gz", data: "opaque source archive; never recursively unpacked" },
      ...(options.entries || [])
    ];
    let formatProof: unknown;
    if (options.archiveBytes) await writeFile(archive, options.archiveBytes);
    else {
      const fixture = spawnSync(python, ["-I", "-S", "-c", zipFixtureProgram, archive], {
        input: JSON.stringify({ entries, mutation: options.mutation, descriptor: options.descriptor, zip64: options.zip64, descriptorVariant: options.descriptorVariant, unsignedDescriptor: options.unsignedDescriptor, descriptorMutation: options.descriptorMutation }),
        encoding: "utf8",
        timeout: 10_000
      });
      if (fixture.error) throw fixture.error;
      if (fixture.status !== 0) throw new Error(`Cannot prepare ZIP fixture: ${fixture.stderr}`);
      formatProof = fixture.stdout.trim() ? JSON.parse(fixture.stdout) : undefined;
    }
    const approvedBytes = await readFile(archive);
    const digest = createHash("sha256").update(approvedBytes).digest("hex");
    const downloaded = path.join(directory, "downloaded.zip");
    await writeFile(downloaded, options.wrongDownloadedBytes ? "not even a ZIP; must fail hashing first" : approvedBytes);
    // Name/run aliases deliberately point to B. The fake service only permits
    // A's explicit ID endpoints, so any alias lookup is an observable failure.
    await writeFile(path.join(directory, "alias-B.zip"), "unapproved B");
    const metadata = {
      id: "__ARTIFACT_ID__", name: "release-package", expired: false, digest: `sha256:${digest}`,
      workflow_run: { id: "__RUN_ID__", repository_id: fixtureRepositoryId, head_repository_id: fixtureRepositoryId, head_sha: platformHeadSha },
      ...options.metadata
    };
    const attempt = {
      id: "__RUN_ID__", run_attempt: "__ATTEMPT__", status: "completed", conclusion: "success", head_sha: platformHeadSha,
      repository: { id: fixtureRepositoryId, full_name: fixtureRepository }, head_repository: { id: fixtureRepositoryId, full_name: fixtureRepository },
      ...options.attempt
    };
    function platformJson(value: unknown) {
      return JSON.stringify(value)
        .replaceAll('"__ARTIFACT_ID__"', options.apiArtifactId || artifactId)
        .replaceAll('"__RUN_ID__"', options.apiRunId || runId)
        .replaceAll('"__ATTEMPT__"', options.apiAttempt || attemptRoute);
    }
    const metadataFile = path.join(directory, "metadata.json");
    const attemptFile = path.join(directory, "attempt.json");
    const callsFile = path.join(directory, "calls");
    await Promise.all([
      writeFile(metadataFile, options.metadataText ?? platformJson(metadata)),
      writeFile(attemptFile, options.attemptText ?? platformJson(attempt)),
      writeFile(callsFile, "")
    ]);
    const gh = path.join(bin, "gh");
    await writeFile(gh, `#!/bin/bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FIXTURE_CALLS"
[[ "$1" == api ]] || exit 90
endpoint=""
for argument in "$@"; do
  case "$argument" in repos/*) endpoint="$argument" ;; esac
done
case "$endpoint" in
  "repos/$FIXTURE_REPOSITORY/actions/artifacts/$FIXTURE_ARTIFACT_ID")
    [[ "$FIXTURE_METADATA_FAILURE" == false ]] || exit 44
    /bin/cat "$FIXTURE_METADATA" ;;
  "repos/$FIXTURE_REPOSITORY/actions/artifacts/$FIXTURE_ARTIFACT_ID/zip")
    [[ "$FIXTURE_DOWNLOAD_FAILURE" == false ]] || exit 45
    /bin/cat "$FIXTURE_DOWNLOAD" ;;
  "repos/$FIXTURE_REPOSITORY/actions/runs/$FIXTURE_RUN_ID/attempts/$FIXTURE_ATTEMPT")
    [[ "$FIXTURE_ATTEMPT_FAILURE" == false ]] || exit 46
    /bin/cat "$FIXTURE_ATTEMPT_JSON" ;;
  *) printf 'Unexpected service endpoint: %s\\n' "$endpoint" >&2; exit 90 ;;
esac
`);
    await chmod(gh, 0o755);
    const result = spawnSync(python, ["-I", "-S", "-"], {
      cwd: directory,
      input: verifierProgram(),
      encoding: "utf8",
      timeout: 10_000,
      env: {
        PATH: `${bin}:${process.env.PATH || "/usr/bin:/bin"}`,
        GITHUB_REPOSITORY: fixtureRepository, GITHUB_REPOSITORY_ID: String(fixtureRepositoryId),
        PREFLIGHT_RUN_ID: runId, PREFLIGHT_ARTIFACT_ID: artifactId, PREFLIGHT_ARTIFACT_SHA256: digest,
        PREFLIGHT_TARGET_SHA: fixtureTarget, GITHUB_SHA: "c".repeat(40), RUNNER_TEMP: runnerTemp,
        FIXTURE_CALLS: callsFile, FIXTURE_METADATA: metadataFile, FIXTURE_ATTEMPT_JSON: attemptFile,
        FIXTURE_DOWNLOAD: downloaded, FIXTURE_RUN_ID: runId, FIXTURE_ARTIFACT_ID: artifactId,
        FIXTURE_ATTEMPT: attemptRoute, FIXTURE_REPOSITORY: fixtureRepository, FIXTURE_METADATA_FAILURE: String(!!options.metadataFailure),
        FIXTURE_DOWNLOAD_FAILURE: String(!!options.downloadFailure), FIXTURE_ATTEMPT_FAILURE: String(!!options.attemptFailure),
        ...options.env,
        ...(options.reviewEnvironment?.(digest) ?? {})
      }
    });
    if (result.error) throw result.error;
    const calls = (await readFile(callsFile, "utf8")).trim().split("\n").filter(Boolean);
    const root = result.stdout.trim();
    const files: Record<string, string> = {};
    const modes: Record<string, number> = {};
    let retainedArchive: Buffer | undefined;
    if (result.status === 0) {
      expect(path.relative(runnerTemp, root)).not.toMatch(/^\.\.|^\//);
      expect(path.isAbsolute(root)).toBe(true);
      async function collect(current: string) {
        for (const entry of await readdir(current, { withFileTypes: true })) {
          const absolute = path.join(current, entry.name);
          const relative = path.relative(root, absolute);
          modes[relative] = (await stat(absolute)).mode & 0o777;
          if (entry.isDirectory()) await collect(absolute);
          else files[relative] = await readFile(absolute, "utf8");
        }
      }
      await collect(root);
      modes["."] = (await stat(root)).mode & 0o777;
      modes[".."] = (await stat(path.dirname(root))).mode & 0o777;
      retainedArchive = await readFile(path.join(path.dirname(root), "package.zip"));
    } else {
      expect(result.stdout).toBe("");
      expect(await readdir(runnerTemp)).toEqual([]);
    }
    return { status: result.status, stderr: result.stderr, calls, files, modes, retainedArchive, approvedBytes, formatProof };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function expectRejected(result: Awaited<ReturnType<typeof runVerifier>>) {
  expect(result.status, result.stderr).not.toBe(0);
  expect(result.stderr).not.toBe("");
}

describe("immutable preflight verifier", () => {
  it("consumes exact approved A and ignores a newer name alias B and unrelated event/target heads", async () => {
    const result = await runVerifier();
    expect(result.status, result.stderr).toBe(0);
    expect(result.files["RELEASE_NOTES.md"]).toBe("independently approved A\n");
    expect(result.files["source.tar.gz"]).toContain("never recursively unpacked");
    expect(result.retainedArchive).toEqual(result.approvedBytes);
    expect(result.calls).toEqual([
      "api repos/fake/repo/actions/artifacts/202",
      "api repos/fake/repo/actions/artifacts/202/zip",
      "api repos/fake/repo/actions/runs/101/attempts/1"
    ]);
    expect(result.modes["."]).toBe(0o700);
    expect(result.modes[".."]).toBe(0o700);
    expect(Object.entries(result.modes).filter(([name]) => name !== "." && name !== "..").every(([, mode]) => mode === 0o600)).toBe(true);
  });

  it.each([
    ["ordinary nested and explicit directories", { entries: [{ name: "nested/", kind: "directory", data: "" }, { name: "nested/deeper/file.txt", data: "nested" }] }],
    ["an explicit directory after its inferred parent", { entries: [{ name: "nested/file.txt" }, { name: "nested/", kind: "directory", data: "" }] }],
    ["explicit directory without slash", { entries: [{ name: "directory", kind: "directory", data: "" }] }],
    ["ordinary DOS-origin entries", { entries: [{ name: "ordinary/", kind: "directory", system: 0, data: "" }, { name: "ordinary/file.txt", system: 0 }] }],
    ["raw deflate", { entries: [{ name: "deflated.txt", data: "A".repeat(8192), deflate: true }] }],
    ["ZIP64 local headers", { zip64: true }],
    ["streaming data descriptors", { descriptor: true, entries: [{ name: "stream.txt", data: "streamed".repeat(100), deflate: true }] }],
    ["case-distinct files", { entries: [{ name: "Case.txt", data: "upper" }, { name: "case.txt", data: "lower" }] }],
    ["Unicode-distinct files", { entries: [{ name: "café.txt", data: "composed" }, { name: "cafe\u0301.txt", data: "decomposed" }] }]
  ] as Array<[string, FixtureOptions]>)("accepts %s when the filesystem represents every distinct name", async (_label, options) => {
    const result = await runVerifier(options);
    // Case/normalization-insensitive filesystems must fail closed rather than
    // merge names. Linux runners must exercise and accept the distinct paths.
    if (process.platform === "linux" || !["case-distinct files", "Unicode-distinct files"].includes(_label)) {
      expect(result.status, result.stderr).toBe(0);
      for (const entry of options.entries || []) {
        if (entry.kind === "directory") expect(result.modes[entry.name.replace(/\/$/, "")]).toBe(0o700);
        else expect(result.files[entry.name]).toBe(entry.data || "fixture payload");
      }
    } else if (result.status === 0) {
      for (const entry of options.entries || []) expect(result.files[entry.name]).toBe(entry.data);
    }
  });

  it("runs reviewed acquisition with pinned fake tools and rejects changed or ambiguous assets", async () => {
    const location = await mkdtemp(path.join(os.tmpdir(), "release-acquisition-test-"));
    try {
      const gitRoot = path.join(location, "git-fixture");
      await mkdir(gitRoot);
      await mkdir(path.join(gitRoot, "empty"));
      const gitEnv = { PATH: "/usr/bin:/bin", HOME: gitRoot, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
      const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", ...args], { cwd: gitRoot, env: gitEnv, ...(input === undefined ? {} : { input }) });
      git(["init", "-q", "--initial-branch=main", `--template=${path.join(gitRoot, "empty")}`]);
      const contents = Buffer.from("fabricated approved source\n");
      const oid = git(["hash-object", "--stdin", "--no-filters", "-w"], contents).toString().trim();
      const sourceNotes = Buffer.from("independently approved A\n");
      const notesOid = git(["hash-object", "--stdin", "--no-filters", "-w"], sourceNotes).toString().trim();
      git(["update-index", "-z", "--index-info"], Buffer.from(`100644 ${oid}\tREADME.md\0` + `100644 ${notesOid}\trelease-notes/v1.2.3.md\0`));
      const sourceTree = git(["write-tree"]).toString().trim();
      const sourceCommit = git(["commit-tree", sourceTree], "synthetic fixture\n").toString().trim();
      const snapshot = verifyGitSnapshot({ baseCommit: sourceCommit, commitBytes: git(["cat-file", "commit", sourceCommit]),
        files: [{ path: "README.md", mode: "100644", bytes: contents }, { path: "release-notes/v1.2.3.md", mode: "100644", bytes: sourceNotes }] });
      const sourceArchive = gzipSync(git(["archive", "--format=tar", "--prefix=bootstrap-v1.2.3/", sourceCommit]));
      const sourceName = "bootstrap-v1.2.3-source.tar.gz";
      const sourceHash = createHash("sha256").update(sourceArchive).digest("hex");
      const checksum = Buffer.from(`${sourceHash}  ${sourceName}\n`);
      const assetDigest = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
      const sourceManifest = Buffer.from(JSON.stringify({ schema_version: 1, repository: "fake/repo", version: "v1.2.3", channel: "stable", distribution: "repository-source-control-plane", source_commit: sourceCommit, source_tree: sourceTree,
        assets: [{ name: sourceName, bytes: sourceArchive.length, sha256: assetDigest(sourceArchive) }, { name: `${sourceName}.sha256`, bytes: checksum.length, sha256: assetDigest(checksum) }, { name: "RELEASE_NOTES.md", bytes: sourceNotes.length, sha256: assetDigest(sourceNotes) }] }));
      const resolved = spawnSync("which", [python], { encoding: "utf8" });
      if (resolved.status !== 0) throw new Error("python unavailable");
      const pythonPath = await realpath(resolved.stdout.trim());
      const pythonSha256 = createHash("sha256").update(await readFile(pythonPath)).digest("hex");
      const gh = path.join(await realpath(location), "gh");
      const archivePath = path.join(await realpath(location), "artifact.zip");
      const metadataPath = path.join(await realpath(location), "metadata.json");
      const attemptPath = path.join(await realpath(location), "attempt.json");
      const quote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";
      await writeFile(gh, `#!/bin/sh\nset -eu\n[ "$1" = api ]\ncase "$2" in\nrepos/fake/repo/actions/artifacts/202) /bin/cat ${quote(metadataPath)} ;;\nrepos/fake/repo/actions/artifacts/202/zip) /bin/cat ${quote(archivePath)} ;;\nrepos/fake/repo/actions/runs/101/attempts/1) /bin/cat ${quote(attemptPath)} ;;\n*) exit 1 ;;\nesac\n`);
      await chmod(gh, 0o700);
      const ghSha256 = createHash("sha256").update(await readFile(gh)).digest("hex");
      const attempt = { id: 101, run_attempt: 1, status: "completed", conclusion: "success", head_sha: "c".repeat(40), repository: { id: 42, full_name: "fake/repo" } };
      await writeFile(attemptPath, JSON.stringify(attempt));
      async function reviewed(extra: Entry[] = [], wrongAsset = false, evidence?: Record<string, unknown>) {
        const archive = await runVerifier({ entries: [{ name: `${sourceName}.sha256`, data: checksum.toString("utf8") },
          { name: "artifact-manifest.json", data: sourceManifest.toString("utf8") }, ...extra], evidence, sourceBytes: sourceArchive, sourceName, targetCommit: sourceCommit });
        expect(archive.status, archive.stderr).toBe(0);
        const digest = createHash("sha256").update(archive.approvedBytes).digest("hex");
        await writeFile(archivePath, archive.approvedBytes);
        await writeFile(metadataPath, JSON.stringify({ id: 202, name: "release-package", expired: false, digest: `sha256:${digest}`,
          workflow_run: { id: 101, repository_id: 42, head_repository_id: 42, head_sha: "c".repeat(40) } }));
        const source = packageFixture();
        const value = JSON.parse(Buffer.from(source.observation.manifestBytes).toString("utf8"));
        const notes = Buffer.from("independently approved A\n");
        const asset = sourceArchive;
        value.target = { commit: sourceCommit, tree: sourceTree };
        value.repository = { id: "42", full_name: "fake/repo" };
        value.preflight.run_id = "101"; value.preflight.artifact_id = "202"; value.preflight.archive_sha256 = digest;
        value.assets = [{ name: "RELEASE_NOTES.md", size: notes.length, sha256: assetDigest(notes) },
          { name: "artifact-manifest.json", size: sourceManifest.length, sha256: assetDigest(sourceManifest) },
          { name: sourceName, size: asset.length, sha256: wrongAsset ? "0".repeat(64) : assetDigest(asset) },
          { name: `${sourceName}.sha256`, size: checksum.length, sha256: assetDigest(checksum) }];
        function sort(input: unknown): unknown {
          if (Array.isArray(input)) return input.map(sort);
          if (input && typeof input === "object") return Object.fromEntries(Object.entries(input).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, sort(item)]));
          return input;
        }
        source.observation.manifestBytes = Buffer.from(`${JSON.stringify(sort(value))}\n`);
        const { approval_id: _id, expires_at: _expires, ...actual } = value;
        source.observation.actual = actual;
        source.observation.pull.repository_id = "42";
        source.observation.reviews[0]!.body = `APPROVE-RELEASE-SHA256 ${createHash("sha256").update(source.observation.manifestBytes).digest("hex")}`;
        const { actual: _actual, ...review } = source.observation;
        return { fact: reviewReleaseManifest(review, source.policy, source.now), source };
      }
      const base = { token: "fabricated-read-token", pythonPath, pythonSha256, ghPath: gh, ghSha256, runtimeDir: location, maxAssetBytes: 1024 * 1024 };
      const selected = await reviewed();
      const assets = await acquireReviewedArtifact({ ...base, reviewed: selected.fact });
      expect(assets.map((asset) => asset.name)).toEqual(["RELEASE_NOTES.md", "artifact-manifest.json", sourceName, `${sourceName}.sha256`]);
      expect(Buffer.from(assets[0]!.bytes).toString()).toBe("independently approved A\n");
      const acquired = await acquireReviewedPreflight({ ...base, reviewed: selected.fact });
      expect(acquired.evidence).toEqual({ version: "v1.2.3", channel: "stable", targetCommit: sourceCommit, runId: "101", attempt: "1" });
      expect(Object.isFrozen(acquired.evidence)).toBe(true);
      const prepared = await prepareReleaseForPublication({ policy: selected.source.policy,
        async readApproval() { const { actual: _actual, ...review } = structuredClone(selected.source.observation); return review; },
        async acquire(env, review) {
          expect(env.PREFLIGHT_ARTIFACT_SHA256).toBe(reviewedReleaseSelectors(review).archiveSha256);
          return { actual: selected.source.observation.actual, assets: await acquireReviewedArtifact({ ...base, reviewed: review }) };
        }
      });
      expect(approvedReleasePackageMetadata(prepared).notes).toBe("independently approved A\n");
      const source = selected.source;
      const manifestBytes = Buffer.from(source.observation.manifestBytes);
      const blobSha = createHash("sha1").update(`blob ${manifestBytes.length}\0`).update(manifestBytes).digest("hex");
      const manifestDigest = createHash("sha256").update(manifestBytes).digest("hex");
      const gitHead = source.observation.pull.head;
      const reviewPath = source.policy.manifest_path;
      const selectedDigest = reviewedReleaseSelectors(selected.fact).archiveSha256;
      const publishRun = { id: 130, run_attempt: 3, workflow_id: 131, path: ".github/workflows/release-publish.yml", event: "workflow_dispatch", status: "in_progress", head_sha: "c".repeat(40), repository: { id: 42 }, head_repository: { id: 42 }, actor: { id: 113, type: "User" }, triggering_actor: { id: 115, type: "User" } };
      const preflightRun = { id: 101, run_attempt: 1, workflow_id: 122, path: ".github/workflows/preflight.yml", event: "workflow_dispatch", status: "completed", conclusion: "success", head_sha: "c".repeat(40), repository: { id: 42 }, head_repository: { id: 42 }, actor: { id: 112, type: "User" }, triggering_actor: { id: 114, type: "User" } };
      const requests: string[] = [];
      const fakeFetch: typeof fetch = async (request) => {
        const url = new URL(String(request)); requests.push(url.pathname);
        let response: unknown;
        if (url.pathname === "/repos/fake/repo") response = { id: 42, full_name: "fake/repo", private: false };
        else if (url.pathname.endsWith("/git/ref/tags/v1.2.3")) response = { ref: "refs/tags/v1.2.3", object: { type: "commit", sha: sourceCommit } };
        else if (url.pathname.endsWith("/actions/runs/130/attempts/3")) response = publishRun;
        else if (url.pathname.endsWith("/actions/runs/101/attempts/1")) response = preflightRun;
        else if (url.pathname.endsWith("/actions/workflows/122")) response = { id: 122, path: preflightRun.path };
        else if (url.pathname.endsWith("/actions/artifacts/202")) response = { id: 202, name: "release-package", expired: false, digest: `sha256:${selectedDigest}`, workflow_run: { id: 101, repository_id: 42, head_repository_id: 42, head_sha: "c".repeat(40) } };
        else if (url.pathname.includes("/git/commits/")) response = { sha: sourceCommit, tree: { sha: sourceTree } };
        else if (url.pathname.endsWith("/pulls/4/files")) response = [{ filename: reviewPath, status: "added", sha: blobSha }];
        else if (url.pathname.includes("/git/blobs/")) response = { sha: blobSha, encoding: "base64", content: manifestBytes.toString("base64"), size: manifestBytes.length };
        else if (url.pathname.endsWith("/pulls/4/reviews")) response = [{ id: 200, user: { id: 111 }, state: "APPROVED", commit_id: gitHead, submitted_at: source.observation.reviews[0]!.submitted_at, body: `APPROVE-RELEASE-SHA256 ${manifestDigest}` }];
        else if (url.pathname.endsWith("/pulls/4")) response = { number: 4, state: "open", changed_files: 1, head: { sha: gitHead, repo: { id: 42 } }, base: { sha: "e".repeat(40), repo: { id: 42 } }, user: { id: 112 } };
        else throw new Error("unexpected fabricated endpoint");
        return new Response(JSON.stringify(response), { status: 200 });
      };
      const targetChecks: string[] = [];
      const githubInput: Parameters<typeof prepareGitHubReleasePackage>[0] = { policy: source.policy,
        approval: { repository: "fake/repo", repositoryId: "42", pullNumber: 4, manifestPath: reviewPath,
          publicationRunId: "130", publicationAttempt: "3", expectedWorkflowId: "131", expectedWorkflowPath: publishRun.path,
          expectedWorkflowCommit: publishRun.head_sha, token: base.token, fetchImpl: fakeFetch },
        preflightWorkflowPath: preflightRun.path, preflightWorkflowCommit: preflightRun.head_sha,
        tag: "v1.2.3", notesAssetName: "RELEASE_NOTES.md", latest: true, requireSignedTag: false,
        pythonPath, pythonSha256, ghPath: gh, ghSha256, runtimeDir: location, maxAssetBytes: base.maxAssetBytes, sourceSnapshot: snapshot,
        async assertTarget(tag, commit) { targetChecks.push(`${tag}:${commit}`); }
      };
      const observed = await prepareGitHubReleasePackage(githubInput);
      expect(approvedReleasePackageMetadata(observed).approvalSha256).toBe(manifestDigest);
      expect(targetChecks).toEqual([`v1.2.3:${sourceCommit}`, `v1.2.3:${sourceCommit}`, `v1.2.3:${sourceCommit}`]);
      expect(requests.filter((request) => request.endsWith("/actions/runs/130/attempts/3"))).toHaveLength(4);
      expect(requests.filter((request) => request.endsWith("/git/ref/tags/v1.2.3"))).toHaveLength(6);
      await expect(prepareGitHubReleasePackage({ ...githubInput, requireSignedTag: true })).rejects.toThrow("GitHub release preparation unavailable.");
      await expect(prepareGitHubReleasePackage({ ...githubInput, sourceSnapshot: { ...snapshot } })).rejects.toThrow("GitHub release preparation unavailable.");
      await expect(prepareGitHubReleasePackage({ ...githubInput, latest: false })).rejects.toThrow("GitHub release preparation unavailable.");
      await expect(acquireReviewedArtifact({ ...base, reviewed: selected.fact, ghSha256: "0".repeat(64) })).rejects.toThrow("Reviewed artifact acquisition unavailable.");
      await expect(acquireReviewedArtifact({ ...base, reviewed: (await reviewed([], true)).fact })).rejects.toThrow();
      await expect(acquireReviewedArtifact({ ...base, reviewed: (await reviewed([{ name: "nested/RELEASE_NOTES.md", data: "different" }])).fact })).rejects.toThrow();
      for (const evidence of [{ version: "v9.0.0" }, { channel: "beta" }, { checks: { prep: "skipped", preflight: "passed", build: "passed" } }]) {
        await expect(acquireReviewedPreflight({ ...base, reviewed: (await reviewed([], false, evidence)).fact })).rejects.toThrow();
      }
      expect((await readdir(location)).filter((name) => name.startsWith("bootstrap-approved-acquisition-"))).toEqual([]);
    } finally { await rm(location, { recursive: true, force: true }); }
  });

  it("uses every reviewed selector to acquire the exact archive and rejects a changed approved attempt", async () => {
    function environment(digest: string, approvedAttempt: string) {
      const source = packageFixture();
      const value = JSON.parse(Buffer.from(source.observation.manifestBytes).toString("utf8"));
      value.repository = { id: "42", full_name: "fake/repo" };
      value.preflight.run_id = "101";
      value.preflight.artifact_id = "202";
      value.preflight.archive_sha256 = digest;
      value.preflight.attempt = approvedAttempt;
      function sorted(input: unknown): unknown {
        if (Array.isArray(input)) return input.map(sorted);
        if (input && typeof input === "object") return Object.fromEntries(Object.entries(input).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, sorted(item)]));
        return input;
      }
      source.observation.manifestBytes = Buffer.from(`${JSON.stringify(sorted(value))}\n`);
      source.observation.pull.repository_id = "42";
      source.observation.reviews[0]!.body = `APPROVE-RELEASE-SHA256 ${createHash("sha256").update(source.observation.manifestBytes).digest("hex")}`;
      const { actual: _actual, ...review } = source.observation;
      const env = reviewedPreflightEnvironment(reviewReleaseManifest(review, source.policy, source.now));
      expect(Object.isFrozen(env)).toBe(true);
      return env;
    }
    const matching = await runVerifier({ reviewEnvironment: (digest) => environment(digest, "1") });
    expect(matching.status, matching.stderr).toBe(0);
    const wrongArchive = await runVerifier({ reviewEnvironment: () => environment("0".repeat(64), "1") });
    expectRejected(wrongArchive);
    expect(wrongArchive.calls).toHaveLength(1);
    const changed = await runVerifier({ reviewEnvironment: (digest) => environment(digest, "2") });
    expectRejected(changed);
    expect(changed.calls.some((call) => call.includes("/attempts/"))).toBe(false);
  });

  it("feeds a reviewed attempt into archive verification and rejects a different successful stamp", async () => {
    const source = packageFixture();
    const { actual: _actual, ...review } = source.observation;
    const selectors = reviewedReleaseSelectors(reviewReleaseManifest(review, source.policy, source.now));
    const matching = await runVerifier({ env: { PREFLIGHT_APPROVED_ATTEMPT: selectors.attempt } });
    expect(matching.status, matching.stderr).toBe(0);
    const changed = await runVerifier({ evidence: { run_attempt: "2" }, attemptRoute: "2", env: { PREFLIGHT_APPROVED_ATTEMPT: selectors.attempt } });
    expectRejected(changed);
    expect(changed.calls.some((call) => call.includes("/attempts/"))).toBe(false);
  });

  it("accepts the independently approved attempt matching the archive stamp", async () => {
    const result = await runVerifier({ env: { PREFLIGHT_APPROVED_ATTEMPT: "1" } });
    expect(result.status, result.stderr).toBe(0);
  });

  it.each(["", "0", "01", "+1", "1.0", " 1"])("rejects malformed approved attempt %j before provider access", async (value) => {
    const result = await runVerifier({ env: { PREFLIGHT_APPROVED_ATTEMPT: value } });
    expectRejected(result);
    expect(result.calls).toEqual([]);
  });

  it("rejects an archive whose stamped attempt differs from the independently approved attempt", async () => {
    const result = await runVerifier({ env: { PREFLIGHT_APPROVED_ATTEMPT: "2" } });
    expectRejected(result);
  });

  it.each(["", "0", "01", "+1", "-1", "1.0", "1e2", " 1", "1\n"])("rejects noncanonical run selector %j before querying the service", async (value) => {
    const result = await runVerifier({ env: { PREFLIGHT_RUN_ID: value } });
    expectRejected(result);
    expect(result.calls).toEqual([]);
  });

  it.each(["", "0", "0202", "+202", "202.0", " 202"])("rejects noncanonical artifact selector %j", async (value) => {
    const result = await runVerifier({ env: { PREFLIGHT_ARTIFACT_ID: value } });
    expectRejected(result);
    expect(result.calls).toEqual([]);
  });

  it.each(["", "A".repeat(64), "a".repeat(63), "g".repeat(64), ` ${"a".repeat(64)}`])("rejects malformed independent digest %j", async (value) => {
    const result = await runVerifier({ env: { PREFLIGHT_ARTIFACT_SHA256: value } });
    expectRejected(result);
    expect(result.calls).toEqual([]);
  });

  it("compares run and artifact IDs beyond JavaScript's safe integer without rounding", async () => {
    const result = await runVerifier({ runId: "9007199254740993", artifactId: "9223372036854775807" });
    expect(result.status, result.stderr).toBe(0);
    expect(result.calls[0]).toContain("9223372036854775807");
    expect(result.calls[2]).toContain("9007199254740993/attempts/1");
  });

  it("rejects a one-unit artifact mismatch beyond JavaScript's safe integer", async () => {
    expectRejected(await runVerifier({ artifactId: "9007199254740993", apiArtifactId: "9007199254740992" }));
  });

  it.each([
    ["wrong artifact", { id: 203 }], ["string artifact ID", { id: "202" }], ["boolean artifact ID", { id: true }],
    ["wrong name", { name: "release-evidence" }], ["expired artifact", { expired: true }], ["missing expiry", { expired: undefined }],
    ["wrong metadata digest", { digest: `sha256:${"0".repeat(64)}` }], ["missing metadata digest", { digest: undefined }],
    ["missing run association", { workflow_run: null }],
    ["wrong run", { workflow_run: { id: 102, repository_id: 42, head_sha: platformHeadSha } }],
    ["wrong repository", { workflow_run: { id: 101, repository_id: 43, head_sha: platformHeadSha } }],
    ["missing platform head", { workflow_run: { id: 101, repository_id: 42 } }]
  ] as Array<[string, Record<string, unknown>]>)("rejects %s before download", async (_label, metadata) => {
    const result = await runVerifier({ metadata });
    expectRejected(result);
    expect(result.calls).toHaveLength(1);
  });

  it.each([
    ["deleted approved A", { metadataFailure: true }], ["unavailable exact ZIP", { downloadFailure: true }],
    ["malformed metadata", { metadataText: "{not JSON" }], ["wrong actual ZIP despite matching metadata", { wrongDownloadedBytes: true }]
  ] as Array<[string, FixtureOptions]>)("fails closed for %s without selecting B or querying an attempt", async (_label, options) => {
    const result = await runVerifier(options);
    expectRejected(result);
    expect(result.calls.every((call) => !call.includes("/attempts/") && !call.includes("run download"))).toBe(true);
    if (options.wrongDownloadedBytes) expect(result.stderr.toLowerCase()).toContain("digest");
  });

  it.each([undefined, null, 1, true, "", "0", "01", "+1", "1.0", "1e0", "1\n"])("rejects noncanonical evidence attempt %j", async (run_attempt) => {
    const result = await runVerifier({ evidence: { run_attempt } });
    expectRejected(result);
    expect(result.calls).toHaveLength(2);
  });

  it.each([
    ["wrong evidence run", { preflight_run_id: "102" }], ["wrong checked-out target", { target_sha: "d".repeat(40) }],
    ["wrong evidence repository", { repo: "other/repo" }]
  ] as Array<[string, Record<string, unknown>]>)("rejects %s", async (_label, evidence) => {
    expectRejected(await runVerifier({ evidence }));
  });

  it.each([
    ["wrong attempt", { run_attempt: 2 }], ["missing attempt", { run_attempt: undefined }], ["string attempt", { run_attempt: "1" }],
    ["wrong run", { id: 102 }], ["boolean run", { id: true }],
    ["running attempt", { status: "in_progress", conclusion: null }], ["queued attempt", { status: "queued", conclusion: null }],
    ["failed attempt", { conclusion: "failure" }], ["cancelled attempt", { conclusion: "cancelled" }],
    ["neutral attempt", { conclusion: "neutral" }], ["skipped attempt", { conclusion: "skipped" }], ["timed out attempt", { conclusion: "timed_out" }],
    ["null status", { status: null }], ["missing status", { status: undefined }],
    ["null conclusion", { conclusion: null }], ["missing conclusion", { conclusion: undefined }],
    ["wrong platform head", { head_sha: "d".repeat(40) }], ["missing platform head", { head_sha: undefined }],
    ["wrong repository ID", { repository: { id: 43, full_name: "fake/repo" } }],
    ["wrong repository name", { repository: { id: 42, full_name: "other/repo" } }], ["missing repository", { repository: null }]
  ] as Array<[string, Record<string, unknown>]>)("rejects exact-attempt API evidence with %s", async (_label, attempt) => {
    expectRejected(await runVerifier({ attempt }));
  });

  it.each([{ attemptFailure: true }, { attemptText: "not JSON" }])("rejects unavailable or invalid exact-attempt data %j", async (options) => {
    expectRejected(await runVerifier(options));
  });

  it("uses successful historical attempt one without consulting a later failed attempt or latest-run alias", async () => {
    const result = await runVerifier();
    expect(result.status, result.stderr).toBe(0);
    expect(result.calls.filter((call) => call.includes("/runs/"))).toEqual(["api repos/fake/repo/actions/runs/101/attempts/1"]);
  });

  it("does not let a later successful partial rerun rescue the failed retained attempt stamp", async () => {
    const result = await runVerifier({ attempt: { conclusion: "failure" } });
    expectRejected(result);
    expect(result.calls.at(-1)).toBe("api repos/fake/repo/actions/runs/101/attempts/1");
  });

  it.each([
    "../escape", "nested/../../escape", "a/../b", "./dot", "a/./dot", "a//empty", "/absolute",
    "//server/share", "C:/drive", "C:drive", "a\\backslash", "\\\\server\\share"
  ])("rejects unsafe original member path %j without exposing partial output", async (name) => {
    expectRejected(await runVerifier({ entries: [{ name }] }));
  });

  it.each([
    ["NUL original name before truncation", { entries: [{ name: "badXname" }], mutation: "nul-name" }],
    ["central/local name disagreement", { entries: [{ name: "probe.bin" }], mutation: "local-name" }],
    ["invalid UTF-8 original name", { entries: [{ name: "probe.bin" }], mutation: "invalid-utf8" }],
    ["duplicate regular files", { entries: [{ name: "duplicate" }, { name: "duplicate" }] }],
    ["duplicate explicit directories", { entries: [{ name: "duplicate/", kind: "directory", data: "" }, { name: "duplicate/", kind: "directory", data: "" }] }],
    ["file before child prefix", { entries: [{ name: "parent" }, { name: "parent/child" }] }],
    ["child prefix before file", { entries: [{ name: "parent/child" }, { name: "parent" }] }],
    ["regular/directory path collision", { entries: [{ name: "parent" }, { name: "parent/", kind: "directory", data: "" }] }],
    ["regular file with slash", { entries: [{ name: "file/", kind: "file" }] }],
    ["contradictory DOS directory flag", { entries: [{ name: "file", dosDirectory: true }] }],
    ["symlink with slash", { entries: [{ name: "link/", kind: "symlink", data: "../outside" }] }],
    ["ordinary symlink", { entries: [{ name: "link", kind: "symlink", data: "../outside" }] }],
    ["FIFO", { entries: [{ name: "pipe", kind: "fifo" }] }],
    ["socket", { entries: [{ name: "socket", kind: "socket" }] }],
    ["character device", { entries: [{ name: "device", kind: "character" }] }],
    ["block device", { entries: [{ name: "device", kind: "block" }] }],
    ["CRC failure in a regular member", { entries: [{ name: "probe.bin" }], mutation: "crc" }],
    ["CRC failure in a directory member", { entries: [{ name: "probe/", kind: "directory", data: "directory payload" }], mutation: "crc" }],
    ["expanded data beyond declared size with matching prefix CRC", { entries: [{ name: "probe.bin", data: "A".repeat(1024), deflate: true }], mutation: "size-prefix" }],
    ["deflate stream lacking its end marker", { entries: [{ name: "probe.bin", data: "A".repeat(1024), deflate: true }], mutation: "deflate-no-eof" }],
    ["trailing data after deflate EOF", { entries: [{ name: "probe.bin", data: "A".repeat(1024), deflate: true }], mutation: "deflate-trailing" }],
    ["encrypted member", { entries: [{ name: "probe.bin" }], mutation: "encrypted" }],
    ["unsupported compression", { entries: [{ name: "probe.bin" }], mutation: "compression" }],
    ["truncated archive", { mutation: "truncated" }]
  ] as Array<[string, FixtureOptions]>)("rejects %s and never emits a partially verified tree", async (_label, options) => {
    const result = await runVerifier(options);
    expectRejected(result);
    expect(result.calls).toHaveLength(2);
  });
});


const descriptorVariants: Array<[string, FixtureOptions, number]> = [
  ["ordinary signed 32-bit", { descriptorVariant: "ordinary" }, 4],
  ["ordinary unsigned 32-bit", { descriptorVariant: "ordinary", unsignedDescriptor: true }, 4],
  ["offset-only central ZIP64 with signed 32-bit sizes", { descriptorVariant: "offset-only" }, 4],
  ["offset-only central ZIP64 with unsigned 32-bit sizes", { descriptorVariant: "offset-only", unsignedDescriptor: true }, 4],
  ["forced local ZIP64 with signed 64-bit sizes", { descriptorVariant: "ordinary", zip64: true }, 8],
  ["forced local ZIP64 with unsigned 64-bit sizes", { descriptorVariant: "ordinary", zip64: true, unsignedDescriptor: true }, 8],
  ["central ZIP64 sizes with signed 64-bit sizes", { descriptorVariant: "central-sizes" }, 8],
  ["central ZIP64 sizes with unsigned 64-bit sizes", { descriptorVariant: "central-sizes", unsignedDescriptor: true }, 8]
];

describe("streamed ZIP descriptor widths", () => {
  it.each(descriptorVariants)("accepts %s without inferring width from an offset", async (_label, options, width) => {
    const data = "descriptor payload".repeat(8);
    const result = await runVerifier({ ...options, descriptor: true, entries: [{ name: "streamed-probe.txt", data, deflate: true }] });
    expect(result.formatProof).toEqual({ stdlibReadSucceeded: true, archiveBytes: result.approvedBytes.length, descriptorWidth: width, signed: !options.unsignedDescriptor, centralSizeSentinels: options.descriptorVariant === "central-sizes", centralOffsetSentinel: options.descriptorVariant === "offset-only", localSizeSentinels: !!options.zip64 });
    expect(result.approvedBytes.length).toBeLessThan(8192);
    expect(result.status, result.stderr).toBe(0);
    expect(result.files["streamed-probe.txt"]).toBe(data);
    expect(result.retainedArchive).toEqual(result.approvedBytes);
  });

  it.each(descriptorVariants)("rejects a mismatched or truncated %s descriptor before exposing a tree", async (_label, options) => {
    const result = await runVerifier({ ...options, descriptor: true, descriptorMutation: options.unsignedDescriptor ? "truncated" : "mismatch", entries: [{ name: "streamed-probe.txt", data: "descriptor payload", deflate: true }] });
    expectRejected(result);
    expect(result.stderr).toContain("ZIP data descriptor mismatch or truncation.");
  });
});
