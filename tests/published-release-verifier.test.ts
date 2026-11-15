import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { publishedReleaseVerifierScript } from "../src/published-release-verifier.js";

const sha = (digit: string) => digit.repeat(64);
function valid() {
  const assets = [
    { name: "bundle.tar.gz", size: 11, sha256: sha("a"), digest_source: "approved-bytes" },
    { name: "bundle.tar.gz.sha256", size: 73, sha256: sha("b"), digest_source: "approved-bytes" },
    { name: "artifact-manifest.json", size: 42, sha256: sha("c"), digest_source: "approved-bytes" },
    { name: "RELEASE_NOTES.md", size: 23, sha256: sha("d"), digest_source: "approved-bytes" },
    { name: "SHA256SUMS", size: 12, sha256: sha("e"), digest_source: "approved-bytes" },
    { name: " spaced é name ", size: 0, sha256: sha("f"), digest_source: "approved-bytes" }
  ];
  const expected = {
    repository: "Owner/Repository", release_id: 17, tag: "v1.2.3", commit: "1".repeat(40),
    notes: "Notes with a newline\n", prerelease: false, latest: true, assets
  };
  const actual = {
    ...structuredClone(expected), repository: "owner/repository", draft: false,
    assets: assets.map((asset, index) => ({
      ...asset, id: index + 1, state: "uploaded",
      digest_source: index % 2 ? "authenticated-stream" : "provider-sha256"
    })).reverse()
  };
  return { schema_version: 1, expected, actual };
}

function execute(input: string | Uint8Array) {
  return spawnSync("python3", ["-I", "-S", "-c", publishedReleaseVerifierScript()], {
    input, encoding: "utf8", maxBuffer: 1024 * 1024
  });
}
function rejected(value: unknown) {
  const result = execute(JSON.stringify(value));
  expect(result.error).toBeUndefined();
  expect(result.status).toBe(1);
  expect(result.stdout).toBe("");
  expect(result.stderr).toBe("Published release verification failed.\n");
}

describe("self-contained published release comparator", () => {
  it("accepts exact complete contents independent of order and preserves literal names", () => {
    const input = valid();
    const before = JSON.stringify(input);
    const result = execute(before);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe('{"eligible":true}\n');
    expect(JSON.stringify(input)).toBe(before);
    expect(execute(before).stdout).toBe(result.stdout);
  });

  it("runs self-contained when embedded in a generated shell with JSON on stdin", () => {
    const script = publishedReleaseVerifierScript();
    expect(script).not.toContain("\nBOOTSTRAP_SCRIPT\n");
    const shell = `python3 -I -S -c "$(cat <<'BOOTSTRAP_SCRIPT'\n${script}\nBOOTSTRAP_SCRIPT\n)"`;
    const result = spawnSync("bash", ["-euo", "pipefail", "-c", shell], {
      input: JSON.stringify(valid()), encoding: "utf8"
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe('{"eligible":true}\n');
  });

  it.each([
    ["repository", (x: ReturnType<typeof valid>) => { x.actual.repository = "other/repository"; }],
    ["release id", (x: ReturnType<typeof valid>) => { x.actual.release_id++; }],
    ["tag case", (x: ReturnType<typeof valid>) => { x.actual.tag = "V1.2.3"; }],
    ["commit", (x: ReturnType<typeof valid>) => { x.actual.commit = "2".repeat(40); }],
    ["draft", (x: ReturnType<typeof valid>) => { x.actual.draft = true; }],
    ["notes newline", (x: ReturnType<typeof valid>) => { x.actual.notes = "Notes with a newline"; }],
    ["prerelease", (x: ReturnType<typeof valid>) => { x.actual.prerelease = true; }],
    ["latest", (x: ReturnType<typeof valid>) => { x.actual.latest = false; }],
    ["asset name", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.name += " "; }],
    ["asset size", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.size++; }],
    ["asset digest", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.sha256 = sha("0"); }],
    ["extra asset", (x: ReturnType<typeof valid>) => { x.actual.assets.push({ ...x.actual.assets[0]!, name: "extra", id: 99 }); }],
    ["missing asset", (x: ReturnType<typeof valid>) => { x.actual.assets.pop(); }],
    ["duplicate name", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.name = x.actual.assets[1]!.name; }],
    ["duplicate id", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.id = x.actual.assets[1]!.id; }],
    ["unuploaded asset", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.state = "starter"; }],
    ["untrusted digest source", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.digest_source = "unverified"; }],
    ["invalid algorithm", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.sha256 = "sha256:" + sha("a"); }],
    ["uppercase digest", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.sha256 = sha("A"); }],
    ["negative size", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.size = -1; }],
    ["fractional size", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.size = 0.5; }],
    ["unsafe integer", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.size = 9007199254740992; }],
    ["invalid asset path", (x: ReturnType<typeof valid>) => { x.actual.assets[0]!.name = "nested/asset"; }],
    ["zero assets", (x: ReturnType<typeof valid>) => { x.expected.assets = []; x.actual.assets = []; }]
  ])("rejects changed or invalid %s", (_name, change) => {
    const input = valid();
    change(input);
    rejected(input);
  });

  it.each(["-v1", "bad tag", "v1..2", "v1@{2", "v1~2", "v1^2", "v1:2", "v1?2", "v1*2", "v1[2", "v1\\2", "v1\n2", "v1\u007f2", "/v1", "v1/", "v1.", "a//b", ".hidden/v1", "a/.hidden", "a.lock/v1", "v1.lock", "@"]) (
    "rejects matching invalid tag %j", (_tag) => {
      const input = valid();
      input.expected.tag = _tag;
      input.actual.tag = _tag;
      rejected(input);
    }
  );

  it.each(["./..", "../project", ".../project", "-owner/project", "owner-/project", "owner/.", "owner/..", "owner/...", "owner/space name", "owner/" + "a".repeat(101)])(
    "rejects matching invalid repository %s", (repository) => {
      const input = valid();
      input.expected.repository = repository;
      input.actual.repository = repository;
      rejected(input);
    }
  );

  it.each([["a/.github", "releases/v1.2.3+build.7"], ["org-123/repo..v1", "release/révision-1"], ["X/repo_name", "v1/normal.locked"], ["managed_user/repo", "v2.0.0"], ["managed.user/my--repo", "v3"]])(
    "accepts valid repository %s and slash-containing tag %s", (repository, tag) => {
      const input = valid();
      input.expected.repository = repository;
      input.actual.repository = repository;
      input.expected.tag = tag;
      input.actual.tag = tag;
      expect(execute(JSON.stringify(input)).status).toBe(0);
    }
  );

  it("agrees with Git's ref-format check on representative non-option tag names", () => {
    for (const tag of ["v1.2.3", "releases/v1+build", "étiquette/1", "v1..2", "v1@{2", "v1.lock", "a/.hidden", "a//b", "a/b."]) {
      const input = valid();
      input.expected.tag = tag;
      input.actual.tag = tag;
      const git = spawnSync("git", ["check-ref-format", `refs/tags/${tag}`]);
      expect(git.error).toBeUndefined();
      expect(execute(JSON.stringify(input)).status === 0).toBe(git.status === 0);
    }
  });

  it("preserves exact Unicode and refuses null, truncated, duplicate or unexpected input", () => {
    const input = valid();
    input.actual.assets[0]!.name = input.actual.assets[0]!.name.normalize("NFD");
    rejected(input);
    for (const raw of [
      "", "null", '{"schema_version":1,"schema_version":1}',
      '{"schema_version":NaN}', '{"schema_version":' + "9".repeat(4096) + '}',
      '{"schema_version":1.0}', JSON.stringify({ ...valid(), unexpected: true }),
      JSON.stringify({ ...valid(), actual: null }),
      JSON.stringify({ ...valid(), actual: { ...valid().actual, notes: null } })
    ]) {
      const result = execute(raw);
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("Published release verification failed.\n");
    }
    expect(execute(new Uint8Array([0xff])).status).toBe(1);
  });

  it("bounds payloads, assets, notes and identifiers before accepting evidence", () => {
    const tooMany = valid();
    tooMany.actual.assets = Array.from({ length: 1001 }, (_, index) => ({ ...tooMany.actual.assets[0]!, id: index + 1, name: String(index) }));
    rejected(tooMany);
    const longNote = valid();
    longNote.actual.notes = "x".repeat(1024 * 1024 + 1);
    rejected(longNote);
    const longName = valid();
    longName.actual.assets[0]!.name = "x".repeat(1025);
    rejected(longName);
    const invalidId = valid();
    invalidId.actual.assets[0]!.id = 0;
    rejected(invalidId);
    const result = execute(" ".repeat(4 * 1024 * 1024 + 1));
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
  });
});
