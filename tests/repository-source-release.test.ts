import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";
import YAML from "yaml";

const version = "v1.1.0";
const archive = `bootstrap-${version}-source.tar.gz`;
const repository = "OMT-Global/bootstrap";
const releaseAssets = [archive, `${archive}.sha256`, "artifact-manifest.json", "RELEASE_NOTES.md"];
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

class ReleaseFixture {
  readonly env: NodeJS.ProcessEnv;
  readonly package: string;
  readonly approved: string;
  sourceCommit = "";

  constructor(readonly directory: string) {
    this.package = path.join(directory, "dist/release");
    this.approved = path.join(directory, "approved-preflight");
    this.env = {
      PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`,
      HOME: directory,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
      GIT_AUTHOR_NAME: "Release fixture",
      GIT_AUTHOR_EMAIL: "fixture@example.invalid",
      GIT_COMMITTER_NAME: "Release fixture",
      GIT_COMMITTER_EMAIL: "fixture@example.invalid",
      VERSION: version,
      CHANNEL: "stable",
      GITHUB_REPOSITORY: repository,
      RUNNER_TEMP: directory,
      PREFLIGHT_RUN_ID: "101",
      ARTIFACT_DIR: "dist/release"
    };
  }

  run(command: string, args: string[]) {
    const result = spawnSync(command, args, {
      cwd: this.directory, env: this.env, encoding: "utf8", timeout: 10_000
    });
    if (result.error) throw result.error;
    return result;
  }

  git(...args: string[]) {
    const result = this.run("/usr/bin/git", args);
    if (result.status !== 0) throw new Error(result.stderr);
    return result.stdout.trim();
  }

  commit() {
    this.git("add", ".");
    // Signing is disabled only for this fabricated disposable repository.
    this.git("-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Synthetic release source");
    this.sourceCommit = this.git("rev-parse", "HEAD");
  }

  hook(name: string, tag = version) {
    return this.run("/bin/bash", [`scripts/release/${name}.sh`, ...(name === "postpublish" ? [tag] : [])]);
  }

  requireHook(name: string) {
    const result = this.hook(name);
    if (result.status !== 0) throw new Error(`${name}: ${result.stderr}`);
    return result;
  }

  async build() {
    this.requireHook("prep");
    this.requireHook("build");
    await writeFile(path.join(this.package, "release-evidence.json"), JSON.stringify({
      schema_version: 1, repo: repository, version, channel: "stable",
      target_sha: this.sourceCommit, preflight_run_id: "101",
      checks: { prep: "passed", preflight: "passed", build: "passed" }
    }));
    await cp(this.package, this.approved, { recursive: true });
  }

  async remoteFixture(inventory: unknown = releaseAssets) {
    const assetNames = path.join(this.directory, "remote-asset-names.json");
    await writeFile(assetNames, JSON.stringify(inventory));
    const bin = path.join(this.directory, "bin");
    await mkdir(bin);
    const gh = path.join(bin, "gh");
    await writeFile(gh, `#!/bin/bash
set -euo pipefail
printf '%s %s\\n' "$1" "$2" >> "$REMOTE_EVENTS"
case "$1 $2" in
  "release view")
    [[ "$3" == "v1.1.0" && "$4" == "--repo" && "$5" == "OMT-Global/bootstrap" ]] || exit 90
    if [[ "$#" == "9" && "$6" == "--json" && "$7" == "assets" && "$8" == "--jq" && "$9" == '[.assets[].name]' ]]; then
      cat "$REMOTE_ASSET_NAMES_FIXTURE"
    elif [[ "$#" == "5" || ( "$#" == "9" && "$6" == "--json" && "$7" == "assets" && "$8" == "--jq" && "$9" == '.assets | length' ) ]]; then
      printf '4\\n'
    else exit 90; fi
    exit 0
    ;;
  "release download") [[ "$3" == "v1.1.0" ]] || exit 90; source="$PACKAGE_FIXTURE" ;;
  "run download")
    [[ "$3" == "101" && "\${NO_APPROVED_PREFLIGHT:-0}" != "1" ]] || exit 44
    source="$APPROVED_PACKAGE_FIXTURE"
    ;;
  *) echo "Unexpected remote operation" >&2; exit 90 ;;
esac
destination=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--dir" ]]; then destination="$2"; break; fi
  shift
done
[[ -n "$destination" ]] || exit 90
cp "$source"/* "$destination"/
`);
    await chmod(gh, 0o755);
    this.env.PATH = `${bin}:${this.env.PATH}`;
    this.env.PACKAGE_FIXTURE = this.package;
    this.env.APPROVED_PACKAGE_FIXTURE = this.approved;
    this.env.REMOTE_EVENTS = path.join(this.directory, "remote-events");
    this.env.REMOTE_ASSET_NAMES_FIXTURE = assetNames;
  }

  async recomputeReleaseManifest() {
    const contents = await readFile(path.join(this.package, archive));
    await writeFile(path.join(this.package, `${archive}.sha256`), `${sha256(contents)}  ${archive}\n`);
    const manifestPath = path.join(this.package, "artifact-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    for (const asset of manifest.assets) {
      const bytes = await readFile(path.join(this.package, asset.name));
      asset.sha256 = sha256(bytes);
      asset.bytes = bytes.length;
    }
    await writeFile(manifestPath, JSON.stringify(manifest));
  }
}

async function fixture(test: (value: ReleaseFixture) => Promise<void>) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-source-release-"));
  try {
    const value = new ReleaseFixture(directory);
    await mkdir(path.join(directory, "scripts/release"), { recursive: true });
    for (const hook of ["prep", "build", "postpublish"]) {
      await cp(path.resolve(`scripts/release/${hook}.sh`), path.join(directory, `scripts/release/${hook}.sh`));
    }
    await mkdir(path.join(directory, "release-notes"));
    await writeFile(path.join(directory, `release-notes/${version}.md`), "# Synthetic release notes\n\nFabricated source fixture; no real release.\n");
    await writeFile(path.join(directory, "README.md"), "Synthetic source distribution\n");
    await writeFile(path.join(directory, "LICENSE"), "Existing legal bytes are preserved exactly.\n");
    value.git("init", "-qb", "fixture");
    value.commit();
    value.git("-c", "tag.gpgSign=false", "tag", version);
    await writeFile(path.join(directory, "untracked-local-state"), "Never archive this file.\n");
    await test(value);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("repository-source release hooks", () => {
  it("archives exactly tracked source with the source identity, checksums and unchanged legal bytes", () => fixture(async f => {
    await f.build();
    const manifest = JSON.parse(await readFile(path.join(f.package, "artifact-manifest.json"), "utf8"));
    expect(manifest.source_commit).toBe(f.sourceCommit);
    expect(manifest.source_tree).toBe(f.git("rev-parse", "HEAD^{tree}"));
    expect(manifest.distribution).toBe("repository-source-control-plane");
    for (const asset of manifest.assets) {
      const bytes = await readFile(path.join(f.package, asset.name));
      expect(asset.sha256).toBe(sha256(bytes));
      expect(asset.bytes).toBe(bytes.length);
    }
    const listing = f.run("/usr/bin/tar", ["-tzf", path.join(f.package, archive)]);
    expect(listing.status, listing.stderr).toBe(0);
    const names = listing.stdout.trim().split("\n").filter(name => !name.endsWith("/"));
    expect(names.sort()).toEqual(f.git("ls-tree", "-r", "--name-only", "HEAD").split("\n").map(name => `bootstrap-${version}/${name}`).sort());
    const legal = f.run("/usr/bin/tar", ["-xOzf", path.join(f.package, archive), `bootstrap-${version}/LICENSE`]);
    expect(legal.status, legal.stderr).toBe(0);
    expect(legal.stdout).toBe(await readFile(path.join(f.directory, "LICENSE"), "utf8"));
    expect(await readFile(path.join(f.package, `${archive}.sha256`), "utf8")).toBe(`${sha256(await readFile(path.join(f.package, archive)))}  ${archive}\n`);
  }));

  it("requires committed release notes before creating the artifact directory", () => fixture(async f => {
    await rm(path.join(f.directory, `release-notes/${version}.md`));
    f.commit();
    expect(f.hook("prep").status).not.toBe(0);
    await expect(readFile(path.join(f.package, "RELEASE_NOTES.md"))).rejects.toMatchObject({ code: "ENOENT" });
  }));

  it("rejects committed placeholder notes", () => fixture(async f => {
    await writeFile(path.join(f.directory, `release-notes/${version}.md`), "Generated placeholder release notes.\n");
    f.commit();
    expect(f.hook("prep").stderr).toContain("Placeholder notes");
  }));

  it("rejects empty committed notes", () => fixture(async f => {
    await writeFile(path.join(f.directory, `release-notes/${version}.md`), "");
    f.commit();
    expect(f.hook("prep").stderr).toContain("cannot be empty");
  }));

  it.each([" ", "\t", "\r\n", "\u00a0\u3000\n"])("rejects whitespace-only committed notes %j before creating artifacts", notes => fixture(async f => {
    await writeFile(path.join(f.directory, `release-notes/${version}.md`), notes);
    f.commit();
    const result = f.hook("prep");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("cannot be empty");
    await expect(readFile(path.join(f.package, "RELEASE_NOTES.md"))).rejects.toMatchObject({ code: "ENOENT" });
  }));

  it("requires successful preparation before building", () => fixture(async f => {
    expect(f.hook("build").stderr).toContain("Run release prep");
  }));

  it("rejects unsupported channels before building or downloading", () => fixture(async f => {
    f.env.CHANNEL = "unrecognized";
    expect(f.hook("build").stderr).toContain("Invalid release channel");
    expect(f.hook("postpublish").stderr).toContain("Invalid release channel");
  }));

  it("uses committed notes despite modified working-copy text", () => fixture(async f => {
    await writeFile(path.join(f.directory, `release-notes/${version}.md`), "Unreviewed working-copy replacement\n");
    f.requireHook("prep");
    expect(await readFile(path.join(f.package, "RELEASE_NOTES.md"), "utf8")).toBe(f.git("show", `HEAD:release-notes/${version}.md`) + "\n");
  }));

  it("rejects prepared notes changed before build", () => fixture(async f => {
    f.requireHook("prep");
    await writeFile(path.join(f.package, "RELEASE_NOTES.md"), "Swapped prepared notes\n");
    expect(f.hook("build").stderr).toContain("do not match");
  }));

  it("verifies published assets against the separately selected preflight package", () => fixture(async f => {
    await f.build();
    await f.remoteFixture();
    expect(f.requireHook("postpublish").stdout).toContain(f.sourceCommit);
  }));

  it("accepts the exact custom asset inventory in a different order", () => fixture(async f => {
    await f.build();
    await f.remoteFixture([...releaseAssets].reverse());
    expect(f.requireHook("postpublish").stdout).toContain(f.sourceCommit);
  }));

  it.each([
    ["extra", [...releaseAssets, "stale.zip"]],
    ["missing", releaseAssets.slice(0, -1)],
    ["replacement", [...releaseAssets.slice(0, -1), "unapproved.zip"]],
    ["duplicate", [...releaseAssets.slice(0, -1), archive]],
    ["malformed", { assets: releaseAssets }]
  ])("rejects %s published release asset inventory", (kind, inventory) => fixture(async f => {
    await f.build();
    if (kind === "extra") await writeFile(path.join(f.package, "stale.zip"), "Unapproved retained asset");
    await f.remoteFixture(inventory);
    const result = f.hook("postpublish");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Published release asset inventory");
  }));

  it("runs the strict hook through the compatible standalone reusable workflow shell", () => fixture(async f => {
    await f.build();
    await f.remoteFixture();
    const workflow = YAML.parse(await readFile(".github/workflows/release-postpublish-reusable.yml", "utf8"));
    const shell = workflow.jobs.postpublish.steps.find((step: { name?: string }) => step.name === "Verify published release").run;
    Object.assign(f.env, { TAG: version, RELEASE_ISSUE: "27", POSTPUBLISH_SCRIPT: "scripts/release/postpublish.sh", GITHUB_RUN_ID: "103" });
    const result = f.run("/bin/bash", ["-c", shell]);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`against approved preflight 101`);
    const evidence = JSON.parse(await readFile(path.join(f.package, "postpublish-evidence.json"), "utf8"));
    expect(evidence).toMatchObject({ repo: repository, tag: version, channel: "stable", postpublish_run_id: "103", release_assets: 4 });
  }));

  it("fails the composed standalone audit without an independently selected preflight run", () => fixture(async f => {
    await f.build();
    await f.remoteFixture();
    const workflow = YAML.parse(await readFile(".github/workflows/release-postpublish-reusable.yml", "utf8"));
    const shell = workflow.jobs.postpublish.steps.find((step: { name?: string }) => step.name === "Verify published release").run;
    Object.assign(f.env, { TAG: version, RELEASE_ISSUE: "27", POSTPUBLISH_SCRIPT: "scripts/release/postpublish.sh", GITHUB_RUN_ID: "103", PREFLIGHT_RUN_ID: "" });
    const result = f.run("/bin/bash", ["-c", shell]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Approved preflight run ID is required");
    await expect(readFile(path.join(f.package, "postpublish-evidence.json"))).rejects.toMatchObject({ code: "ENOENT" });
  }));

  it("rejects changed published asset bytes", () => fixture(async f => {
    await f.build();
    await writeFile(path.join(f.package, archive), "Changed remote asset");
    await f.remoteFixture();
    expect(f.hook("postpublish").stderr).toContain("digest or size mismatch");
  }));

  it.each(["archive", "notes"])("rejects substituted %s with a self-consistent recomputed manifest", kind => fixture(async f => {
    await f.build();
    await writeFile(path.join(f.package, kind === "archive" ? archive : "RELEASE_NOTES.md"), "Substituted bytes retaining claimed source identity");
    await f.recomputeReleaseManifest();
    await f.remoteFixture();
    expect(f.hook("postpublish").status).not.toBe(0);
  }));

  it("requires an independently selected preflight run", () => fixture(async f => {
    await f.build();
    await f.remoteFixture();
    delete f.env.PREFLIGHT_RUN_ID;
    expect(f.hook("postpublish").status).not.toBe(0);
  }));

  it("rejects an unavailable selected preflight package", () => fixture(async f => {
    await f.build();
    await f.remoteFixture();
    f.env.NO_APPROVED_PREFLIGHT = "1";
    expect(f.hook("postpublish").status).not.toBe(0);
  }));

  it.each(["preflight_run_id", "repo", "version", "channel", "target_sha"])("rejects preflight evidence with different %s", field => fixture(async f => {
    await f.build();
    const filename = path.join(f.approved, "release-evidence.json");
    const evidence = JSON.parse(await readFile(filename, "utf8"));
    evidence[field] = "different";
    await writeFile(filename, JSON.stringify(evidence));
    await f.remoteFixture();
    expect(f.hook("postpublish").status).not.toBe(0);
  }));

  it("requires all source preflight checks to have passed", () => fixture(async f => {
    await f.build();
    const filename = path.join(f.approved, "release-evidence.json");
    const evidence = JSON.parse(await readFile(filename, "utf8"));
    evidence.checks.build = "skipped";
    await writeFile(filename, JSON.stringify(evidence));
    await f.remoteFixture();
    expect(f.hook("postpublish").status).not.toBe(0);
  }));

  it.each(["../escape", "--help", "v01.1.0"])("rejects unsafe or unsupported version %s before constructing paths", invalid => fixture(async f => {
    f.env.VERSION = invalid;
    expect(f.hook("prep").stderr).toContain("Invalid source-release version");
    expect(f.hook("build").stderr).toContain("Invalid source-release version");
    expect(f.hook("postpublish", invalid).stderr).toContain("Invalid source-release version");
  }));

  it("rejects invalid selected run IDs before remote calls", () => fixture(async f => {
    await f.build();
    await f.remoteFixture();
    f.env.PREFLIGHT_RUN_ID = "--help";
    expect(f.hook("postpublish").stderr).toContain("Invalid approved preflight run ID");
    await expect(readFile(f.env.REMOTE_EVENTS!)).rejects.toMatchObject({ code: "ENOENT" });
  }));
});
