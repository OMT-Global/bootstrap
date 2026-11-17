import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { acquireReviewedPreflight } from "../src/release-artifact-acquisition.js";
import { reviewReleaseManifest } from "../src/release-approval.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

const boundary = vi.hoisted(() => ({ path: "", mutate: undefined as undefined | (() => void) }));
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, realpath: async (file: Parameters<typeof actual.realpath>[0]) => {
    const result = await actual.realpath(file);
    if (file === boundary.path) { const mutate = boundary.mutate; boundary.mutate = undefined; mutate?.(); }
    return result;
  } };
});
afterEach(() => { boundary.path = ""; boundary.mutate = undefined; });

describe("release acquisition input capture", () => {
  it("does not execute an unpinned replacement with its fabricated token after awaiting gh verification", async () => {
    const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "release-input-capture-")));
    try {
      const source = packageFixture();
      const { actual: _actual, ...review } = source.observation;
      const reviewed = reviewReleaseManifest(review, source.policy, source.now);
      const pinned = path.join(directory, "pinned-python");
      const replacement = path.join(directory, "unpinned-python");
      const gh = path.join(directory, "gh");
      const ran = path.join(directory, "pinned-ran");
      const exposed = path.join(directory, "fabricated-token-exposed");
      const quote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";
      await writeFile(pinned, `#!/bin/sh\n/bin/cat >/dev/null\nprintf pinned >${quote(ran)}\nexit 1\n`);
      await writeFile(replacement, `#!/bin/sh\n/bin/cat >/dev/null\nprintf '%s' "$GH_TOKEN" >${quote(exposed)}\nexit 1\n`);
      await writeFile(gh, "#!/bin/sh\nexit 1\n");
      await Promise.all([pinned, replacement, gh].map((file) => chmod(file, 0o700)));
      const digest = async (file: string) => createHash("sha256").update(await readFile(file)).digest("hex");
      const options = { reviewed, token: "fabricated-capture-token", pythonPath: pinned, pythonSha256: await digest(pinned),
        ghPath: gh, ghSha256: await digest(gh), runtimeDir: directory, maxAssetBytes: 1024 * 1024,
        maxArchiveBytes: 1024 * 1024, maxExpandedBytes: 1024 * 1024, maxMembers: 100 };
      boundary.path = gh;
      boundary.mutate = () => { options.pythonPath = replacement; };
      await expect(acquireReviewedPreflight(options)).rejects.toThrow("Reviewed artifact acquisition unavailable.");
      await expect(readFile(exposed)).rejects.toMatchObject({ code: "ENOENT" });
      expect(await readFile(ran, "utf8")).toBe("pinned");
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});
