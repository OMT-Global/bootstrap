import { createHash, timingSafeEqual } from "node:crypto";
import { gunzipSync } from "node:zlib";

import { ISOLATION_LIMITS } from "./isolation/node-profile.js";
import { openDataRepository, type VerifiedGitSnapshot } from "./upgrade-git.js";

/**
 * Compare approved compressed bytes with Git's archive of a verified snapshot.
 * The caller must authenticate expected commit/tree and archive digest, and bind
 * these bytes to the selected preflight artifact. This is not release approval.
 */
export async function verifySourceReleaseArchive(
  snapshot: VerifiedGitSnapshot,
  compressed: Uint8Array,
  expected: { commit: string; tree: string; tag: string; sha256: string }
): Promise<{ commit: string; tree: string; archive_sha256: string; tar_sha256: string }> {
  try {
    const { commit, tree, tag, sha256 } = expected;
    if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree) || !/^[0-9a-f]{64}$/.test(sha256) ||
      !/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:rc|beta)\.[0-9]+)?$/.test(tag) || tag.length > 240 ||
      !(compressed instanceof Uint8Array) || compressed.byteLength === 0 || compressed.byteLength > ISOLATION_LIMITS.archiveBytes ||
      snapshot.baseCommit !== commit || snapshot.tree !== tree) throw new Error();
    const input = Buffer.from(compressed);
    const archiveDigest = createHash("sha256").update(input).digest("hex");
    if (archiveDigest !== sha256) throw new Error();
    const actual = gunzipSync(input, { maxOutputLength: ISOLATION_LIMITS.outputBytes });
    const repository = await openDataRepository(snapshot);
    try {
      const rebuilt = await repository.archive(`bootstrap-${tag}/`);
      if (actual.length !== rebuilt.length || !timingSafeEqual(actual, rebuilt)) throw new Error();
      return { commit, tree, archive_sha256: archiveDigest, tar_sha256: createHash("sha256").update(rebuilt).digest("hex") };
    } finally {
      await repository.dispose();
    }
  } catch {
    throw new Error("Source release archive verification failed.");
  }
}
