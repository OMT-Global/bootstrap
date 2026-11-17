import { constants } from "node:fs";
import { link, mkdtemp, open, rm } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { Command } from "commander";

import {
  canonicalizeProvenanceJson,
  provenanceSigningKeyFingerprint,
  signPublicProvenance,
  validatePublicProvenance,
  verifySignedPublicProvenance
} from "./provenance.js";
import { publicPullRequestContextSchema, resolvePublicGitHubReviewers } from "./provenance-github.js";

const keyPart = z.string().regex(/^[A-Za-z0-9_-]{43}$/)
  .refine((value) => Buffer.from(value, "base64url").length === 32 && Buffer.from(value, "base64url").toString("base64url") === value);
const publicKeySchema = z.object({ kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: keyPart }).strict();
const privateKeySchema = publicKeySchema.extend({ d: keyPart }).strict();
const keyringSchema = z.array(publicKeySchema).min(1).max(64).refine((keys) => {
  return new Set(keys.map(provenanceSigningKeyFingerprint)).size === keys.length;
});

async function readJson(file: string, maximum: number): Promise<unknown> {
  if (!(constants.O_NOFOLLOW > 0) || !(constants.O_NONBLOCK > 0)) throw new Error("Safe local input flags are unavailable.");
  const handle = await open(path.resolve(file), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > maximum) throw new Error("Input file is invalid.");
    const buffer = Buffer.alloc(maximum + 1);
    let size = 0;
    while (size < buffer.length) {
      const result = await handle.read(buffer, size, buffer.length - size, null);
      if (result.bytesRead === 0) break;
      size += result.bytesRead;
    }
    const after = await handle.stat();
    if (size > maximum || size !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error("Input file changed or exceeded its bound.");
    }
    return JSON.parse(buffer.subarray(0, size).toString("utf8"));
  } finally { await handle.close(); }
}

async function writeNewJson(output: string, value: unknown): Promise<void> {
  const destination = path.resolve(output);
  const staging = await mkdtemp(path.join(path.dirname(destination), ".bootstrap-provenance-"));
  try {
    const staged = path.join(staging, "envelope.json");
    const handle = await open(staged, "wx", 0o600);
    try {
      const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
      if (bytes.length > 1_048_576) throw new Error("Signed output exceeds its bound.");
      await handle.writeFile(bytes);
      await handle.sync();
    } finally { await handle.close(); }
    // A hard link publishes a complete file exclusively; it never overwrites an existing path.
    await link(staged, destination);
  } finally { await rm(staging, { recursive: true, force: true }); }
}

interface Options {
  input: string;
  output?: string;
  privateKey?: string;
  keyring?: string;
  repository: string;
  commit: string;
  pr: string;
}

function context(options: Options) {
  if (!/^[1-9][0-9]{0,9}$/.test(options.pr)) throw new Error("Invalid PR number.");
  return publicPullRequestContextSchema.parse({ repository: options.repository, commitSha: options.commit, pullRequest: Number(options.pr) });
}

function expectedOptions(command: Command): Command {
  return command
    .requiredOption("--input <path>", "Input public-v2 manifest or signed envelope")
    .requiredOption("--repository <owner/name>", "Independently expected public github.com base repository")
    .requiredOption("--commit <sha>", "Independently expected current PR head SHA")
    .requiredOption("--pr <number>", "Independently expected pull request number");
}

/** Register public-only consumers; the existing unsigned commands remain independent. */
export function registerSignedProvenanceCommands(provenance: Command): void {
  expectedOptions(provenance.command("sign").description("Sign public provenance using actual exact-head GitHub reviewer lineage."))
    .requiredOption("--private-key <path>", "Selected local Ed25519 private JWK file; never sent to GitHub")
    .requiredOption("--output <path>", "New signed output file in an existing directory; existing paths are preserved")
    .action(async (options: Options) => {
      try {
        const expected = context(options);
        const manifest = validatePublicProvenance(await readJson(options.input, 1_048_576));
        if (manifest.subject.repository !== expected.repository || manifest.subject.commitSha !== expected.commitSha) {
          throw new Error("Manifest subject mismatch.");
        }
        const privateKey = privateKeySchema.parse(await readJson(options.privateKey!, 4_096));
        const reviewers = await resolvePublicGitHubReviewers(expected);
        const envelope = signPublicProvenance({ ...manifest, reviewers }, { privateKey });
        if (envelope.signature.publicKey.x !== privateKey.x) throw new Error("Selected key identity mismatch.");
        verifySignedPublicProvenance(envelope, { trustedPublicKeys: [envelope.signature.publicKey], expectedSubject: expected });
        const fresh = await resolvePublicGitHubReviewers(expected);
        if (canonicalizeProvenanceJson(reviewers) !== canonicalizeProvenanceJson(fresh)) throw new Error("GitHub reviewers changed.");
        await writeNewJson(options.output!, envelope);
        process.stdout.write("Wrote signed public provenance with observed GitHub reviewer lineage.\n");
      } catch {
        throw new Error("Public provenance signing failed; no key or lookup details are included.");
      }
    });
  expectedOptions(provenance.command("verify").description("Verify trusted signature, expected subject and current GitHub reviewer lineage."))
    .requiredOption("--keyring <path>", "Separate JSON array of trusted public Ed25519 JWKs")
    .action(async (options: Options) => {
      try {
        const expected = context(options);
        const trustedPublicKeys = keyringSchema.parse(await readJson(options.keyring!, 65_536));
        const manifest = verifySignedPublicProvenance(await readJson(options.input, 1_048_576), { trustedPublicKeys, expectedSubject: expected });
        const reviewers = await resolvePublicGitHubReviewers(expected);
        if (canonicalizeProvenanceJson(manifest.reviewers) !== canonicalizeProvenanceJson(reviewers)) throw new Error("GitHub reviewers do not match.");
        process.stdout.write("Verified public signature, expected subject and observed GitHub reviewer lineage.\n");
      } catch {
        throw new Error("Public provenance verification failed; no key or lookup details are included.");
      }
    });
}
