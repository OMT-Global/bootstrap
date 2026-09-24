import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type JsonWebKey
} from "node:crypto";
import { z } from "zod";

export const PUBLIC_PROVENANCE_SCHEMA_VERSION = 2;
export const REDACTED_CREDENTIAL = "[REDACTED:CREDENTIAL]";

const shaPattern = /^[0-9a-f]{40}$/;
const credentialPatterns = [
  new RegExp(`\\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|${"github"}_pat_[A-Za-z0-9_]{20,})\\b`, "i"),
  new RegExp(`\\b${"AK" + "IA"}[0-9A-Z]{16}\\b`),
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
  /\b(?:api[_-]?key|access[_-]?token|password|secret|token)\s*[:=]\s*[^\s]+/i
];
export const LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION = 1;
export const CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION = PUBLIC_PROVENANCE_SCHEMA_VERSION;
const MAX_PUBLIC_METADATA_INPUT_LENGTH = 512;
const MAX_PUBLIC_METADATA_OUTPUT_LENGTH = MAX_PUBLIC_METADATA_INPUT_LENGTH * 4;

const legacyReviewerSchema = z.object({
  login: z.string().min(1),
  state: z.enum(["approved", "commented", "changes_requested"])
}).strict();

export const legacyPublicProvenanceSchema = z
  .object({
    schemaVersion: z.literal(LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION),
    runId: z.string().regex(/^[A-Za-z0-9._-]+$/),
    subject: z.object({
      repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/),
      commitSha: z.string().regex(shaPattern),
      ref: z.string().min(1)
    }).strict(),
    execution: z.object({
      workflow: z.string().min(1),
      runUrl: z.string().url().optional(),
      createdAt: z.string().datetime({ offset: true })
    }).strict(),
    reviewers: z.array(legacyReviewerSchema),
    metadata: z.record(z.string(), z.string()),
    redaction: z.object({
      policyVersion: z.literal(1),
      replacements: z.number().int().nonnegative()
    }).strict()
  })
  .strict()
  .superRefine((manifest, context) => {
    const publicStrings: Array<[string, string]> = [
      ["runId", manifest.runId],
      ["subject.repository", manifest.subject.repository],
      ["subject.ref", manifest.subject.ref],
      ["execution.workflow", manifest.execution.workflow]
    ];
    if (manifest.execution.runUrl) publicStrings.push(["execution.runUrl", manifest.execution.runUrl]);
    manifest.reviewers.forEach((reviewer, index) => publicStrings.push([`reviewers.${index}.login`, reviewer.login]));
    Object.entries(manifest.metadata).forEach(([key, value]) => {
      publicStrings.push([`metadata key ${key}`, key], [`metadata.${key}`, value]);
    });
    for (const [path, value] of publicStrings) {
      if (containsCredential(value)) {
        context.addIssue({
          code: "custom",
          message: `Legacy public provenance field ${path} contains a credential-like literal.`
        });
      }
    }
  });

const publicText = (label: string, maximumLength: number) =>
  z
    .string()
    .min(1)
    .max(maximumLength)
    .refine((value) => !containsCredential(value), `${label} contains a credential-like literal.`);

const reviewerSchema = z.object({
  login: z
    .string()
    .max(100)
    .regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?(?:\[bot\])?$/)
    .refine((value) => !containsCredential(value), "Reviewer login contains a credential-like literal."),
  state: z.enum(["approved", "commented", "changes_requested"])
}).strict();

const subjectSchema = z.object({
  repository: z
    .string()
    .regex(/^[^/\s]+\/[^/\s]+$/)
    .max(201)
    .refine((value) => !containsCredential(value), "Subject repository contains a credential-like literal."),
  commitSha: z.string().regex(shaPattern),
  ref: publicText("Subject ref", 256)
}).strict();

const executionSchema = z.object({
  workflow: publicText("Workflow name", 200),
  runUrl: z.string().url().max(2_048).refine((value) => !containsCredential(value), "Run URL contains a credential-like literal.").optional(),
  createdAt: z.string().datetime({ offset: true })
}).strict();

const metadataInputValue = z
  .string()
  .min(1)
  .max(MAX_PUBLIC_METADATA_INPUT_LENGTH)
  .refine(
    (value) => !value.includes(REDACTED_CREDENTIAL),
    "Public provenance input must not contain the reserved redaction placeholder."
  );
const metadataOutputValue = publicText("Public provenance metadata", MAX_PUBLIC_METADATA_OUTPUT_LENGTH);
const metadataInputShape = {
  policy: metadataInputValue.optional(),
  generator: metadataInputValue.optional(),
  aiProvider: metadataInputValue.optional(),
  aiModel: metadataInputValue.optional(),
  promptHash: metadataInputValue.optional(),
  changeClass: metadataInputValue.optional()
};
const metadataOutputShape = {
  policy: metadataOutputValue.optional(),
  generator: metadataOutputValue.optional(),
  aiProvider: metadataOutputValue.optional(),
  aiModel: metadataOutputValue.optional(),
  promptHash: metadataOutputValue.optional(),
  changeClass: metadataOutputValue.optional()
};

export const PUBLIC_PROVENANCE_METADATA_KEYS = [
  "policy",
  "generator",
  "aiProvider",
  "aiModel",
  "promptHash",
  "changeClass"
] as const;

export const publicProvenanceMetadataSchema = z.object(metadataOutputShape).strict();

export const publicProvenanceInputSchema = z.object({
  runId: z
    .string()
    .max(128)
    .regex(/^[A-Za-z0-9._-]+$/)
    .refine((value) => !containsCredential(value), "Run ID contains a credential-like literal."),
  subject: subjectSchema,
  execution: executionSchema,
  reviewers: z.array(reviewerSchema),
  metadata: z.object(metadataInputShape).strict().optional()
}).strict();

export const publicProvenanceSchema = z
  .object({
    schemaVersion: z.literal(CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION),
    runId: z
      .string()
      .max(128)
      .regex(/^[A-Za-z0-9._-]+$/)
      .refine((value) => !containsCredential(value), "Run ID contains a credential-like literal."),
    subject: subjectSchema,
    execution: executionSchema,
    reviewers: z.array(reviewerSchema),
    metadata: publicProvenanceMetadataSchema,
    redaction: z.object({
      policyVersion: z.literal(1),
      replacements: z.number().int().nonnegative()
    }).strict()
  })
  .strict()
  .superRefine((manifest, context) => {
    const recordedReplacements = Object.values(manifest.metadata).reduce(
      (total, value) => total + countOccurrences(value ?? "", REDACTED_CREDENTIAL),
      0
    );
    if (recordedReplacements !== manifest.redaction.replacements) {
      context.addIssue({
        code: "custom",
        path: ["redaction", "replacements"],
        message: "Public provenance redaction evidence does not match the typed placeholders in metadata."
      });
    }
  });

export type PublicProvenance = z.infer<typeof publicProvenanceSchema>;
export type LegacyPublicProvenance = z.infer<typeof legacyPublicProvenanceSchema>;
export type SupportedPublicProvenance = PublicProvenance | LegacyPublicProvenance;
export type PublicProvenanceInput = z.input<typeof publicProvenanceInputSchema>;

export function containsCredential(value: string): boolean {
  return credentialPatterns.some((pattern) => pattern.test(value));
}

export function redactPublicText(value: string): { value: string; replacements: number } {
  let redacted = value;
  let replacements = 0;
  for (const pattern of credentialPatterns) {
    const globalPattern = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
    redacted = redacted.replace(globalPattern, () => {
      replacements += 1;
      return REDACTED_CREDENTIAL;
    });
  }
  return { value: redacted, replacements };
}

export function createPublicProvenance(input: PublicProvenanceInput): PublicProvenance {
  const parsedInput = publicProvenanceInputSchema.parse(input);
  let replacements = 0;
  const metadata = Object.fromEntries(
    Object.entries(parsedInput.metadata ?? {})
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      .map(([key, rawValue]) => {
        const redacted = redactPublicText(rawValue);
        replacements += redacted.replacements;
        return [key, redacted.value];
      })
  );

  return publicProvenanceSchema.parse({
    schemaVersion: CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION,
    runId: parsedInput.runId,
    subject: parsedInput.subject,
    execution: parsedInput.execution,
    reviewers: parsedInput.reviewers,
    metadata,
    redaction: { policyVersion: 1, replacements }
  });
}

export function validatePublicProvenance(value: unknown): PublicProvenance {
  return publicProvenanceSchema.parse(value);
}

export function readLegacyPublicProvenance(value: unknown): LegacyPublicProvenance {
  return legacyPublicProvenanceSchema.parse(value);
}

function countOccurrences(value: string, needle: string): number {
  return value.split(needle).length - 1;
}

export const SIGNED_PROVENANCE_ENVELOPE_VERSION = 1;
export const PROVENANCE_SIGNATURE_ALGORITHM = "ed25519";
export const PROVENANCE_CANONICALIZATION_ID = "sorted-json-v1";
const SIGNING_DOMAIN = "bootstrap-signed-provenance";

const ed25519PublicKeySchema = z
  .object({
    kty: z.literal("OKP"),
    crv: z.literal("Ed25519"),
    x: z.string().regex(/^[A-Za-z0-9_-]+$/)
  })
  .strict();

export const signedPublicProvenanceSchema = z
  .object({
    envelopeVersion: z.literal(SIGNED_PROVENANCE_ENVELOPE_VERSION),
    manifest: publicProvenanceSchema,
    signature: z
      .object({
        algorithm: z.literal(PROVENANCE_SIGNATURE_ALGORITHM),
        canonicalization: z.literal(PROVENANCE_CANONICALIZATION_ID),
        publicKey: ed25519PublicKeySchema,
        fingerprint: z.string().regex(/^[0-9a-f]{64}$/),
        signedAt: z.string().datetime({ offset: true }),
        value: z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/)
      })
      .strict()
  })
  .strict()
  .superRefine((envelope, context) => {
    if (envelope.manifest.reviewers.length === 0) {
      context.addIssue({
        code: "custom",
        path: ["manifest", "reviewers"],
        message: "Signed public provenance requires at least one reviewer."
      });
    }
    if (!envelope.manifest.reviewers.some((reviewer) => reviewer.state === "approved")) {
      context.addIssue({
        code: "custom",
        path: ["manifest", "reviewers"],
        message: "Signed public provenance requires at least one approved reviewer."
      });
    }
  });

export type SignedPublicProvenance = z.infer<typeof signedPublicProvenanceSchema>;
export type ProvenanceSigningPublicKey = z.infer<typeof ed25519PublicKeySchema>;

export interface ProvenanceSigningKeyPair {
  publicKey: ProvenanceSigningPublicKey;
  privateKey: JsonWebKey;
}

export interface ProvenanceSigningOptions {
  privateKey: JsonWebKey;
  signedAt?: string;
}

export interface VerifySignedPublicProvenanceOptions {
  trustedPublicKeys: ReadonlyArray<ProvenanceSigningPublicKey>;
  expectedSubject?: { repository: string; commitSha: string };
}

export function canonicalizeProvenanceJson(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeProvenanceJson(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalizeProvenanceJson(item)}`);
    return `{${entries.join(",")}}`;
  }
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  throw new Error("Cannot canonicalize a non-JSON value.");
}

export function signedProvenanceSigningPayload(manifest: unknown, signedAt: string): string {
  return signingPayload(publicProvenanceSchema.parse(manifest), signedAt);
}

export function provenanceSigningKeyFingerprint(publicKey: ProvenanceSigningPublicKey): string {
  const parsed = ed25519PublicKeySchema.parse(publicKey);
  return createHash("sha256").update(canonicalizeProvenanceJson(parsed), "utf8").digest("hex");
}

export function generateProvenanceSigningKeyPair(): ProvenanceSigningKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: ed25519PublicKeySchema.parse(publicKey.export({ format: "jwk" })),
    privateKey: privateKey.export({ format: "jwk" })
  };
}

export function signPublicProvenance(manifest: unknown, options: ProvenanceSigningOptions): SignedPublicProvenance {
  const parsedManifest = publicProvenanceSchema.parse(manifest);
  assertApprovedReviewerLineage(parsedManifest);
  const privateKeyObject = createPrivateKey({ key: options.privateKey, format: "jwk" });
  if (privateKeyObject.asymmetricKeyType !== "ed25519") {
    throw new Error("Provenance signing requires an Ed25519 private JWK.");
  }
  const publicKey = ed25519PublicKeySchema.parse(createPublicKey(privateKeyObject).export({ format: "jwk" }));
  const signedAt = options.signedAt ?? new Date().toISOString();
  const payload = Buffer.from(signingPayload(parsedManifest, signedAt), "utf8");
  const value = cryptoSign(null, payload, privateKeyObject).toString("base64");

  return signedPublicProvenanceSchema.parse({
    envelopeVersion: SIGNED_PROVENANCE_ENVELOPE_VERSION,
    manifest: parsedManifest,
    signature: {
      algorithm: PROVENANCE_SIGNATURE_ALGORITHM,
      canonicalization: PROVENANCE_CANONICALIZATION_ID,
      publicKey,
      fingerprint: provenanceSigningKeyFingerprint(publicKey),
      signedAt,
      value
    }
  });
}

export function verifySignedPublicProvenance(
  envelope: unknown,
  options: VerifySignedPublicProvenanceOptions
): PublicProvenance {
  const parsed = signedPublicProvenanceSchema.parse(envelope);
  const embeddedFingerprint = provenanceSigningKeyFingerprint(parsed.signature.publicKey);
  if (embeddedFingerprint !== parsed.signature.fingerprint) {
    throw new Error("Signed public provenance verification failed: embedded public key does not match its fingerprint.");
  }
  const trustedKey = options.trustedPublicKeys.find(
    (key) => provenanceSigningKeyFingerprint(key) === embeddedFingerprint
  );
  if (!trustedKey) {
    throw new Error("Signed public provenance verification failed: signing key is not trusted.");
  }
  const payload = Buffer.from(signingPayload(parsed.manifest, parsed.signature.signedAt), "utf8");
  const signatureBytes = Buffer.from(parsed.signature.value, "base64");
  const publicKeyObject = createPublicKey({ key: trustedKey, format: "jwk" });
  if (!cryptoVerify(null, payload, publicKeyObject, signatureBytes)) {
    throw new Error("Signed public provenance verification failed: signature does not match the canonical signing payload.");
  }
  const expectedSubject = options.expectedSubject;
  if (
    expectedSubject &&
    (parsed.manifest.subject.repository !== expectedSubject.repository ||
      parsed.manifest.subject.commitSha !== expectedSubject.commitSha)
  ) {
    throw new Error("Signed public provenance verification failed: manifest subject does not match the expected subject.");
  }
  return parsed.manifest;
}

function signingPayload(manifest: PublicProvenance, signedAt: string): string {
  return canonicalizeProvenanceJson({
    algorithm: PROVENANCE_SIGNATURE_ALGORITHM,
    canonicalization: PROVENANCE_CANONICALIZATION_ID,
    domain: SIGNING_DOMAIN,
    envelopeVersion: SIGNED_PROVENANCE_ENVELOPE_VERSION,
    manifest,
    signedAt
  });
}

function assertApprovedReviewerLineage(manifest: PublicProvenance): void {
  if (manifest.reviewers.length === 0 || !manifest.reviewers.some((reviewer) => reviewer.state === "approved")) {
    throw new Error("Signed public provenance requires at least one approved reviewer.");
  }
}
