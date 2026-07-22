import { z } from "zod";

export const PUBLIC_PROVENANCE_SCHEMA_VERSION = 1;
export const REDACTED_CREDENTIAL = "[REDACTED:CREDENTIAL]";

const shaPattern = /^[0-9a-f]{40}$/;
const credentialPatterns = [
  new RegExp(`\\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|${"github"}_pat_[A-Za-z0-9_]{20,})\\b`, "i"),
  new RegExp(`\\b${"AK" + "IA"}[0-9A-Z]{16}\\b`),
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
  /\b(?:api[_-]?key|access[_-]?token|password|secret|token)\s*[:=]\s*[^\s]+/i
];

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
  .max(512)
  .refine(
    (value) => !value.includes(REDACTED_CREDENTIAL),
    "Public provenance input must not contain the reserved redaction placeholder."
  );
const metadataOutputValue = publicText("Public provenance metadata", 512);
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
    schemaVersion: z.literal(PUBLIC_PROVENANCE_SCHEMA_VERSION),
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
    schemaVersion: PUBLIC_PROVENANCE_SCHEMA_VERSION,
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

function countOccurrences(value: string, needle: string): number {
  return value.split(needle).length - 1;
}
