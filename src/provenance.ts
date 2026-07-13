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

const reviewerSchema = z.object({
  login: z.string().min(1),
  state: z.enum(["approved", "commented", "changes_requested"])
});

export const publicProvenanceSchema = z
  .object({
    schemaVersion: z.literal(PUBLIC_PROVENANCE_SCHEMA_VERSION),
    runId: z.string().regex(/^[A-Za-z0-9._-]+$/),
    subject: z.object({
      repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/),
      commitSha: z.string().regex(shaPattern),
      ref: z.string().min(1)
    }),
    execution: z.object({
      workflow: z.string().min(1),
      runUrl: z.string().url().optional(),
      createdAt: z.string().datetime({ offset: true })
    }),
    reviewers: z.array(reviewerSchema),
    metadata: z.record(z.string(), z.string()),
    redaction: z.object({
      policyVersion: z.literal(1),
      replacements: z.number().int().nonnegative()
    })
  })
  .superRefine((manifest, context) => {
    for (const [key, value] of Object.entries(manifest.metadata)) {
      if (containsCredential(value)) {
        context.addIssue({
          code: "custom",
          message: `Public provenance metadata ${key} contains a credential-like literal. Redact it before validation.`
        });
      }
    }
  });

export type PublicProvenance = z.infer<typeof publicProvenanceSchema>;
export type PublicProvenanceInput = Omit<PublicProvenance, "schemaVersion" | "metadata" | "redaction"> & {
  metadata?: Record<string, string | undefined>;
};

export function containsCredential(value: string): boolean {
  return credentialPatterns.some((pattern) => pattern.test(value));
}

export function redactPublicText(value: string): { value: string; replacements: number } {
  let redacted = value;
  let replacements = 0;
  for (const pattern of credentialPatterns) {
    redacted = redacted.replace(pattern, () => {
      replacements += 1;
      return REDACTED_CREDENTIAL;
    });
  }
  return { value: redacted, replacements };
}

export function createPublicProvenance(input: PublicProvenanceInput): PublicProvenance {
  let replacements = 0;
  const metadata = Object.fromEntries(
    Object.entries(input.metadata ?? {}).map(([key, rawValue]) => {
      if (rawValue === undefined) return [key, ""];
      const redacted = redactPublicText(rawValue);
      replacements += redacted.replacements;
      return [key, redacted.value];
    })
  );

  return publicProvenanceSchema.parse({
    schemaVersion: PUBLIC_PROVENANCE_SCHEMA_VERSION,
    runId: input.runId,
    subject: input.subject,
    execution: input.execution,
    reviewers: input.reviewers,
    metadata,
    redaction: { policyVersion: 1, replacements }
  });
}

export function validatePublicProvenance(value: unknown): PublicProvenance {
  return publicProvenanceSchema.parse(value);
}
