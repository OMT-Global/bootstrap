import path from "node:path";
import { z } from "zod";

const positive = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const slug = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/);
const reference = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
export const governanceRole = z.enum(["cohort", "pilot", "exception", "major"]);
const identity = z.object({ repository: slug, id: positive }).strict();

export const runtimePolicyProjectionSchema = z.object({
  schemaVersion: z.literal(1),
  organization: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/),
  repositories: z.array(identity).min(1).max(500),
  governance: identity.extend({ issue: positive }),
  actors: z.array(z.object({
    id: positive,
    login: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/),
    roles: z.array(governanceRole).min(1).max(4)
  }).strict()).min(1).max(100),
  signing: z.object({
    principal: reference,
    publicKey: z.string().regex(/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/),
    keyReference: reference
  }).strict().optional(),
  review: z.object({
    profile: z.literal("fleet-native-sol-high-v1"),
    authorSession: reference,
    reviewerPrincipal: reference
  }).strict().optional(),
  app: z.object({
    appId: positive,
    installationId: positive,
    keyReference: reference,
    profile: z.enum(["fleet-publication-v1", "fleet-workflow-publication-v1"])
  }).strict().optional(),
  attemptDirectory: z.string().max(4096).refine(path.isAbsolute).optional()
}).strict();

export type RuntimePolicyProjection = z.infer<typeof runtimePolicyProjectionSchema>;

export function runtimePolicyProjectionConflict(projection: RuntimePolicyProjection): string | undefined {
  const { actors, repositories } = projection;
  if (new Set(repositories.map(({ id }) => id)).size !== repositories.length ||
      new Set(repositories.map(({ repository }) => repository.toLowerCase())).size !== repositories.length) {
    return "duplicate-repository";
  }
  if (new Set(actors.map(({ id }) => id)).size !== actors.length ||
      new Set(actors.map(({ login }) => login.toLowerCase())).size !== actors.length) {
    return "duplicate-actor";
  }
  if (actors.some(({ roles }) => new Set(roles).size !== roles.length)) return "duplicate-role";
}
