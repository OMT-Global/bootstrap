import { extractPolicyStatements, type PolicyStatements } from "./security-response-markdown.js";
import type { ConformanceResult } from "./conformance.js";
import type { PolicyException } from "./types.js";

export interface ConformanceWaiverTarget {
  readonly policy: string;
  readonly scope: string;
}

type RetainedConformanceResult = Readonly<Omit<ConformanceResult, "evidence">> & {
  readonly evidence: readonly string[];
};

/** Neutral evaluated data, never source ownership, native evidence or approval. */
export interface EvaluatedConformanceDeviation {
  readonly underlying: RetainedConformanceResult;
  readonly target: Readonly<ConformanceWaiverTarget>;
  readonly candidates: readonly Readonly<PolicyException>[];
}

export function evaluateConformanceDeviation(
  entry: ConformanceResult,
  exceptions: readonly PolicyException[],
  validExceptionIds: ReadonlySet<string>,
  target: ConformanceWaiverTarget
): EvaluatedConformanceDeviation {
  const underlying = Object.freeze({ ...entry, evidence: Object.freeze([...entry.evidence]) });
  // Eligibility is ordinary validation data. The future governed owner must
  // separately establish unique matches, freshness and actual native evidence.
  const candidates = entry.severity === "pass" ? [] : exceptions.filter((exception) =>
    exception.policy === target.policy && exception.scope === target.scope && validExceptionIds.has(exception.id)
  ).map((exception) => Object.freeze({ ...exception }));
  return Object.freeze({ underlying, target: Object.freeze({ ...target }), candidates: Object.freeze(candidates) });
}

/** Preserve the existing diagnostic first-match and display behavior. */
export function diagnosticForDeviation(evaluation: EvaluatedConformanceDeviation): ConformanceResult {
  const { underlying, candidates } = evaluation;
  const waiver = candidates[0];
  if (!waiver || underlying.severity === "pass") return { ...underlying, evidence: [...underlying.evidence] };
  return {
    ruleId: underlying.ruleId,
    severity: "pass",
    classification: "waived",
    evidence: [...underlying.evidence, `approved exception ${waiver.id}`].sort(),
    remediation: `Keep approved exception ${waiver.id} current until the governed deviation is resolved.`
  };
}

type SupportedStatements = Extract<PolicyStatements, { kind: "supported" }>;
export type ResponseCommitmentEvaluation =
  | Readonly<Extract<PolicyStatements, { kind: "unsupported" }>>
  | {
    readonly kind: "supported";
    readonly statements: readonly Readonly<SupportedStatements["statements"][number]>[];
    readonly missingCommitments: readonly string[];
  };

/** Evaluate the existing bounded Markdown grammar without reading or applying files. */
export function evaluateResponseCommitments(text: string, commitments: readonly string[]): ResponseCommitmentEvaluation {
  const extracted = extractPolicyStatements(text);
  if (extracted.kind === "unsupported") return Object.freeze({ ...extracted });
  const statements = Object.freeze(extracted.statements.map((statement) => Object.freeze({ ...statement })));
  const actual = new Set(statements.map((statement) => statement.text));
  return Object.freeze({
    kind: "supported",
    statements,
    missingCommitments: Object.freeze(commitments.filter((commitment) => !actual.has(commitment.toLowerCase())))
  });
}
