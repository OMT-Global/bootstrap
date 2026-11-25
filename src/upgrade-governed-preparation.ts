import { observeUpgradeGovernance, readOwnedGovernance, type GovernanceObservation } from "./upgrade-governance.js";
import { preparePublicUpgrade } from "./upgrade-history.js";
import { readOwnedPolicyObservation, type OwnedPolicyObservation } from "./upgrade-policy.js";
import { describePreparedUpgrade, discardPreparedUpgrade, type PreparedUpgrade } from "./upgrade-preparation.js";
import { readRuntimePolicy, runtimeDemand, runtimeDigest } from "./upgrade-runtime-policy.js";

function policyBinding({ repository, generator, sourceBinding, localBinding, targetBinding }: OwnedPolicyObservation) {
  return { repository, generator, sourceBinding, localBinding, targetBinding };
}

/** Prepare only the candidate selected by a current, owned governance observation. */
export async function prepareGovernedCandidate(
  observation: GovernanceObservation, options: { signal?: AbortSignal } = {}
): Promise<PreparedUpgrade> {
  const owned = readOwnedGovernance(observation);
  const signals = [owned.signal, options.signal].filter((value): value is AbortSignal => value !== undefined);
  const signal = signals.length ? AbortSignal.any(signals) : undefined;
  const cancellation = signal ? { signal } : {};
  signal?.throwIfAborted();

  const { generator } = readRuntimePolicy(owned.runtimePolicy);
  const policy = readOwnedPolicyObservation(owned.policy);
  const expected = runtimeDigest([observation, policyBinding(policy)]);
  const recheck = async () => {
    const fresh = await observeUpgradeGovernance(owned.runtimePolicy, owned.request, cancellation);
    signal?.throwIfAborted();
    const freshPolicy = readOwnedPolicyObservation(readOwnedGovernance(fresh).policy);
    runtimeDemand(runtimeDigest([fresh, policyBinding(freshPolicy)]) === expected, "governance-changed");
  };

  await recheck();
  const candidate = await preparePublicUpgrade({
    observation: owned.policy, generator, originalRoot: owned.request.originalRoot, ...cancellation
  });
  try {
    signal?.throwIfAborted();
    const facts = describePreparedUpgrade(candidate);
    runtimeDemand(facts.repository === observation.repository && facts.repositoryId === observation.repositoryId &&
      facts.baseCommit === observation.baseCommit && facts.baseTree === policy.repository.tree &&
      facts.generatorCommit === generator.sourceCommit && facts.generatorSourceSha256 === generator.sourceSha256 &&
      facts.sourceVersion === observation.plan.currentPolicy && facts.targetVersion === observation.plan.targetPolicy &&
      facts.targetRef === owned.request.target.ref && facts.targetSha256 === observation.targetDigest &&
      facts.risk === observation.plan.risk, "governed-preparation-mismatch");
    await recheck();
    return candidate;
  } catch (error) {
    discardPreparedUpgrade(candidate);
    throw error;
  }
}
