import { createHash } from "node:crypto";
import { lstat, mkdir, opendir, writeFile } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";

import { ISOLATION_LIMITS, type IsolatedSourceFile } from "./isolation/node-profile.js";
import { loadManifest } from "./manifest.js";
import { loadResolvedFlowPolicy, resolveFlowPolicy } from "./policy.js";
import { applyRepo, planRepo, type RepoPlan } from "./render.js";
import type { BootstrapManifest } from "./types.js";
import { auditCheckout } from "./upgrade-checkout.js";
import { generatorSnapshot, type PublicGeneratorCapture } from "./upgrade-generator.js";
import { copySnapshotFiles, decodeGitPath, openDataRepository, type DataRepository, type VerifiedGitSnapshot } from "./upgrade-git.js";
import { boundedGitCommand, decode, demand, gitArguments, neutralEnvironment, PRLIMIT_ARGS, readRegular, requireLinuxHost } from "./upgrade-host.js";
import { patchManifestPolicyPins } from "./upgrade-manifest-pins.js";
import { copyOwnedTargetPolicyBytes, POLICY_PUBLISHER, readOwnedPolicyObservation, type OwnedPolicyObservation, type PolicyObservation } from "./upgrade-policy.js";
import { publicHead, publicRepository, PublicObservationRead, resolvePublicCommit } from "./upgrade-public-read.js";
import { classifyPolicyUpgrade, type UpgradeRisk } from "./upgrades.js";

declare const preparedBrand: unique symbol;
export type PreparedUpgrade = { readonly [preparedBrand]: true };
export interface PreparedUpgradeFacts {
  readonly repository: string; readonly repositoryId: number; readonly baseCommit: string; readonly baseTree: string;
  readonly tree: string; readonly sourceSha256: string; readonly generatorCommit: string; readonly generatorSourceSha256: string;
  readonly sourceVersion: string; readonly targetVersion: string; readonly targetRef: string; readonly targetSha256: string;
  readonly risk: Exclude<UpgradeRisk, "invalid">; readonly files: number; readonly sourceBytes: number; readonly changedPaths: readonly string[];
  readonly authority: "none"; readonly pilot: "unverified"; readonly hook: "pending"; readonly signing: "pending";
  readonly finalCheck: "pending"; readonly independentReview: "pending"; readonly publication: "pending";
}
interface PreparedData { facts: PreparedUpgradeFacts; files: IsolatedSourceFile[]; base: VerifiedGitSnapshot; signal?: AbortSignal }
const prepared = new WeakMap<PreparedUpgrade, PreparedData>();
const failure = () => new Error("Governed upgrade preparation unavailable.");
const sha256 = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const statePaths = [".bootstrap/bootstrap-state.json", ".bootstrap/home-state.json", ".new-project-bootstrap/home-state.json"];
const forbiddenInput = new Set(["project.bootstrap.yaml", "LICENSE", "THIRD_PARTY_NOTICES.md", ".bootstrap/managed-files.json", ...statePaths].map((name) => name.toLowerCase()));
const legalName = /^(?:unlicense|licen[cs]e|copying|copyright|notice|third[-_]?party[-_]?notices)(?:[-._][\s\S]+)?$/i;

function fixedPoint(plan: RepoPlan): void { demand(plan.changes.every((change) => change.type === "unchanged")); }
function samePlan(left: RepoPlan, right: RepoPlan): void {
  demand(isDeepStrictEqual(left.changes, right.changes) && isDeepStrictEqual(left.files, right.files));
}
function copied(files: readonly IsolatedSourceFile[]): IsolatedSourceFile[] {
  return files.map((file) => ({ ...file, bytes: Buffer.from(file.bytes) }));
}
function checkedFiles(files: readonly IsolatedSourceFile[]): void {
  demand(files.length > 0 && files.length <= ISOLATION_LIMITS.files);
  const names = new Set<string>(); const directories = new Set<string>(); let total = 0;
  for (const file of files) {
    demand(decodeGitPath(Buffer.from(file.path)) === file.path && !names.has(file.path) &&
      ["100644", "100755"].includes(file.mode) && file.bytes instanceof Uint8Array);
    demand(!["node_modules", "dist"].includes(file.path.split("/")[0]!.toLowerCase()));
    names.add(file.path); total += file.bytes.byteLength; demand(total <= ISOLATION_LIMITS.sourceBytes);
    const parts = file.path.split("/");
    for (let end = 1; end < parts.length; end++) directories.add(parts.slice(0, end).join("/"));
  }
  demand(names.size + directories.size <= ISOLATION_LIMITS.entries && [...directories].every((name) => !names.has(name)));
}
async function exactSource(root: string, expected: readonly IsolatedSourceFile[], check: () => void): Promise<void> {
  const files = new Map(expected.map((file) => [file.path, file])); const directories = new Set<string>(); const found = new Set<string>(); let count = 0;
  for (const file of expected) {
    const parts = file.path.split("/");
    for (let end = 1; end < parts.length; end++) directories.add(parts.slice(0, end).join("/"));
  }
  const walk = async (prefix: string): Promise<void> => {
    for await (const entry of await opendir(path.join(root, prefix))) {
      check(); if (!prefix && entry.name === ".git") continue;
      demand(++count <= ISOLATION_LIMITS.entries); const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      const stat = await lstat(path.join(root, name));
      if (stat.isDirectory()) { demand(directories.has(name)); await walk(name); }
      else {
        const file = files.get(name);
        demand(file && stat.isFile() && stat.nlink === 1 && !found.has(name) && stat.size === file.bytes.byteLength &&
          (stat.mode & 0o100 ? "100755" : "100644") === file.mode);
        demand((await readRegular(path.join(root, name), file.bytes.byteLength)).equals(Buffer.from(file.bytes))); found.add(name);
      }
    }
  };
  await walk(""); demand(found.size === files.size); check();
}
async function refresh(owned: OwnedPolicyObservation, signal: AbortSignal): Promise<void> {
  const read = new PublicObservationRead(signal, owned.repository.repository);
  try {
    await publicRepository(read, owned.repository);
    demand(await publicHead(read, owned.repository.repository, owned.repository.defaultBranch) === owned.repository.head);
    await publicRepository(read, POLICY_PUBLISHER);
    for (const binding of [owned.sourceBinding, owned.targetBinding]) {
      demand(await resolvePublicCommit(read, POLICY_PUBLISHER.repository, binding.ref) === binding.commit);
    }
    read.check();
  } finally { await read.close(); }
}
async function writeTree(repository: DataRepository, files: readonly IsolatedSourceFile[], signal: AbortSignal): Promise<string> {
  const tools = await requireLinuxHost(); const empty = path.join(repository.root, ".git", "bootstrap-preparation-empty");
  await mkdir(empty);
  const env = { ...neutralEnvironment(empty, empty), GIT_DIR: path.join(repository.root, ".git"), GIT_WORK_TREE: repository.root, GIT_EXEC_PATH: empty };
  const run = (args: string[], input?: Uint8Array) => boundedGitCommand(tools.prlimit,
    [...PRLIMIT_ARGS, tools.git, ...gitArguments({ empty }, args)], { cwd: repository.root, env, signal, ...(input ? { input } : {}) });
  const index: Buffer[] = [];
  for (const file of files) {
    const oid = createHash("sha1").update(`blob ${file.bytes.byteLength}\0`).update(file.bytes).digest("hex");
    demand(decode(await run(["hash-object", "--no-filters", "-w", "--stdin"], file.bytes)).trim() === oid);
    index.push(Buffer.from(`${file.mode} ${oid}\t${file.path}\0`));
  }
  await run(["read-tree", "--empty"]); await run(["update-index", "-z", "--index-info"], Buffer.concat(index));
  const tree = decode(await run(["write-tree"])).trim(); demand(/^[0-9a-f]{40}$/.test(tree)); return tree;
}

/**
 * Internal source preparation only. Genuine owned observations bind the raw
 * snapshot to public Git identity; no inventory JSON, pilot pass or write
 * authority is accepted. It never executes target hooks, signs or publishes.
 */
export async function prepareObservedUpgrade(input: {
  observation: PolicyObservation; generator: PublicGeneratorCapture; source: VerifiedGitSnapshot; originalRoot: string; signal?: AbortSignal;
}): Promise<PreparedUpgrade> {
  let repository: DataRepository | undefined;
  try {
    const { observation, generator, source, originalRoot, signal: parent } = input;
    demand(typeof originalRoot === "string" && path.isAbsolute(originalRoot) && (parent === undefined || parent instanceof AbortSignal));
    const signal = AbortSignal.any([AbortSignal.timeout(ISOLATION_LIMITS.phaseMs), ...(parent ? [parent] : [])]);
    const check = () => signal.throwIfAborted(); check();
    const owned = readOwnedPolicyObservation(observation); const captured = generatorSnapshot(generator);
    demand(captured.baseCommit === owned.generator.sourceCommit && captured.sourceSha256 === owned.generator.sourceSha256 &&
      source.baseCommit === owned.repository.head && source.tree === owned.repository.tree);
    const original = copySnapshotFiles(source); checkedFiles(original);
    demand(!original.some((file) => statePaths.some((name) => name.toLowerCase() === file.path.toLowerCase())));
    const risk = classifyPolicyUpgrade(owned.source.policy.version, owned.target.policy.version); demand(risk !== "invalid");
    const targetBytes = copyOwnedTargetPolicyBytes(observation);
    demand(targetBytes.length <= ISOLATION_LIMITS.manifestBytes && sha256(targetBytes) === owned.targetBinding.rawSha256);
    await refresh(owned, signal); check();
    const originalAudit = await auditCheckout(originalRoot, source, `https://github.com/${owned.repository.repository}.git`, { signal }); check();
    repository = await openDataRepository(source, { signal }); check();
    const root = repository.root;
    const manifestFile = original.find((file) => file.path === "project.bootstrap.yaml"); demand(manifestFile);
    const current = await loadManifest(path.join(root, manifestFile.path)); check();
    demand(isDeepStrictEqual(current, owned.manifest) && current.policy?.flow && current.project.visibility === "public");
    const currentPolicy = await loadResolvedFlowPolicy(current, root); check();
    demand(isDeepStrictEqual(currentPolicy, owned.source));
    const currentPlan = await planRepo(current, root, currentPolicy); check(); fixedPoint(currentPlan);
    for (const file of currentPlan.files) {
      const actual = original.find((value) => value.path === file.path);
      demand(actual && actual.mode === (file.executable ? "100755" : "100644") && Buffer.from(actual.bytes).equals(Buffer.from(file.contents)));
    }
    samePlan(currentPlan, await applyRepo(current, root)); check();
    fixedPoint(await planRepo(current, root)); check(); await exactSource(root, original, check);
    const target: BootstrapManifest = { ...current, policy: { ...current.policy, flow: { ...current.policy.flow,
      ref: owned.targetBinding.ref, sha256: owned.targetBinding.canonicalSha256 } } };
    const targetPolicy = resolveFlowPolicy(target, owned.target.policy, owned.target.source, target.unknownSettings);
    demand(isDeepStrictEqual(targetPolicy, owned.target));
    const planned = await planRepo(target, root, targetPolicy); check();
    const bundlePath = current.policy.flow.bundlePath; const bundleFile = original.find((file) => file.path === bundlePath);
    const legalInputs = [current.license?.template.path, ...(current.license?.transition?.reconciles?.map((entry) => entry.path) ?? [])].filter((value): value is string => !!value);
    demand(bundleFile && !forbiddenInput.has(bundlePath.toLowerCase()) && !legalName.test(path.posix.basename(bundlePath)) &&
      !legalInputs.some((name) => path.posix.normalize(name).toLowerCase() === bundlePath.toLowerCase()));
    const managed = new Set([...currentPlan.files, ...planned.files].map((file) => file.path));
    demand(![...managed].some((name) => name === bundlePath || name.startsWith(bundlePath + "/") || bundlePath.startsWith(name + "/")));
    const manifestManaged = currentPlan.files.some((file) => file.path === manifestFile.path);
    demand(manifestManaged === planned.files.some((file) => file.path === manifestFile.path));
    const patched = manifestManaged ? undefined : patchManifestPolicyPins(manifestFile.bytes, current, target);
    const expected = new Map(original.map((file) => [file.path, file]));
    for (const change of planned.changes) if (change.type === "delete") expected.delete(change.path);
    for (const file of planned.files) expected.set(file.path, { path: file.path, mode: file.executable ? "100755" : "100644", bytes: Buffer.from(file.contents) });
    expected.set(bundlePath, { ...bundleFile, bytes: targetBytes });
    if (patched) expected.set(manifestFile.path, { ...manifestFile, bytes: patched });
    const files = [...expected.values()].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))); checkedFiles(files);
    await writeFile(path.join(root, bundlePath), targetBytes);
    if (patched) await writeFile(path.join(root, manifestFile.path), patched);
    check(); samePlan(planned, await applyRepo(target, root)); check();
    const disk = await loadManifest(path.join(root, manifestFile.path)); demand(isDeepStrictEqual(disk, target)); check();
    const diskPolicy = await loadResolvedFlowPolicy(disk, root);
    demand(isDeepStrictEqual(resolveFlowPolicy(disk, diskPolicy.policy, targetPolicy.source, disk.unknownSettings), targetPolicy)); check();
    fixedPoint(await planRepo(disk, root, diskPolicy)); check(); await exactSource(root, files, check);
    const tree = await writeTree(repository, files, signal); check();
    const after = await auditCheckout(originalRoot, source, `https://github.com/${owned.repository.repository}.git`, { signal });
    demand(after.originalStateSha256 === originalAudit.originalStateSha256); check(); await refresh(owned, signal); check();
    const changedPaths = files.filter((file) => {
      const before = original.find((value) => value.path === file.path);
      return !before || before.mode !== file.mode || !Buffer.from(before.bytes).equals(Buffer.from(file.bytes));
    }).map((file) => file.path).concat(original.filter((file) => !expected.has(file.path)).map((file) => file.path)).sort();
    const facts: PreparedUpgradeFacts = Object.freeze({ repository: owned.repository.repository, repositoryId: owned.repository.id,
      baseCommit: source.baseCommit, baseTree: source.tree, tree, generatorCommit: captured.baseCommit, generatorSourceSha256: captured.sourceSha256,
      sourceSha256: sha256(Buffer.from(JSON.stringify(files.map(({ path, mode, bytes }) => ({ path, mode, sha256: sha256(bytes) }))))),
      sourceVersion: currentPolicy.policy.version, targetVersion: targetPolicy.policy.version, targetRef: owned.targetBinding.ref,
      targetSha256: owned.targetBinding.canonicalSha256, risk, files: files.length, sourceBytes: files.reduce((sum, file) => sum + file.bytes.byteLength, 0),
      changedPaths: Object.freeze(changedPaths), authority: "none", pilot: "unverified", hook: "pending", signing: "pending",
      finalCheck: "pending", independentReview: "pending", publication: "pending" });
    // Successful cleanup is part of preparation; failure never creates a handle.
    await repository.dispose(); repository = undefined; check();
    const handle = Object.freeze({}) as PreparedUpgrade;
    prepared.set(handle, { facts, files, base: source, ...(parent ? { signal: parent } : {}) }); return handle;
  } catch { throw failure(); }
  finally {
    if (repository) {
      try { await repository.dispose(); }
      catch { try { await repository.dispose(); } catch { /* Remains failed even if cleanup cannot finish. */ } throw failure(); }
    }
  }
}
function data(handle: PreparedUpgrade): PreparedData {
  const value = prepared.get(handle); if (!value || value.signal?.aborted) throw failure(); return value;
}
export function describePreparedUpgrade(handle: PreparedUpgrade): PreparedUpgradeFacts { return data(handle).facts; }
/** Copies are data for trusted next consumers, not proof of hook/check/review completion. */
export function copyPreparedUpgradeSource(handle: PreparedUpgrade): { base: VerifiedGitSnapshot; files: IsolatedSourceFile[] } {
  const value = data(handle); return { base: value.base, files: copied(value.files) };
}
export function discardPreparedUpgrade(handle: PreparedUpgrade): void {
  if (!prepared.has(handle)) throw failure(); prepared.delete(handle);
}
