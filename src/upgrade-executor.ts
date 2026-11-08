import { lstat, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { z } from "zod";

import { validatePolicyExceptions } from "./exceptions.js";
import { loadManifest, normalizeManifest } from "./manifest.js";
import { execRunner, type CommandRunner } from "./lib/process.js";
import { flowPolicyDigest, loadResolvedFlowPolicy, resolveFlowPolicy } from "./policy.js";
import { containsCredential, redactPublicText } from "./provenance.js";
import { applyRepo, planRepo } from "./render.js";
import { classifyPolicyUpgrade, type UpgradeRisk } from "./upgrades.js";

const sha = z.string().regex(/^[0-9a-f]{40}$/);
const repoName = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*\/[a-zA-Z0-9][a-zA-Z0-9_.-]*$/);
const link = z.string().regex(/^https:\/\/github\.com\/[a-zA-Z0-9_./-]+$/).refine((value) => !containsCredential(value));
const version = z.string().regex(/^\d+\.\d+\.\d+$/);
const inputSchema = z.object({
  generatorCommit: sha,
  target: z.object({ ref: z.string(), sha256: z.string().regex(/^[0-9a-f]{64}$/), bundlePath: z.string().min(1) }).strict(),
  evidence: z.array(z.object({ repo: repoName, issue: link, policyDiff: link, tests: link, exceptions: link, provenance: link, autoreview: link }).strict()),
  pilots: z.array(z.object({
    repo: repoName,
    repoClass: z.string().min(1),
    currentPolicy: version,
    targetPolicy: version,
    commit: sha,
    sourceCommit: sha,
    outcome: z.enum(["passed", "failed"]),
    validationWorkflow: z.string().regex(/^\.github\/workflows\/[a-zA-Z0-9_-]+\.ya?ml$/),
    evidence: link
  }).strict())
}).strict();

export interface UpgradeExecutionResult {
  repo: string;
  status: "planned" | "pr-opened" | "blocked" | "failed" | "skipped" | "unchanged";
  reason: string;
  repoClass?: string;
  currentPolicy?: string;
  targetPolicy?: string;
  currentPin?: { ref: string; sha256: string };
  drift?: string[];
  exceptions?: string[];
  risk?: UpgradeRisk;
  role?: "pilot" | "batch";
  autoMergeEligible?: boolean;
  branch?: string;
  pullRequestUrl?: string;
}

export interface FleetPolicyUpgradeOptions {
  workspaceRoot: string;
  repos: string[];
  input: unknown;
  apply?: boolean;
  maxBatchSize?: number;
  runner?: CommandRunner;
}

class UpgradeGuardError extends Error {}

function requireCondition(condition: unknown, reason: string): asserts condition {
  if (!condition) throw new UpgradeGuardError(reason);
}

async function safePath(root: string, relative: string): Promise<string> {
  requireCondition(
    relative === path.posix.normalize(relative) && !path.isAbsolute(relative) && !relative.split("/").some((part) => part === ".." || part === ".git") && !relative.includes("\\"),
    "Unsafe repository path."
  );
  let current = root;
  for (const part of relative.split("/")) {
    current = path.join(current, part);
    const stat = await lstat(current).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; return undefined; });
    requireCondition(!stat || stat.isDirectory() || (stat.isFile() && stat.nlink === 1), "Non-regular, symlink, or hardlinked paths require manual migration.");
  }
  return current;
}

/** Explicit allowlist only; GitHub settings, home profiles, merges, and auto-merge are never mutated. */
export async function executeFleetPolicyUpgrades(options: FleetPolicyUpgradeOptions): Promise<{ mode: "plan" | "apply"; results: UpgradeExecutionResult[] }> {
  const parsed = inputSchema.safeParse(options.input);
  requireCondition(parsed.success, "Invalid upgrade input; check the documented schema without publishing its contents.");
  const input = parsed.data;
  const repos = z.array(repoName).min(1).parse(options.repos);
  requireCondition(
    new Set(repos.map((repo) => repo.toLowerCase())).size === repos.length && new Set(repos.map((repo) => repo.split("/")[1]!.toLowerCase())).size === repos.length,
    "Duplicate or ambiguous repository allowlist."
  );
  requireCondition(
    new Set(input.evidence.map((item) => item.repo)).size === input.evidence.length && new Set(input.pilots.map((item) => item.repoClass)).size === input.pilots.length,
    "Duplicate evidence or class pilot."
  );
  const limit = options.maxBatchSize ?? 1;
  requireCondition(Number.isInteger(limit) && limit > 0 && limit <= 10, "maxBatchSize must be an integer from 1 to 10.");
  const runner = options.runner ?? execRunner;
  const command = async (cwd: string, executable: string, args: string[]) => {
    const response = await runner(executable, args, { cwd });
    requireCondition(response.exitCode === 0, `${executable} ${args[0]} failed; inspect local command logs and recovery state.`);
    return response.stdout.trim();
  };
  const api = async (cwd: string, endpoint: string) => JSON.parse(await command(cwd, "gh", ["api", endpoint])) as any;
  const generatorRoot = fileURLToPath(new URL("../", import.meta.url));
  requireCondition(await command(generatorRoot, "git", ["rev-parse", "HEAD"]) === input.generatorCommit, "Generator commit differs from approved plan.");
  if (options.apply) requireCondition(!(await command(generatorRoot, "git", ["status", "--porcelain"])), "Generator checkout must be clean before execution.");
  const targetText = await readFile(path.resolve(input.target.bundlePath), "utf8");
  requireCondition(!containsCredential(targetText), "Target policy contains credential-like text.");
  const target = YAML.parse(targetText) as { standard: string; version: string };
  requireCondition(flowPolicyDigest(target) === input.target.sha256, "Target policy digest differs from approved plan.");
  const workspace = await realpath(options.workspaceRoot);
  const results: UpgradeExecutionResult[] = [];
  const representatives = new Map<string, string>();
  const failedClasses = new Set<string>();
  let applied = 0;
  for (const repo of [...repos].sort()) {
    const result: UpgradeExecutionResult = { repo: "[unverified]", status: "skipped", reason: "Public managed checkout unavailable; no metadata published." };
    results.push(result);
    let cwd: string;
    try {
      cwd = await safePath(workspace, repo.split("/")[1]!);
      const manifestPath = await safePath(cwd, "project.bootstrap.yaml");
      const manifest = await loadManifest(manifestPath);
      if (manifest.project.visibility !== "public" || `${manifest.project.owner}/${manifest.project.name}` !== repo) continue;
      const remote = await api(cwd, `repos/${repo}`);
      if (remote.visibility !== "public" || remote.private !== false || remote.archived !== false || remote.full_name !== repo) continue;
      result.repo = repo;
      const repoClass = manifest.repo.class;
      requireCondition(repoClass, "An explicit repository class is required.");
      const representative = representatives.get(repoClass) ?? repo;
      representatives.set(repoClass, representative);
      result.repoClass = repoClass;
      result.role = representative === repo ? "pilot" : "batch";
      requireCondition(!failedClasses.has(repoClass), "Earlier class execution failed; stop this batch and record remediation.");
      result.status = "blocked";
      result.reason = "Upgrade preflight did not complete.";
      requireCondition(manifest.project.defaultBranch === remote.default_branch, "Manifest default branch differs from live GitHub.");
      const expectedOrigins = [`https://github.com/${repo}.git`, `git@github.com:${repo}.git`, `https://github.com/${repo}`];
      const origin = await command(cwd, "git", ["remote", "get-url", "--all", "origin"]);
      const pushOrigin = await command(cwd, "git", ["remote", "get-url", "--push", "--all", "origin"]);
      requireCondition(expectedOrigins.includes(origin) && expectedOrigins.includes(pushOrigin), "Origin differs from the allowlisted repository.");
      requireCondition(!(await command(cwd, "git", ["status", "--porcelain"])), "Dirty checkout; inspect and recover before retrying.");
      const starting = await command(cwd, "git", ["branch", "--show-current"]);
      requireCondition(starting === remote.default_branch, "Checkout must start on its live default branch.");
      const base = await command(cwd, "git", ["rev-parse", "HEAD"]);
      requireCondition(
        (await api(cwd, `repos/${repo}/commits/${encodeURIComponent(remote.default_branch)}`)).sha === base,
        "Checkout differs from the live default branch; refresh it before retrying."
      );
      requireCondition(!manifest.unknownSettings?.length, "Unknown manifest settings require manual migration.");
      requireCondition(manifest.policy?.flow, "A verified current Flow policy pin is required.");
      const bundlePath = await safePath(cwd, manifest.policy.flow.bundlePath);
      const current = await loadResolvedFlowPolicy(manifest, cwd);
      requireCondition(manifest.policy!.flow.bundlePath !== "project.bootstrap.yaml", "Policy bundle collides with the manifest.");
      result.currentPolicy = current.policy.version;
      result.targetPolicy = target.version;
      result.currentPin = current.source;
      result.exceptions = manifest.exceptions.map((entry) => entry.id);
      result.risk = classifyPolicyUpgrade(current.policy.version, target.version);
      const nextManifest = { ...manifest, policy: { flow: { ...manifest.policy!.flow, ref: input.target.ref, sha256: input.target.sha256 } } };
      requireCondition(result.risk !== "major", "Major upgrades require notification and an accepted ADR; this executor supports only compatible Flow v1 policies.");
      resolveFlowPolicy(nextManifest, target, input.target);
      requireCondition(result.risk !== "invalid", "Target must be a forward compatible exact policy version.");
      requireCondition(
        current.policy.version !== target.version || (current.source.ref === input.target.ref && current.source.sha256 === input.target.sha256),
        "An existing policy version cannot be repinned to different content."
      );
      const branch = `codex/flow-policy-${target.version}-${base.slice(0, 12)}`;
      if (options.apply) {
        result.branch = branch;
        const existing = await runner("git", ["show-ref", "--verify", "--quiet", `refs/heads/${branch}`], { cwd });
        requireCondition(existing.exitCode === 1, "Recovery branch exists or branch check failed; inspect it before retrying.");
        requireCondition(!(await command(cwd, "git", ["ls-remote", "--heads", "origin", `refs/heads/${branch}`])), "Remote recovery branch exists; inspect it before retrying.");
      }
      const plan = await planRepo(nextManifest, cwd);
      requireCondition(!plan.files.some((file) => file.path === manifest.policy!.flow.bundlePath), "Policy bundle collides with generator output.");
      for (const change of plan.changes) await safePath(cwd, change.path);
      result.drift = plan.changes.filter((change) => change.type !== "unchanged").map((change) => change.path);
      if (current.source.ref === input.target.ref && current.source.sha256 === input.target.sha256 && !result.drift.length) { result.status = "unchanged"; result.reason = "Policy pin and generated output already match."; continue; }
      requireCondition(current.policy.version !== target.version, "Policy version is already selected; reconcile generator drift separately.");
      requireCondition(validatePolicyExceptions(manifest.exceptions).blocking === false, "Invalid or expired exceptions require remediation.");
      const evidence = input.evidence.find((item) => item.repo === repo);
      requireCondition(
        evidence && new RegExp(`^https://github\\.com/${repo.replace(/[.]/g, "\\.")}/issues/[1-9][0-9]*$`).test(evidence.issue),
        "Repository-specific issue and policy diff, tests, exceptions, provenance, and autoreview evidence are required."
      );
      requireCondition(
        Object.entries(evidence).every(([key, value]) => key === "repo" || (value.startsWith(`https://github.com/${repo}/`) && new URL(value).href === value)),
        "Evidence links must remain within the verified public repository."
      );
      const pilot = input.pilots.find((item) => item.repoClass === repoClass);
      let passed = false;
      if (pilot) {
        requireCondition(
          pilot.repo === representative && pilot.targetPolicy === target.version,
          "Pilot evidence is not bound to this representative, source version, and target version."
        );
        requireCondition(
          pilot.evidence.startsWith(`https://github.com/${pilot.repo}/`) && new URL(pilot.evidence).href === pilot.evidence,
          "Pilot evidence must remain within its verified public repository."
        );
        requireCondition(pilot.outcome !== "failed", "Representative pilot failed; stop this class and record remediation.");
        const pilotRemote = await api(cwd, `repos/${pilot.repo}`);
        requireCondition(pilotRemote.visibility === "public" && pilotRemote.private === false && pilotRemote.full_name === pilot.repo, "Pilot public identity is unverified.");
        requireCondition(
          (await api(cwd, `repos/${pilot.repo}/commits/${encodeURIComponent(pilotRemote.default_branch)}`)).sha === pilot.commit,
          "Pilot commit differs from its live default branch."
        );
        const comparison = await api(cwd, `repos/${pilot.repo}/compare/${pilot.sourceCommit}...${pilot.commit}`);
        requireCondition(
          comparison.status === "ahead" && comparison.base_commit?.sha === pilot.sourceCommit && comparison.merge_base_commit?.sha === pilot.sourceCommit,
          "Pilot source commit is not a verified ancestor of its validated target commit."
        );
        const sourceFile = await api(cwd, `repos/${pilot.repo}/contents/project.bootstrap.yaml?ref=${pilot.sourceCommit}`);
        const sourceManifest = normalizeManifest(YAML.parse(Buffer.from(sourceFile.content, "base64").toString("utf8")));
        requireCondition(
          sourceManifest.project.visibility === "public" && `${sourceManifest.project.owner}/${sourceManifest.project.name}` === pilot.repo && sourceManifest.repo.class === repoClass && sourceManifest.policy?.flow,
          "Pilot source commit does not contain the verified public representative class and policy."
        );
        const sourceBundlePath = sourceManifest.policy.flow.bundlePath.split("/").map(encodeURIComponent).join("/");
        const sourceBundle = await api(cwd, `repos/${pilot.repo}/contents/${sourceBundlePath}?ref=${pilot.sourceCommit}`);
        const source = resolveFlowPolicy(sourceManifest, YAML.parse(Buffer.from(sourceBundle.content, "base64").toString("utf8")), sourceManifest.policy.flow);
        requireCondition(source.policy.version === pilot.currentPolicy, "Declared pilot source version differs from its verified immutable source commit.");
        requireCondition(
          current.policy.version === source.policy.version && current.source.ref === source.source.ref && current.source.sha256 === source.source.sha256,
          "Batch source policy does not match the proven pilot source version and pin; validate a matching representative migration."
        );
        const pilotFile = await api(cwd, `repos/${pilot.repo}/contents/project.bootstrap.yaml?ref=${pilot.commit}`);
        const pilotManifest = normalizeManifest(YAML.parse(Buffer.from(pilotFile.content, "base64").toString("utf8")));
        requireCondition(
          pilotManifest.repo.class === repoClass && pilotManifest.policy?.flow.ref === input.target.ref && pilotManifest.policy.flow.sha256 === input.target.sha256,
          "Pilot commit does not contain the target class and policy pin."
        );
        const pilotBundle = await api(cwd, `repos/${pilot.repo}/contents/${pilotManifest.policy!.flow.bundlePath.split("/").map(encodeURIComponent).join("/")}?ref=${pilot.commit}`);
        requireCondition(
          flowPolicyDigest(YAML.parse(Buffer.from(pilotBundle.content, "base64").toString("utf8"))) === input.target.sha256,
          "Pilot commit bundle differs from the approved target digest."
        );
        const runId = new RegExp(`^https://github\\.com/${pilot.repo.replace(/[.]/g, "\\.")}/actions/runs/([1-9][0-9]*)$`).exec(pilot.evidence)?.[1];
        requireCondition(runId, "Pilot evidence must name an exact public Actions validation run.");
        const validation = await api(cwd, `repos/${pilot.repo}/actions/runs/${runId}`);
        requireCondition(
          validation.repository?.full_name === pilot.repo && validation.head_sha === pilot.commit && validation.status === "completed" && validation.conclusion === "success" && ["push", "workflow_dispatch"].includes(validation.event) && validation.path === pilot.validationWorkflow,
          "Pilot validation run does not prove this exact trusted commit and workflow."
        );
        const workflow = await api(cwd, `repos/${pilot.repo}/contents/${pilot.validationWorkflow}?ref=${pilot.commit}`);
        requireCondition(workflow.type === "file" && workflow.path === pilot.validationWorkflow, "Pilot validation workflow is not checked in at the proven commit.");
        const statuses = await api(cwd, `repos/${pilot.repo}/commits/${pilot.commit}/status`);
        requireCondition(statuses.total_count === 0 || statuses.state === "success", "Pilot commit statuses are pending or failing.");
        const checks = await api(cwd, `repos/${pilot.repo}/commits/${pilot.commit}/check-runs?per_page=100`);
        requireCondition(
          checks.total_count === checks.check_runs?.length && checks.check_runs.every((check: any) => check.status === "completed" && check.conclusion === "success"),
          "Pilot checks are incomplete or failing; record remediation."
        );
        passed = true;
      }
      requireCondition(result.role === "pilot" || passed, "Representative pilot has not passed; later class upgrades remain blocked.");
      requireCondition(manifest.exceptions.length === 0, "Exception-bearing upgrades require a separate human-reviewed migration.");
      result.autoMergeEligible = passed && result.risk === "patch";
      result.reason = result.risk === "minor" ? "Independent review is required before merging this minor upgrade." : passed ? "Patch eligible after verified pilot; merge automation remains off." : "Representative draft only; validate its exact commit before further class rollout.";
      result.status = "planned";
      if (!options.apply) continue;
      requireCondition(applied < limit, "Batch limit reached; inspect results before another explicit apply.");
      const temporary = await mkdtemp(path.join(os.tmpdir(), "bootstrap-upgrade-"));
      let created = false;
      applied += 1;
      try {
        await command(cwd, "git", ["checkout", "-b", branch]);
        created = true;
        const document = YAML.parseDocument(await readFile(manifestPath, "utf8"));
        document.setIn(["policy", "flow", "ref"], input.target.ref);
        document.setIn(["policy", "flow", "sha256"], input.target.sha256);
        await writeFile(manifestPath, document.toString());
        await writeFile(bundlePath, targetText);
        await applyRepo(await loadManifest(manifestPath), cwd);
        await safePath(cwd, "scripts/ci/run-fast-checks.sh");
        await command(cwd, "bash", ["scripts/ci/run-fast-checks.sh"]);
        const appliedManifest = await loadManifest(manifestPath);
        await loadResolvedFlowPolicy(appliedManifest, cwd);
        const repeated = await planRepo(appliedManifest, cwd);
        requireCondition(repeated.changes.every((change) => change.type === "unchanged"), "Generated output is not idempotent after validation.");
        const allowed = new Set(["project.bootstrap.yaml", manifest.policy!.flow.bundlePath, ...result.drift]);
        const changed = `${await command(cwd, "git", ["diff", "--name-only", "--no-renames", "-z"])}\0${await command(cwd, "git", ["ls-files", "--others", "--exclude-standard", "-z"])}\0${await command(cwd, "git", ["diff", "--cached", "--name-only", "--no-renames", "-z"])}`.split("\0").filter(Boolean);
        requireCondition(changed.every((file) => allowed.has(file)), "Validation changed unrelated files; inspect the recovery branch.");
        await command(cwd, "git", ["add", "--all", "--", ...allowed]);
        await command(cwd, "git", ["commit", "--signoff", "-m", `chore: upgrade Flow policy to ${target.version}`]);
        const upgradeCommit = await command(cwd, "git", ["rev-parse", "HEAD"]);
        requireCondition(!(await command(cwd, "git", ["status", "--porcelain"])), "Commit left dirty output; inspect the recovery branch.");
        await command(cwd, "autoreview", ["--mode", "branch", "--base", base]);
        requireCondition(
          await command(cwd, "git", ["rev-parse", "HEAD"]) === upgradeCommit && !(await command(cwd, "git", ["status", "--porcelain"])),
          "Review changed the prepared commit or worktree; inspect the recovery branch."
        );
        const body = [
          "## Summary",
          `Upgrade Flow ${current.policy.version} to ${target.version} using generator ${input.generatorCommit}.`,
          `Policy diff: ${evidence.policyDiff}`,
          "## Governing Issue",
          `Refs ${evidence.issue}`,
          "## Validation",
          `Tests: ${evidence.tests}`,
          `Provenance: ${evidence.provenance}`,
          `Prior review: ${evidence.autoreview}`,
          `Autoreview command and result: autoreview --mode branch --base ${base}; passed with no actionable findings.`,
          "## Bootstrap Governance",
          "- [x] No real secrets, runtime auth, or machine-local env files committed.",
          "Material change: no",
          "## Merge Automation",
          "Auto-merge is unsafe until independent review, required checks, and pilot governance are satisfied; automation remains disabled.",
          "## Notes",
          result.reason,
          `Exceptions: ${evidence.exceptions}`,
          `Pilot: ${pilot?.evidence ?? "pending; representative draft only"}`
        ].join("\n\n");
        const bodyPath = path.join(temporary, "body.md");
        await writeFile(bodyPath, body);
        await command(cwd, "git", ["push", "-u", "origin", branch]);
        const output = await command(cwd, "gh", ["pr", "create", "--repo", repo, "--base", starting, "--head", branch, "--draft", "--title", `chore: upgrade Flow policy to ${target.version}`, "--body-file", bodyPath]);
        const url = output.match(new RegExp(`https://github\\.com/${repo.replace(/[.]/g, "\\.")}/pull/[1-9][0-9]*`))?.[0];
        requireCondition(url, "PR creation did not return a verified repository PR URL; inspect remote state.");
        result.pullRequestUrl = url;
        result.status = "pr-opened";
      } catch (error) {
        result.status = "failed";
        result.reason = error instanceof UpgradeGuardError ? error.message : "Upgrade execution failed; inspect local recovery state.";
      } finally {
        if (created) {
          try {
            requireCondition(!(await command(cwd, "git", ["status", "--porcelain"])), "Dirty recovery output remains on the upgrade branch.");
            await command(cwd, "git", ["checkout", starting]);
          } catch { result.status = "failed"; result.reason += " Could not restore starting branch; inspect recovery branch and local status."; }
        }
        if (result.status === "failed") failedClasses.add(repoClass);
        await rm(temporary, { recursive: true, force: true }).catch(() => { result.reason += " Temporary PR-body cleanup failed; inspect the local temporary directory."; });
      }
    } catch (error) {
      if (result.repo !== "[unverified]") {
        result.status = "blocked";
        result.reason = redactPublicText(error instanceof UpgradeGuardError ? error.message : "Upgrade preflight failed; inspect the local checkout without publishing its contents.").value;
      }
    }
  }
  return { mode: options.apply ? "apply" : "plan", results };
}
