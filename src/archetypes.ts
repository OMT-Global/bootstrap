import path from "node:path";
import { readFileSync } from "node:fs";

import { dedent, indentBlock, yamlList } from "./lib/text.js";
import { stringifyManifest } from "./manifest.js";
import { formatRunsOn, resolveRunsOn } from "./runners.js";
import type { BootstrapManifest, RenderedFile } from "./types.js";

function repoUrl(manifest: BootstrapManifest): string {
  return `https://github.com/${manifest.project.owner}/${manifest.project.name}`;
}

function projectDisplayName(manifest: BootstrapManifest): string {
  return manifest.project.displayName?.trim() || manifest.project.name;
}

function projectIdentityLines(manifest: BootstrapManifest): string {
  const lines = [];
  const displayName = projectDisplayName(manifest);

  if (displayName !== manifest.project.name) {
    lines.push(`- Product name: \`${displayName}\``);
  }

  lines.push(`- Repository: \`${manifest.project.owner}/${manifest.project.name}\``);
  lines.push("- Manifest: `project.bootstrap.yaml`");

  return lines.join("\n");
}

function requiredStatusChecksDisplay(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks.map((check) => `\`${check}\``).join(", ");
}

function requiredStatusChecksPlain(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks.join(", ");
}

function primaryRequiredStatusCheck(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks[0] ?? "CI Gate";
}

function requiredStatusCheckGuardrail(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks.length === 1
    ? `- Keep ${requiredStatusChecksDisplay(manifest)} as the single required PR status check.`
    : `- Keep required PR status checks aligned with ${requiredStatusChecksDisplay(manifest)}.`;
}

function requiredStatusCheckConfirmation(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks.length === 1
    ? `Confirm branch protection points at the ${requiredStatusChecksDisplay(manifest)} status.`
    : `Confirm branch protection points at the expected required status checks: ${requiredStatusChecksDisplay(manifest)}.`;
}

function requiredStatusCheckConfirmationLead(manifest: BootstrapManifest): string {
  return requiredStatusCheckConfirmation(manifest).replace(/\.$/, "");
}

function autoMergeReadinessPolicy(): string {
  return "When GitHub plan limits make auto-merge unavailable for a private repo, use the fallback merge-readiness policy: required checks pass or are intentionally skipped, approvals and conversation resolution are satisfied, no blocking review state remains, and a maintainer performs the merge manually.";
}

function autoMergeOnboardingConfirmation(): string {
  return "Confirm `delete branch on merge` and `allow auto-merge` are enabled when the GitHub plan supports them; otherwise record the plan-limit evidence and use the fallback merge-readiness policy.";
}

function additionalWorkflowLines(manifest: BootstrapManifest): string[] {
  return manifest.ci.additionalWorkflows.map(
    (workflow) => `- \`${workflow.path}\`: ${workflow.purpose}`
  );
}

function additionalWorkflowSection(manifest: BootstrapManifest): string {
  if (manifest.ci.additionalWorkflows.length === 0) {
    return "";
  }

  return dedent`
    ## Repo-Specific Workflow Lanes

${indentBlock(additionalWorkflowLines(manifest).join("\n"), 4)}

    These lanes are adjunct to the standard CI shape. Keep the required PR status checks aligned with ${requiredStatusChecksDisplay(manifest)}, and keep heavyweight or specialized logic out of the fast PR gate unless the manifest explicitly changes that contract.
  `;
}

function organizationRepoCreationPolicy(manifest: BootstrapManifest): string {
  const organization = manifest.github.organization;
  if (!organization) {
    return "";
  }

  const disabledScopes = [
    !organization.membersCanCreatePublicRepositories ? "public" : null,
    !organization.membersCanCreatePrivateRepositories ? "private" : null,
    organization.membersCanCreateInternalRepositories === false ? "internal" : null
  ].filter((scope): scope is string => Boolean(scope));

  if (
    !organization.membersCanCreateRepositories &&
    !organization.membersCanCreatePublicRepositories &&
    !organization.membersCanCreatePrivateRepositories &&
    organization.membersCanCreateInternalRepositories !== true
  ) {
    return "member repository creation is disabled.";
  }

  if (disabledScopes.length === 0) {
    return "member repository creation matches the explicit manifest overrides.";
  }

  return `member repository creation is disabled for ${disabledScopes.join("/")}.`;
}

function organizationSecurityDefaultsLabel(manifest: BootstrapManifest): string {
  const organization = manifest.github.organization;
  if (!organization) {
    return "";
  }

  const enabledDefaults = [
    organization.newRepositorySecurity.dependencyGraph ? "dependency graph" : null,
    organization.newRepositorySecurity.dependabotAlerts ? "Dependabot alerts" : null,
    organization.newRepositorySecurity.dependabotSecurityUpdates ? "Dependabot security updates" : null,
    organization.newRepositorySecurity.secretScanning ? "secret scanning" : null,
    organization.newRepositorySecurity.secretScanningPushProtection ? "push protection" : null
  ].filter((value): value is string => Boolean(value));

  return enabledDefaults.join(", ");
}

function organizationGovernanceSection(manifest: BootstrapManifest): string {
  const organization = manifest.github.organization;
  if (!organization) {
    return "";
  }

  return dedent`
    ## Org Governance

    - Confirm the org default repository permission is \`${organization.defaultRepositoryPermission}\`.
    - Confirm ${organizationRepoCreationPolicy(manifest)}
    - Confirm new-repo security defaults keep ${organizationSecurityDefaultsLabel(manifest)} enabled.
    - Treat upstream-aligned forks as explicit exceptions; keep them aligned with the source fork unless you intentionally manage their GitHub policy here.
  `;
}

function codeowners(manifest: BootstrapManifest): string {
  if (manifest.github.codeowners.length === 0) {
    return "# Add CODEOWNERS entries when reviewer mapping is ready.\n";
  }

  return `${manifest.github.codeowners
    .map((rule) => `${rule.pattern} ${rule.owners.join(" ")}`)
    .join("\n")}\n`;
}

function baseGitignore(manifest: BootstrapManifest): string {
  const shared = [
    ".DS_Store",
    ".env.local",
    ".env.*.local",
    "node_modules/",
    "dist/",
    "coverage/",
    ".playwright-cli/",
    "tmp/",
    ".bootstrap/*",
    "!.bootstrap/managed-files.json",
    ".new-project-bootstrap/"
  ];

  const archetypeSpecific: Record<BootstrapManifest["archetype"]["kind"], string[]> = {
    "nextjs-web": [".next/", "node_modules/", "out/"],
    "node-ts-service": ["node_modules/", "*.tsbuildinfo"],
    "python-service": [".venv/", "__pycache__/", ".pytest_cache/", "*.pyc"],
    "generic-empty": []
  };

  return `${[...shared, ...archetypeSpecific[manifest.archetype.kind]].join("\n")}\n`;
}

function repoAgents(manifest: BootstrapManifest): string {
  const stack =
    manifest.archetype.kind === "nextjs-web"
      ? "Next.js + TypeScript"
      : manifest.archetype.kind === "node-ts-service"
        ? "Node.js + TypeScript"
        : manifest.archetype.kind === "python-service"
          ? "Python service"
          : "Generic polyglot";

  return dedent`
    # AGENTS

    - Always work on a feature branch. Hooks block commits to \`main\` and \`master\`; enable them with \`git config core.hooksPath .githooks\`.
    - Stack baseline: ${stack}.
    - CI baseline: fast PR checks stay cheap and shell-safe; extended validation runs on \`main\`, nightly, or manual dispatch.
    - Self-hosted runner policy: private-repository trusted jobs may use their matching capability pool. Public repository security workflows use GitHub-hosted isolation; fork pull-request jobs always remain read-only and GitHub-hosted.
    - Add or update tests for every interactive, branching, or operator-facing behavior change.
    - For a task that may open or update a PR, handle autoreview access before implementation: request required network access immediately and, for a private repository, explicit authorization to send the forthcoming intended PR diff to the external reviewer. At closeout, use the \`autoreview\` skill against the actual base. Verify every finding, fix accepted in-scope findings, and rerun affected tests and autoreview after changes. Proceed only when no accepted/actionable findings remain, and record the final command and result in the PR validation evidence. If authorization is declined or the skill is unavailable or cannot complete, stop and report the blocker instead of bypassing the gate.
    - PRs must use the generated pull request template. The required PR gate validates summary, issue linkage, validation evidence, and risk notes.
    - Never commit real secrets, runtime auth, or machine-local env files. Use templates and GitHub environments instead.

    ## Kingdom Governance

    - Pheidon is the orchestrator and current gate for repo execution work.
    - GitHub issues are the source of record for agent execution work.
    - Worker agents should act from assigned or explicitly enabled issues, not free-roaming backlog grabs.
    - If an agent authors a PR, that same agent may not approve it. This is a hard rule.
    - Healthy PRs should converge toward auto-merge once required checks are green or intentionally skipped, approvals are satisfied, and no blocking review state remains.
    - ${autoMergeReadinessPolicy()}
    - PRs should link and close their governing issue where possible so issue state remains the durable work contract.

    ## Local Conventions

    - Keep scope tight and favor predictable templates over clever scaffolding.
    - Treat \`project.bootstrap.yaml\` as the source of truth for repo governance, environments, CI policy, and home profile sync.
    - Review \`docs/bootstrap/onboarding.md\` before first merge to confirm reviewers, runner labels, and environment gates match the project.
  `;
}

function releaseTagExamples(manifest: BootstrapManifest): { exact: string; minor: string; major: string } {
  const prefix = manifest.release.tagPrefix;

  return {
    exact: `${prefix}1.2.3`,
    minor: `${prefix}1.2`,
    major: `${prefix}1`
  };
}

function isControlPlaneBootstrap(manifest: BootstrapManifest): boolean {
  return manifest.project.owner === "OMT-Global" && manifest.project.name === "bootstrap";
}

function repoReadme(manifest: BootstrapManifest): string {
  const displayName = projectDisplayName(manifest);
  const releaseTags = releaseTagExamples(manifest);
  const aiAttestationSection = manifest.ci.aiAttestation.enabled
    ? dedent`

      ## AI Attestation

      This bootstrap also renders \`.github/workflows/ai-attestation.yml\` as a caller for the shared attestation workflow at \`${manifest.ci.aiAttestation.reusableWorkflowRepo}/.github/workflows/ai-attestation-reusable.yml@${manifest.ci.aiAttestation.reusableWorkflowRef}\`.

      Override the default provider, model, and prompt hash with repo variables (\`AI_ATTESTATION_PROVIDER\`, \`AI_ATTESTATION_MODEL\`, \`AI_ATTESTATION_PROMPT_HASH\`) or update \`project.bootstrap.yaml\` before production rollout.
    `
    : "";
  const releaseSection = manifest.release.enabled
    ? dedent`

      ## Release Standard

      This bootstrap uses immutable exact SemVer tags such as \`${releaseTags.exact}\`, then automatically advances the floating compatibility tags \`${releaseTags.minor}\` and \`${releaseTags.major}\` to the same commit.

      Cut patch releases from \`release/X.Y\` branches when you maintain an older minor line. Cut new minor and major releases from \`${manifest.project.defaultBranch}\`.
    `
    : "";
  const tierASection = isControlPlaneBootstrap(manifest)
    ? dedent`

      ## Tier A Control Plane

      This repo now carries the shared Tier A workflow contracts:

      - \`.github/workflows/security-pr.yml\`
      - \`.github/workflows/release.yml\`
      - \`.github/workflows/ai-attestation-reusable.yml\`

      Use \`docs/bootstrap/tier-a-ci-contract.md\` for the consumer interface and rollout pattern. Use \`docs/bootstrap/next-steps.md\` as the publish checklist before downstream repos pin to a tag or immutable SHA.
    `
    : "";

  return dedent`
    # ${displayName}

    ${manifest.project.description}

    Use \`project.bootstrap.yaml\` as the control plane for repo-local scaffolding, GitHub governance, CI policy, and portable Codex profile sync. Plan first, then apply repo, GitHub, and home targets deliberately.

    ## What The Bootstrap Owns

    - GitHub governance, issue labels, environments, and optional org defaults
    ${manifest.ci.additionalWorkflows.length > 0
      ? "- Optional repo-specific workflow lanes declared in the manifest without replacing the standard CI frame"
      : ""}
    - Repo-local \`AGENTS.md\`, \`CONTRIBUTING.md\`, and pull request template guidance
    - Fast PR checks plus heavier extended validation lanes
    ${manifest.release.enabled ? "- SemVer release automation with floating major/minor compatibility tags" : ""}
    ${manifest.ci.aiAttestation.enabled ? "- Optional signed AI attestation workflow backed by the control-plane reusable contract" : ""}
    - Portable Codex home profile sync
    - Operator docs for onboarding, hosted agents, and follow-up setup

    ## Quickstart

    \`\`\`sh
    bootstrap plan --manifest ./project.bootstrap.yaml
    bootstrap apply repo --manifest ./project.bootstrap.yaml
    bootstrap apply github --manifest ./project.bootstrap.yaml
    bootstrap apply home --manifest ./project.bootstrap.yaml
    bootstrap doctor --manifest ./project.bootstrap.yaml
    \`\`\`

    Daily fleet reconciliation should start in plan mode and write a report:

    \`\`\`sh
    bootstrap reconcile --workspace-root ~/src --report bootstrap-reconcile.json
    \`\`\`

    To discover GitHub repos first, add \`--org ${manifest.project.owner}\`; repositories without local bootstrapped checkouts are skipped in the report.

    Once the repo allowlist is trusted, run repo file drift through draft PRs:

    \`\`\`sh
    bootstrap reconcile --workspace-root ~/src --apply-repo --create-pr --report bootstrap-reconcile.json
    \`\`\`

    ${manifest.github.organization
      ? `If \`github.organization\` is set and \`${manifest.project.owner}\` is an organization, \`bootstrap apply github\` also reconciles org defaults for new repos.`
      : ""} It also syncs \`github.issueLabels\` for issue routing, risk, status, and review gates.

    ${requiredStatusCheckConfirmationLead(manifest)} and require approval from someone other than the most recent pusher. ${autoMergeReadinessPolicy()}

    ## Contributor And PR Guidance

    - \`CONTRIBUTING.md\` is the canonical contributor onboarding and local validation surface.
    - \`.github/PULL_REQUEST_TEMPLATE.md\` is the canonical pull request format for summaries, governing issue links, validation notes, and merge-readiness checks.
    - Existing bootstrapped repos can retrofit these surfaces with \`bootstrap apply repo --manifest ./project.bootstrap.yaml\`; repos with restricted \`repo.managedPaths\` should include both paths before applying.

    ## Project Identity

${indentBlock(projectIdentityLines(manifest), 4)}
    - Visibility: \`${manifest.project.visibility}\`
    - Default branch: \`${manifest.project.defaultBranch}\`
    - Archetype: \`${manifest.archetype.kind}\`
${indentBlock(additionalWorkflowSection(manifest), 4)}
${indentBlock(releaseSection, 4)}
${indentBlock(aiAttestationSection, 4)}
${indentBlock(tierASection, 4)}

    ## Repository URL

    - ${repoUrl(manifest)}
  `;
}

function contributingDoc(manifest: BootstrapManifest): string {
  return dedent`
    # Contributing

    Contributions should start from a GitHub issue that is assigned or explicitly enabled by Pheidon. Keep changes scoped to that issue, work on a feature branch, and link the issue from the pull request.

    ## Local Setup

    - Install dependencies for the selected stack before changing code.
    - Enable repo hooks with \`git config core.hooksPath .githooks\`; they block direct commits to \`${manifest.project.defaultBranch}\` and catch committed runtime env files.
    - Use \`project.bootstrap.yaml\` as the source of truth for governance, CI, environments, and bootstrap-managed guidance files.

    ## Change Expectations

    - Keep implementation changes minimal and relevant to the governing issue.
    - Add or update tests for interactive, branching, or operator-facing behavior changes.
    - Keep fast PR checks cheap and shell-safe; move heavyweight validation to \`scripts/ci/run-extended-validation.sh\`.
    - Do not commit real secrets, runtime auth, generated credentials, caches, or machine-local env files.

    ## Validation

    - Run the relevant local checks before opening a PR.
    - At the start of agent-authored PR work, request autoreview network access and, for private repository diffs, explicit authorization for the forthcoming intended PR diff. At closeout, use the \`autoreview\` skill against the actual base. Verify every finding, address accepted in-scope findings, and rerun affected checks and autoreview after edits until no accepted/actionable findings remain.
    - Record the final autoreview command and result in the PR. If authorization is declined or the skill is unavailable or cannot complete, stop and report that blocker instead of opening or updating the PR.
    - For this bootstrap contract, the required PR check surface is ${requiredStatusChecksDisplay(manifest)}.
    - Document any skipped checks in the PR with a concrete reason.

    ## Pull Requests

    - Use \`.github/PULL_REQUEST_TEMPLATE.md\`.
    - Link the governing issue with a closing keyword when the PR should close it.
    - PR authors may not approve their own PRs.
    - A healthy PR should converge toward auto-merge after required checks pass or are intentionally skipped, approvals are satisfied, and no blocking review state remains.
    - ${autoMergeReadinessPolicy()}
  `;
}

function flowPullRequestSection(manifest: BootstrapManifest): string {
  if (!manifest.github.flowGovernance) {
    return "";
  }

  return dedent`
    ## Flow Contract

    - Owner lane:
    - Repair owner:
    - Autonomy class:
    - Risk class:

    ## Flow Merge Readiness

    - [ ] Every blocker has a next actor and next action
    - [ ] No active blocking requested changes remain
    - [ ] Non-author approval is present when required
    - [ ] PR author enabled auto-merge where GitHub allows it, or recorded why it is unavailable/unsafe
  `;
}

function pullRequestTemplate(manifest: BootstrapManifest): string {
  return dedent`
    ## Summary

    -

    ## Governing Issue

    Refs #<issue-number>  <!-- use Closes/Fixes/Resolves only when this PR fully completes the issue; otherwise use Refs/Part of, owner/repo#123, a full GitHub issue URL, or explain why no issue is linked -->

    ## Validation

    - [ ] Relevant local checks passed
    - [ ] Agent-authored changes passed \`autoreview\` against the intended PR diff with no accepted/actionable findings
    - Autoreview command and result:
    - [ ] Required PR checks are expected to satisfy ${requiredStatusChecksDisplay(manifest)}
    - [ ] Skipped checks are explained below

    ## Bootstrap Governance

    - [ ] Changes are scoped to the linked issue
    - [ ] Contributor or PR guidance changes are reflected in \`CONTRIBUTING.md\`, \`.github/PULL_REQUEST_TEMPLATE.md\`, and \`docs/bootstrap/onboarding.md\` when applicable
    - [ ] PR author enabled auto-merge where GitHub allows it, or GitHub plan-limit evidence/unavailable reason is recorded and the fallback merge-readiness policy applies
    - [ ] No real secrets, runtime auth, or machine-local env files are committed

    Material change: no
    ADR: docs/decisions/ADR-<number>-<slug>.md  <!-- required when Material change is yes; ADR status must be Accepted -->

${indentBlock(flowPullRequestSection(manifest), 4)}

    ## Merge Automation

    - [ ] PR author enabled auto-merge with \`gh pr merge --auto --squash\`, or the reason it is unavailable/unsafe is noted below

    ## Notes

    -
  `;
}

function implementationIssueTemplate(): string {
  return dedent`
    name: Implementation work
    description: Durable contract for autonomous or review-gated implementation work
    title: ""
    labels:
      - state:intake
    body:
      - type: textarea
        id: problem
        attributes:
          label: Problem / intent
          description: What should change and why?
        validations:
          required: true
      - type: textarea
        id: acceptance
        attributes:
          label: Acceptance criteria
          description: Concrete conditions that make this done.
        validations:
          required: true
      - type: textarea
        id: validation
        attributes:
          label: Validation commands
          description: Commands or checks the worker should run.
        validations:
          required: true
      - type: dropdown
        id: autonomy
        attributes:
          label: Autonomy class
          options:
            - Class 0 - Observe only
            - Class 1 - Safe autonomous
            - Class 2 - Review-gated autonomous
            - Class 3 - Human decision required
            - Class 4 - Forbidden unattended
        validations:
          required: true
      - type: dropdown
        id: lane
        attributes:
          label: Recommended lane
          options:
            - Pheidon
            - Apollo
            - Ares
            - Daedalus
            - Hephaestus
            - Hermes
            - Human
        validations:
          required: true
  `;
}

function flowBlockerIssueTemplate(): string {
  return dedent`
    name: Flow blocker
    description: Record a blocked unit of work with a next actor and unblock target
    title: "Flow blocker: "
    labels:
      - state:blocked-infra
    body:
      - type: textarea
        id: blocked_item
        attributes:
          label: Blocked issue/PR
          description: Link the blocked item.
        validations:
          required: true
      - type: dropdown
        id: blocked_type
        attributes:
          label: Blocker type
          options:
            - Human decision
            - Infrastructure
            - Scope
            - Auth/credential
            - External dependency
        validations:
          required: true
      - type: textarea
        id: evidence
        attributes:
          label: Evidence
          description: Logs, checks, review comments, or command output proving the block.
        validations:
          required: true
      - type: dropdown
        id: next_actor
        attributes:
          label: Next actor
          options:
            - Pheidon
            - Apollo
            - Ares
            - Daedalus
            - Hephaestus
            - Hermes
            - Human
        validations:
          required: true
      - type: textarea
        id: unblock
        attributes:
          label: Required unblock action
        validations:
          required: true
  `;
}

function envExample(): string {
  return dedent`
    # Add non-secret defaults here.
    # Real credentials belong in GitHub environment secrets, not committed files.

    APP_ENV=development
  `;
}

function preCommitHook(): string {
  return dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || echo HEAD)"
    if [[ "$branch" == "main" || "$branch" == "master" ]]; then
      echo "ERROR: commits to $branch are blocked. Create a feature branch." >&2
      exit 1
    fi

    staged_files=()
    while IFS= read -r -d '' staged_file; do
      staged_files+=("$staged_file")
    done < <(git diff --cached --name-only --diff-filter=ACMR -z)

    for f in "\${staged_files[@]:-}"; do
      [[ -n "$f" ]] || continue
      case "$f" in
        *.env|.env.*)
          if [[ "$f" != *.example ]]; then
            echo "ERROR: cannot commit env file '$f'. Use .env.example templates instead." >&2
            exit 1
          fi
          ;;
      esac
    done

    if [[ -x scripts/check-detect-secrets.sh ]]; then
      bash scripts/check-detect-secrets.sh --staged
    fi
  `;
}

function detectSecretsScript(): string {
  return dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    mode="\${1:-"--all-files"}"
    ignore_globs=("scripts/check-detect-secrets.sh")
    if [[ -f .detect-secrets-ignore ]]; then
      while IFS= read -r ignore_glob; do
        if [[ -z "$ignore_glob" ]]; then
          continue
        fi
        if [[ "\${ignore_glob:0:1}" == "#" ]]; then
          continue
        fi
        ignore_globs+=("$ignore_glob")
      done < .detect-secrets-ignore
    fi

    should_skip_file() {
      local candidate="$1"
      local ignore_glob
      for ignore_glob in "\${ignore_globs[@]}"; do
        case "$candidate" in
          $ignore_glob)
            return 0
            ;;
        esac
      done
      return 1
    }

    files=()
    if [[ "$mode" == "--staged" ]]; then
      while IFS= read -r -d '' file; do
        files+=("$file")
      done < <(git diff --cached --name-only --diff-filter=ACMR -z)
    else
      while IFS= read -r -d '' file; do
        files+=("$file")
      done < <(git ls-files -z)
    fi

    if [[ "\${#files[@]}" -eq 0 ]]; then
      echo "No files to scan."
      exit 0
    fi

    patterns=(
      'ghp_'
      'github_pat_'
      'sk-live-'
      'sk-proj-'
      'AKIA[0-9A-Z]{16}'
      'BEGIN (RSA|OPENSSH|EC) PRIVATE KEY'
      'OPENAI_API_KEY='
      'SUDO_PASS='
      'BW_SESSION='
    )

    tmp_file="$(mktemp)"
    trap 'rm -f "$tmp_file"' EXIT

    for file in "\${files[@]}"; do
      if [[ ! -f "$file" ]] || should_skip_file "$file"; then
        continue
      fi
      printf '%s\n' "$file" >>"$tmp_file"
    done

    failed=0
    while IFS= read -r file; do
      for pattern in "\${patterns[@]}"; do
        if grep -E -n "$pattern" "$file" >/dev/null 2>&1; then
          echo "Potential secret pattern '$pattern' found in $file" >&2
          failed=1
        fi
      done
    done <"$tmp_file"

    exit "$failed"
  `;
}

function nodeFastChecks(packageManager: BootstrapManifest["archetype"]["packageManager"]): string {
  const installCommand =
    packageManager === "pnpm"
      ? "pnpm install --frozen-lockfile"
      : packageManager === "yarn"
        ? "yarn install --immutable"
        : "npm ci";

  const runPrefix = packageManager === "npm" ? "npm run" : `${packageManager}`;

  return dedent`
    if [[ ! -f package.json ]]; then
      echo "No package.json found. Skipping Node-based fast checks."
      exit 0
    fi

    has_script() {
      local script_name="$1"
      node --input-type=module -e "import fs from 'node:fs'; const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8')); process.exit(pkg.scripts && pkg.scripts['$1'] ? 0 : 1);" >/dev/null 2>&1
    }

    ${installCommand}

    for script_name in lint typecheck test build; do
      if has_script "$script_name"; then
        ${runPrefix} "$script_name"
      else
        echo "Skipping missing script: $script_name"
      fi
    done
  `;
}

function nodeExtendedChecks(packageManager: BootstrapManifest["archetype"]["packageManager"]): string {
  const runPrefix = packageManager === "npm" ? "npm run" : `${packageManager}`;

  return dedent`
    if [[ ! -f package.json ]]; then
      echo "No package.json found. Skipping Node-based extended checks."
      exit 0
    fi

    has_script() {
      local script_name="$1"
      node --input-type=module -e "import fs from 'node:fs'; const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8')); process.exit(pkg.scripts && pkg.scripts['$1'] ? 0 : 1);" >/dev/null 2>&1
    }

    bash scripts/ci/run-fast-checks.sh

    for script_name in test:integration test:e2e release:check; do
      if has_script "$script_name"; then
        ${runPrefix} "$script_name"
      else
        echo "Skipping missing script: $script_name"
      fi
    done
  `;
}

function pythonFastChecks(): string {
  return dedent`
    if [[ ! -f pyproject.toml ]]; then
      echo "No pyproject.toml found. Skipping Python fast checks."
      exit 0
    fi

    if [[ ! -d .venv ]]; then
      python3 -m venv .venv
    fi

    source .venv/bin/activate
    python -m pip install --upgrade pip setuptools wheel
    python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true

    if python -c "import pytest" >/dev/null 2>&1; then
      python -m pytest -q
    else
      echo "pytest not installed. Skipping unit tests."
    fi
  `;
}

function pythonExtendedChecks(): string {
  return dedent`
    if [[ ! -f pyproject.toml ]]; then
      echo "No pyproject.toml found. Skipping Python extended checks."
      exit 0
    fi

    bash scripts/ci/run-fast-checks.sh

    source .venv/bin/activate
    if python -c "import pytest" >/dev/null 2>&1; then
      python -m pytest -q -m "integration or e2e" || echo "No integration or e2e markers defined yet."
    fi
  `;
}

function genericFastChecks(): string {
  return dedent`
    echo "Generic archetype selected."
    echo "Add project-specific scripts and tighten scripts/ci/run-fast-checks.sh when the stack is finalized."
  `;
}

function genericExtendedChecks(): string {
  return dedent`
    bash scripts/ci/run-fast-checks.sh
    echo "No extended checks configured for the generic archetype yet."
  `;
}

function codexCloudSetupScript(manifest: BootstrapManifest): string {
  const installBody =
    manifest.archetype.kind === "python-service"
      ? dedent`
          if [[ -f pyproject.toml ]]; then
            python3 -m venv .venv
            source .venv/bin/activate
            python -m pip install --upgrade pip setuptools wheel
            python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
          fi
        `
      : manifest.archetype.kind === "generic-empty"
        ? dedent`
            if [[ -f package-lock.json ]]; then
              npm ci --prefer-offline --no-audit --no-fund
            elif [[ -f pnpm-lock.yaml ]]; then
              corepack enable
              pnpm install --frozen-lockfile
            elif [[ -f yarn.lock ]]; then
              corepack enable
              yarn install --immutable
            elif [[ -f package.json ]]; then
              npm install --prefer-offline --no-audit --no-fund
            fi

            if [[ -f pyproject.toml ]]; then
              python3 -m venv .venv
              source .venv/bin/activate
              python -m pip install --upgrade pip setuptools wheel
              python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
            fi
          `
        : dedent`
            if [[ -f package-lock.json ]]; then
              npm ci --prefer-offline --no-audit --no-fund
            elif [[ -f pnpm-lock.yaml ]]; then
              corepack enable
              pnpm install --frozen-lockfile
            elif [[ -f yarn.lock ]]; then
              corepack enable
              yarn install --immutable
            elif [[ -f package.json ]]; then
              npm install --prefer-offline --no-audit --no-fund
            fi
          `;

  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    ${installBody}
  `}\n`;
}

function codexCloudMaintenanceScript(manifest: BootstrapManifest): string {
  const maintenanceBody =
    manifest.archetype.kind === "python-service"
      ? dedent`
          if [[ -f pyproject.toml && -d .venv ]]; then
            source .venv/bin/activate
            python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
          fi
        `
      : dedent`
          if [[ -f package-lock.json ]]; then
            npm ci --prefer-offline --no-audit --no-fund
          elif [[ -f pnpm-lock.yaml ]]; then
            corepack enable
            pnpm install --frozen-lockfile
          elif [[ -f yarn.lock ]]; then
            corepack enable
            yarn install --immutable
          elif [[ -f package.json ]]; then
            npm install --prefer-offline --no-audit --no-fund
          fi

          if [[ -f pyproject.toml && -d .venv ]]; then
            source .venv/bin/activate
            python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
          fi
        `;

  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    ${maintenanceBody}
  `}\n`;
}

function codexCloudDoc(manifest: BootstrapManifest): string {
  return dedent`
    # Codex Cloud Environment

    Configure the Codex Web environment in Codex settings for this bootstrap-managed repository.

    ## Project

${indentBlock(projectIdentityLines(manifest), 4)}

    ## Environment Settings

    - Base image: \`universal\`
    - Setup mode: manual setup script
    - Setup script: \`bash scripts/codex-cloud/setup.sh\`
    - Maintenance script: \`bash scripts/codex-cloud/maintenance.sh\`
    - Agent internet access: off by default; enable limited or unrestricted access only when a task needs it
    - Secrets: none required for review tasks by default

    ## Notes

    - Codex cloud tasks automatically read \`AGENTS.md\` in this repo.
    - Setup scripts run in a separate shell session from the agent. Persistent env vars belong in Codex environment settings or \`~/.bashrc\`.
    - This repo uses required PR checks ${requiredStatusChecksDisplay(manifest)}, so cloud review tasks should preserve that contract.
  `;
}

function fastChecksScript(manifest: BootstrapManifest): string {
  if (manifest.ci.customScripts.fast) {
    return `${dedent`
      #!/usr/bin/env bash
      set -euo pipefail

    `}\n${manifest.ci.customScripts.fast.trimEnd()}\n`;
  }

  const body =
    manifest.archetype.kind === "python-service"
      ? pythonFastChecks()
      : manifest.archetype.kind === "generic-empty"
        ? genericFastChecks()
        : nodeFastChecks(manifest.archetype.packageManager);

  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

  `}\n${body}\n`;
}

function extendedChecksScript(manifest: BootstrapManifest): string {
  if (manifest.ci.customScripts.extended) {
    return `${dedent`
      #!/usr/bin/env bash
      set -euo pipefail

    `}\n${manifest.ci.customScripts.extended.trimEnd()}\n`;
  }

  const body =
    manifest.archetype.kind === "python-service"
      ? pythonExtendedChecks()
      : manifest.archetype.kind === "generic-empty"
        ? genericExtendedChecks()
        : nodeExtendedChecks(manifest.archetype.packageManager);

  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

  `}\n${body}\n`;
}

function prGovernanceScript(manifest: BootstrapManifest): string {
  return dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    required=(PR_TITLE PR_BODY PR_AUTHOR)
    for name in "\${required[@]}"; do
      if [[ -z "\${!name:-}" ]]; then
        echo "Missing required PR governance input: $name" >&2
        exit 2
      fi
    done

    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT

    fetch() {
      local url="$1"
      local destination="$2"
      curl --fail --silent --show-error --location --retry 2 \\
        --header "Accept: application/vnd.github+json" \\
        --header "Authorization: Bearer $GITHUB_TOKEN" \\
        "$url" >"$destination"
    }

    load_response() {
      local fixture="$1"
      local url="$2"
      local suffix="$3"
      local destination="$4"
      if [[ -n "$fixture" ]]; then
        cp "$fixture" "$destination"
      elif [[ -n "$url" && -n "\${GITHUB_TOKEN:-}" ]]; then
        fetch "$url?$suffix" "$destination"
      else
        echo "Provide a fixture file or API URL plus GITHUB_TOKEN for $destination" >&2
        exit 2
      fi
    }

    load_response "\${PR_FILES_FILE:-}" "\${PR_FILES_URL:-}" "per_page=100" "$workdir/files.json"
    load_response "\${PR_COMMITS_FILE:-}" "\${PR_COMMITS_URL:-}" "per_page=250" "$workdir/commits.json"
    load_response "\${PR_REVIEWS_FILE:-}" "\${PR_REVIEWS_URL:-}" "per_page=100" "$workdir/reviews.json"

    python3 - "$PR_TITLE" "$PR_BODY" "$PR_AUTHOR" "\${PR_CREATED_AT:-}" "\${PR_GOVERNANCE_ENFORCE_AFTER:-}" "$workdir/files.json" "$workdir/commits.json" "$workdir/reviews.json" <<'PY'
    from datetime import datetime
    import json
    import re
    import sys
    from pathlib import Path

    title, body, author, created_at, enforce_after, files_path, commits_path, reviews_path = sys.argv[1:]
    files = json.loads(Path(files_path).read_text())
    commits = json.loads(Path(commits_path).read_text())
    reviews = json.loads(Path(reviews_path).read_text())
    failures = []

    if enforce_after:
        try:
            created_at_value = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            enforce_after_value = datetime.fromisoformat(enforce_after.replace("Z", "+00:00"))
            if created_at_value.tzinfo is None or enforce_after_value.tzinfo is None:
                raise ValueError
        except ValueError:
            failures.append("PRS-ENFORCEMENT-INPUT-001: PR_CREATED_AT and PR_GOVERNANCE_ENFORCE_AFTER must be ISO-8601 timestamps.")
        else:
            if created_at_value < enforce_after_value:
                print(f"PASS PRS-PR-GOVERNANCE-LEGACY-001: PR opened at {created_at} before enforcement began at {enforce_after}.")
                sys.exit(0)

    if not re.match(r"^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\\([^)]+\\))?!?: .+", title):
        failures.append("PRS-PR-TITLE-001: use a Conventional Commit-style PR title, for example 'feat: add policy gate'.")

    excluded = []
    counted_lines = 0
    for changed in files:
        name = changed.get("filename", "unknown")
        if name.startswith(("docs/", "test/", "tests/")) or name.endswith((".md", ".lock")) or name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
            excluded.append(name)
        else:
            counted_lines += int(changed.get("additions", 0)) + int(changed.get("deletions", 0))
    print(f"INFO PRS-PR-SIZE-001: {counted_lines} counted changed lines; excluded {len(excluded)} documentation, test, and lockfile paths.")
    if excluded:
        print("INFO PRS-PR-SIZE-001 excluded: " + ", ".join(sorted(excluded)))
    if counted_lines > 800:
        failures.append(f"PRS-PR-SIZE-001: {counted_lines} counted changed lines exceeds the 800-line review threshold; split the change before requesting review.")

    missing_dco = []
    for commit in commits:
        login = (commit.get("author") or {}).get("login", "")
        account_type = (commit.get("author") or {}).get("type", "")
        if account_type == "Bot" or login.endswith("[bot]"):
            continue
        message = (commit.get("commit") or {}).get("message", "")
        if not re.search(r"(?im)^signed-off-by:\\s+.+ <[^>]+>$", message):
            missing_dco.append(commit.get("sha", "unknown")[:12])
    if missing_dco:
        failures.append("PRS-DCO-001: contributed commits without a Signed-off-by trailer: " + ", ".join(missing_dco))

    declaration = re.search(r"(?im)^material change:\\s*(yes|no)\\s*$", body)
    if not declaration:
        failures.append("PRS-MATERIAL-001: declare 'Material change: yes' or 'Material change: no' in the PR body.")
    elif declaration.group(1).lower() == "yes":
        adr = re.search(r"(?im)^adr:\\s*(docs/decisions/[^\\s]+\\.md)\\s*$", body)
        if not adr:
            failures.append("PRS-ADR-001: material changes require an ADR line pointing at an accepted docs/decisions/*.md file.")
        else:
            adr_path = Path(adr.group(1))
            if not adr_path.is_file() or not re.search(r"(?im)^status:\\s*accepted\\s*$", adr_path.read_text()):
                failures.append(f"PRS-ADR-001: {adr_path} must exist in this PR and declare 'Status: Accepted'.")

        independent_approvers = {
            (review.get("user") or {}).get("login", "")
            for review in reviews
            if review.get("state", "").upper() == "APPROVED"
            and (review.get("user") or {}).get("login", "") != author
            and (review.get("user") or {}).get("type", "") != "Bot"
        }
        if not independent_approvers:
            failures.append("PRS-INDEPENDENT-REVIEW-001: material changes require an approving reviewer other than the PR author.")

    if failures:
        print("\\n".join("FAIL " + failure for failure in failures), file=sys.stderr)
        sys.exit(1)
    print("PASS PRS-PR-GOVERNANCE-001: title, DCO, change accounting, and material evidence are valid.")
    PY
  `;
}

function actionPinScript(): string {
  return dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    python3 - "\${1:-.github/workflows}" <<'PY'
    import re
    import sys
    from pathlib import Path

    workflow_root = Path(sys.argv[1])
    uses_pattern = re.compile(r"^\\s*(?:-\\s+)?uses:\\s*([^\\s#]+)@([^\\s#]+)(?:\\s+#\\s*(.+))?\\s*$")
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")
    failures = []
    checked = 0

    for workflow in sorted([*workflow_root.rglob("*.yml"), *workflow_root.rglob("*.yaml")]):
        for line_number, line in enumerate(workflow.read_text().splitlines(), start=1):
            match = uses_pattern.match(line)
            if not match:
                continue
            action, ref, metadata = match.groups()
            if action.startswith("./") or action.startswith("OMT-Global/bootstrap/"):
                continue
            checked += 1
            location = f"{workflow}:{line_number}"
            if not sha_pattern.fullmatch(ref):
                failures.append(f"SA-ACTION-PIN-001 {location}: {action}@{ref} is not an immutable 40-character commit SHA.")
            elif not metadata:
                failures.append(f"SA-ACTION-PIN-002 {location}: {action} is pinned but lacks readable tag or release metadata after '#'.")

    if failures:
        print("\\n".join(failures), file=sys.stderr)
        raise SystemExit(1)

    print(f"PASS SA-ACTION-PIN-000: validated {checked} third-party action pin(s) under {workflow_root}.")
    PY
  `;
}

function releaseVerificationScript(manifest: BootstrapManifest): string {
  if (manifest.ci.customScripts.releaseVerification) {
    return `${dedent`
      #!/usr/bin/env bash
      set -euo pipefail

    `}\n${manifest.ci.customScripts.releaseVerification.trimEnd()}\n`;
  }

  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    bash scripts/ci/run-fast-checks.sh
    bash scripts/ci/run-extended-validation.sh
  `}\n`;
}

function releasePublishScript(manifest: BootstrapManifest): string {
  const releaseTags = releaseTagExamples(manifest);

  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    echo "No repo-specific artifact publish step is configured."
    echo "Create exact release tags such as ${releaseTags.exact}; the reusable release workflow handles GitHub release publication and floating tag promotion."
  `}\n`;
}

function releaseVersionScript(manifest: BootstrapManifest): string {
  const prefix = manifest.release.tagPrefix;
  const versions = manifest.release.versions;

  const header = dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    tag="\${GITHUB_REF_NAME:-}"
    if [[ -z "\${tag}" ]]; then
      echo "GITHUB_REF_NAME is required to validate release versions." >&2
      exit 1
    fi
    prefix="${prefix}"
    version="\${tag#"\${prefix}"}"
  `;

  if (versions.length === 0) {
    return `${header}\n\n${dedent`
      echo "No release version surfaces are configured in project.bootstrap.yaml."
      echo "Skipping version validation for \${tag}; version bump pull requests must merge before the release tag is pushed."
    `}\n`;
  }

  const blocks = versions.map((entry) => {
    if (entry.type === "npm") {
      return dedent`
        npm_file="${entry.path}"
        if [[ ! -f "\${npm_file}" ]]; then
          echo "Expected npm version file \${npm_file} is missing." >&2
          exit 1
        fi
        npm_version="$(grep -m1 -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "\${npm_file}" | sed -E 's/.*"([^"]+)"[[:space:]]*$/\\1/')"
        if [[ "\${npm_version}" != "\${version}" ]]; then
          echo "\${npm_file} version \${npm_version} does not match release tag \${tag} (expected \${version})." >&2
          echo "Land the version bump in a pull request before pushing the release tag." >&2
          exit 1
        fi
        echo "\${npm_file} matches \${tag}."
      `;
    }

    if (entry.type === "python") {
      return dedent`
        py_file="${entry.path}"
        if [[ ! -f "\${py_file}" ]]; then
          echo "Expected Python version file \${py_file} is missing." >&2
          exit 1
        fi
        py_version="$(grep -m1 -oE '^[[:space:]]*version[[:space:]]*=[[:space:]]*"[^"]+"' "\${py_file}" | sed -E 's/.*"([^"]+)".*/\\1/')"
        if [[ "\${py_version}" != "\${version}" ]]; then
          echo "\${py_file} version \${py_version} does not match release tag \${tag} (expected \${version})." >&2
          echo "Land the version bump in a pull request before pushing the release tag." >&2
          exit 1
        fi
        echo "\${py_file} matches \${tag}."
      `;
    }

    return dedent`
      echo "Container release version for ${entry.path} is derived from \${tag} at publish time; no in-repo file to validate."
    `;
  });

  return `${header}\n\n${blocks.join("\n\n")}\n`;
}

function releaseBuildScript(manifest: BootstrapManifest): string {
  const dir = manifest.release.artifacts.directory;
  const checksumBlock =
    manifest.release.artifacts.checksum === "sha256"
      ? dedent`
          (
            cd "\${artifact_dir}"
            : > SHA256SUMS
            for entry in "\${artifacts[@]}"; do
              sha256sum -- "\${entry#"\${artifact_dir}/"}" >> SHA256SUMS
            done
          )
          echo "Wrote \${artifact_dir}/SHA256SUMS for \${#artifacts[@]} artifact(s)."
        `
      : dedent`
          echo "Checksum generation is disabled in project.bootstrap.yaml; skipping SHA256SUMS."
        `;

  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    artifact_dir="${dir}"
    mkdir -p "\${artifact_dir}"

    # Add repo-specific build steps above this line to populate \${artifact_dir}
    # with downloadable release assets before checksums are generated.

    mapfile -t artifacts < <(find "\${artifact_dir}" -maxdepth 1 -type f ! -name SHA256SUMS ! -name release-evidence.json ! -name validation-evidence.json | sort)
    if [[ \${#artifacts[@]} -eq 0 ]]; then
      echo "No release artifacts were produced in \${artifact_dir}."
      echo "This repo ships no downloadable assets; add build steps to scripts/ci/run-release-build.sh when it does."
      exit 0
    fi
  `}\n${checksumBlock}\n`;
}

function releaseChangelogConfig(manifest: BootstrapManifest): string {
  const categories = [
    ...manifest.release.changelog.categories,
    { title: "Other Changes", labels: ["*"] }
  ];

  const body = categories
    .map(
      (category) =>
        `    - title: ${category.title}\n      labels:\n${category.labels
          .map((label) => `        - "${label}"`)
          .join("\n")}`
    )
    .join("\n");

  return `changelog:\n  categories:\n${body}\n`;
}

function nextJsStarter(): RenderedFile[] {
  return [
    {
      path: "app/layout.tsx",
      reason: "Minimal Next.js shell",
      contents: dedent`
        import "./globals.css";
        import type { ReactNode } from "react";

        export default function RootLayout({ children }: { children: ReactNode }) {
          return (
            <html lang="en">
              <body>{children}</body>
            </html>
          );
        }
      `
    },
    {
      path: "app/page.tsx",
      reason: "Minimal Next.js homepage",
      contents: dedent`
        export default function HomePage() {
          return (
            <main>
              <h1>Bootstrap</h1>
              <p>Replace this starter page with the real application entrypoint.</p>
            </main>
          );
        }
      `
    },
    {
      path: "app/globals.css",
      reason: "Minimal global styling",
      contents: dedent`
        :root {
          color-scheme: light;
          font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
        }

        body {
          margin: 0;
          padding: 2rem;
          background: linear-gradient(180deg, #f6f4ed 0%, #ffffff 100%);
          color: #17212b;
        }
      `
    }
  ];
}

function nodeStarter(): RenderedFile[] {
  return [
    {
      path: "src/index.ts",
      reason: "Minimal Node.js entrypoint",
      contents: dedent`
        export function main(): string {
          return "bootstrap";
        }

        if (import.meta.url === \`file://\${process.argv[1]}\`) {
          process.stdout.write(\`\${main()}\n\`);
        }
      `
    }
  ];
}

function pythonStarter(moduleName: string): RenderedFile[] {
  return [
    {
      path: path.posix.join("src", moduleName, "__init__.py"),
      reason: "Python package marker",
      contents: "__all__ = ['app']\n"
    },
    {
      path: path.posix.join("src", moduleName, "app.py"),
      reason: "Minimal Python entrypoint",
      contents: dedent`
        def main() -> str:
            return "bootstrap"


        if __name__ == "__main__":
            print(main())
      `
    },
    {
      path: "tests/test_smoke.py",
      reason: "Minimal Python smoke test",
      contents: dedent`
        from ${moduleName}.app import main


        def test_main() -> None:
            assert main() == "bootstrap"
      `
    }
  ];
}

function genericStarter(manifest: BootstrapManifest): RenderedFile[] {
  const controlPlaneLines = isControlPlaneBootstrap(manifest)
    ? [
        "- Validate reusable control-plane workflows (`security-pr`, `release`, and AI attestation) before publishing a consumer-facing tag.",
        "- Publish a stable control-plane tag or immutable SHA before moving Tier A repos off branch-ref callers."
      ]
    : [];

  return [
    {
      path: "docs/bootstrap/next-steps.md",
      reason: "Follow-up checklist for generic projects",
      contents: dedent`
        # Next Steps

        - Add the primary runtime and package manifest for this project.
        - Tighten \`scripts/ci/run-fast-checks.sh\` and \`scripts/ci/run-extended-validation.sh\` once the toolchain is known.
${indentBlock(controlPlaneLines.join("\n"), 8)}
        - Review CODEOWNERS, environment reviewers, and required PR checks before the first merge.
        - Re-run \`bootstrap plan --manifest ./project.bootstrap.yaml\` after major manifest changes to confirm intended drift.
      `
    }
  ];
}

function workflowPaths(manifest: BootstrapManifest): { app: string[]; ci: string[]; extended: string[] } {
  const common = [
    "project.bootstrap.yaml",
    "AGENTS.md",
    "CONTRIBUTING.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".githooks/**",
    ".github/workflows/**",
    "scripts/**",
    "docs/bootstrap/**"
  ];

  let paths: { app: string[]; ci: string[]; extended: string[] };

  switch (manifest.archetype.kind) {
    case "nextjs-web":
      paths = {
        app: [...common, "app/**", "components/**", "src/**", "public/**", "package.json", "tsconfig.json"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["tests/**", "playwright/**", "docker/**", "infra/**"]
      };
      break;
    case "node-ts-service":
      paths = {
        app: [...common, "src/**", "tests/**", "package.json", "tsconfig.json"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["docker/**", "infra/**", "ops/**"]
      };
      break;
    case "python-service":
      paths = {
        app: [...common, "src/**", "tests/**", "pyproject.toml", ".python-version"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["docker/**", "infra/**", "ops/**"]
      };
      break;
    case "generic-empty":
      paths = {
        app: [...common, "README.md", "docs/**"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["infra/**", "ops/**"]
      };
      break;
  }

  return {
    app: [...paths.app, ...manifest.ci.appPaths],
    ci: [...paths.ci, ...manifest.ci.ciPaths],
    extended: [...paths.extended, ...manifest.ci.extendedPaths]
  };
}

function setupSteps(manifest: BootstrapManifest): string {
  const lines: string[] = [];

  if (manifest.archetype.kind === "nextjs-web" || manifest.archetype.kind === "node-ts-service") {
    lines.push(
      `- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4`,
      `  with:`,
      `    node-version: \${{ env.NODE_VERSION }}`,
      `    cache: ${manifest.archetype.packageManager}`,
      `    cache-dependency-path: ${
        manifest.archetype.packageManager === "pnpm"
          ? "pnpm-lock.yaml"
          : manifest.archetype.packageManager === "yarn"
            ? "yarn.lock"
            : "package-lock.json"
      }`
    );
  }

  if (manifest.archetype.kind === "python-service") {
    lines.push(
      `- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5`,
      `  with:`,
      `    python-version: \${{ env.PYTHON_VERSION }}`
    );
  }

  return lines.join("\n");
}

function dependabotConfig(manifest: BootstrapManifest): string {
  const updates = manifest.ci.dependabot.ecosystems
    .map((ecosystem) => {
      const lines = [
        `  - package-ecosystem: "${ecosystem.packageEcosystem}"`,
        `    directory: "${ecosystem.directory}"`,
        "    schedule:",
        `      interval: "${ecosystem.interval}"`
      ];

      if (ecosystem.groupMinorAndPatch) {
        lines.push(
          "    groups:",
          `      ${ecosystem.packageEcosystem.replace(/[^a-z0-9]+/g, "-")}-minor-patch:`,
          "        update-types:",
          "          - \"minor\"",
          "          - \"patch\""
        );
      }

      if (ecosystem.ignoreMajorUpdates) {
        lines.push(
          "    ignore:",
          "      - dependency-name: \"*\"",
          "        update-types:",
          "          - \"version-update:semver-major\""
        );
      }

      return lines.join("\n");
    })
    .join("\n\n");

  return [
    "# Generated by OMT Bootstrap. Keep dependency policy in project.bootstrap.yaml.",
    "# Dependabot alerts + security updates are managed through GitHub security settings;",
    "# this file governs routine scheduled version update PRs.",
    "version: 2",
    "updates:",
    updates
  ].join("\n");
}

function codeQlLanguages(manifest: BootstrapManifest): string {
  if (manifest.ci.codeqlLanguages.length === 0) {
    throw new Error(
      "Public repositories using the generic-empty archetype must configure ci.codeqlLanguages before Bootstrap can project a CodeQL baseline."
    );
  }
  return manifest.ci.codeqlLanguages.join(",");
}

function publicSecurityWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Public Security Baseline

    on:
      pull_request:
      push:
        branches: [${JSON.stringify(manifest.project.defaultBranch)}]
      schedule:
        - cron: '23 6 * * 1'

    permissions:
      contents: read

    jobs:
      dependency-review:
        if: github.event_name == 'pull_request' && vars.DEPENDENCY_REVIEW_ENABLED == 'true'
        runs-on: ubuntu-latest
        permissions:
          contents: read
          pull-requests: read
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
          - uses: actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294 # v5.0.0
            with:
              fail-on-severity: high

      codeql:
        if: github.event_name == 'push' || github.event_name == 'schedule'
        runs-on: ubuntu-latest
        strategy:
          fail-fast: false
          matrix:
            language: ${JSON.stringify(manifest.ci.codeqlLanguages)}
        permissions:
          contents: read
          security-events: write
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
          - uses: github/codeql-action/init@7188fc363630916deb702c7fdcf4e481b751f97a # v4
            with:
              languages: \${{ matrix.language }}
              build-mode: none
          - uses: github/codeql-action/analyze@7188fc363630916deb702c7fdcf4e481b751f97a # v4
            with:
              category: "/language:\${{ matrix.language }}"

      sbom:
        if: github.event_name == 'push' || github.event_name == 'schedule'
        runs-on: ubuntu-latest
        permissions:
          contents: write
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
          - uses: anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0
            with:
              path: .
              format: spdx-json
              artifact-name: sbom.spdx.json
              upload-release-assets: false
  `;
}

function aiAttestationCallerWorkflow(manifest: BootstrapManifest): string {
  const config = manifest.ci.aiAttestation;
  const reusableWorkflow =
    config.reusableWorkflowRepo === `${manifest.project.owner}/${manifest.project.name}`
      ? "./.github/workflows/ai-attestation-reusable.yml"
      : `${config.reusableWorkflowRepo}/.github/workflows/ai-attestation-reusable.yml@${config.reusableWorkflowRef}`;

  return dedent`
    name: AI Attestation

    on:
      pull_request:
      push:
        branches: [${manifest.project.defaultBranch}]

    permissions:
      contents: read
      id-token: write

    jobs:
      attest:
        uses: ${reusableWorkflow}
        with:
          artifact_name: '${config.artifactName}'
          retention_days: ${config.retentionDays}
          ai_provider: \${{ vars.AI_ATTESTATION_PROVIDER || '${config.provider}' }}
          ai_model: \${{ vars.AI_ATTESTATION_MODEL || '${config.model}' }}
          prompt_hash: \${{ vars.AI_ATTESTATION_PROMPT_HASH || '${config.promptHash}' }}
  `;
}

function releaseCallerWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Release

    on:
      push:
        tags:
          - '${manifest.release.tagPrefix}*.*.*'

    permissions:
      contents: write
      id-token: write
      packages: write

    jobs:
      release:
        uses: ${manifest.release.reusableWorkflowRepo}/.github/workflows/release.yml@${manifest.release.reusableWorkflowRef}
        with:
          runs-on: '["ubuntu-latest"]'
          verify-script: scripts/ci/run-release-verification.sh
          version-script: scripts/ci/run-release-version.sh
          build-script: scripts/ci/run-release-build.sh
          publish-script: scripts/ci/run-release-publish.sh
          release-notes-file: ${manifest.release.artifacts.directory}/RELEASE_NOTES.md
          artifact-dir: ${manifest.release.artifacts.directory}
          create-github-release: ${manifest.release.createGitHubRelease ? "true" : "false"}
          tag-prefix: '${manifest.release.tagPrefix}'
          update-major-tag: ${manifest.release.updateMajorTag ? "true" : "false"}
          update-minor-tag: ${manifest.release.updateMinorTag ? "true" : "false"}
  `;
}

function governedReleaseWorkflowRef(manifest: BootstrapManifest, workflow: string): string {
  return `${manifest.release.reusableWorkflowRepo}/.github/workflows/${workflow}@${manifest.release.reusableWorkflowRef}`;
}

function releasePreflightCallerWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Release Preflight

    on:
      workflow_dispatch:
        inputs:
          version:
            description: Release version, e.g. ${manifest.release.tagPrefix}1.2.3-rc.1
            required: true
            type: string
          channel:
            description: Release channel
            required: true
            default: rc
            type: choice
            options: [rc, beta, stable, maintenance]
          target_ref:
            description: Branch, tag, or full SHA to preflight
            required: true
            type: string
          release_issue:
            description: Release issue number
            required: false
            type: string

    jobs:
      preflight:
        uses: ${governedReleaseWorkflowRef(manifest, "release-preflight-reusable.yml")}
        with:
          version: \${{ inputs.version }}
          channel: \${{ inputs.channel }}
          target_ref: \${{ inputs.target_ref }}
          release_issue: \${{ inputs.release_issue }}
          prep_script: scripts/release/prep.sh
          preflight_script: scripts/release/preflight.sh
          build_script: scripts/release/build.sh
          artifact_dir: ${manifest.release.artifacts.directory}
          release_notes_file: ${manifest.release.artifacts.directory}/RELEASE_NOTES.md
          tag_prefix: '${manifest.release.tagPrefix}'
          default_branch: ${manifest.project.defaultBranch}
          evidence_artifact_name: release-evidence
          evidence_retention_days: 365
  `;
}

function fullReleaseValidationCallerWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Full Release Validation

    on:
      workflow_dispatch:
        inputs:
          target_ref:
            description: Branch, tag, or full SHA to validate
            required: true
            type: string
          release_profile:
            description: Validation depth
            required: true
            default: standard
            type: choice
            options: [smoke, standard, full]

    jobs:
      validate:
        uses: ${governedReleaseWorkflowRef(manifest, "full-release-validation-reusable.yml")}
        with:
          target_ref: \${{ inputs.target_ref }}
          release_profile: \${{ inputs.release_profile }}
          validate_script: scripts/release/validate.sh
          artifact_dir: ${manifest.release.artifacts.directory}
          evidence_artifact_name: release-evidence
          evidence_retention_days: 365
  `;
}

function releasePublishCallerWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Release Publish

    on:
      workflow_dispatch:
        inputs:
          tag:
            description: Exact release tag, e.g. ${manifest.release.tagPrefix}1.2.3
            required: true
            type: string
          channel:
            description: Release channel
            required: true
            default: stable
            type: choice
            options: [rc, beta, stable, maintenance]
          preflight_run_id:
            description: Successful Release Preflight run ID
            required: true
            type: string
          validation_run_id:
            description: Successful Full Release Validation run ID
            required: true
            type: string
          release_issue:
            description: Release issue number
            required: false
            type: string

    jobs:
      publish:
        uses: ${governedReleaseWorkflowRef(manifest, "release-publish-reusable.yml")}
        with:
          tag: \${{ inputs.tag }}
          channel: \${{ inputs.channel }}
          preflight_run_id: \${{ inputs.preflight_run_id }}
          validation_run_id: \${{ inputs.validation_run_id }}
          release_issue: \${{ inputs.release_issue }}
          publish_script: scripts/release/publish.sh
          postpublish_script: scripts/release/postpublish.sh
          artifact_dir: ${manifest.release.artifacts.directory}
          release_notes_file: ${manifest.release.artifacts.directory}/RELEASE_NOTES.md
          create_github_release: ${manifest.release.createGitHubRelease ? "true" : "false"}
          update_major_tag: ${manifest.release.updateMajorTag ? "true" : "false"}
          update_minor_tag: ${manifest.release.updateMinorTag ? "true" : "false"}
          tag_prefix: '${manifest.release.tagPrefix}'
          default_branch: ${manifest.project.defaultBranch}
          require_release_issue: true
          require_signed_tag: ${manifest.release.maturity === "regulated" ? "true" : "false"}
          require_postpublish_verification: true
          evidence_artifact_name: release-evidence
          publish_environment: release-publish
        secrets: inherit
  `;
}

function releasePostpublishCallerWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Release Postpublish

    on:
      workflow_dispatch:
        inputs:
          tag:
            description: Exact release tag to verify
            required: true
            type: string
          channel:
            description: Release channel
            required: true
            default: stable
            type: choice
            options: [rc, beta, stable, maintenance]
          release_issue:
            description: Release issue number
            required: false
            type: string

    jobs:
      postpublish:
        uses: ${governedReleaseWorkflowRef(manifest, "release-postpublish-reusable.yml")}
        with:
          tag: \${{ inputs.tag }}
          channel: \${{ inputs.channel }}
          release_issue: \${{ inputs.release_issue }}
          postpublish_script: scripts/release/postpublish.sh
          artifact_dir: ${manifest.release.artifacts.directory}
          evidence_artifact_name: release-evidence
  `;
}

function releasePreflightReusableWorkflow(): string {
  return dedent`
    name: Reusable Release Preflight

    on:
      workflow_call:
        inputs:
          version: { required: true, type: string }
          channel: { required: true, type: string }
          target_ref: { required: true, type: string }
          runs_on: { required: false, type: string, default: '["ubuntu-latest"]' }
          artifact_dir: { required: false, type: string, default: dist/release }
          release_notes_file: { required: false, type: string, default: dist/release/RELEASE_NOTES.md }
          release_issue: { required: false, type: string, default: "" }
          prep_script: { required: false, type: string, default: scripts/release/prep.sh }
          preflight_script: { required: false, type: string, default: scripts/release/preflight.sh }
          build_script: { required: false, type: string, default: scripts/release/build.sh }
          tag_prefix: { required: false, type: string, default: v }
          default_branch: { required: false, type: string, default: main }
          evidence_artifact_name: { required: false, type: string, default: release-evidence }
          evidence_retention_days: { required: false, type: number, default: 365 }

    permissions:
      contents: read
      actions: read
      id-token: write

    jobs:
      preflight:
        runs-on: \${{ fromJSON(inputs.runs_on || '["ubuntu-latest"]') }}
        defaults:
          run:
            shell: bash
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ inputs.target_ref }}
              fetch-depth: 0

          - name: Preflight release candidate
            env:
              VERSION: \${{ inputs.version }}
              CHANNEL: \${{ inputs.channel }}
              TARGET_REF: \${{ inputs.target_ref }}
              RELEASE_ISSUE: \${{ inputs.release_issue }}
              ARTIFACT_DIR: \${{ inputs.artifact_dir }}
              VALIDATION_ARTIFACT_DIR: \${{ runner.temp }}/release-validation
              RELEASE_NOTES_FILE: \${{ inputs.release_notes_file }}
              PREP_SCRIPT: \${{ inputs.prep_script }}
              PREFLIGHT_SCRIPT: \${{ inputs.preflight_script }}
              BUILD_SCRIPT: \${{ inputs.build_script }}
              TAG_PREFIX: \${{ inputs.tag_prefix }}
              DEFAULT_BRANCH: \${{ inputs.default_branch }}
            run: |
              set -euo pipefail
              semver='(0|[1-9][0-9]*)'
              escaped_prefix="$(printf '%s' "$TAG_PREFIX" | sed -E 's/[][(){}.^$+*?|\\]/\\&/g')"
              [[ "$VERSION" =~ ^\${escaped_prefix}\${semver}\\.\${semver}\\.\${semver}(-(rc|beta)\\.[0-9]+)?$ ]] || { echo "Invalid release version: $VERSION" >&2; exit 1; }
              target_sha="$(git rev-parse HEAD)"
              prep_status=skipped; preflight_status=skipped; build_status=skipped
              if [[ -x "$PREP_SCRIPT" ]]; then
                "$PREP_SCRIPT"
                prep_status=passed
              fi
              if [[ -x "$PREFLIGHT_SCRIPT" ]]; then
                "$PREFLIGHT_SCRIPT"
                preflight_status=passed
              fi
              if [[ -x "$BUILD_SCRIPT" ]]; then
                "$BUILD_SCRIPT"
                build_status=passed
              fi
              mkdir -p "$ARTIFACT_DIR" "$(dirname "$RELEASE_NOTES_FILE")"
              [[ -f "$RELEASE_NOTES_FILE" ]] || printf '# Release Notes\\n\\nCandidate: %s\\n' "$VERSION" >"$RELEASE_NOTES_FILE"
              : >"$ARTIFACT_DIR/SHA256SUMS"
              find "$ARTIFACT_DIR" -maxdepth 1 -type f ! -name SHA256SUMS ! -name release-evidence.json ! -name validation-evidence.json -print0 | sort -z | xargs -0 shasum -a 256 >>"$ARTIFACT_DIR/SHA256SUMS"
              cat >"$ARTIFACT_DIR/release-evidence.json" <<JSON
              {"schema_version":1,"repo":"\${GITHUB_REPOSITORY}","version":"\${VERSION}","channel":"\${CHANNEL}","target_ref":"\${TARGET_REF}","target_sha":"\${target_sha}","release_issue":"\${RELEASE_ISSUE}","preflight_run_id":"\${GITHUB_RUN_ID}","checks":{"prep":"\${prep_status}","preflight":"\${preflight_status}","build":"\${build_status}"}}
              JSON

          - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
            with:
              name: release-package
              path: \${{ inputs.artifact_dir }}/
              retention-days: \${{ inputs.evidence_retention_days }}

          - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
            with:
              name: \${{ inputs.evidence_artifact_name }}
              path: |
                \${{ inputs.artifact_dir }}/release-evidence.json
                \${{ inputs.artifact_dir }}/SHA256SUMS
                \${{ inputs.release_notes_file }}
              retention-days: \${{ inputs.evidence_retention_days }}
  `;
}

function fullReleaseValidationReusableWorkflow(): string {
  return dedent`
    name: Reusable Full Release Validation

    on:
      workflow_call:
        inputs:
          target_ref: { required: true, type: string }
          release_profile: { required: true, type: string }
          runs_on: { required: false, type: string, default: '["ubuntu-latest"]' }
          validate_script: { required: false, type: string, default: scripts/release/validate.sh }
          artifact_dir: { required: false, type: string, default: dist/release }
          evidence_artifact_name: { required: false, type: string, default: release-evidence }
          evidence_retention_days: { required: false, type: number, default: 365 }

    permissions:
      contents: read
      actions: read

    jobs:
      validate:
        runs-on: \${{ fromJSON(inputs.runs_on || '["ubuntu-latest"]') }}
        defaults:
          run:
            shell: bash
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ inputs.target_ref }}
              fetch-depth: 0
          - name: Run release validation
            env:
              TARGET_REF: \${{ inputs.target_ref }}
              RELEASE_PROFILE: \${{ inputs.release_profile }}
              VALIDATE_SCRIPT: \${{ inputs.validate_script }}
              ARTIFACT_DIR: \${{ inputs.artifact_dir }}
            run: |
              set -euo pipefail
              mkdir -p "$ARTIFACT_DIR"
              validate_status=skipped
              standard_status=skipped
              if [[ -x "$VALIDATE_SCRIPT" ]]; then
                "$VALIDATE_SCRIPT"
                validate_status=passed
              fi
              if [[ -f package.json ]] && node -e "const p=require('./package.json'); process.exit(p.scripts?.check ? 0 : 1)" >/dev/null 2>&1; then
                npm run check
                standard_status=passed
              fi
              target_sha="$(git rev-parse HEAD)"
              cat >"$ARTIFACT_DIR/validation-evidence.json" <<JSON
              {"schema_version":1,"repo":"\${GITHUB_REPOSITORY}","target_ref":"\${TARGET_REF}","target_sha":"\${target_sha}","validation_run_id":"\${GITHUB_RUN_ID}","release_profile":"\${RELEASE_PROFILE}","checks":{"validate_script":"\${validate_status}","standard_checks":"\${standard_status}"}}
              JSON
          - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
            with:
              name: \${{ inputs.evidence_artifact_name }}-validation
              path: \${{ inputs.artifact_dir }}/validation-evidence.json
              retention-days: \${{ inputs.evidence_retention_days }}
  `;
}

function releasePublishReusableWorkflow(): string {
  return dedent`
    name: Reusable Release Publish

    on:
      workflow_call:
        inputs:
          tag: { required: true, type: string }
          preflight_run_id: { required: true, type: string }
          validation_run_id: { required: true, type: string }
          channel: { required: true, type: string }
          runs_on: { required: false, type: string, default: '["ubuntu-latest"]' }
          publish_script: { required: false, type: string, default: scripts/release/publish.sh }
          postpublish_script: { required: false, type: string, default: scripts/release/postpublish.sh }
          artifact_dir: { required: false, type: string, default: dist/release }
          release_notes_file: { required: false, type: string, default: dist/release/RELEASE_NOTES.md }
          create_github_release: { required: false, type: boolean, default: true }
          update_major_tag: { required: false, type: boolean, default: true }
          update_minor_tag: { required: false, type: boolean, default: true }
          tag_prefix: { required: false, type: string, default: v }
          default_branch: { required: false, type: string, default: main }
          release_issue: { required: false, type: string, default: "" }
          require_release_issue: { required: false, type: boolean, default: true }
          require_signed_tag: { required: false, type: boolean, default: false }
          require_postpublish_verification: { required: false, type: boolean, default: true }
          evidence_artifact_name: { required: false, type: string, default: release-evidence }
          publish_environment: { required: false, type: string, default: release-publish }

    permissions:
      contents: write
      actions: read
      packages: write
      id-token: write
      attestations: write

    jobs:
      publish:
        runs-on: \${{ fromJSON(inputs.runs_on || '["ubuntu-latest"]') }}
        environment: \${{ inputs.publish_environment || 'release-publish' }}
        defaults:
          run:
            shell: bash
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ inputs.tag }}
              fetch-depth: 0
          - name: Publish proven release artifact
            env:
              GH_TOKEN: \${{ github.token }}
              TAG: \${{ inputs.tag }}
              CHANNEL: \${{ inputs.channel }}
              PREFLIGHT_RUN_ID: \${{ inputs.preflight_run_id }}
              VALIDATION_RUN_ID: \${{ inputs.validation_run_id }}
              RELEASE_ISSUE: \${{ inputs.release_issue }}
              REQUIRE_RELEASE_ISSUE: \${{ inputs.require_release_issue }}
              REQUIRE_SIGNED_TAG: \${{ inputs.require_signed_tag }}
              REQUIRE_POSTPUBLISH_VERIFICATION: \${{ inputs.require_postpublish_verification }}
              CREATE_GITHUB_RELEASE: \${{ inputs.create_github_release }}
              UPDATE_MAJOR_TAG: \${{ inputs.update_major_tag }}
              UPDATE_MINOR_TAG: \${{ inputs.update_minor_tag }}
              TAG_PREFIX: \${{ inputs.tag_prefix }}
              ARTIFACT_DIR: \${{ inputs.artifact_dir }}
              RELEASE_NOTES_FILE: \${{ inputs.release_notes_file }}
              PUBLISH_SCRIPT: \${{ inputs.publish_script }}
              POSTPUBLISH_SCRIPT: \${{ inputs.postpublish_script }}
            run: |
              set -euo pipefail
              [[ "$REQUIRE_RELEASE_ISSUE" != "true" || -n "$RELEASE_ISSUE" ]] || { echo "release_issue is required." >&2; exit 1; }
              tag_sha="$(git rev-parse "$TAG^{commit}")"
              if [[ "$REQUIRE_SIGNED_TAG" == "true" ]]; then
                git tag -v "$TAG" >/dev/null
              fi
              rm -rf "$ARTIFACT_DIR"; mkdir -p "$ARTIFACT_DIR"
              PREFLIGHT_ARTIFACT_DIR="$(mktemp -d "\${RUNNER_TEMP:-/tmp}/release-preflight.XXXXXX")"
              gh run download "$PREFLIGHT_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-package --dir "$PREFLIGHT_ARTIFACT_DIR"
              [[ -f "$PREFLIGHT_ARTIFACT_DIR/release-evidence.json" ]] || { echo "Missing preflight release-evidence.json." >&2; exit 1; }
              evidence_target_sha="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!p.target_sha) process.exit(2); process.stdout.write(p.target_sha)' "$PREFLIGHT_ARTIFACT_DIR/release-evidence.json")"
              [[ "$evidence_target_sha" == "$tag_sha" ]] || { echo "Preflight evidence target SHA does not match tag SHA." >&2; exit 1; }
              evidence_preflight_run_id="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!p.preflight_run_id) process.exit(2); process.stdout.write(p.preflight_run_id)' "$PREFLIGHT_ARTIFACT_DIR/release-evidence.json")"
              [[ "$evidence_preflight_run_id" == "$PREFLIGHT_RUN_ID" ]] || { echo "Preflight evidence run ID does not match the requested preflight run." >&2; exit 1; }
              VALIDATION_ARTIFACT_DIR="$(mktemp -d "\${RUNNER_TEMP:-/tmp}/release-validation.XXXXXX")"
              gh run download "$VALIDATION_RUN_ID" --repo "$GITHUB_REPOSITORY" --name release-evidence-validation --dir "$VALIDATION_ARTIFACT_DIR"
              [[ -f "$VALIDATION_ARTIFACT_DIR/validation-evidence.json" ]] || { echo "Missing validation validation-evidence.json." >&2; exit 1; }
              validation_target_sha="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!p.target_sha) process.exit(2); process.stdout.write(p.target_sha)' "$VALIDATION_ARTIFACT_DIR/validation-evidence.json")"
              [[ "$validation_target_sha" == "$tag_sha" ]] || { echo "Validation evidence target SHA does not match tag SHA." >&2; exit 1; }
              validation_run_id="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!p.validation_run_id) process.exit(2); process.stdout.write(p.validation_run_id)' "$VALIDATION_ARTIFACT_DIR/validation-evidence.json")"
              [[ "$validation_run_id" == "$VALIDATION_RUN_ID" ]] || { echo "Validation evidence run ID does not match the requested validation run." >&2; exit 1; }
              validation_repo="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!p.repo) process.exit(2); process.stdout.write(p.repo)' "$VALIDATION_ARTIFACT_DIR/validation-evidence.json")"
              [[ "$validation_repo" == "$GITHUB_REPOSITORY" ]] || { echo "Validation evidence repo does not match the current repository." >&2; exit 1; }
              gh run view "$VALIDATION_RUN_ID" --repo "$GITHUB_REPOSITORY" --json conclusion --jq '.conclusion' | grep -qx success
              if [[ -x "$PUBLISH_SCRIPT" ]]; then
                "$PUBLISH_SCRIPT"
              fi
              if [[ "$CREATE_GITHUB_RELEASE" == "true" ]]; then
                [[ -f "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS" ]] || { echo "Missing preflight SHA256SUMS manifest." >&2; exit 1; }
                resolve_preflight_asset() {
                  local asset_path="$1"
                  local candidate="$PREFLIGHT_ARTIFACT_DIR/$asset_path"
                  if [[ -f "$candidate" ]]; then
                    printf '%s\\n' "$candidate"
                    return 0
                  fi
                  if [[ "$asset_path" == "$ARTIFACT_DIR/"* ]]; then
                    candidate="$PREFLIGHT_ARTIFACT_DIR/\${asset_path#"$ARTIFACT_DIR"/}"
                    if [[ -f "$candidate" ]]; then
                      printf '%s\\n' "$candidate"
                      return 0
                    fi
                  fi
                  candidate="$PREFLIGHT_ARTIFACT_DIR/\$(basename "$asset_path")"
                  if [[ -f "$candidate" ]]; then
                    printf '%s\\n' "$candidate"
                    return 0
                  fi
                  return 1
                }
                if ! release_notes_source="\$(resolve_preflight_asset "$RELEASE_NOTES_FILE")"; then
                  echo "Missing preflight release notes file: $RELEASE_NOTES_FILE" >&2
                  exit 1
                fi
                mkdir -p "\$(dirname "$RELEASE_NOTES_FILE")"
                cp -p -- "$release_notes_source" "$RELEASE_NOTES_FILE"
                RELEASE_ASSET_DIR="\$(mktemp -d "\${RUNNER_TEMP:-/tmp}/release-assets.XXXXXX")"
                [[ "$RELEASE_ASSET_DIR" != "$PREFLIGHT_ARTIFACT_DIR" && "$RELEASE_ASSET_DIR" != "$VALIDATION_ARTIFACT_DIR" ]] || { echo "Release asset staging directory must be isolated from evidence download directories." >&2; exit 1; }
                release_assets=()
                while read -r asset_sha asset_path; do
                  [[ -n "\${asset_sha:-}" && -n "\${asset_path:-}" ]] || continue
                  [[ "$asset_path" != *"release-evidence.json" && "$asset_path" != *"validation-evidence.json" ]] || continue
                  if ! asset_source="\$(resolve_preflight_asset "$asset_path")"; then
                    echo "Missing preflight release asset: $asset_path" >&2
                    exit 1
                  fi
                  asset_name="\$(basename "$asset_path")"
                  cp -p -- "$asset_source" "$RELEASE_ASSET_DIR/$asset_name"
                  release_assets+=("$RELEASE_ASSET_DIR/$asset_name")
                done < "$PREFLIGHT_ARTIFACT_DIR/SHA256SUMS"
                [[ \${#release_assets[@]} -gt 0 ]] || { echo "No release assets were staged for upload." >&2; exit 1; }
                release_args=()
                [[ "$TAG" == *"-rc."* || "$TAG" == *"-beta."* ]] && release_args+=(--prerelease --latest=false)
                gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1 \
                  && gh release upload "$TAG" "\${release_assets[@]}" --repo "$GITHUB_REPOSITORY" --clobber \
                  || gh release create "$TAG" "\${release_assets[@]}" --repo "$GITHUB_REPOSITORY" --notes-file "$RELEASE_NOTES_FILE" "\${release_args[@]}"
              fi
              if [[ "$TAG" != *"-rc."* && "$TAG" != *"-beta."* ]]; then
                version="\${TAG#"$TAG_PREFIX"}"; IFS=. read -r major minor patch <<<"$version"
                git config user.name "github-actions[bot]"
                git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
                [[ "$UPDATE_MINOR_TAG" == "true" ]] && git tag -f "\${TAG_PREFIX}\${major}.\${minor}" "$tag_sha" && git push -f origin "refs/tags/\${TAG_PREFIX}\${major}.\${minor}"
                [[ "$UPDATE_MAJOR_TAG" == "true" ]] && git tag -f "\${TAG_PREFIX}\${major}" "$tag_sha" && git push -f origin "refs/tags/\${TAG_PREFIX}\${major}"
              fi
              if [[ -x "$POSTPUBLISH_SCRIPT" ]]; then
                "$POSTPUBLISH_SCRIPT" "$TAG"
              elif [[ "$REQUIRE_POSTPUBLISH_VERIFICATION" == "true" ]]; then
                echo "Postpublish verification script is required but missing or not executable." >&2
                exit 1
              fi
              printf '{"schema_version":1,"repo":"%s","tag":"%s","tag_sha":"%s","publish_run_id":"%s"}\\n' "$GITHUB_REPOSITORY" "$TAG" "$tag_sha" "$GITHUB_RUN_ID" >"$ARTIFACT_DIR/postpublish-evidence.json"
          - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
            with:
              name: \${{ inputs.evidence_artifact_name }}-publish
              path: \${{ inputs.artifact_dir }}/postpublish-evidence.json
  `;
}

function releasePostpublishReusableWorkflow(): string {
  return dedent`
    name: Reusable Release Postpublish

    on:
      workflow_call:
        inputs:
          tag: { required: true, type: string }
          channel: { required: true, type: string }
          release_issue: { required: false, type: string, default: "" }
          postpublish_script: { required: false, type: string, default: scripts/release/postpublish.sh }
          artifact_dir: { required: false, type: string, default: dist/release }
          evidence_artifact_name: { required: false, type: string, default: release-evidence }

    permissions:
      contents: read
      actions: read

    jobs:
      postpublish:
        runs-on: ubuntu-latest
        defaults:
          run:
            shell: bash
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ inputs.tag }}
              fetch-depth: 0
          - name: Verify published release
            env:
              GH_TOKEN: \${{ github.token }}
              TAG: \${{ inputs.tag }}
              CHANNEL: \${{ inputs.channel }}
              RELEASE_ISSUE: \${{ inputs.release_issue }}
              POSTPUBLISH_SCRIPT: \${{ inputs.postpublish_script }}
              ARTIFACT_DIR: \${{ inputs.artifact_dir }}
            run: |
              set -euo pipefail
              mkdir -p "$ARTIFACT_DIR"
              gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null
              asset_count="$(gh release view "$TAG" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets | length')"
              [[ "$asset_count" -ge 1 ]] || { echo "Release has no assets." >&2; exit 1; }
              if [[ -x "$POSTPUBLISH_SCRIPT" ]]; then
                "$POSTPUBLISH_SCRIPT" "$TAG"
              else
                echo "Postpublish verification hook is missing or not executable: $POSTPUBLISH_SCRIPT" >&2
                exit 1
              fi
              printf '{"schema_version":1,"repo":"%s","tag":"%s","channel":"%s","release_issue":"%s","postpublish_run_id":"%s","release_assets":%s}\\n' "$GITHUB_REPOSITORY" "$TAG" "$CHANNEL" "$RELEASE_ISSUE" "$GITHUB_RUN_ID" "$asset_count" >"$ARTIFACT_DIR/postpublish-evidence.json"
          - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
            with:
              name: \${{ inputs.evidence_artifact_name }}-postpublish
              path: \${{ inputs.artifact_dir }}/postpublish-evidence.json
  `;
}

function releaseTrainIssueTemplate(): string {
  return dedent`
    name: Release Train
    about: Governed release train for an OMT-Global repository
    title: "Release: vX.Y.Z"
    labels:
      - release:train
      - review:release
    body:
      - type: input
        id: version
        attributes:
          label: Version
          placeholder: v1.2.3 or v1.2.3-rc.1
        validations:
          required: true
      - type: dropdown
        id: channel
        attributes:
          label: Channel
          options:
            - rc
            - beta
            - stable
            - maintenance
        validations:
          required: true
      - type: input
        id: release_branch
        attributes:
          label: Release branch
          placeholder: release/1.2
      - type: input
        id: target_sha
        attributes:
          label: Target SHA
          placeholder: Full commit SHA for the release candidate
      - type: textarea
        id: scope
        attributes:
          label: Scope
          description: User-facing changes, fixes, risks, exclusions.
        validations:
          required: true
      - type: textarea
        id: gates
        attributes:
          label: Gates
          value: |
            - [ ] Release branch created
            - [ ] Scope locked
            - [ ] Changelog/release notes prepared
            - [ ] Version surfaces updated
            - [ ] Preflight passed
            - [ ] preflight_run_id recorded:
            - [ ] Full validation passed
            - [ ] validation_run_id recorded:
            - [ ] Exact tag created
            - [ ] Publish approval granted
            - [ ] Artifacts published
            - [ ] GitHub Release created or updated
            - [ ] Release evidence uploaded
            - [ ] Postpublish verification passed
            - [ ] Floating tags/channels promoted if applicable
            - [ ] Release issue closed
  `;
}

function governedReleaseHookScripts(): RenderedFile[] {
  return [
    {
      path: "scripts/release/prep.sh",
      reason: "Governed release preparation hook",
      executable: true,
      contents: "#!/usr/bin/env bash\nset -euo pipefail\n\necho \"No repo-specific release prep step is configured.\"\n"
    },
    {
      path: "scripts/release/preflight.sh",
      reason: "Governed release preflight hook",
      executable: true,
      contents:
        "#!/usr/bin/env bash\nset -euo pipefail\n\nif [[ -x scripts/ci/run-fast-checks.sh ]]; then\n  bash scripts/ci/run-fast-checks.sh\nelse\n  echo \"No fast-check script found. Skipping release preflight checks.\"\nfi\n"
    },
    {
      path: "scripts/release/validate.sh",
      reason: "Governed full release validation hook",
      executable: true,
      contents:
        "#!/usr/bin/env bash\nset -euo pipefail\n\nif [[ -x scripts/ci/run-extended-validation.sh ]]; then\n  bash scripts/ci/run-extended-validation.sh\nelif [[ -x scripts/ci/run-fast-checks.sh ]]; then\n  bash scripts/ci/run-fast-checks.sh\nelse\n  echo \"No validation script found. Skipping release validation checks.\"\nfi\n"
    },
    {
      path: "scripts/release/build.sh",
      reason: "Governed release artifact build hook",
      executable: true,
      contents: dedent`
        #!/usr/bin/env bash
        set -euo pipefail

        artifact_dir="dist/release"
        mkdir -p "\${artifact_dir}"

        if [[ ! -f "\${artifact_dir}/artifact-manifest.json" ]]; then
          cat >"\${artifact_dir}/artifact-manifest.json" <<JSON
        {
          "schema_version": 1,
          "note": "Default bootstrap-generated release artifact manifest. Replace this with repo-specific build output when publishable assets exist."
        }
        JSON
        fi

        if [[ ! -f "\${artifact_dir}/RELEASE_NOTES.md" ]]; then
          {
            echo "# Release Notes"
            echo
            echo "Generated placeholder release notes. Replace during release prep."
          } >"\${artifact_dir}/RELEASE_NOTES.md"
        fi

        echo "Prepared release artifact directory \${artifact_dir}."
      `
    },
    {
      path: "scripts/release/publish.sh",
      reason: "Governed release publish hook",
      executable: true,
      contents:
        "#!/usr/bin/env bash\nset -euo pipefail\n\necho \"No external package publish step is configured.\"\necho \"The reusable publish workflow creates or updates the GitHub Release from the preflight artifact.\"\n"
    },
    {
      path: "scripts/release/postpublish.sh",
      reason: "Governed release postpublish verification hook",
      executable: true,
      contents: dedent`
        #!/usr/bin/env bash
        set -euo pipefail

        tag="\${1:-\${GITHUB_REF_NAME:-}}"
        if [[ -n "\${tag}" && -n "\${GITHUB_REPOSITORY:-}" && -n "\${GH_TOKEN:-}" ]]; then
          gh release view "\${tag}" --repo "\${GITHUB_REPOSITORY}" >/dev/null
          echo "GitHub Release \${tag} exists."
        else
          echo "No GitHub release lookup context available. Skipping postpublish remote check."
        fi
      `
    }
  ];
}

function releaseTrainDoc(): string {
  return dedent`
    # Governed Release Train

    This repository uses release maturity level \`governed\`.

    ## Manual Flow

    1. Open a release train issue with \`.github/ISSUE_TEMPLATE/release_train.yml\`.
    2. Create or update the \`release/{major}.{minor}\` release branch.
    3. Run \`Release Preflight\` with the candidate version, channel, target ref, and release issue.
    4. Copy the successful preflight run ID into the release issue.
    5. Run \`Full Release Validation\` against the same target ref.
    6. Copy the successful validation run ID into the release issue.
    7. Create the exact release tag only after validation evidence exists.
    8. Run \`Release Publish\` with the tag, preflight run ID, validation run ID, channel, and release issue.
    9. Run or review \`Release Postpublish\`, then close or supersede the release issue.

    Publish must consume the artifact bundle proven by preflight. If the preflight artifact cannot be downloaded or its recorded target SHA differs from the tag SHA, publish must fail instead of rebuilding.

    ## Customization

    Repo-specific behavior belongs in these hook scripts:

    - \`scripts/release/prep.sh\`
    - \`scripts/release/preflight.sh\`
    - \`scripts/release/validate.sh\`
    - \`scripts/release/build.sh\`
    - \`scripts/release/publish.sh\`
    - \`scripts/release/postpublish.sh\`

    The generated defaults do not require secrets and do not publish external packages.
  `;
}

function releaseTrainContractDoc(manifest: BootstrapManifest): string {
  return dedent`
    # Governed Release Train Contract

    Bootstrap supports four release maturity levels:

    | Level | Name | Behavior |
    | ---: | --- | --- |
    | 0 | \`none\` | No managed release files are generated. |
    | 1 | \`simple\` | Existing tag-triggered SemVer release workflow remains available. |
    | 2 | \`governed\` | Adds release preflight, full validation, publish orchestration, postpublish verification, and release evidence. |
    | 3 | \`regulated\` | Uses governed release flow plus stricter gates where supported, including signed tag verification when required. |

    Backwards compatibility is intentional: \`release.enabled: true\` without \`release.maturity\` is treated as \`simple\`, and \`release.enabled: false\` is treated as \`none\`.

    ## Configure

    \`\`\`yaml
    release:
      enabled: true
      maturity: governed
      reusableWorkflowRepo: ${manifest.release.reusableWorkflowRepo}
      reusableWorkflowRef: ${manifest.release.reusableWorkflowRef}
    \`\`\`

    Governed repos receive thin caller workflows for preflight, validation, publish, and postpublish verification. Package-specific behavior belongs in hook scripts under \`scripts/release/\`.

    ## Manual Release Flow

    1. Open a release train issue.
    2. Create or update the release branch.
    3. Run \`Release Preflight\` and record \`preflight_run_id\`.
    4. Run \`Full Release Validation\` and record \`validation_run_id\`.
    5. Create the exact tag after validation evidence exists.
    6. Run \`Release Publish\` with the tag, \`preflight_run_id\`, and \`validation_run_id\`.
    7. Verify postpublish evidence and close or supersede the release issue.

    Publish must consume the artifact bundle from the preflight run. If the preflight artifact cannot be downloaded, or if evidence does not match the tag SHA, publish fails rather than rebuilding.

    ## Secrets

    Generated hooks are safe no-ops by default. Production credentials belong in GitHub environments, secrets, packages, or OIDC configuration, not in manifests or generated scripts.
  `;
}

function releaseEvidenceSchemaDoc(): string {
  return dedent`
    # Release Evidence Schema

    Governed releases emit machine-readable evidence into \`dist/release/\`.

    Minimum release evidence:

    \`\`\`json
    {
      "schema_version": 1,
      "repo": "OMT-Global/example",
      "version": "v1.2.3",
      "channel": "stable",
      "target_ref": "release/1.2",
      "target_sha": "full_sha",
      "release_issue": "123",
      "preflight_run_id": "123456789",
      "validation_run_id": "123456790",
      "publish_run_id": "123456791",
      "artifacts": [{ "name": "example-v1.2.3.tar.gz", "sha256": "..." }],
      "checks": {
        "prep": "passed",
        "preflight": "passed",
        "build": "passed",
        "full_validation": "passed",
        "publish": "passed",
        "postpublish": "passed"
      }
    }
    \`\`\`

    Expected files:

    - \`dist/release/release-evidence.json\`
    - \`dist/release/postpublish-evidence.json\`
    - \`dist/release/SHA256SUMS\`
    - \`dist/release/RELEASE_NOTES.md\`

    Evidence links the release issue, target SHA, workflow run IDs, artifact checksums, release notes, and postpublish status so a release can be audited without relying on local operator state.
  `;
}

function prWorkflow(manifest: BootstrapManifest): string {
  const paths = workflowPaths(manifest);
  const shellRunner = formatRunsOn(resolveRunsOn(manifest.ci.runnerPolicy, manifest.project.visibility, ["shell"]));

  return dedent`
    name: PR Fast CI

    on:
      pull_request:
        types: [opened, edited, synchronize, reopened, ready_for_review]
      pull_request_review:
        types: [submitted, edited, dismissed]

    concurrency:
      group: pr-fast-\${{ github.event.pull_request.number || github.ref }}
      cancel-in-progress: true

    permissions:
      contents: read
      pull-requests: read

    env:
      NODE_VERSION: '${manifest.ci.nodeVersion}'
      PYTHON_VERSION: '${manifest.ci.pythonVersion}'

    defaults:
      run:
        shell: bash

    jobs:
      changes:
        name: Detect Relevant Changes
        runs-on: ${shellRunner}
        outputs:
          app: \${{ steps.filter.outputs.app }}
          ci: \${{ steps.filter.outputs.ci }}
        steps:
          - uses: dorny/paths-filter@7b450fff21473bca461d4b92ce414b9d0420d706 # v4
            id: filter
            with:
              filters: |
                app:
${yamlList(paths.app, 18)}
                ci:
${yamlList(paths.ci, 18)}

      fast-checks:
        name: Fast Checks
        runs-on: ${shellRunner}
        timeout-minutes: 15
        needs: changes
        if: >-
          github.event.pull_request.draft == false &&
          (needs.changes.outputs.app == 'true' || needs.changes.outputs.ci == 'true')
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ github.event.pull_request.head.sha }}
${indentBlock(setupSteps(manifest), 10)}
          - name: Run fast checks
            run: bash scripts/ci/run-fast-checks.sh

      validate-pr-description:
        name: Validate PR Description
        runs-on: ${shellRunner}
        timeout-minutes: 5
        if: github.event.pull_request.draft == false
        env:
          PR_BODY: \${{ github.event.pull_request.body }}
        steps:
          - name: Require generated PR template content
            run: |
              failed=0

              require_line() {
                local line="$1"
                if ! grep -Fqx "$line" <<<"$PR_BODY"; then
                  echo "Missing required PR section: $line"
                  failed=1
                fi
              }

              require_line "## Summary"
              require_line "## Governing Issue"
              require_line "## Validation"
              require_line "## Bootstrap Governance"
              require_line "## Merge Automation"
              require_line "## Notes"

              if grep -Eiq 'Closes #$|#<issue-number>|what changed|why it changed|notable tradeoffs|migration or rollout notes|follow-up work if any' <<<"$PR_BODY"; then
                echo "PR body still contains template placeholder text."
                failed=1
              fi

              if ! grep -Eiq '(^|[[:space:]-])(((close[sd]?|fix(e[sd])?|resolve[sd]?|refs?|part[[:space:]]+of)[[:space:]]+)?(#|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#|https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/)[0-9]+|no issue is linked|no linked issue|without a linked issue|no governing issue)' <<<"$PR_BODY"; then
                echo "PR body must close/link an issue or explicitly explain why no issue is linked."
                failed=1
              fi

              if ! grep -Eiq '(^|[[:space:]-])(\\[[xX]\\]|not run|not applicable|n/a)' <<<"$PR_BODY"; then
                echo "PR body must include validation evidence, a checked validation item, or a reason validation was not run."
                failed=1
              fi

              auto_merge_evidence="$(grep -Eiv '^[[:space:]]*-[[:space:]]+\\[[[:space:]]\\][[:space:]]' <<<"$PR_BODY" || true)"
              if ! grep -Eiq 'auto-merge (is )?(enabled|armed)|enabled auto-merge|gh pr merge --auto|auto_merge|auto merge enabled|auto-merge (is )?(unavailable|unsafe|not available|not safe)|plan-limit|fallback merge-readiness' <<<"$auto_merge_evidence"; then
                echo "PR body must state that the PR author enabled auto-merge, or explain why auto-merge is unavailable/unsafe."
                failed=1
              fi

              exit "$failed"

      validate-secrets:
        name: Validate Secrets
        runs-on: ${shellRunner}
        timeout-minutes: 10
        if: github.event.pull_request.draft == false
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ github.event.pull_request.head.sha }}
          - name: Scan repository for secret patterns
            run: bash scripts/check-detect-secrets.sh --all-files

      validate-pr-governance:
        name: Validate PR Governance
        runs-on: ${shellRunner}
        timeout-minutes: 5
        if: github.event.pull_request.draft == false
        env:
          PR_TITLE: \${{ github.event.pull_request.title }}
          PR_BODY: \${{ github.event.pull_request.body }}
          PR_AUTHOR: \${{ github.event.pull_request.user.login }}
          PR_CREATED_AT: \${{ github.event.pull_request.created_at }}
          PR_GOVERNANCE_ENFORCE_AFTER: '${manifest.ci.prGovernance?.enforceAfter ?? ""}'
          PR_FILES_URL: \${{ github.event.pull_request.url }}/files
          PR_COMMITS_URL: \${{ github.event.pull_request.commits_url }}
          PR_REVIEWS_URL: \${{ github.event.pull_request.url }}/reviews
          GITHUB_TOKEN: \${{ github.token }}
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ github.event.pull_request.head.sha }}
          - name: Validate title, DCO, size, ADR, and reviewer evidence
            run: bash scripts/ci/check-pr-governance.sh

      validate-action-pins:
        name: Validate Action Pins
        runs-on: ${shellRunner}
        timeout-minutes: 5
        if: github.event.pull_request.draft == false
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            with:
              ref: \${{ github.event.pull_request.head.sha }}
          - name: Require immutable third-party action pins
            run: bash scripts/ci/check-action-pins.sh

      ci-gate:
        name: ${primaryRequiredStatusCheck(manifest)}
        runs-on: ${shellRunner}
        if: always()
        needs:
          - changes
          - fast-checks
          - validate-pr-description
          - validate-secrets
          - validate-pr-governance
          - validate-action-pins
        steps:
          - name: Check required PR jobs
            env:
              RESULTS: >-
                changes=\${{ needs.changes.result }}
                fast-checks=\${{ needs.fast-checks.result }}
                validate-pr-description=\${{ needs.validate-pr-description.result }}
                validate-secrets=\${{ needs.validate-secrets.result }}
                validate-pr-governance=\${{ needs.validate-pr-governance.result }}
                validate-action-pins=\${{ needs.validate-action-pins.result }}
            run: |
              failed=0
              for entry in $RESULTS; do
                job="\${entry%%=*}"
                status="\${entry##*=}"
                if [[ "$status" == "success" || "$status" == "skipped" ]]; then
                  echo "OK   $job => $status"
                else
                  echo "FAIL $job => $status"
                  failed=1
                fi
              done
              exit "$failed"
  `;
}

function issueHygieneWorkflow(manifest: BootstrapManifest): string {
  const shellRunner = formatRunsOn(resolveRunsOn(manifest.ci.runnerPolicy, manifest.project.visibility, ["shell"]));

  return dedent`
    name: Issue Hygiene Report

    on:
      schedule:
        - cron: '17 9 * * 1'
      workflow_dispatch:

    permissions:
      contents: read
      issues: read

    jobs:
      report:
        name: Report Aging Issues
        runs-on: ${shellRunner}
        timeout-minutes: 10
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
          - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
            with:
              node-version: '${manifest.ci.nodeVersion}'
          - name: Build deterministic issue hygiene report
            shell: bash
            env:
              GITHUB_TOKEN: \${{ github.token }}
            run: |
              node scripts/ci/report-issue-hygiene.mjs \\
                --repo "$GITHUB_REPOSITORY" \\
                --json-output issue-hygiene-report.json \\
                | tee "$RUNNER_TEMP/issue-hygiene-summary.md"
              cat "$RUNNER_TEMP/issue-hygiene-summary.md" >> "$GITHUB_STEP_SUMMARY"
          - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
            with:
              name: issue-hygiene-report
              path: issue-hygiene-report.json
              if-no-files-found: error
              retention-days: 30
  `;
}

function issueHygieneScript(): string {
  return readFileSync(new URL("../scripts/ci/report-issue-hygiene.mjs", import.meta.url), "utf8");
}

function extendedWorkflow(manifest: BootstrapManifest): string {
  const paths = workflowPaths(manifest);
  const shellRunner = formatRunsOn(resolveRunsOn(manifest.ci.runnerPolicy, manifest.project.visibility, ["shell"]));

  return dedent`
    name: Extended Validation

    on:
      push:
        branches: [${manifest.project.defaultBranch}]
      schedule:
        - cron: '${manifest.ci.nightlyCron}'
      workflow_dispatch:

    concurrency:
      group: extended-validation-\${{ github.ref }}
      cancel-in-progress: \${{ github.event_name != 'workflow_dispatch' }}

    permissions:
      contents: read

    env:
      NODE_VERSION: '${manifest.ci.nodeVersion}'
      PYTHON_VERSION: '${manifest.ci.pythonVersion}'

    defaults:
      run:
        shell: bash

    jobs:
      changes:
        name: Detect Extended Validation Scope
        runs-on: ${shellRunner}
        outputs:
          app: \${{ steps.preset.outputs.app || steps.filter.outputs.app || 'false' }}
          ci: \${{ steps.preset.outputs.ci || steps.filter.outputs.ci || 'false' }}
          extended: \${{ steps.preset.outputs.extended || steps.filter.outputs.extended || 'false' }}
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
            if: github.event_name == 'push'
            with:
              fetch-depth: 0

          - name: Run full suite for nightly or manual invocations
            id: preset
            if: github.event_name != 'push'
            run: |
              cat >>"$GITHUB_OUTPUT" <<'EOF'
              app=true
              ci=true
              extended=true
              EOF

          - uses: dorny/paths-filter@7b450fff21473bca461d4b92ce414b9d0420d706 # v4
            id: filter
            if: github.event_name == 'push'
            with:
              filters: |
                app:
${yamlList(paths.app, 18)}
                ci:
${yamlList(paths.ci, 18)}
                extended:
${yamlList(paths.extended, 18)}

      fast-checks:
        name: Fast Checks
        runs-on: ${shellRunner}
        timeout-minutes: 15
        needs: changes
        if: needs.changes.outputs.app == 'true' || needs.changes.outputs.ci == 'true'
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
${indentBlock(setupSteps(manifest), 10)}
          - name: Run fast checks
            run: bash scripts/ci/run-fast-checks.sh

      extended-checks:
        name: Extended Checks
        runs-on: ${shellRunner}
        timeout-minutes: 20
        needs: changes
        if: needs.changes.outputs.extended == 'true' || needs.changes.outputs.app == 'true'
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
${indentBlock(setupSteps(manifest), 10)}
          - name: Run extended validation
            run: bash scripts/ci/run-extended-validation.sh

      validate-secrets:
        name: Validate Secrets
        runs-on: ${shellRunner}
        timeout-minutes: 10
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
          - name: Scan repository for secret patterns
            run: bash scripts/check-detect-secrets.sh --all-files

      extended-validation-gate:
        name: Extended Validation Gate
        runs-on: ${shellRunner}
        if: always()
        needs:
          - changes
          - fast-checks
          - extended-checks
          - validate-secrets
        steps:
          - name: Check extended validation jobs
            env:
              RESULTS: >-
                changes=\${{ needs.changes.result }}
                fast-checks=\${{ needs.fast-checks.result }}
                extended-checks=\${{ needs.extended-checks.result }}
                validate-secrets=\${{ needs.validate-secrets.result }}
            run: |
              failed=0
              for entry in $RESULTS; do
                job="\${entry%%=*}"
                status="\${entry##*=}"
                if [[ "$status" == "success" || "$status" == "skipped" ]]; then
                  echo "OK   $job => $status"
                else
                  echo "FAIL $job => $status"
                  failed=1
                fi
              done
              exit "$failed"
  `;
}

function onboardingDoc(manifest: BootstrapManifest): string {
  const releaseTags = releaseTagExamples(manifest);

  return dedent`
    # Bootstrap Onboarding

    Use this checklist after the first bootstrap render or whenever \`project.bootstrap.yaml\` changes in a way that affects GitHub policy, environments, or home-profile sync.

    ## Project

${indentBlock(projectIdentityLines(manifest), 4)}

    ## Repo Governance

    - Confirm branch protection or rulesets on \`${manifest.project.defaultBranch}\` require one approval, code owner review, and approval from someone other than the most recent pusher.
    - ${requiredStatusCheckConfirmation(manifest)}
    - Confirm \`CONTRIBUTING.md\` and \`.github/PULL_REQUEST_TEMPLATE.md\` are present as the required contributor and PR guidance surfaces.
    - Confirm \`AGENTS.md\` requires the \`autoreview\` skill against the intended PR diff before an agent opens or updates a PR, and that the PR template records the final command and result.
    - Confirm the pull request template is present and PR Fast CI validates the required PR description sections before ${primaryRequiredStatusCheck(manifest)} can pass.
    ${manifest.github.repoFeatures.hasIssues ? "- Confirm `Issue Hygiene Report` runs weekly with read-only issue permission and retains its JSON evidence artifact." : ""}
    - ${autoMergeOnboardingConfirmation()}
    - Fallback merge readiness requires passing or intentionally skipped required checks, satisfied approvals, resolved conversations, no blocking review state, and a manual maintainer merge.

${indentBlock(organizationGovernanceSection(manifest), 4)}
${indentBlock(additionalWorkflowSection(manifest), 4)}
${manifest.project.visibility === "public"
  ? indentBlock(
      dedent`
        ## Public Security Baseline

        - Review \`docs/bootstrap/security.md\` before changing security workflow events, permissions, or runner labels.
        - Confirm dependency review is the only security job reachable from fork pull requests and runs on GitHub-hosted isolation; CodeQL and SBOM jobs must remain trusted-event only and GitHub-hosted.
        - Capture the seven required GitHub capability observations before treating remote security controls as verified.
        - Confirm \`SECURITY.md\` private reporting and response targets match the maintained operational policy.
      `,
      4
    )
  : ""}

    ## Environments

    - \`dev\`: open by default for rapid iteration.
    - \`stage\`: one reviewer required and self-review blocked.
    - \`prod\`: one reviewer required, self-review blocked, deployments limited to \`${manifest.project.defaultBranch}\`.

    ## Runner Policy

    - Private-repository trusted shell-safe jobs use \`[self-hosted, linux, shell-only, private]\`.
    - Public repository security workflows use GitHub-hosted isolation. Fork pull-request jobs always remain read-only and GitHub-hosted.
    - Native repos must use self-hosted runners for trusted required automation; Docker, service-container, browser, and \`container:\` workloads require a dedicated self-hosted runner pool with matching capability labels.
    - Keep PR checks cheap. Add heavy validation to \`scripts/ci/run-extended-validation.sh\` instead of the PR lane.
    ${manifest.ci.additionalWorkflows.length > 0
      ? `- Keep repo-specific workflow lanes (${manifest.ci.additionalWorkflows
          .map((workflow) => `\`${workflow.path}\``)
          .join(", ")}) as adjuncts to the standard CI frame. Do not repurpose them as the required PR gate unless the manifest's required status checks change deliberately.`
      : ""}
    - Consume shared security, release, and AI attestation workflows from the control-plane repo once those contracts are pinned for production use.

    ## Contributor And PR Guidance

    - \`CONTRIBUTING.md\` defines the contributor workflow, branch expectations, validation expectations, and secret-handling baseline.
    - \`.github/PULL_REQUEST_TEMPLATE.md\` defines the standard PR shape: summary, governing issue link, validation notes, and bootstrap governance checklist.
    - To retrofit an existing bootstrapped repo, add \`CONTRIBUTING.md\` and \`.github/PULL_REQUEST_TEMPLATE.md\` to \`repo.managedPaths\` when that repo restricts managed paths, then run \`bootstrap apply repo --manifest ./project.bootstrap.yaml\`.
    - Keep these files repo-generic unless project metadata or the manifest requires a stricter local rule.

${manifest.github.repoFeatures.hasIssues
  ? indentBlock(
      dedent`
        ## Issue Hygiene

        - Review \`docs/bootstrap/issue-hygiene.md\` before acting on a 30-day review or 90-day close-or-rescope proposal.
        - The scheduled workflow is report-only: it never comments, labels, closes, or reschedules issues.
        - A 90-day proposal always requires a maintainer decision. Record a structured, evidenced future action when the issue should remain open.
      `,
      4
    )
  : ""}

    ## Licensing

    - Repository visibility never selects or grants a license. Declare \`license.mode\` explicitly before Bootstrap manages \`LICENSE\`.
    - Current manifest mode: ${manifest.license ? `\`${manifest.license.mode === "spdx" ? `spdx:${manifest.license.identifier}` : "proprietary"}\` using approval \`${manifest.license.template.approval}\`` : "not declared; Bootstrap will not create, replace, or remove a license"}.
    - Keep \`THIRD_PARTY_NOTICES.md\` separate from the first-party notice and inventory dependencies, assets, fonts, media, and incorporated source.
    - Any existing-license replacement requires legal ownership, contributor, distribution-history, issue, and approver evidence in the manifest. Previously granted rights are not revoked.
    - Verify GitHub license detection after publishing an SPDX license. Never describe a proprietary notice as SPDX, OSI approved, or GitHub-recognized.

    ## Fleet Reconciliation

    - Run \`bootstrap reconcile --workspace-root ~/src --report bootstrap-reconcile.json\` first; this is plan-only and does not write files.
    - Add \`--org ${manifest.project.owner}\` when OpenClaw should enumerate GitHub repos first; missing local checkouts or repos without \`project.bootstrap.yaml\` are skipped and reported.
    - Use \`--repo <name...>\` as the initial allowlist when onboarding daily OpenClaw reconciliation.
    - Use \`--apply-repo --create-pr\` for unattended repo drift so generated changes go through draft PRs instead of default-branch pushes.
    - Use \`--apply-github\` only after the report shape is trusted because it mutates repository settings, environments, branch protection, and labels directly through the GitHub API.
    - Dirty target worktrees are blocked and reported instead of being overwritten.

${manifest.release.enabled
  ? indentBlock(
      dedent`
        ## Release Standard

        - Use immutable exact SemVer tags such as \`${releaseTags.exact}\` as the source of truth.
        - Automatically advance \`${releaseTags.minor}\` and \`${releaseTags.major}\` to the newest compatible exact tag; never retag an exact release.
        - Cut patch releases from \`release/X.Y\` when you maintain older minors; cut new minors and majors from \`${manifest.project.defaultBranch}\`.
      `,
      4
    )
  : ""}

${manifest.ci.aiAttestation.enabled
  ? indentBlock(
      dedent`
        ## AI Attestation

        - \`.github/workflows/ai-attestation.yml\` calls \`${manifest.ci.aiAttestation.reusableWorkflowRepo}/.github/workflows/ai-attestation-reusable.yml@${manifest.ci.aiAttestation.reusableWorkflowRef}\`.
        - Override default metadata with repo variables (\`AI_ATTESTATION_PROVIDER\`, \`AI_ATTESTATION_MODEL\`, \`AI_ATTESTATION_PROMPT_HASH\`) before treating the artifact metadata as authoritative.
        - Pin the reusable workflow to a tag or SHA once the control-plane contract is stable.
      `,
      4
    )
  : ""}

    ## Home Profiles

    - Run \`bootstrap apply home --manifest ./project.bootstrap.yaml\` after reviewing the bundled profile content.
    - The bootstrap manages portable Codex assets only. Auth, sessions, caches, and machine-local state stay unmanaged.
  `;
}

function issueHygieneDoc(): string {
  return dedent`
    # Report-First Issue Hygiene

    \`.github/workflows/issue-hygiene.yml\` inventories open issues every Monday and on manual dispatch. It uses only \`contents: read\` and \`issues: read\`, writes a complete versioned JSON artifact, and appends a Markdown report capped at 900 KiB to the workflow summary.

    ## Aging Rules

    - Fewer than 30 inactive days: current; no report entry.
    - At least 30 inactive days: review proposal.
    - At least 90 inactive days without a credible next action: close-or-rescope proposal that requires a maintainer decision.
    - Automation never comments, labels, closes, reschedules, or otherwise mutates an issue.

    GitHub's \`updated_at\` timestamp is the inactivity source. Pull requests returned by the issues API are excluded.

    ## Preserve A Stale Issue

    Add one structured marker to the issue body. \`outcome\` or an evidence-shaped \`dependency\` is required, \`checkpoint\` must be a future ISO date, and \`evidence\` must be a canonical public GitHub issue, pull-request, or Actions-run URL without query or fragment data, or a positive numeric \`issue:\`, \`pr:\`, or \`run:\` reference.

    \`\`\`html
    <!-- prs-next-action {"outcome":"Ship resolver","dependency":"issue:54","checkpoint":"2026-08-01","evidence":"issue:10"} -->
    \`\`\`

    The report publishes only the issue number, single-line title, URL, timestamps, checkpoint, and evidence reference. It never emits the issue body or the next-action outcome.

    ## Local Fixture

    \`\`\`sh
    node scripts/ci/report-issue-hygiene.mjs \\
      --fixture /path/to/issues.json \\
      --as-of 2026-07-18T12:00:00Z \\
      --json-output issue-hygiene-report.json
    \`\`\`
  `;
}

function releaseVersioningDoc(manifest: BootstrapManifest): string {
  const releaseTags = releaseTagExamples(manifest);

  return dedent`
    # Release Versioning

    This bootstrap standardizes on Semantic Versioning with immutable exact tags and automatically promoted compatibility aliases.

    ## Tag Rules

    - Exact release tags are immutable: \`${releaseTags.exact}\`
    - Minor compatibility tags move forward automatically: \`${releaseTags.minor}\`
    - Major compatibility tags move forward automatically: \`${releaseTags.major}\`

    Consumers should prefer \`${releaseTags.major}\` for the default compatibility channel, \`${releaseTags.minor}\` when they need to stay on one minor line, and an exact tag or SHA when they need full reproducibility.

    ## Branch Rules

    - \`${manifest.project.defaultBranch}\` is the next minor or major release train.
    - \`release/X.Y\` branches are maintenance lines for patch releases on older minors.
    - Promote fixes forward: oldest supported \`release/X.Y\` first, then newer maintenance branches, then \`${manifest.project.defaultBranch}\`.

    ## Automation

    - \`.github/workflows/release-tag.yml\` runs when an exact SemVer tag matching \`${manifest.release.tagPrefix}*.*.*\` is pushed.
    - \`scripts/ci/run-release-verification.sh\` runs the repo release gate before publication.
    - \`scripts/ci/run-release-version.sh\` validates that the repo version surfaces match the pushed tag before build and publish.
    - \`scripts/ci/run-release-build.sh\` populates the release artifact directory and writes SHA256 checksums when enabled.
    - \`scripts/ci/run-release-publish.sh\` is the repo hook for artifact publication; the generated default is a no-op until the repo needs more than GitHub releases.
    - The shared reusable release workflow creates or updates the GitHub release and then advances the floating compatibility tags when enabled in \`project.bootstrap.yaml\`.

    ## Version Validation

    - Version bumps land in a normal pull request before the release tag is pushed; the workflow never creates post-tag commits.
    - Configure version surfaces under \`release.versions\` in \`project.bootstrap.yaml\` with a \`type\` of \`npm\`, \`python\`, or \`container\` and the file \`path\`.
    - \`scripts/ci/run-release-version.sh\` fails the release when a configured \`package.json\` or \`pyproject.toml\` version does not equal the tag (with the \`${manifest.release.tagPrefix}\` prefix stripped). Container surfaces are derived from the tag at publish time.
    - With no configured surfaces the hook prints an explicit no-op rather than silently passing.

    ## Release Artifacts

    - The default release artifact directory is \`${manifest.release.artifacts.directory}/\`.
    - \`scripts/ci/run-release-build.sh\` is where repo-specific build steps populate that directory; with no artifacts it prints an explicit no-op message instead of failing silently.
    - Checksum generation is \`${manifest.release.artifacts.checksum}\`; when set to \`sha256\` a \`SHA256SUMS\` file is written alongside the artifacts.
    - The reusable workflow uploads every file in the artifact directory to the GitHub Release.
    - SBOM/provenance is \`${manifest.release.artifacts.sbom}\` and is designed into the manifest for repos that opt in.

    ## Release Notes

    - Release notes are generated automatically for every exact tag from changes since the previous exact SemVer tag.
    - The default implementation uses GitHub generated notes; \`.github/release.yml\` maps bootstrap labels to categories.
    - Override categories under \`release.changelog.categories\` in \`project.bootstrap.yaml\`. The default categories are Features, Fixes, Operations, and Documentation, with everything else under Other Changes.
    - The reusable workflow writes the notes to \`${manifest.release.artifacts.directory}/RELEASE_NOTES.md\` before creating the GitHub Release.
  `;
}


function repoDocEnabled(
  manifest: BootstrapManifest,
  key: "readme" | "contributing" | "security",
  fallback: boolean
): boolean {
  if (manifest.repo.docs?.[key] !== undefined) {
    return manifest.repo.docs[key];
  }

  // Public repositories need a discoverable vulnerability-reporting route even
  // when the manifest predates the v2 docs block. The generated policy uses
  // GitHub's private advisory flow and does not add a contact address. An
  // explicit `repo.docs.security: false` remains the migration opt-out.
  if (key === "security") {
    return manifest.project.visibility === "public";
  }

  return fallback;
}

function envExampleEnabled(manifest: BootstrapManifest): boolean {
  return manifest.repo.env?.exampleFile ?? true;
}

function pullRequestTemplateEnabled(manifest: BootstrapManifest): boolean {
  return manifest.repo.templates?.pullRequest !== "none";
}

function issueTemplateEnabled(manifest: BootstrapManifest, template: "bug" | "feature"): boolean {
  return manifest.repo.templates?.issueTemplates.includes(template) ?? false;
}

function preCommitHookEnabled(manifest: BootstrapManifest): boolean {
  return manifest.repo.hooks?.preCommit !== "none";
}

function prePushHookEnabled(manifest: BootstrapManifest): boolean {
  return manifest.repo.hooks?.prePush === "standard";
}

function workflowEnabled(
  manifest: BootstrapManifest,
  workflow: "prFastCi" | "extendedValidation" | "claude" | "pagesDeploy" | "ci",
  fallback: boolean
): boolean {
  return manifest.ci.workflows?.[workflow] ?? fallback;
}

function claudeEnabled(manifest: BootstrapManifest): boolean {
  return Boolean(
    manifest.agents.manageClaudeHome ||
      manifest.agents.enableClaudeWebEnvironment ||
      manifest.agents.enableClaudeDevcontainer ||
      manifest.agents.enableClaudeGitHubAction ||
      workflowEnabled(manifest, "claude", false)
  );
}

function securityDoc(manifest: BootstrapManifest): string {
  const dependabot = manifest.github.security?.dependabot ?? manifest.ci.dependabot.enabled;
  const secretHints = manifest.github.security?.secretScanningHints ?? true;

  return dedent`
    # Security Policy

    ## Supported Surface

    This repository follows the bootstrap-managed security baseline for ${manifest.project.owner}/${manifest.project.name}.

    ## Reporting

    Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/${manifest.project.owner}/${manifest.project.name}/security/advisories/new). If that form is unavailable, open a public issue titled \`Private security contact requested\` without vulnerability details; maintainers will establish a confidential channel before accepting the report. Never include exploit details in public issues or discussions.

    ## Response Targets

    - Acknowledge a complete report within 3 business days.
    - Provide a status update within 10 business days, even when investigation is ongoing.
    - Target remediation within 7 days for critical findings, 30 days for high findings, and 90 days for moderate findings. Low-severity findings are scheduled by maintainers.
    - Coordinate disclosure timing with the reporter after a fix or documented mitigation is available.

    ## Baseline

    - Dependabot policy: ${dependabot ? "enabled" : "disabled by manifest"}
    - Secret scanning hints: ${secretHints ? "enabled" : "disabled by manifest"}
    - Generated hooks and CI helpers must not require committed secrets or machine-local environment files.
  `;
}

function securityModelDoc(manifest: BootstrapManifest): string {
  return dedent`
    # Public Repository Security Model

    ## Trust Boundaries

    - Pull requests, including forks, are untrusted input. The pull-request lane runs on GitHub-hosted isolation with read-only repository permissions, does not read GitHub Actions secrets, and runs only dependency review after GitHub provisioning enables the dependency graph and sets \`DEPENDENCY_REVIEW_ENABLED=true\`.
    - Code scanning and SBOM generation run only for trusted default-branch pushes and schedules on GitHub-hosted isolation.
    - GitHub-hosted security capabilities are evaluated from a versioned capability snapshot so unsupported plan features remain distinct from repository misconfiguration.

    ## Required Controls

    - Dependency graph, Dependabot alerts and security updates, secret scanning, push protection, code scanning, and private vulnerability reporting are required capability observations for public repositories. The dependency-graph observation must also record \`dependencyReviewEnabled: true\` after provisioning verifies \`DEPENDENCY_REVIEW_ENABLED=true\`.
    - \`.github/dependabot.yml\` keeps both dependency and GitHub Actions pins updateable.
    - \`.github/workflows/security.yml\` performs dependency review, CodeQL analysis for \`${codeQlLanguages(manifest)}\`, and SPDX JSON SBOM generation using immutable action SHAs.
    - \`SECURITY.md\` directs reporters to a private advisory and defines acknowledgement, update, remediation, and coordinated-disclosure targets.

    ## Fork Safety

    The security workflow uses \`pull_request\`, never \`pull_request_target\`. Its top-level permission is \`contents: read\`; the only job reachable from a pull request uses a GitHub-hosted runner, has read-only permissions, and has no secret references. Jobs needing \`security-events: write\` are explicitly excluded from pull-request events.

    ## Capability Evidence

    Capture authorized observations for these controls and pass them to \`bootstrap conform --github-capabilities <path>\`: \`dependency-graph\`, \`dependabot-alerts\`, \`dependabot-security-updates\`, \`secret-scanning\`, \`push-protection\`, \`code-scanning\`, and \`private-vulnerability-reporting\`. Record \`dependencyReviewEnabled: true\` only after verifying the repository activation variable. Unsupported controls remain warnings with remediation; available but disabled controls are blocking misconfigurations. Current typed exceptions may waive only their matching \`github.<control>\` scope.
  `;
}

function bugIssueTemplate(): string {
  return dedent`
    name: Bug Report
    description: Report a reproducible defect.
    title: "[Bug]: "
    labels: ["type:bug", "status:needs-spec"]
    body:
      - type: textarea
        id: summary
        attributes:
          label: Summary
        validations:
          required: true
      - type: textarea
        id: reproduction
        attributes:
          label: Reproduction
        validations:
          required: true
      - type: textarea
        id: validation
        attributes:
          label: Expected Validation
        validations:
          required: true
  `;
}

function featureIssueTemplate(): string {
  return dedent`
    name: Feature Request
    description: Propose a scoped feature or improvement.
    title: "[Feature]: "
    labels: ["type:feature", "status:needs-spec"]
    body:
      - type: textarea
        id: outcome
        attributes:
          label: Desired Outcome
        validations:
          required: true
      - type: textarea
        id: scope
        attributes:
          label: Scope
        validations:
          required: true
      - type: textarea
        id: validation
        attributes:
          label: Validation
        validations:
          required: true
  `;
}

function prePushHook(): string {
  return dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ -x scripts/ci/run-fast-checks.sh ]]; then
      bash scripts/ci/run-fast-checks.sh
    fi
  `;
}

function repoClaude(manifest: BootstrapManifest): string {
  return dedent`
    # CLAUDE.md

    ## Project Context

    - Repository: ${manifest.project.owner}/${manifest.project.name}
    - Default branch: ${manifest.project.defaultBranch}
    - Required PR checks: ${requiredStatusChecksPlain(manifest)}

    ## Guardrails

    - Use AGENTS.md and docs/bootstrap/onboarding.md as the governing repo policy.
    - Keep Claude automation separate from required PR status checks unless the manifest explicitly changes that contract.
    - Do not commit secrets or machine-local environment files.
  `;
}

function claudeCloudSetupScript(manifest: BootstrapManifest): string {
  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    bash scripts/codex-cloud/setup.sh
    echo "Claude cloud setup complete for ${manifest.project.owner}/${manifest.project.name}."
  `}\n`;
}

function claudeDevcontainer(manifest: BootstrapManifest): string {
  return `${JSON.stringify(
    {
      name: `${manifest.project.name} Claude Code`,
      image: "mcr.microsoft.com/devcontainers/base:ubuntu-24.04",
      remoteUser: "vscode",
      updateRemoteUserUID: true,
      features: {
        "ghcr.io/anthropics/devcontainer-features/claude-code:1": {},
        "ghcr.io/devcontainers/features/github-cli:1": {},
        "ghcr.io/devcontainers/features/node:1": { version: manifest.ci.nodeVersion },
        "ghcr.io/devcontainers/features/python:1": { version: manifest.ci.pythonVersion }
      },
      mounts: ["source=${localEnv:HOME}/.claude,target=/home/vscode/.claude,type=bind"],
      postCreateCommand: "bash scripts/claude/setup-devcontainer.sh"
    },
    null,
    2
  )}\n`;
}

function claudeDevcontainerSetupScript(): string {
  return `${dedent`
    #!/usr/bin/env bash
    set -euo pipefail

    bash scripts/codex-cloud/setup.sh
  `}\n`;
}

function claudeWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Claude Code

    on:
      workflow_dispatch:
        inputs:
          prompt:
            description: Optional manual task prompt
            required: false
            type: string
      issue_comment:
        types: [created]
      pull_request_review_comment:
        types: [created]
      pull_request_review:
        types: [submitted]

    concurrency:
      group: claude-\${{ github.event.pull_request.number || github.event.issue.number || github.run_id }}
      cancel-in-progress: false

    permissions:
      contents: read
      pull-requests: write
      issues: write

    jobs:
      claude:
        if: |
          github.event_name == 'workflow_dispatch' ||
          (github.event_name == 'issue_comment' && contains(github.event.comment.body, '@claude')) ||
          (github.event_name == 'pull_request_review_comment' && contains(github.event.comment.body, '@claude')) ||
          (github.event_name == 'pull_request_review' && contains(github.event.review.body, '@claude'))
        runs-on: ubuntu-latest
        timeout-minutes: 30
        steps:
          - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
          - name: Run Claude Code
            uses: anthropics/claude-code-action@e90deca47693f9457b72f2b53c17d7c445a87342 # v1
            with:
              anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
              prompt: |
                REPO: \${{ github.repository }}
                DEFAULT BRANCH: ${manifest.project.defaultBranch}
                REQUIRED CHECKS: ${requiredStatusChecksPlain(manifest)}
                Use CLAUDE.md, AGENTS.md, and docs/bootstrap/onboarding.md as policy context.
                MANUAL TASK: \${{ github.event.inputs.prompt }}
  `;
}

function claudeEnvironmentDoc(manifest: BootstrapManifest): string {
  return dedent`
    # Claude Environment

    ## Project

${indentBlock(projectIdentityLines(manifest), 4)}

    ## Enabled Surfaces

    ${manifest.agents.enableClaudeWebEnvironment ? "- Claude Code on the web with `bash scripts/claude-cloud/setup.sh`" : "- Claude Code on the web is not enabled by this manifest."}
    ${manifest.agents.enableClaudeDevcontainer ? "- Interactive devcontainer through `.devcontainer/devcontainer.json`" : "- Claude devcontainer is not enabled by this manifest."}
    ${manifest.agents.enableClaudeGitHubAction || workflowEnabled(manifest, "claude", false) ? "- GitHub-hosted Claude workflow at `.github/workflows/claude.yml`" : "- Claude GitHub Action is not enabled by this manifest."}

    ## Guardrails

    - Keep Claude automation out of the required PR check set unless the manifest explicitly changes branch protection.
    - Prefer repo-scoped secrets and avoid mounting additional host credentials into the devcontainer.
  `;
}


function filterRenderedFiles(manifest: BootstrapManifest, files: RenderedFile[]): RenderedFile[] {
  return files.filter((file) => {
    if (file.path === "README.md") return repoDocEnabled(manifest, "readme", true);
    if (file.path === "CONTRIBUTING.md") return repoDocEnabled(manifest, "contributing", true);
    if (file.path === ".env.example") return envExampleEnabled(manifest);
    if (file.path === ".githooks/pre-commit") return preCommitHookEnabled(manifest);
    if (file.path === ".github/PULL_REQUEST_TEMPLATE.md") return pullRequestTemplateEnabled(manifest);
    if (file.path === ".github/workflows/pr-fast-ci.yml") return workflowEnabled(manifest, "prFastCi", true);
    if (file.path === ".github/workflows/extended-validation.yml") {
      return workflowEnabled(manifest, "extendedValidation", true);
    }
    return true;
  });
}

export function renderManagedFiles(manifest: BootstrapManifest): RenderedFile[] {
  const releaseIsGoverned = manifest.release.maturity === "governed" || manifest.release.maturity === "regulated";
  const files: RenderedFile[] = [
    {
      path: "project.bootstrap.yaml",
      reason: "Bootstrap manifest source of truth",
      contents: stringifyManifest(manifest)
    },
    {
      path: "README.md",
      reason: "Repository overview",
      contents: `${repoReadme(manifest)}\n`
    },
    {
      path: "AGENTS.md",
      reason: "Repo-local Codex instructions",
      contents: `${repoAgents(manifest)}\n`
    },
    {
      path: "CONTRIBUTING.md",
      reason: "Contributor workflow guidance",
      contents: `${contributingDoc(manifest)}\n`
    },
    ...(repoDocEnabled(manifest, "security", false)
      ? [
          {
            path: "SECURITY.md",
            reason: "Security reporting policy",
            contents: `${securityDoc(manifest)}\n`
          }
        ]
      : []),
    ...(manifest.project.visibility === "public"
      ? [
          {
            path: "docs/bootstrap/security.md",
            reason: "Public repository security model and response targets",
            contents: `${securityModelDoc(manifest)}\n`
          }
        ]
      : []),
    ...(claudeEnabled(manifest)
      ? [
          {
            path: "CLAUDE.md",
            reason: "Repo-local Claude instructions",
            contents: `${repoClaude(manifest)}\n`
          }
        ]
      : []),
    {
      path: ".env.example",
      reason: "Safe environment template",
      contents: `${envExample()}\n`
    },
    {
      path: ".gitignore",
      reason: "Project baseline ignores",
      contents: baseGitignore(manifest)
    },
    {
      path: ".githooks/pre-commit",
      reason: "Commit guardrail hook",
      contents: `${preCommitHook()}\n`,
      executable: true
    },
    ...(prePushHookEnabled(manifest)
      ? [
          {
            path: ".githooks/pre-push",
            reason: "Push validation hook",
            contents: `${prePushHook()}\n`,
            executable: true
          }
        ]
      : []),
    {
      path: "CODEOWNERS",
      reason: "Code owner mapping",
      contents: codeowners(manifest)
    },
    {
      path: ".github/PULL_REQUEST_TEMPLATE.md",
      reason: "Pull request guidance template",
      contents: `${pullRequestTemplate(manifest)}\n`
    },
    ...(issueTemplateEnabled(manifest, "bug")
      ? [
          {
            path: ".github/ISSUE_TEMPLATE/bug.yml",
            reason: "Bug issue template",
            contents: `${bugIssueTemplate()}\n`
          }
        ]
      : []),
    ...(issueTemplateEnabled(manifest, "feature")
      ? [
          {
            path: ".github/ISSUE_TEMPLATE/feature.yml",
            reason: "Feature issue template",
            contents: `${featureIssueTemplate()}\n`
          }
        ]
      : []),
    ...(manifest.github.flowGovernance
      ? [
          {
            path: ".github/ISSUE_TEMPLATE/implementation.yml",
            reason: "Flow implementation issue template",
            contents: `${implementationIssueTemplate()}\n`
          },
          {
            path: ".github/ISSUE_TEMPLATE/flow_blocker.yml",
            reason: "Flow blocker issue template",
            contents: `${flowBlockerIssueTemplate()}\n`
          }
        ]
      : []),
    ...(releaseIsGoverned
      ? [
          {
            path: ".github/ISSUE_TEMPLATE/release_train.yml",
            reason: "Governed release train issue template",
            contents: `${releaseTrainIssueTemplate()}\n`
          }
        ]
      : []),
    {
      path: ".github/workflows/pr-fast-ci.yml",
      reason: "Fast pull request workflow",
      contents: `${prWorkflow(manifest)}\n`
    },
    {
      path: ".github/workflows/extended-validation.yml",
      reason: "Extended validation workflow",
      contents: `${extendedWorkflow(manifest)}\n`
    },
    ...(manifest.project.visibility === "public"
      ? [
          {
            path: ".github/workflows/security.yml",
            reason: "Fork-safe public repository security baseline",
            contents: `${publicSecurityWorkflow(manifest)}\n`
          }
        ]
      : []),
    ...(manifest.github.repoFeatures.hasIssues
      ? [
          {
            path: ".github/workflows/issue-hygiene.yml",
            reason: "Read-only scheduled issue aging report",
            contents: `${issueHygieneWorkflow(manifest)}\n`
          }
        ]
      : []),
    ...(manifest.ci.dependabot.enabled && manifest.ci.dependabot.versionUpdates
      ? [
          {
            path: ".github/dependabot.yml",
            reason: "Dependabot scheduled version update policy",
            contents: `${dependabotConfig(manifest)}\n`
          }
        ]
      : []),
    ...(manifest.release.enabled && !releaseIsGoverned
      ? [
          {
            path: ".github/workflows/release-tag.yml",
            reason: "Shared release workflow caller",
            contents: `${releaseCallerWorkflow(manifest)}\n`
          }
        ]
      : []),
    ...(releaseIsGoverned
      ? [
          {
            path: ".github/workflows/release-preflight.yml",
            reason: "Governed release preflight caller",
            contents: `${releasePreflightCallerWorkflow(manifest)}\n`
          },
          {
            path: ".github/workflows/full-release-validation.yml",
            reason: "Governed full release validation caller",
            contents: `${fullReleaseValidationCallerWorkflow(manifest)}\n`
          },
          {
            path: ".github/workflows/release-publish.yml",
            reason: "Governed release publish caller",
            contents: `${releasePublishCallerWorkflow(manifest)}\n`
          },
          {
            path: ".github/workflows/release-postpublish.yml",
            reason: "Governed release postpublish caller",
            contents: `${releasePostpublishCallerWorkflow(manifest)}\n`
          },
          {
            path: ".github/workflows/release-preflight-reusable.yml",
            reason: "Reusable governed release preflight workflow",
            contents: `${releasePreflightReusableWorkflow()}\n`
          },
          {
            path: ".github/workflows/full-release-validation-reusable.yml",
            reason: "Reusable governed full release validation workflow",
            contents: `${fullReleaseValidationReusableWorkflow()}\n`
          },
          {
            path: ".github/workflows/release-publish-reusable.yml",
            reason: "Reusable governed release publish workflow",
            contents: `${releasePublishReusableWorkflow()}\n`
          },
          {
            path: ".github/workflows/release-postpublish-reusable.yml",
            reason: "Reusable governed release postpublish workflow",
            contents: `${releasePostpublishReusableWorkflow()}\n`
          }
        ]
      : []),
    ...(manifest.release.enabled && manifest.release.changelog.enabled
      ? [
          {
            path: ".github/release.yml",
            reason: "Categorized release notes configuration",
            contents: releaseChangelogConfig(manifest)
          }
        ]
      : []),
    ...(workflowEnabled(manifest, "claude", Boolean(manifest.agents.enableClaudeGitHubAction))
      ? [
          {
            path: ".github/workflows/claude.yml",
            reason: "Claude GitHub automation workflow",
            contents: `${claudeWorkflow(manifest)}\n`
          }
        ]
      : []),
    ...(manifest.ci.aiAttestation.enabled
      ? [
          {
            path: ".github/workflows/ai-attestation.yml",
            reason: "Shared AI attestation workflow caller",
            contents: `${aiAttestationCallerWorkflow(manifest)}\n`
          }
        ]
      : []),
    {
      path: "scripts/check-detect-secrets.sh",
      reason: "Repository secret scan helper",
      contents: `${detectSecretsScript()}\n`,
      executable: true
    },
    {
      path: "scripts/ci/run-fast-checks.sh",
      reason: "Fast CI entrypoint",
      contents: fastChecksScript(manifest),
      executable: true
    },
    {
      path: "scripts/ci/run-extended-validation.sh",
      reason: "Extended CI entrypoint",
      contents: extendedChecksScript(manifest),
      executable: true
    },
    {
      path: "scripts/ci/check-pr-governance.sh",
      reason: "Fork-safe pull request governance validation",
      contents: `${prGovernanceScript(manifest)}\n`,
      executable: true
    },
    {
      path: "scripts/ci/check-action-pins.sh",
      reason: "Immutable third-party action pin validation",
      contents: `${actionPinScript()}\n`,
      executable: true
    },
    ...(manifest.github.repoFeatures.hasIssues
      ? [
          {
            path: "scripts/ci/report-issue-hygiene.mjs",
            reason: "Deterministic report-first issue aging evaluator",
            contents: issueHygieneScript(),
            executable: true
          }
        ]
      : []),
    ...(manifest.release.enabled
      ? [
          {
            path: "scripts/ci/run-release-verification.sh",
            reason: "Release verification entrypoint",
            contents: releaseVerificationScript(manifest),
            executable: true
          },
          {
            path: "scripts/ci/run-release-version.sh",
            reason: "Release version validation entrypoint",
            contents: releaseVersionScript(manifest),
            executable: true
          },
          {
            path: "scripts/ci/run-release-build.sh",
            reason: "Release artifact build entrypoint",
            contents: releaseBuildScript(manifest),
            executable: true
          },
          {
            path: "scripts/ci/run-release-publish.sh",
            reason: "Release publication entrypoint",
            contents: releasePublishScript(manifest),
            executable: true
          }
        ]
      : []),
    ...(releaseIsGoverned ? governedReleaseHookScripts() : []),
    {
      path: "scripts/codex-cloud/setup.sh",
      reason: "Codex cloud setup script",
      contents: codexCloudSetupScript(manifest),
      executable: true
    },
    {
      path: "scripts/codex-cloud/maintenance.sh",
      reason: "Codex cloud maintenance script",
      contents: codexCloudMaintenanceScript(manifest),
      executable: true
    },
    ...(manifest.agents.enableClaudeWebEnvironment
      ? [
          {
            path: "scripts/claude-cloud/setup.sh",
            reason: "Claude cloud setup script",
            contents: claudeCloudSetupScript(manifest),
            executable: true
          }
        ]
      : []),
    ...(manifest.agents.enableClaudeDevcontainer
      ? [
          {
            path: ".devcontainer/devcontainer.json",
            reason: "Claude interactive devcontainer",
            contents: claudeDevcontainer(manifest)
          },
          {
            path: "scripts/claude/setup-devcontainer.sh",
            reason: "Claude devcontainer dependency bootstrap",
            contents: claudeDevcontainerSetupScript(),
            executable: true
          }
        ]
      : []),
    {
      path: "docs/bootstrap/onboarding.md",
      reason: "Operator onboarding checklist",
      contents: `${onboardingDoc(manifest)}\n`
    },
    ...(manifest.github.repoFeatures.hasIssues
      ? [
          {
            path: "docs/bootstrap/issue-hygiene.md",
            reason: "Report-first issue aging operator guide",
            contents: `${issueHygieneDoc()}\n`
          }
        ]
      : []),
    {
      path: "docs/bootstrap/codex-cloud-environment.md",
      reason: "Codex web environment setup guide",
      contents: `${codexCloudDoc(manifest)}\n`
    },
    ...(claudeEnabled(manifest)
      ? [
          {
            path: "docs/bootstrap/claude-environment.md",
            reason: "Claude environment setup guide",
            contents: `${claudeEnvironmentDoc(manifest)}\n`
          }
        ]
      : []),
    ...(manifest.release.enabled
      ? [
          {
            path: "docs/bootstrap/versioning.md",
            reason: "Release and versioning guide",
            contents: `${releaseVersioningDoc(manifest)}\n`
          }
        ]
      : []),
    ...(releaseIsGoverned
      ? [
          {
            path: "docs/bootstrap/release-train-contract.md",
            reason: "Governed release train contract",
            contents: `${releaseTrainContractDoc(manifest)}\n`
          },
          {
            path: "docs/bootstrap/release-evidence-schema.md",
            reason: "Governed release evidence schema",
            contents: `${releaseEvidenceSchemaDoc()}\n`
          },
          {
            path: "docs/release-train.md",
            reason: "Repo-local governed release train guide",
            contents: `${releaseTrainDoc()}\n`
          }
        ]
      : []),
  ];

  switch (manifest.archetype.kind) {
    case "nextjs-web":
      return filterRenderedFiles(manifest, [...files, ...nextJsStarter()]);
    case "node-ts-service":
      return filterRenderedFiles(manifest, [...files, ...nodeStarter()]);
    case "python-service":
      return filterRenderedFiles(manifest, [...files, ...pythonStarter(manifest.archetype.moduleName)]);
    case "generic-empty":
      return filterRenderedFiles(manifest, [...files, ...genericStarter(manifest)]);
  }
}
