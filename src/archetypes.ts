import path from "node:path";

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
    ".claude/",
    ".bootstrap/",
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
    - Self-hosted runner policy: shell-safe jobs may use \`[self-hosted, synology, shell-only, ${manifest.project.visibility === "public" ? "public" : "private"}]\`; anything needing Docker, service containers, browser infra, or \`container:\` must stay on GitHub-hosted runners.
    - Add or update tests for every interactive, branching, or operator-facing behavior change.
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

function repoClaude(manifest: BootstrapManifest): string {
  const projectMapLines = [
    "- `project.bootstrap.yaml`: source of truth for bootstrap policy",
    "- `.github/workflows/`: generated fast and extended CI lanes",
    ...additionalWorkflowLines(manifest),
    "- `CONTRIBUTING.md`: human contributor workflow and local validation guidance",
    "- `.github/PULL_REQUEST_TEMPLATE.md`: standard PR summary, issue link, and validation checklist",
    manifest.agents.enableClaudeWebEnvironment
      ? "- `scripts/claude-cloud/setup.sh`: first-party Claude Code on the web setup script"
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- `.github/workflows/claude.yml`: opt-in Claude GitHub Action for manual or `@claude` review flows"
      : null,
    manifest.agents.enableClaudeDevcontainer
      ? "- `.devcontainer/devcontainer.json`: interactive Claude Code workspace baseline"
      : null,
    "- `.github/workflows/`: repo CI and review workflows",
    "- `scripts/ci/`: bootstrap CI entrypoints when this repo uses the generated workflow lane",
    manifest.agents.enableClaudeDevcontainer
      ? "- `scripts/claude/setup-devcontainer.sh`: installs repo dependencies inside the devcontainer"
      : null,
    "- `.githooks/pre-commit`: branch and env-file guardrail when local hooks are bootstrap-managed",
    "- `docs/bootstrap/onboarding.md`: operator checklist for repo/governance setup",
    manifest.agents.enableClaudeWebEnvironment || manifest.agents.enableClaudeDevcontainer || manifest.agents.enableClaudeGitHubAction
      ? "- `docs/bootstrap/claude-environment.md`: Claude setup guide for hosted, interactive, and GitHub-hosted use"
      : null
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");

  const guardrailLines = [
    requiredStatusCheckGuardrail(manifest),
    `- Use one approval plus code owners on \`${manifest.project.defaultBranch}\` unless the manifest explicitly changes it.`,
    "- Contributors and agents must use `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md` for PR shape unless a repo intentionally replaces those files.",
    "- `stage` and `prod` environments require reviewers and prevent self-review by default.",
    "- Home-level Codex and Claude profile sync is managed by the bootstrap tool, not by ad-hoc manual edits.",
    manifest.agents.enableClaudeWebEnvironment
      ? "- Claude Code on the web should use the repo-managed setup script and keep network access limited by default."
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- The generated Claude GitHub Action is a separate review lane. It must not become a required status check."
      : null,
    manifest.ci.additionalWorkflows.length > 0
      ? `- Repo-specific workflow lanes (${manifest.ci.additionalWorkflows.map((workflow) => `\`${workflow.path}\``).join(", ")}) stay adjunct to the standard PR and extended validation lanes.`
      : null,
    manifest.agents.enableClaudeDevcontainer
      ? "- Treat the devcontainer as a trusted-repo workspace. Do not mount extra secrets beyond the persisted `~/.claude` profile unless you explicitly need them."
      : null
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");

  return dedent`
    # CLAUDE.md

    ## Project Map

${indentBlock(projectMapLines, 4)}

    ## Guardrails

${indentBlock(guardrailLines, 4)}
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
  const claudeBullets = [
    manifest.agents.enableClaudeWebEnvironment
      ? "- First-party Claude Code on the web via `claude.ai/code` and `bash scripts/claude-cloud/setup.sh`"
      : null,
    manifest.agents.enableClaudeDevcontainer
      ? "- Interactive containerized work via `.devcontainer/devcontainer.json` and `bash scripts/claude/setup-devcontainer.sh`"
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- Remote GitHub-hosted automation via `.github/workflows/claude.yml`"
      : null
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");

  const claudeSection = claudeBullets.length > 0
    ? dedent`

      ## Claude Code

      This bootstrap can prepare these Claude workflows:

${indentBlock(claudeBullets, 6)}

      The full checklist is in \`docs/bootstrap/claude-environment.md\`.
    `
    : "";

  return dedent`
    # ${displayName}

    ${manifest.project.description}

    Use \`project.bootstrap.yaml\` as the control plane for repo-local scaffolding, GitHub governance, CI policy, and portable Codex/Claude profile sync. Plan first, then apply repo, GitHub, and home targets deliberately.

    ## What The Bootstrap Owns

    - GitHub governance, environments, and optional org defaults
    ${manifest.ci.additionalWorkflows.length > 0
      ? "- Optional repo-specific workflow lanes declared in the manifest without replacing the standard CI frame"
      : ""}
    - Repo-local \`AGENTS.md\`, \`CLAUDE.md\`, \`CONTRIBUTING.md\`, and pull request template guidance
    - Fast PR checks plus heavier extended validation lanes
    ${manifest.release.enabled ? "- SemVer release automation with floating major/minor compatibility tags" : ""}
    ${manifest.ci.aiAttestation.enabled ? "- Optional signed AI attestation workflow backed by the control-plane reusable contract" : ""}
    - Portable Codex and Claude home profile sync
    - Operator docs for onboarding, hosted agents, and follow-up setup

    ## Quickstart

    \`\`\`sh
    bootstrap plan --manifest ./project.bootstrap.yaml
    bootstrap apply repo --manifest ./project.bootstrap.yaml
    bootstrap apply github --manifest ./project.bootstrap.yaml
    bootstrap apply home --manifest ./project.bootstrap.yaml
    bootstrap doctor --manifest ./project.bootstrap.yaml
    \`\`\`

    ${manifest.github.organization
      ? `If \`github.organization\` is set and \`${manifest.project.owner}\` is an organization, \`bootstrap apply github\` also reconciles org defaults for new repos.`
      : ""}

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
${indentBlock(claudeSection, 4)}

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

function pullRequestTemplate(manifest: BootstrapManifest): string {
  return dedent`
    ## Summary

    -

    ## Governing Issue

    Closes #

    ## Validation

    - [ ] Relevant local checks passed
    - [ ] Required PR checks are expected to satisfy ${requiredStatusChecksDisplay(manifest)}
    - [ ] Skipped checks are explained below

    ## Bootstrap Governance

    - [ ] Changes are scoped to the linked issue
    - [ ] Contributor or PR guidance changes are reflected in \`CONTRIBUTING.md\`, \`.github/PULL_REQUEST_TEMPLATE.md\`, and \`docs/bootstrap/onboarding.md\` when applicable
    - [ ] Auto-merge is enabled, or GitHub plan-limit evidence is recorded and the fallback merge-readiness policy applies
    - [ ] No real secrets, runtime auth, or machine-local env files are committed

    ## Notes

    -
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

    for f in "\${staged_files[@]}"; do
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
      'ANTHROPIC_API_KEY='
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

function claudeCloudSetupScript(manifest: BootstrapManifest): string {
  const installBody =
    manifest.archetype.kind === "python-service"
      ? dedent`
          if ! command -v gh >/dev/null 2>&1; then
            apt-get update
            apt-get install -y gh
          fi

          if [[ -f pyproject.toml ]]; then
            if [[ ! -d .venv ]]; then
              python3 -m venv .venv
            fi
            source .venv/bin/activate
            python -m pip install --upgrade pip setuptools wheel
            python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
          fi
        `
      : manifest.archetype.kind === "generic-empty"
        ? dedent`
            if ! command -v gh >/dev/null 2>&1; then
              apt-get update
              apt-get install -y gh
            fi

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
              if [[ ! -d .venv ]]; then
                python3 -m venv .venv
              fi
              source .venv/bin/activate
              python -m pip install --upgrade pip setuptools wheel
              python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
            fi
          `
        : dedent`
            if ! command -v gh >/dev/null 2>&1; then
              apt-get update
              apt-get install -y gh
            fi

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

function claudeDevcontainerFeatures(manifest: BootstrapManifest): Record<string, Record<string, string>> {
  const features: Record<string, Record<string, string>> = {
    "ghcr.io/anthropics/devcontainer-features/claude-code:1": {},
    "ghcr.io/devcontainers/features/github-cli:1": {}
  };

  if (
    manifest.archetype.kind === "nextjs-web" ||
    manifest.archetype.kind === "node-ts-service" ||
    manifest.archetype.kind === "generic-empty"
  ) {
    features["ghcr.io/devcontainers/features/node:1"] = {
      version: manifest.ci.nodeVersion
    };
  }

  if (manifest.archetype.kind === "python-service" || manifest.archetype.kind === "generic-empty") {
    features["ghcr.io/devcontainers/features/python:1"] = {
      version: manifest.ci.pythonVersion
    };
  }

  return features;
}

function claudeDevcontainer(manifest: BootstrapManifest): string {
  return `${JSON.stringify(
    {
      name: `${manifest.project.name} Claude Code`,
      image: "mcr.microsoft.com/devcontainers/base:ubuntu-24.04",
      remoteUser: "vscode",
      updateRemoteUserUID: true,
      features: claudeDevcontainerFeatures(manifest),
      mounts: ["source=${localEnv:HOME}/.claude,target=/home/vscode/.claude,type=bind"],
      postCreateCommand: "bash scripts/claude/setup-devcontainer.sh",
      customizations: {
        vscode: {
          settings: {
            "terminal.integrated.defaultProfile.linux": "bash"
          }
        }
      }
    },
    null,
    2
  )}\n`;
}

function claudeDevcontainerSetupScript(manifest: BootstrapManifest): string {
  const installBody =
    manifest.archetype.kind === "python-service"
      ? dedent`
          git config --global --add safe.directory "$(pwd)"

          if [[ -f pyproject.toml ]]; then
            if [[ ! -d .venv ]]; then
              python3 -m venv .venv
            fi

            source .venv/bin/activate
            python -m pip install --upgrade pip setuptools wheel
            python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
          fi
        `
      : manifest.archetype.kind === "generic-empty"
        ? dedent`
            git config --global --add safe.directory "$(pwd)"

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
              if [[ ! -d .venv ]]; then
                python3 -m venv .venv
              fi

              source .venv/bin/activate
              python -m pip install --upgrade pip setuptools wheel
              python -m pip install -e ".[dev]" >/dev/null 2>&1 || python -m pip install -e . >/dev/null 2>&1 || true
            fi
          `
        : dedent`
            git config --global --add safe.directory "$(pwd)"

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

function claudeWorkflow(manifest: BootstrapManifest): string {
  return dedent`
    name: Claude Code

    on:
      workflow_dispatch:
        inputs:
          prompt:
            description: 'Task for Claude to run in this repository'
            required: true
            default: 'Review the current branch changes for bugs, CI regressions, and missing tests.'
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

    jobs:
      claude:
        if: |
          github.event_name == 'workflow_dispatch' ||
          (github.event_name == 'issue_comment' && contains(github.event.comment.body, '@claude')) ||
          (github.event_name == 'pull_request_review_comment' && contains(github.event.comment.body, '@claude')) ||
          (github.event_name == 'pull_request_review' && contains(github.event.review.body, '@claude'))
        runs-on: ubuntu-latest
        timeout-minutes: 30
        permissions:
          contents: write
          pull-requests: write
          issues: write
          id-token: write
          actions: read
        steps:
          - name: Checkout repository
            uses: actions/checkout@v6
            with:
              fetch-depth: 1

          - name: Require Claude auth
            env:
              ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
            run: |
              if [[ -z "\${ANTHROPIC_API_KEY}" ]]; then
                echo "Missing repository secret ANTHROPIC_API_KEY. Run /install-github-app in Claude Code or add the secret before using this workflow." >&2
                exit 1
              fi

          - name: Run Claude Code
            uses: anthropics/claude-code-action@v1
            with:
              anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
              track_progress: true
              use_sticky_comment: true
              additional_permissions: "actions: read"
              prompt: |
                REPO: \${{ github.repository }}
                DEFAULT BRANCH: ${manifest.project.defaultBranch}

                Use CLAUDE.md and docs/bootstrap/onboarding.md as repo policy context.
                ${
                  manifest.github.requiredStatusChecks.length === 1
                    ? `Keep ${primaryRequiredStatusCheck(manifest)} as the single required PR status check.`
                    : `Keep required PR status checks aligned with ${requiredStatusChecksPlain(manifest)}.`
                }
                Preserve the split fast and extended validation model.
                Shell-safe jobs may use \`[self-hosted, synology, shell-only, ${manifest.project.visibility === "public" ? "public" : "private"}]\`.
                Docker, service-container, browser, and \`container:\` jobs stay on GitHub-hosted runners.
                Prefer the smallest safe change and add tests for behavior changes.

                MANUAL TASK: \${{ github.event.inputs.prompt }}
                If this is not a manual run, ignore the MANUAL TASK line and respond to the current \`@claude\` request instead.
  `;
}

function claudeEnvironmentDoc(manifest: BootstrapManifest): string {
  const featureList = [
    manifest.agents.enableClaudeWebEnvironment ? "- First-party hosted sessions at `claude.ai/code`" : null,
    manifest.agents.enableClaudeDevcontainer
      ? "- Interactive containerized work with `.devcontainer/devcontainer.json`"
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- GitHub-hosted automation with `.github/workflows/claude.yml`"
      : null
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");

  const webSection = manifest.agents.enableClaudeWebEnvironment
    ? dedent`

      ## Claude Code On The Web

      - Hosted entrypoint: \`https://claude.ai/code\`
      - Repo: \`${manifest.project.owner}/${manifest.project.name}\`
      - Setup script: \`bash scripts/claude-cloud/setup.sh\`
      - Network access: start with limited access; only expand it when a task truly needs more than registries and GitHub
      - Environment variables: configure them in the Claude environment UI as \`.env\`-style key-value pairs
      - GitHub integration: connect GitHub, install the Claude GitHub App, then pick this repo as an allowed target
      - Repo guidance: Claude on the web reads \`CLAUDE.md\` from the repository

      ## Teleport And Remote Sessions

      - Start a hosted task from the terminal with \`claude --remote "your task"\`
      - Pull a hosted session back into the terminal with \`claude --teleport\`
      - Hosted tasks clone the default branch unless you specify a branch in the prompt
      - Teleport requires a clean git state and the same repository/account pairing
    `
    : "";

  const devcontainerSection = manifest.agents.enableClaudeDevcontainer
    ? dedent`

      ## Interactive Devcontainer

      - Open the repo in a devcontainer-capable editor and reopen in container.
      - The container installs the Claude Code feature plus repo dependencies via \`bash scripts/claude/setup-devcontainer.sh\`.
      - \`~/.claude\` is mounted into the container so Claude Code auth persists between sessions.
      - Only use this with trusted repositories. Mounted Claude credentials are available inside the container.
    `
    : "";

  const actionSection = manifest.agents.enableClaudeGitHubAction
    ? dedent`

      ## GitHub Action

      - Workflow file: \`.github/workflows/claude.yml\`
      - Runner: \`ubuntu-latest\`
      - Triggers:
        - manual \`workflow_dispatch\`
        - PR or issue comments containing \`@claude\`
        - review comments or review bodies containing \`@claude\`
      - Auth:
        - preferred: run \`/install-github-app\` in Claude Code as a repo admin
        - fallback: add a repository secret named \`ANTHROPIC_API_KEY\`
    `
    : "";

  const guardrailLines = [
    manifest.agents.enableClaudeGitHubAction
      ? `- Keep the Claude workflow out of the required PR check set. The required checks are ${requiredStatusChecksDisplay(manifest)}.`
      : null,
    manifest.agents.enableClaudeWebEnvironment
      ? "- Prefer Claude Code on the web for long-running async review or fix tasks; use the devcontainer when you need a local interactive container."
      : null,
    manifest.agents.enableClaudeDevcontainer
      ? "- Treat the devcontainer as a trusted-repo workspace because the mounted `~/.claude` profile is available inside the container."
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- Do not relax the action to allow non-write users on public repos unless you intentionally accept the prompt-injection risk."
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- Keep Claude review and automation on GitHub-hosted runners; do not move it onto the self-hosted shell-only fleet."
      : null
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");

  return dedent`
    # Claude Environment

    Claude Code on the web provides a first-party cloud environment comparable to Codex Web. This bootstrap prepares the hosted path first, then adds optional local and GitHub-native alternatives:

${indentBlock(featureList, 4)}

    ## Project

${indentBlock(projectIdentityLines(manifest), 4)}
${indentBlock(webSection, 4)}
${indentBlock(devcontainerSection, 4)}
${indentBlock(actionSection, 4)}

    ## Guardrails

${indentBlock(guardrailLines, 4)}

    ## Project

    - Default branch: \`${manifest.project.defaultBranch}\`
  `;
}

function fastChecksScript(manifest: BootstrapManifest): string {
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

function releaseVerificationScript(): string {
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
    "CLAUDE.md",
    "CONTRIBUTING.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".devcontainer/**",
    ".githooks/**",
    ".github/workflows/**",
    "scripts/**",
    "docs/bootstrap/**"
  ];

  switch (manifest.archetype.kind) {
    case "nextjs-web":
      return {
        app: [...common, "app/**", "components/**", "src/**", "public/**", "package.json", "tsconfig.json"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["tests/**", "playwright/**", "docker/**", "infra/**"]
      };
    case "node-ts-service":
      return {
        app: [...common, "src/**", "tests/**", "package.json", "tsconfig.json"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["docker/**", "infra/**", "ops/**"]
      };
    case "python-service":
      return {
        app: [...common, "src/**", "tests/**", "pyproject.toml", ".python-version"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["docker/**", "infra/**", "ops/**"]
      };
    case "generic-empty":
      return {
        app: [...common, "README.md", "docs/**"],
        ci: [...common, ".env.example", "CODEOWNERS"],
        extended: ["infra/**", "ops/**"]
      };
  }
}

function setupSteps(manifest: BootstrapManifest): string {
  const lines: string[] = [];

  if (manifest.archetype.kind === "nextjs-web" || manifest.archetype.kind === "node-ts-service") {
    lines.push(
      `- uses: actions/setup-node@v4`,
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
      `- uses: actions/setup-python@v5`,
      `  with:`,
      `    python-version: \${{ env.PYTHON_VERSION }}`
    );
  }

  return lines.join("\n");
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
          publish-script: scripts/ci/run-release-publish.sh
          create-github-release: ${manifest.release.createGitHubRelease ? "true" : "false"}
          tag-prefix: '${manifest.release.tagPrefix}'
          update-major-tag: ${manifest.release.updateMajorTag ? "true" : "false"}
          update-minor-tag: ${manifest.release.updateMinorTag ? "true" : "false"}
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

    concurrency:
      group: pr-fast-\${{ github.event.pull_request.number || github.ref }}
      cancel-in-progress: true

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
        name: Detect Relevant Changes
        runs-on: ${shellRunner}
        outputs:
          app: \${{ steps.filter.outputs.app }}
          ci: \${{ steps.filter.outputs.ci }}
        steps:
          - uses: dorny/paths-filter@v3
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
          - uses: actions/checkout@v4
            with:
              ref: \${{ github.event.pull_request.head.sha }}
${indentBlock(setupSteps(manifest), 6)}
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
              require_line "## Notes"

              if grep -Eiq 'Closes #$|#<issue-number>|what changed|why it changed|notable tradeoffs|migration or rollout notes|follow-up work if any' <<<"$PR_BODY"; then
                echo "PR body still contains template placeholder text."
                failed=1
              fi

              if ! grep -Eiq '(^|[[:space:]-])((close[sd]?|fix(e[sd])?|resolve[sd]?)[[:space:]]+#[0-9]+|no issue is linked|no linked issue|without a linked issue|no governing issue)' <<<"$PR_BODY"; then
                echo "PR body must close/link an issue or explicitly explain why no issue is linked."
                failed=1
              fi

              if ! grep -Eiq '(^|[[:space:]-])(\\[[xX]\\]|not run|not applicable|n/a)' <<<"$PR_BODY"; then
                echo "PR body must include validation evidence, a checked validation item, or a reason validation was not run."
                failed=1
              fi

              exit "$failed"

      validate-secrets:
        name: Validate Secrets
        runs-on: ${shellRunner}
        timeout-minutes: 10
        if: github.event.pull_request.draft == false
        steps:
          - uses: actions/checkout@v4
            with:
              ref: \${{ github.event.pull_request.head.sha }}
          - name: Scan repository for secret patterns
            run: bash scripts/check-detect-secrets.sh --all-files

      ci-gate:
        name: ${primaryRequiredStatusCheck(manifest)}
        runs-on: ${shellRunner}
        if: always()
        needs:
          - changes
          - fast-checks
          - validate-pr-description
          - validate-secrets
        steps:
          - name: Check required PR jobs
            env:
              RESULTS: >-
                changes=\${{ needs.changes.result }}
                fast-checks=\${{ needs.fast-checks.result }}
                validate-pr-description=\${{ needs.validate-pr-description.result }}
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
          - uses: actions/checkout@v4
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

          - uses: dorny/paths-filter@v3
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
          - uses: actions/checkout@v4
${indentBlock(setupSteps(manifest), 6)}
          - name: Run fast checks
            run: bash scripts/ci/run-fast-checks.sh

      extended-checks:
        name: Extended Checks
        runs-on: ${shellRunner}
        timeout-minutes: 20
        needs: changes
        if: needs.changes.outputs.extended == 'true' || needs.changes.outputs.app == 'true'
        steps:
          - uses: actions/checkout@v4
${indentBlock(setupSteps(manifest), 6)}
          - name: Run extended validation
            run: bash scripts/ci/run-extended-validation.sh

      validate-secrets:
        name: Validate Secrets
        runs-on: ${shellRunner}
        timeout-minutes: 10
        steps:
          - uses: actions/checkout@v4
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
  const claudeSetupLines = [
    manifest.agents.enableClaudeWebEnvironment
      ? "- First-party Claude web sessions should use `bash scripts/claude-cloud/setup.sh` in `claude.ai/code`."
      : null,
    manifest.agents.enableClaudeDevcontainer
      ? "- Interactive Claude work is prepared through `.devcontainer/devcontainer.json`."
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- GitHub-hosted Claude automation lives in `.github/workflows/claude.yml` and is intentionally separate from the required PR checks."
      : null,
    manifest.agents.enableClaudeGitHubAction
      ? "- Finish GitHub-side auth by running `/install-github-app` in Claude Code or adding `ANTHROPIC_API_KEY` as a repo secret."
      : null
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");

  return dedent`
    # Bootstrap Onboarding

    Use this checklist after the first bootstrap render or whenever \`project.bootstrap.yaml\` changes in a way that affects GitHub policy, environments, or home-profile sync.

    ## Project

${indentBlock(projectIdentityLines(manifest), 4)}

    ## Repo Governance

    - Confirm branch protection or rulesets on \`${manifest.project.defaultBranch}\` require one approval, code owner review, and approval from someone other than the most recent pusher.
    - ${requiredStatusCheckConfirmation(manifest)}
    - Confirm \`CONTRIBUTING.md\` and \`.github/PULL_REQUEST_TEMPLATE.md\` are present as the required contributor and PR guidance surfaces.
    - Confirm the pull request template is present and PR Fast CI validates the required PR description sections before ${primaryRequiredStatusCheck(manifest)} can pass.
    - ${autoMergeOnboardingConfirmation()}
    - Fallback merge readiness requires passing or intentionally skipped required checks, satisfied approvals, resolved conversations, no blocking review state, and a manual maintainer merge.

${indentBlock(organizationGovernanceSection(manifest), 4)}
${indentBlock(additionalWorkflowSection(manifest), 4)}

    ## Environments

    - \`dev\`: open by default for rapid iteration.
    - \`stage\`: one reviewer required and self-review blocked.
    - \`prod\`: one reviewer required, self-review blocked, deployments limited to \`${manifest.project.defaultBranch}\`.

    ## Runner Policy

    - Shell-safe jobs may use \`[self-hosted, synology, shell-only, ${manifest.project.visibility === "public" ? "public" : "private"}]\`.
    - Docker, service-container, browser, and \`container:\` workloads stay on GitHub-hosted runners.
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
    - The bootstrap manages portable Codex and Claude assets only. Auth, sessions, caches, and machine-local state stay unmanaged.

    ## Claude Setup

${indentBlock(claudeSetupLines, 4)}
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
    - \`scripts/ci/run-release-publish.sh\` is the repo hook for artifact publication; the generated default is a no-op until the repo needs more than GitHub releases.
    - The shared reusable release workflow creates or updates the GitHub release and then advances the floating compatibility tags when enabled in \`project.bootstrap.yaml\`.
  `;
}

export function renderManagedFiles(manifest: BootstrapManifest): RenderedFile[] {
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
      path: "CLAUDE.md",
      reason: "Repo-local Claude instructions",
      contents: `${repoClaude(manifest)}\n`
    },
    {
      path: "CONTRIBUTING.md",
      reason: "Contributor workflow guidance",
      contents: `${contributingDoc(manifest)}\n`
    },
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
    ...(manifest.release.enabled
      ? [
          {
            path: ".github/workflows/release-tag.yml",
            reason: "Shared release workflow caller",
            contents: `${releaseCallerWorkflow(manifest)}\n`
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
    ...(manifest.release.enabled
      ? [
          {
            path: "scripts/ci/run-release-verification.sh",
            reason: "Release verification entrypoint",
            contents: releaseVerificationScript(),
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
            contents: claudeDevcontainerSetupScript(manifest),
            executable: true
          }
        ]
      : []),
    ...(manifest.agents.enableClaudeGitHubAction
      ? [
          {
            path: ".github/workflows/claude.yml",
            reason: "Claude GitHub automation workflow",
            contents: `${claudeWorkflow(manifest)}\n`
          }
        ]
      : []),
    {
      path: "docs/bootstrap/onboarding.md",
      reason: "Operator onboarding checklist",
      contents: `${onboardingDoc(manifest)}\n`
    },
    {
      path: "docs/bootstrap/codex-cloud-environment.md",
      reason: "Codex web environment setup guide",
      contents: `${codexCloudDoc(manifest)}\n`
    },
    ...(manifest.release.enabled
      ? [
          {
            path: "docs/bootstrap/versioning.md",
            reason: "Release and versioning guide",
            contents: `${releaseVersioningDoc(manifest)}\n`
          }
        ]
      : []),
    ...(manifest.agents.enableClaudeWebEnvironment ||
    manifest.agents.enableClaudeDevcontainer ||
    manifest.agents.enableClaudeGitHubAction
      ? [
          {
            path: "docs/bootstrap/claude-environment.md",
            reason: "Claude environment setup guide",
            contents: `${claudeEnvironmentDoc(manifest)}\n`
          }
        ]
      : [])
  ];

  switch (manifest.archetype.kind) {
    case "nextjs-web":
      return [...files, ...nextJsStarter()];
    case "node-ts-service":
      return [...files, ...nodeStarter()];
    case "python-service":
      return [...files, ...pythonStarter(manifest.archetype.moduleName)];
    case "generic-empty":
      return [...files, ...genericStarter(manifest)];
  }
}
