import path from "node:path";

import { renderManagedFiles } from "./archetypes.js";
import { sha256 } from "./lib/hash.js";
import { readTextIfExists, removeFileIfExists, writeTextFile } from "./lib/fs.js";
import { resolveLanguageProfiles, type LanguageProfileResolution } from "./language-profiles.js";
import { LICENSE_PATH, projectLicensePolicy, type LicensePlanSummary } from "./licensing.js";
import {
  createOwnershipSidecar,
  createRepoState,
  FALLBACK_REPO_STATE_PATH,
  loadRepoState,
  OWNERSHIP_SIDECAR_PATH,
  REPO_STATE_FILENAME,
  writeRepoState
} from "./state.js";
import type { BootstrapManifest, PlannedFileChange, RenderedFile, RepoState } from "./types.js";

export interface RepoPlan {
  changes: PlannedFileChange[];
  files: RenderedFile[];
  languageProfiles: LanguageProfileResolution;
  license?: LicensePlanSummary;
}

export const BOOTSTRAP_STATE_OUTPUT_PATHS = [
  OWNERSHIP_SIDECAR_PATH,
  FALLBACK_REPO_STATE_PATH,
  `.git/info/${REPO_STATE_FILENAME}`
] as const;

function globToRegExp(pattern: string): RegExp {
  const normalized = pattern.replace(/\\/g, "/");
  let source = "^";

  for (let index = 0; index < normalized.length; index += 1) {
    const character = normalized[index]!;
    if (character === "*") {
      const nextCharacter = normalized[index + 1];
      if (nextCharacter === "*") {
        source += ".*";
        index += 1;
      } else {
        source += "[^/]*";
      }
      continue;
    }

    source += /[|\\{}()[\]^$+?.]/.test(character) ? `\\${character}` : character;
  }

  source += "$";
  return new RegExp(source);
}

function matchesManagedPath(filePath: string, pattern: string): boolean {
  return globToRegExp(pattern).test(filePath.replace(/\\/g, "/"));
}

function isManagedContentHash(value: string | undefined): value is string {
  return value !== undefined && /^[a-f0-9]{64}$/i.test(value);
}

function isSafeManagedPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return normalized.length > 0 && normalized === filePath && !path.posix.isAbsolute(normalized) &&
    path.posix.normalize(normalized) === normalized && normalized !== ".." && !normalized.startsWith("../") &&
    !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(normalized);
}

interface OwnershipSidecar {
  schemaVersion?: unknown;
  owner?: unknown;
  managedFiles?: Record<string, { sha256?: unknown }>;
  license?: { mode?: unknown; identifier?: unknown; contentSha256?: unknown };
}

interface OwnershipHashes {
  hashes: Record<string, string>;
  claimsLicense: boolean;
}

export async function loadEffectiveRepoState(
  targetDir: string,
  renderedFiles: RenderedFile[]
): Promise<{ state?: RepoState; ownership: OwnershipHashes }> {
  const existingState = await loadRepoState(targetDir);
  const ownership = await loadOwnershipHashes(targetDir, renderedFiles);
  if (existingState && Object.keys(existingState.managedFiles).some((filePath) => !isSafeManagedPath(filePath))) {
    return invalidOwnershipSidecar();
  }
  return { ...(existingState ? { state: existingState } : {}), ownership };
}

function invalidOwnershipSidecar(): never {
  throw new Error("Bootstrap ownership sidecar is invalid or incomplete. Regenerate it with bootstrap apply repo before making managed-file changes.");
}

async function loadOwnershipHashes(targetDir: string, renderedFiles: RenderedFile[]): Promise<OwnershipHashes> {
  const raw = await readTextIfExists(path.join(targetDir, ".bootstrap/managed-files.json"));
  if (raw === undefined) return { hashes: {}, claimsLicense: false };

  try {
    const sidecar = JSON.parse(raw) as OwnershipSidecar;
    if (sidecar.schemaVersion !== 1 || sidecar.owner !== "bootstrap" || !sidecar.managedFiles || Array.isArray(sidecar.managedFiles)) {
      return invalidOwnershipSidecar();
    }
    const entries = Object.entries(sidecar.managedFiles);
    if (entries.some(([filePath, entry]) =>
      !isSafeManagedPath(filePath) || !isManagedContentHash(typeof entry?.sha256 === "string" ? entry.sha256 : undefined)
    )) {
      return invalidOwnershipSidecar();
    }
    const hashes = Object.fromEntries(entries.map(([filePath, entry]) => [filePath, entry.sha256 as string]));
    if (renderedFiles.some((file) => hashes[file.path] === undefined)) {
      return invalidOwnershipSidecar();
    }
    if (sidecar.license !== undefined) {
      const { mode, identifier, contentSha256 } = sidecar.license;
      if (
        (mode !== "spdx" && mode !== "proprietary") ||
        !isManagedContentHash(typeof contentSha256 === "string" ? contentSha256 : undefined) ||
        hashes[LICENSE_PATH] !== contentSha256 ||
        (mode === "spdx" && typeof identifier !== "string") ||
        (mode === "proprietary" && identifier !== undefined)
      ) return invalidOwnershipSidecar();
    }
    return {
      hashes,
      // A mutable sidecar license entry is validated for internal consistency
      // but never returned as authoritative prior legal classification.
      claimsLicense: hashes[LICENSE_PATH] !== undefined
    };
  } catch {
    return invalidOwnershipSidecar();
  }
}

const managedPathDependencies = [
  {
    path: "AGENTS.md",
    requires: [
      ".githooks/pre-commit",
      ".github/PULL_REQUEST_TEMPLATE.md",
      "docs/bootstrap/onboarding.md"
    ]
  },
  {
    path: "CONTRIBUTING.md",
    requires: [".githooks/pre-commit", ".github/PULL_REQUEST_TEMPLATE.md"]
  },
  {
    path: ".github/PULL_REQUEST_TEMPLATE.md",
    requires: ["docs/bootstrap/onboarding.md"]
  }
];

function expandManagedPathDependencies(files: RenderedFile[], selectedFiles: RenderedFile[]): RenderedFile[] {
  const availablePaths = new Set(files.map((file) => file.path));
  const selectedPaths = new Set(selectedFiles.map((file) => file.path));
  let changed = true;

  while (changed) {
    changed = false;
    for (const { path: managedPath, requires } of managedPathDependencies) {
      if (!selectedPaths.has(managedPath)) {
        continue;
      }

      for (const requiredPath of requires) {
        if (!selectedPaths.has(requiredPath) && availablePaths.has(requiredPath)) {
          selectedPaths.add(requiredPath);
          changed = true;
        }
      }
    }
  }

  return files.filter((file) => selectedPaths.has(file.path));
}

export function selectManagedFiles(manifest: BootstrapManifest, files: RenderedFile[]): RenderedFile[] {
  if (manifest.repo.managedPaths.length === 0) {
    return files;
  }

  let selectedFiles = files.filter((file) =>
    manifest.repo.managedPaths.some((pattern) => matchesManagedPath(file.path, pattern))
  );
  if (manifest.version === 2) {
    selectedFiles = expandManagedPathDependencies(files, selectedFiles);
  }
  validateManagedPathDependencies(selectedFiles);
  return selectedFiles;
}

function validateManagedPathDependencies(files: RenderedFile[]): void {
  const selectedPaths = new Set(files.map((file) => file.path));
  const dependencies = managedPathDependencies;

  const violations = dependencies.flatMap(({ path: managedPath, requires }) => {
    if (!selectedPaths.has(managedPath)) {
      return [];
    }

    const missing = requires.filter((requiredPath) => !selectedPaths.has(requiredPath));
    return missing.length > 0 ? [{ path: managedPath, missing }] : [];
  });

  if (violations.length === 0) {
    return;
  }

  const details = violations
    .map(({ path: managedPath, missing }) => `${managedPath} requires ${missing.join(", ")}`)
    .join("; ");
  throw new Error(
    `Invalid repo.managedPaths: selected bootstrap guidance excludes required companion files. ${details}.`
  );
}

export async function planRepo(manifest: BootstrapManifest, targetDir: string): Promise<RepoPlan> {
  const selectedManagedFiles = selectManagedFiles(manifest, renderManagedFiles(manifest));
  const { state: effectiveState, ownership: ownershipHashes } = await loadEffectiveRepoState(targetDir, selectedManagedFiles);
  if (
    !manifest.license &&
    (effectiveState?.license || effectiveState?.managedFiles[LICENSE_PATH] || ownershipHashes.claimsLicense)
  ) {
    throw new Error(
      "PRS-LICENSE-TRANSITION-001: removing an existing managed license policy is forbidden; choose an explicit replacement mode with legal transition evidence."
    );
  }
  const licenseProjection = await projectLicensePolicy(
    manifest,
    targetDir,
    effectiveState,
    [
      ...selectedManagedFiles.map((file) => file.path),
      ...Object.keys(effectiveState?.managedFiles ?? {}),
      ...BOOTSTRAP_STATE_OUTPUT_PATHS
    ]
  );
  const renderedFiles = [
    ...selectedManagedFiles,
    ...(licenseProjection?.files ?? [])
  ];
  const files = [...renderedFiles, createOwnershipSidecar(manifest, renderedFiles)];
  const languageProfiles = await resolveLanguageProfiles(manifest, targetDir);
  const changes: PlannedFileChange[] = [];

  for (const file of files) {
    const existingContents = await readTextIfExists(path.join(targetDir, file.path));
    const managedHash = effectiveState?.managedFiles[file.path];
    const sidecarClaimHash = ownershipHashes.hashes[file.path];
    const hasSidecarOnlyClaim = managedHash === undefined && isManagedContentHash(sidecarClaimHash);
    const hasExplicitLicenseTransition =
      file.path === LICENSE_PATH && licenseProjection?.summary.transitionRequired === true;
    // The caller-supplied control plane authorizes its own canonical rendering;
    // all other sidecar-only updates need an independent migration authority.
    const isManifestControlPlane = file.path === "project.bootstrap.yaml";
    if (existingContents === undefined && hasSidecarOnlyClaim) {
      throw new Error(
        `Managed file ${file.path} was deleted, but only mutable sidecar ownership is available. Restore the file and re-establish local state before applying Bootstrap changes.`
      );
    }
    if (
      existingContents !== undefined &&
      existingContents !== file.contents &&
      hasSidecarOnlyClaim &&
      !hasExplicitLicenseTransition &&
      !isManifestControlPlane
    ) {
      throw new Error(
        `Managed file ${file.path} cannot be updated from mutable sidecar ownership alone. Re-establish local state from an unchanged projection or use an explicit migration.`
      );
    }
    if (
      existingContents !== undefined &&
      isManagedContentHash(managedHash) &&
      sha256(existingContents) !== managedHash &&
      existingContents !== file.contents
    ) {
      throw new Error(
        `Managed file ${file.path} was directly modified. Restore it, remove it from managed paths, or use an explicit migration before applying Bootstrap changes.`
      );
    }
    const type =
      existingContents === undefined
        ? "create"
        : existingContents === file.contents
          ? "unchanged"
          : "update";

    changes.push({
      path: file.path,
      type,
      reason: file.reason
    });
  }

  const plannedPaths = new Set(files.map((file) => file.path));
  for (const claimedPath of Object.keys(ownershipHashes.hashes)) {
    if (!plannedPaths.has(claimedPath) && effectiveState?.managedFiles[claimedPath] === undefined) {
      throw new Error(
        `Managed file ${claimedPath} cannot be removed from mutable sidecar ownership alone. Re-establish local state or use an explicit migration.`
      );
    }
  }

  if (effectiveState) {
    for (const stalePath of Object.keys(effectiveState.managedFiles)) {
      if (!plannedPaths.has(stalePath)) {
        const existingContents = await readTextIfExists(path.join(targetDir, stalePath));
        if (
          existingContents !== undefined &&
          isManagedContentHash(effectiveState.managedFiles[stalePath]) &&
          sha256(existingContents) !== effectiveState.managedFiles[stalePath]
        ) {
          throw new Error(
            `Managed file ${stalePath} was directly modified. Restore it or use an explicit migration before Bootstrap removes it.`
          );
        }
        changes.push({
          path: stalePath,
          type: "delete",
          reason: "Previously managed file is no longer rendered by the manifest"
        });
      }
    }
  }

  return {
    changes: changes.sort((left, right) => left.path.localeCompare(right.path)),
    files,
    languageProfiles,
    ...(licenseProjection ? { license: licenseProjection.summary } : {})
  };
}

export async function applyRepo(manifest: BootstrapManifest, targetDir: string): Promise<RepoPlan> {
  const plan = await planRepo(manifest, targetDir);

  for (const file of plan.files) {
    const nextPath = path.join(targetDir, file.path);
    await writeTextFile(nextPath, file.contents, file.executable);
  }

  for (const change of plan.changes) {
    if (change.type === "delete") {
      await removeFileIfExists(path.join(targetDir, change.path));
    }
  }

  await writeRepoState(targetDir, createRepoState(manifest, plan.files));
  return plan;
}
