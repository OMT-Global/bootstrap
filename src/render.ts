import path from "node:path";

import { renderManagedFiles } from "./archetypes.js";
import { sha256 } from "./lib/hash.js";
import { readTextIfExists, removeFileIfExists, writeTextFile } from "./lib/fs.js";
import { resolveLanguageProfiles, type LanguageProfileResolution } from "./language-profiles.js";
import { createOwnershipSidecar, createRepoState, loadRepoState, writeRepoState } from "./state.js";
import type { BootstrapManifest, PlannedFileChange, RenderedFile } from "./types.js";

export interface RepoPlan {
  changes: PlannedFileChange[];
  files: RenderedFile[];
  languageProfiles: LanguageProfileResolution;
}

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

interface OwnershipSidecar {
  schemaVersion?: unknown;
  owner?: unknown;
  managedFiles?: Record<string, { sha256?: unknown }>;
}

interface OwnershipHashes {
  hashes: Record<string, string>;
  sidecarPresent: boolean;
}

async function loadOwnershipHashes(targetDir: string): Promise<OwnershipHashes> {
  const raw = await readTextIfExists(path.join(targetDir, ".bootstrap/managed-files.json"));
  if (!raw) return { hashes: {}, sidecarPresent: false };

  try {
    const sidecar = JSON.parse(raw) as OwnershipSidecar;
    if (sidecar.schemaVersion !== 1 || sidecar.owner !== "bootstrap" || !sidecar.managedFiles) {
      return { hashes: {}, sidecarPresent: false };
    }
    return {
      hashes: Object.fromEntries(
        Object.entries(sidecar.managedFiles)
          .filter(([, entry]) => isManagedContentHash(typeof entry?.sha256 === "string" ? entry.sha256 : undefined))
          .map(([filePath, entry]) => [filePath, entry.sha256 as string])
      ),
      sidecarPresent: true
    };
  } catch {
    return { hashes: {}, sidecarPresent: false };
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

function selectManagedFiles(manifest: BootstrapManifest, files: RenderedFile[]): RenderedFile[] {
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
  const renderedFiles = selectManagedFiles(manifest, renderManagedFiles(manifest));
  const files = [...renderedFiles, createOwnershipSidecar(renderedFiles)];
  const languageProfiles = await resolveLanguageProfiles(manifest, targetDir);
  const existingState = await loadRepoState(targetDir);
  const ownershipHashes = await loadOwnershipHashes(targetDir);
  const changes: PlannedFileChange[] = [];

  for (const file of files) {
    const existingContents = await readTextIfExists(path.join(targetDir, file.path));
    const managedHash = existingState?.managedFiles[file.path] ?? ownershipHashes.hashes[file.path];
    const missingSidecarHash =
      !existingState &&
      ownershipHashes.sidecarPresent &&
      file.path !== ".bootstrap/managed-files.json" &&
      existingContents !== undefined &&
      managedHash === undefined &&
      existingContents !== file.contents;
    if (
      missingSidecarHash ||
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

  if (existingState) {
    const plannedPaths = new Set(files.map((file) => file.path));
    for (const stalePath of Object.keys(existingState.managedFiles)) {
      if (!plannedPaths.has(stalePath)) {
        const existingContents = await readTextIfExists(path.join(targetDir, stalePath));
        if (
          existingContents !== undefined &&
          isManagedContentHash(existingState.managedFiles[stalePath]) &&
          sha256(existingContents) !== existingState.managedFiles[stalePath]
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
    languageProfiles
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
