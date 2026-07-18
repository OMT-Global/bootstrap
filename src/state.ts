import { stat } from "node:fs/promises";
import path from "node:path";

import { readTextIfExists, writeTextFile } from "./lib/fs.js";
import { sha256 } from "./lib/hash.js";
import type { BootstrapManifest, RenderedFile, RepoState } from "./types.js";

export const TEMPLATE_VERSION = "2026.03.28.2";
export const FALLBACK_REPO_STATE_PATH = ".bootstrap/bootstrap-state.json";
export const HOME_STATE_PATH = ".bootstrap/home-state.json";
export const LEGACY_HOME_STATE_PATH = ".new-project-bootstrap/home-state.json";
export const REPO_STATE_FILENAME = "bootstrap-state.json";
export const LEGACY_REPO_STATE_FILENAME = "new-project-bootstrap-state.json";
export const OWNERSHIP_SIDECAR_PATH = ".bootstrap/managed-files.json";

async function resolveGitDir(targetDir: string): Promise<string | undefined> {
  const gitPath = path.join(targetDir, ".git");
  try {
    const gitStat = await stat(gitPath);
    if (gitStat.isDirectory()) {
      return gitPath;
    }
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }

  const raw = await readTextIfExists(gitPath);
  if (!raw) {
    return undefined;
  }

  const trimmed = raw.trim();
  if (trimmed.startsWith("gitdir:")) {
    return path.resolve(targetDir, trimmed.replace(/^gitdir:\s*/i, ""));
  }

  return gitPath;
}

async function resolveRepoStatePath(targetDir: string): Promise<string> {
  const gitDir = await resolveGitDir(targetDir);
  return gitDir
    ? path.join(gitDir, "info", REPO_STATE_FILENAME)
    : path.join(targetDir, FALLBACK_REPO_STATE_PATH);
}

async function resolveLegacyRepoStatePath(targetDir: string): Promise<string | undefined> {
  const gitDir = await resolveGitDir(targetDir);
  return gitDir ? path.join(gitDir, "info", LEGACY_REPO_STATE_FILENAME) : undefined;
}

export async function loadRepoState(targetDir: string): Promise<RepoState | undefined> {
  const nextPath = await resolveRepoStatePath(targetDir);
  const legacyPath = await resolveLegacyRepoStatePath(targetDir);
  const raw =
    (await readTextIfExists(nextPath)) ??
    (legacyPath ? await readTextIfExists(legacyPath) : undefined);
  if (!raw) {
    return undefined;
  }

  return JSON.parse(raw) as RepoState;
}

export async function writeRepoState(targetDir: string, state: RepoState): Promise<void> {
  await writeTextFile(await resolveRepoStatePath(targetDir), `${JSON.stringify(state, null, 2)}\n`);
}

export function createRepoState(manifest: BootstrapManifest, files: RenderedFile[]): RepoState {
  const licenseFile = files.find((file) => file.path === "LICENSE");
  return {
    manifestHash: sha256(JSON.stringify(manifest)),
    templateVersion: TEMPLATE_VERSION,
    managedFiles: Object.fromEntries(files.map((file) => [file.path, sha256(file.contents)])),
    ...(manifest.license && licenseFile
      ? {
          license: {
            mode: manifest.license.mode,
            ...(manifest.license.mode === "spdx" ? { identifier: manifest.license.identifier } : {}),
            contentSha256: sha256(licenseFile.contents)
          }
        }
      : {})
  };
}

export function createOwnershipSidecar(manifest: BootstrapManifest, files: RenderedFile[]): RenderedFile {
  const managedFiles = Object.fromEntries(
    files
      .filter((file) => file.path !== OWNERSHIP_SIDECAR_PATH)
      .sort((left, right) => left.path.localeCompare(right.path))
      .map((file) => [file.path, { sha256: sha256(file.contents), source: "bootstrap" }])
  );

  return {
    path: OWNERSHIP_SIDECAR_PATH,
    contents: `${JSON.stringify(
      {
        schemaVersion: 1,
        owner: "bootstrap",
        templateVersion: TEMPLATE_VERSION,
        regenerationCommand: "bootstrap apply repo --manifest ./project.bootstrap.yaml",
        ...(manifest.license && managedFiles.LICENSE
          ? {
              license: {
                mode: manifest.license.mode,
                ...(manifest.license.mode === "spdx" ? { identifier: manifest.license.identifier } : {}),
                contentSha256: managedFiles.LICENSE.sha256
              }
            }
          : {}),
        managedFiles
      },
      null,
      2
    )}\n`,
    reason: "Managed-file ownership sidecar"
  };
}
