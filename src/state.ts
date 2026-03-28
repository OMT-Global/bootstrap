import { stat } from "node:fs/promises";
import path from "node:path";

import { readTextIfExists, writeTextFile } from "./lib/fs.js";
import { sha256 } from "./lib/hash.js";
import type { BootstrapManifest, RenderedFile, RepoState } from "./types.js";

export const TEMPLATE_VERSION = "2026.03.28.2";
export const FALLBACK_REPO_STATE_PATH = ".bootstrap/bootstrap-state.json";
export const HOME_STATE_PATH = ".new-project-bootstrap/home-state.json";

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
    ? path.join(gitDir, "info", "new-project-bootstrap-state.json")
    : path.join(targetDir, FALLBACK_REPO_STATE_PATH);
}

export async function loadRepoState(targetDir: string): Promise<RepoState | undefined> {
  const raw = await readTextIfExists(await resolveRepoStatePath(targetDir));
  if (!raw) {
    return undefined;
  }

  return JSON.parse(raw) as RepoState;
}

export async function writeRepoState(targetDir: string, state: RepoState): Promise<void> {
  await writeTextFile(await resolveRepoStatePath(targetDir), `${JSON.stringify(state, null, 2)}\n`);
}

export function createRepoState(manifest: BootstrapManifest, files: RenderedFile[]): RepoState {
  return {
    manifestHash: sha256(JSON.stringify(manifest)),
    templateVersion: TEMPLATE_VERSION,
    managedFiles: Object.fromEntries(files.map((file) => [file.path, sha256(file.contents)]))
  };
}
