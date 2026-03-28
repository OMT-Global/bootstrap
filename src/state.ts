import path from "node:path";

import { readTextIfExists, writeTextFile } from "./lib/fs.js";
import { sha256 } from "./lib/hash.js";
import type { BootstrapManifest, RenderedFile, RepoState } from "./types.js";

export const TEMPLATE_VERSION = "2026.03.28.1";
export const REPO_STATE_PATH = ".bootstrap/bootstrap-state.json";
export const HOME_STATE_PATH = ".new-project-bootstrap/home-state.json";

export async function loadRepoState(targetDir: string): Promise<RepoState | undefined> {
  const raw = await readTextIfExists(path.join(targetDir, REPO_STATE_PATH));
  if (!raw) {
    return undefined;
  }

  return JSON.parse(raw) as RepoState;
}

export async function writeRepoState(targetDir: string, state: RepoState): Promise<void> {
  await writeTextFile(path.join(targetDir, REPO_STATE_PATH), `${JSON.stringify(state, null, 2)}\n`);
}

export function createRepoState(manifest: BootstrapManifest, files: RenderedFile[]): RepoState {
  return {
    manifestHash: sha256(JSON.stringify(manifest)),
    templateVersion: TEMPLATE_VERSION,
    managedFiles: Object.fromEntries(files.map((file) => [file.path, sha256(file.contents)]))
  };
}
