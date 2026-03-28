import path from "node:path";

import { renderManagedFiles } from "./archetypes.js";
import { readTextIfExists, removeFileIfExists, writeTextFile } from "./lib/fs.js";
import { createRepoState, loadRepoState, writeRepoState } from "./state.js";
import type { BootstrapManifest, PlannedFileChange, RenderedFile } from "./types.js";

export interface RepoPlan {
  changes: PlannedFileChange[];
  files: RenderedFile[];
}

export async function planRepo(manifest: BootstrapManifest, targetDir: string): Promise<RepoPlan> {
  const files = renderManagedFiles(manifest);
  const existingState = await loadRepoState(targetDir);
  const changes: PlannedFileChange[] = [];

  for (const file of files) {
    const existingContents = await readTextIfExists(path.join(targetDir, file.path));
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
    files
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
