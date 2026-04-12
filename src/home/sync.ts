import { readdir, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { readTextIfExists, removeFileIfExists, writeTextFile } from "../lib/fs.js";
import { sha256 } from "../lib/hash.js";
import { HOME_STATE_PATH, LEGACY_HOME_STATE_PATH } from "../state.js";
import type {
  BootstrapManifest,
  ChangeType,
  PlannedHomeAction
} from "../types.js";

interface HomeFile {
  sourcePath: string;
  relativePath: string;
  targetPath: string;
  contents: string;
}

interface HomeState {
  managedFiles: Record<string, string>;
}

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
}

async function walkFiles(rootDir: string, prefix = ""): Promise<string[]> {
  const entries = await readdir(rootDir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const relativePath = path.posix.join(prefix, entry.name);
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walkFiles(fullPath, relativePath)));
    } else if (entry.isFile()) {
      files.push(relativePath);
    }
  }

  return files.sort();
}

async function loadProfileFiles(sourceDir: string, targetRoot: string): Promise<HomeFile[]> {
  const relativePaths = await walkFiles(sourceDir);
  return Promise.all(
    relativePaths.map(async (relativePath) => {
      const sourcePath = path.join(sourceDir, relativePath);
      return {
        sourcePath,
        relativePath,
        targetPath: path.join(targetRoot, relativePath),
        contents: await readFile(sourcePath, "utf8")
      };
    })
  );
}

async function loadHomeState(homeDir: string): Promise<HomeState> {
  const raw =
    (await readTextIfExists(path.join(homeDir, HOME_STATE_PATH))) ??
    (await readTextIfExists(path.join(homeDir, LEGACY_HOME_STATE_PATH)));
  if (!raw) {
    return { managedFiles: {} };
  }

  try {
    return JSON.parse(raw) as HomeState;
  } catch {
    return { managedFiles: {} };
  }
}

async function writeHomeState(homeDir: string, state: HomeState): Promise<void> {
  await writeTextFile(path.join(homeDir, HOME_STATE_PATH), `${JSON.stringify(state, null, 2)}\n`);
}

function changeTypeFor(existingContents: string | undefined, nextContents: string): ChangeType {
  if (existingContents === undefined) {
    return "create";
  }

  return existingContents === nextContents ? "unchanged" : "update";
}

export async function planHome(
  manifest: BootstrapManifest,
  homeDir = os.homedir()
): Promise<{ actions: PlannedHomeAction[]; files: HomeFile[] }> {
  const mappings: Array<{ sourceDir: string; targetRoot: string }> = [];
  const baseRoot = repoRoot();

  if (manifest.agents.manageCodexHome) {
    mappings.push({
      sourceDir: path.join(baseRoot, "profiles/home/codex"),
      targetRoot: path.join(homeDir, ".codex")
    });
  }

  if (manifest.agents.manageClaudeHome) {
    mappings.push({
      sourceDir: path.join(baseRoot, "profiles/home/claude"),
      targetRoot: path.join(homeDir, ".claude")
    });
  }

  const files = (await Promise.all(
    mappings.map((mapping) => loadProfileFiles(mapping.sourceDir, mapping.targetRoot))
  )).flat();

  const actions: PlannedHomeAction[] = [];
  for (const file of files) {
    const existingContents = await readTextIfExists(file.targetPath);
    actions.push({
      path: path.relative(homeDir, file.targetPath),
      type: changeTypeFor(existingContents, file.contents),
      reason: "Managed portable home profile asset"
    });
  }

  const homeState = await loadHomeState(homeDir);
  const nextManagedPaths = new Set(files.map((file) => path.relative(homeDir, file.targetPath)));

  for (const stalePath of Object.keys(homeState.managedFiles)) {
    if (!nextManagedPaths.has(stalePath)) {
      actions.push({
        path: stalePath,
        type: "delete",
        reason: "Previously managed home asset is no longer part of the profile"
      });
    }
  }

  return {
    actions: actions.sort((left, right) => left.path.localeCompare(right.path)),
    files
  };
}

export async function applyHome(manifest: BootstrapManifest, homeDir = os.homedir()): Promise<PlannedHomeAction[]> {
  const plan = await planHome(manifest, homeDir);

  for (const file of plan.files) {
    await writeTextFile(file.targetPath, file.contents);
  }

  for (const action of plan.actions) {
    if (action.type === "delete") {
      await removeFileIfExists(path.join(homeDir, action.path));
    }
  }

  const managedFiles = Object.fromEntries(
    plan.files.map((file) => [path.relative(homeDir, file.targetPath), sha256(file.contents)])
  );
  await writeHomeState(homeDir, { managedFiles });
  return plan.actions;
}
