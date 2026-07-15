import { readdir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import path from "node:path";

import type { ArchetypeKind, BootstrapManifest } from "./types.js";

export const LANGUAGE_PROFILES = [
  "typescript",
  "python",
  "rust",
  "go",
  "swift",
  "terraform",
  "shell",
  "sql-sqlite",
  "documentation"
] as const;

export type LanguageProfile = (typeof LANGUAGE_PROFILES)[number];

export interface LanguageProfileConflict {
  profile: LanguageProfile;
  reason: string;
}

export interface LanguageProfileResolution {
  detected: LanguageProfile[];
  selected: LanguageProfile[];
  conflicts: LanguageProfileConflict[];
}

const ignoredDirectories = new Set([".git", ".next", ".turbo", "build", "coverage", "dist", "node_modules", "target", "vendor"]);

function profileForPath(relativePath: string): LanguageProfile[] {
  const basename = path.posix.basename(relativePath).toLowerCase();
  const extension = path.posix.extname(relativePath).toLowerCase();
  const profiles = new Set<LanguageProfile>();

  if (basename === "package.swift" || extension === ".swift") profiles.add("swift");
  if (basename === "cargo.toml" || extension === ".rs") profiles.add("rust");
  if (basename === "go.mod" || extension === ".go") profiles.add("go");
  if (basename === "pyproject.toml" || basename === "setup.py" || extension === ".py") profiles.add("python");
  if (basename === "tsconfig.json" || basename === "tsconfig.base.json" || extension === ".ts" || extension === ".tsx") profiles.add("typescript");
  if (extension === ".tf") profiles.add("terraform");
  if (extension === ".sh") profiles.add("shell");
  if (extension === ".sql" || extension === ".sqlite" || extension === ".db") profiles.add("sql-sqlite");
  if (basename.startsWith("readme") || relativePath.startsWith("docs/")) profiles.add("documentation");

  return [...profiles];
}

async function collectProfiles(root: string, relativeDir = "", profiles = new Set<LanguageProfile>()): Promise<void> {
  let entries: Dirent<string>[];
  try {
    entries = await readdir(path.join(root, relativeDir), { encoding: "utf8", withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }

  for (const entry of entries) {
    const relativePath = relativeDir ? `${relativeDir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        if (relativePath === "docs") profiles.add("documentation");
        await collectProfiles(root, relativePath, profiles);
      }
      continue;
    }
    if (entry.isFile()) {
      for (const profile of profileForPath(relativePath)) profiles.add(profile);
    }
  }
}

function expectedProfiles(kind: ArchetypeKind): LanguageProfile[] {
  switch (kind) {
    case "nextjs-web":
    case "node-ts-service":
      return ["typescript"];
    case "python-service":
      return ["python"];
    case "generic-empty":
      return [];
  }
}

export async function resolveLanguageProfiles(
  manifest: BootstrapManifest,
  targetDir: string
): Promise<LanguageProfileResolution> {
  const profileSet = new Set<LanguageProfile>();
  await collectProfiles(targetDir, "", profileSet);
  const detected = LANGUAGE_PROFILES.filter((profile) => profileSet.has(profile));
  const expected = expectedProfiles(manifest.archetype.kind);
  const conflicts =
    detected.length === 0
      ? []
      : expected
          .filter((profile) => !profileSet.has(profile))
          .map((profile) => ({
            profile,
            reason: `${manifest.archetype.kind} expects the ${profile} profile, but the target detects ${detected.join(", ")}.`
          }));

  return { detected, selected: detected, conflicts };
}
