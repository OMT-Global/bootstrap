import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";

export async function readTextIfExists(filePath: string): Promise<string | undefined> {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (isNotFound(error)) {
      return undefined;
    }
    throw error;
  }
}

export async function ensureDirectory(dirPath: string): Promise<void> {
  await mkdir(dirPath, { recursive: true });
}

export async function writeTextFile(
  filePath: string,
  contents: string,
  executable = false
): Promise<void> {
  await ensureDirectory(path.dirname(filePath));
  await writeFile(filePath, contents, "utf8");
  if (executable) {
    await chmod(filePath, 0o755);
  }
}

export async function removeFileIfExists(filePath: string): Promise<void> {
  await rm(filePath, { force: true });
}

export async function exists(filePath: string): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch (error) {
    if (isNotFound(error)) {
      return false;
    }
    throw error;
  }
}

function isNotFound(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}
