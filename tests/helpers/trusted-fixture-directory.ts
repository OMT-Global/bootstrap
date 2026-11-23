import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readRegular } from "../../src/upgrade-host.js";

// The checkout can be under a sticky or read-only mount. Exercise the same ancestry checks as the generator.
export async function trustedFixtureDirectory(prefix: string): Promise<string> {
  for (const parent of [path.join(process.cwd(), "node_modules"), os.tmpdir()]) {
    let directory: string | undefined;
    try {
      directory = await mkdtemp(path.join(await realpath(parent), prefix));
      const probe = path.join(directory, "probe");
      await writeFile(probe, "fixture");
      await readRegular(probe, 7, true);
      await rm(probe);
      return directory;
    } catch {
      if (directory) await rm(directory, { recursive: true, force: true });
    }
  }
  throw new Error("Generator fixture requires private writable ancestry.");
}
