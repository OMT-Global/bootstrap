import type { CommandRunner } from "../lib/process.js";
import { execRunner } from "../lib/process.js";

export interface GitHubApiOptions {
  runner?: CommandRunner;
  cwd?: string;
}

export class GitHubClient {
  private readonly runner: CommandRunner;
  private readonly cwd: string | undefined;

  constructor(options: GitHubApiOptions = {}) {
    this.runner = options.runner ?? execRunner;
    this.cwd = options.cwd;
  }

  async isAvailable(): Promise<boolean> {
    const result = await this.runner("gh", ["--version"], this.cwd ? { cwd: this.cwd } : undefined);
    return result.exitCode === 0;
  }

  async isAuthenticated(): Promise<boolean> {
    const result = await this.runner(
      "gh",
      ["auth", "status"],
      this.cwd ? { cwd: this.cwd } : undefined
    );
    return result.exitCode === 0;
  }

  async api<T>(method: string, endpoint: string, payload?: unknown): Promise<T> {
    const args = [
      "api",
      "--method",
      method,
      "-H",
      "Accept: application/vnd.github+json",
      "-H",
      "X-GitHub-Api-Version: 2022-11-28",
      endpoint
    ];

    if (payload !== undefined) {
      args.push("--input", "-");
    }

    const options =
      payload === undefined
        ? this.cwd
          ? { cwd: this.cwd }
          : undefined
        : this.cwd
          ? { cwd: this.cwd, input: JSON.stringify(payload) }
          : { input: JSON.stringify(payload) };

    const result = await this.runner("gh", args, options);

    if (result.exitCode !== 0) {
      throw new Error(result.stderr.trim() || result.stdout.trim() || `gh api failed for ${endpoint}`);
    }

    if (result.stdout.trim().length === 0) {
      return {} as T;
    }

    return JSON.parse(result.stdout) as T;
  }

  async tryApi<T>(method: string, endpoint: string, payload?: unknown): Promise<T | undefined> {
    try {
      return await this.api<T>(method, endpoint, payload);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("404")) {
        return undefined;
      }
      throw error;
    }
  }
}
