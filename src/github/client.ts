import type { CommandRunner } from "../lib/process.js";
import { execRunner } from "../lib/process.js";

export interface GitHubApiOptions {
  runner?: CommandRunner;
  cwd?: string;
}

function releaseReadUnknown(category: string, status?: number): never {
  throw new Error(
    `release-publish read UNKNOWN: ${category}${status === undefined ? "" : ` (HTTP ${status})`}`
  );
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

  async getReleaseEnvironment<T>(owner: string, repo: string): Promise<T | undefined> {
    if ([owner, repo].some((part) =>
      typeof part !== "string" || part.length === 0 || part === "." || part === ".."
    )) {
      return releaseReadUnknown("target");
    }
    const endpoint = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/environments`;
    const existing = await this.readReleaseEnvironment<T>(`${endpoint}/release-publish`);
    if (existing !== undefined) return existing;

    // A private-resource 404 may mask missing Actions read permission, even when
    // Administration write permits PUT. Require an independent complete list.
    const ids = new Set<number>();
    const names = new Set<string>();
    let total: number | undefined;
    for (let page = 1; page <= 11; page += 1) {
      const body = await this.readReleaseEnvironment<unknown>(`${endpoint}?per_page=100&page=${page}`);
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        return releaseReadUnknown("environment list schema");
      }
      const list = body as Record<string, unknown>;
      const count = list.total_count as number;
      if (
        !Number.isSafeInteger(count) || count < 0 || count > 1000 ||
        !Array.isArray(list.environments) || list.environments.length > 100 ||
        (total !== undefined && count !== total)
      ) {
        return releaseReadUnknown("environment list count or limit");
      }
      total = count;
      for (const entry of list.environments) {
        if (
          entry === null || typeof entry !== "object" || Array.isArray(entry) ||
          !Number.isSafeInteger(entry.id) || entry.id <= 0 ||
          typeof entry.name !== "string" || entry.name.length === 0 || entry.name.length > 255
        ) {
          return releaseReadUnknown("environment list item");
        }
        const name = entry.name.toLowerCase();
        if (ids.has(entry.id) || names.has(name) || name === "release-publish") {
          return releaseReadUnknown("environment list duplicate or existing target");
        }
        ids.add(entry.id);
        names.add(name);
      }
      if (ids.size > total) return releaseReadUnknown("environment list count drift");
      if (list.environments.length < 100) {
        if (ids.size !== total) return releaseReadUnknown("environment list incomplete");
        return undefined;
      }
    }
    return releaseReadUnknown("environment list page limit");
  }

  private async readReleaseEnvironment<T>(endpoint: string): Promise<T | undefined> {
    let result: Awaited<ReturnType<CommandRunner>>;
    try {
      result = await this.runner(
        "gh",
        [
          "api",
          "--method",
          "GET",
          "--include",
          "-H",
          "Accept: application/vnd.github+json",
          "-H",
          "X-GitHub-Api-Version: 2022-11-28",
          endpoint
        ],
        this.cwd ? { cwd: this.cwd } : undefined
      );
    } catch {
      return releaseReadUnknown("transport");
    }

    // gh prints the status with LF and headers with CRLF; accept both line endings.
    const separator = /\r?\n\r?\n/.exec(result.stdout);
    if (!separator) return releaseReadUnknown("response framing");
    const lines = result.stdout.slice(0, separator.index).split(/\r?\n/);
    const statusLine = /^HTTP\/(?:1\.[01]|2\.0) ([1-5][0-9]{2})(?: [\x20-\x7e]*)?$/.exec(lines.shift() ?? "");
    if (!statusLine) return releaseReadUnknown("response framing");
    const headers = new Map<string, string>();
    for (const line of lines) {
      const header = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([^\x00-\x08\x0a-\x1f\x7f]*)$/.exec(line);
      if (!header || headers.has(header[1]!.toLowerCase())) return releaseReadUnknown("response framing");
      headers.set(header[1]!.toLowerCase(), header[2]!);
    }
    const status = Number(statusLine[1]);
    if (!/^application\/(?:json|vnd\.github\+json)(?:[ \t]*;[ \t]*charset=(?:utf-8|"utf-8"))?$/i.test(headers.get("content-type") ?? "")) {
      return releaseReadUnknown("response content type", status);
    }
    let body: unknown;
    try {
      body = JSON.parse(result.stdout.slice(separator.index + separator[0].length));
    } catch {
      return releaseReadUnknown("response JSON", status);
    }
    if (status === 200 && result.exitCode === 0 && result.stderr === "") return body as T;
    if (status !== 404) return releaseReadUnknown("HTTP response", status);
    if (result.exitCode !== 1 || result.stderr.replace(/\r\n/g, "\n") !== "gh: Not Found (HTTP 404)\n") {
      return releaseReadUnknown("inconsistent transport result", status);
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) return releaseReadUnknown("error response", status);
    const errorBody = body as Record<string, unknown>;
    if (
      errorBody.message !== "Not Found" ||
      (errorBody.status !== undefined && errorBody.status !== "404") ||
      (errorBody.documentation_url !== undefined && typeof errorBody.documentation_url !== "string")
    ) {
      return releaseReadUnknown("error response", status);
    }
    // Status comes only from the captured response. Canonical stderr is a secondary
    // completion check: extra/unknown diagnostics fail closed. A valid 404 still
    // needs an independently successful complete list before it can permit PUT.
    return undefined;
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
