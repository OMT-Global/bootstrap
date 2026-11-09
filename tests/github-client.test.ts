import { describe, expect, it } from "vitest";

import { GitHubClient } from "../src/github/client.js";
import type { CommandOptions, CommandResult, CommandRunner } from "../src/lib/process.js";

const endpoint = "/repos/acme/example/environments/release-publish";
const notFound = { message: "Not Found", documentation_url: "https://docs.github.com/rest", status: "404" };
const environment = { name: "release-publish", protection_rules: [] };

function response(status: number, body: unknown, overrides: Partial<CommandResult> = {}): CommandResult {
  return {
    stdout: `HTTP/2.0 ${status} ${status === 200 ? "OK" : status === 404 ? "Not Found" : "Error"}\nContent-Type: application/json; charset=utf-8\r\n\r\n${JSON.stringify(body)}`,
    stderr: status === 404 ? "gh: Not Found (HTTP 404)\n" : "",
    exitCode: status === 200 ? 0 : 1,
    ...overrides
  };
}

function clientFor(result: CommandResult) {
  return new GitHubClient({ runner: async () => result });
}

async function expectUnknown(result: CommandResult) {
  await expect(clientFor(result).getReleaseEnvironment("acme", "example")).rejects.toThrow("release-publish read UNKNOWN:");
}

describe("GitHubClient scoped release environment read", () => {
  it("requests only the fixed environment with response status and the existing headers", async () => {
    const calls: Array<{ command: string; args: string[] | undefined; options: CommandOptions | undefined }> = [];
    const runner: CommandRunner = async (command, args, options) => {
      calls.push({ command, args, options });
      return response(200, environment);
    };
    const client = new GitHubClient({ runner, cwd: "/fixture/repo" });
    await expect(client.getReleaseEnvironment("acme", "example")).resolves.toEqual(environment);
    expect(calls).toEqual([{
      command: "gh",
      args: ["api", "--method", "GET", "--include", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint],
      options: { cwd: "/fixture/repo" }
    }]);
  });

  it.each(["mixed", "LF", "CRLF"])("accepts captured 404 with valid JSON and canonical completion (%s)", async (ending) => {
    const result = response(404, notFound);
    if (ending === "LF") result.stdout = result.stdout.replace(/\r\n/g, "\n");
    if (ending === "CRLF") {
      result.stdout = result.stdout.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
      result.stderr = result.stderr.replace(/\n/g, "\r\n");
    }
    await expect(clientFor(result).getReleaseEnvironment("acme", "example")).resolves.toBeUndefined();
  });

  it("accepts the documented error shape without the optional status and documentation fields", async () => {
    await expect(clientFor(response(404, { message: "Not Found" })).getReleaseEnvironment("acme", "example")).resolves.toBeUndefined();
  });

  it("returns a successful body containing 404 as data rather than absence", async () => {
    const body = { name: "release-publish", message: "404", status: "404" };
    await expect(clientFor(response(200, body)).getReleaseEnvironment("acme", "example")).resolves.toEqual(body);
  });

  it.each([401, 403, 500, 502])("rejects actual HTTP %s even when its body and stderr say 404", async (status) => {
    const result = response(status, notFound, { stderr: "gh: Not Found (HTTP 404)\n" });
    await expect(clientFor(result).getReleaseEnvironment("acme", "example")).rejects.toThrow(`HTTP ${status}`);
  });

  it.each([0, 2, 4, -1])("rejects 404 with inconsistent exit code %s", async (exitCode) => {
    await expectUnknown(response(404, notFound, { exitCode }));
  });

  it.each([1, 4, -1])("rejects 200 with non-success exit code %s", async (exitCode) => {
    await expectUnknown(response(200, environment, { exitCode }));
  });

  it.each(["connection reset HTTP 404", "", "gh: Not Found (HTTP 404)\nextra diagnostic\n"])("rejects 404 with unverified completion diagnostics %j", async (stderr) => {
    await expectUnknown(response(404, notFound, { stderr }));
  });

  it("rejects unexpected diagnostics on a nominal successful response", async () => {
    await expectUnknown(response(200, environment, { stderr: "transport warning" }));
  });

  it.each([
    "",
    '{"message":"Not Found"}',
    'gh: Not Found (HTTP 404)\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\n\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\nContent-Type: application/json\nHTTP/2.0 404 Not Found\n\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\nContent-Type: application/json\ncontent-type: application/json\n\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\nContent-Type: application/json\n invalid-header\n\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\nContent-Type: text/plain\n\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\nContent-Type: application/json\u0000\n\n{"message":"Not Found"}',
    'HTTP/2.0 404 Not Found\nContent-Type: application/json\n\n{"message":"Not Found"}\nHTTP/2.0 200 OK\n\n{}',
    'HTTP/2.0 404 Not Found\nContent-Type: application/json\n\n{"message":"Not Found"}{}',
    'HTTP/2.0 0404 Not Found\nContent-Type: application/json\n\n{"message":"Not Found"}',
    'HTTP/2.0 4044 Not Found\nContent-Type: application/json\n\n{"message":"Not Found"}',
    'HTTP/9.0 404 Not Found\nContent-Type: application/json\n\n{"message":"Not Found"}'
  ])("rejects unavailable, malformed or ambiguous framing %#", async (stdout) => {
    await expectUnknown({ stdout, stderr: "gh: Not Found (HTTP 404)\n", exitCode: 1 });
  });

  it.each([null, [], "Not Found", {}, { message: 404 }, { message: "Not Found", status: 404 }, { message: "Not Found", status: "403" }, { message: "Not Found", documentation_url: [] }])("rejects malformed 404 error response %#", async (body) => {
    await expectUnknown(response(404, body));
  });

  it.each([200, 404])("rejects malformed JSON on HTTP %s without reporting response details", async (status) => {
    await expectUnknown(response(status, null, { stdout: `HTTP/2.0 ${status} Error\nContent-Type: application/json\n\n{"fixture-body-canary"` }));
  });

  it("does not turn a JSON parse error at position 404 into absence", async () => {
    const body = '{"key":0' + " ".repeat(396) + "x}";
    expect(() => JSON.parse(body)).toThrow("404");
    await expectUnknown(response(200, null, { stdout: `HTTP/2.0 200 OK\nContent-Type: application/json\n\n${body}` }));
  });

  it("does not expose response headers, JSON, stderr or a transport cause", async () => {
    const results = [
      response(403, { message: "fixture-body-canary" }, { stderr: "fixture-stderr-canary" }),
      response(404, notFound, { stderr: "fixture-stderr-canary" }),
      response(200, null, { stdout: "HTTP/2.0 200 OK\nContent-Type: application/json\nX-Canary: fixture-header-canary\n\nfixture-body-canary" })
    ];
    for (const result of results) {
      const error = await clientFor(result).getReleaseEnvironment("acme", "example").catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).toContain("UNKNOWN");
      expect(String(error)).not.toMatch(/fixture-(?:header|body|stderr)-canary/);
      expect((error as Error).cause).toBeUndefined();
    }
    const runner: CommandRunner = async () => { throw new Error("fixture-transport-canary HTTP 404"); };
    const error = await new GitHubClient({ runner }).getReleaseEnvironment("acme", "example").catch((caught: unknown) => caught);
    expect(String(error)).toBe("Error: release-publish read UNKNOWN: transport");
    expect((error as Error).cause).toBeUndefined();
  });

  it.each(["", ".", ".."])("rejects an invalid fixed-target component %j before invoking gh", async (invalid) => {
    let calls = 0;
    const client = new GitHubClient({ runner: async () => { calls += 1; return response(404, notFound); } });
    await expect(client.getReleaseEnvironment(invalid, "example")).rejects.toThrow("UNKNOWN: target");
    await expect(client.getReleaseEnvironment("acme", invalid)).rejects.toThrow("UNKNOWN: target");
    expect(calls).toBe(0);
  });
});

describe("GitHubClient legacy API contract", () => {
  it("preserves existing commands, request headers, JSON input and cwd", async () => {
    const calls: Array<{ command: string; args: string[] | undefined; options: CommandOptions | undefined }> = [];
    const runner: CommandRunner = async (command, args, options) => {
      calls.push({ command, args, options });
      return { stdout: '{"id":7}', stderr: "", exitCode: 0 };
    };
    const client = new GitHubClient({ runner, cwd: "/fixture/repo" });
    await expect(client.api("PUT", "/repos/acme/example", { enabled: true })).resolves.toEqual({ id: 7 });
    expect(calls).toEqual([{
      command: "gh",
      args: ["api", "--method", "PUT", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28", "/repos/acme/example", "--input", "-"],
      options: { cwd: "/fixture/repo", input: '{"enabled":true}' }
    }]);
  });

  it("preserves empty successful responses and unconfigured command options", async () => {
    let options: CommandOptions | undefined = { cwd: "unexpected" };
    const client = new GitHubClient({ runner: async (_command, _args, receivedOptions) => {
      options = receivedOptions;
      return { stdout: " \n", stderr: "", exitCode: 0 };
    } });
    await expect(client.api("GET", "/fixture")).resolves.toEqual({});
    expect(options).toBeUndefined();
  });

  it("preserves legacy errors and its existing text-based tryApi behavior", async () => {
    const client = clientFor({ stdout: "", stderr: "legacy transport HTTP 404", exitCode: 1 });
    await expect(client.api("GET", "/fixture")).rejects.toThrow("legacy transport HTTP 404");
    await expect(client.tryApi("GET", "/fixture")).resolves.toBeUndefined();
    const malformed = clientFor({ stdout: "invalid-json", stderr: "", exitCode: 0 });
    await expect(malformed.api("GET", "/fixture")).rejects.toBeInstanceOf(SyntaxError);
  });
});
