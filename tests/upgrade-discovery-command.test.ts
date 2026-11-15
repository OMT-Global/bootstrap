import { Readable } from "node:stream";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { formatPublicDiscovery, readPublicReadToken, runPublicDiscovery } from "../src/upgrade-discovery-command.js";
import type { PublicManifestDiscovery } from "../src/upgrade-discovery.js";

const token = "fabricated-read-capability-0123456789";
const report = (status: "complete" | "incomplete"): PublicManifestDiscovery => ({
  organization: "acme", scope: "public-manifest-discovery", verification: { policy: "unverified", drift: "unverified", exceptions: "unverified", pilots: "unverified" }, status, requests: 3, receivedBytes: 100,
  repositories: [{ repository: "acme/service", repositoryId: 1, defaultBranch: "main", fork: false, archived: false, disabled: false, outcome: "managed" }],
  ...(status === "incomplete" ? { failure: { code: "rate-limit" as const } } : {})
});

afterEach(() => vi.useRealTimers());

describe("public fleet discovery command", () => {
  it.each([token, `${token}\n`, `${token}\r\n`])("accepts a bounded capability from a pipe without echoing it (%#)", async (value) => {
    await expect(readPublicReadToken(Readable.from([value]))).resolves.toBe(token);
  });

  it.each(["", "short", `${token}\nextra`, `${token}\0`, `\ufeff${token}`, "x".repeat(4097), Buffer.from([0xff])])(
    "rejects invalid, oversized or non-UTF-8 input without echoing it (%#)", async (value) => {
      await expect(readPublicReadToken(Readable.from([value]))).rejects.toThrow("Unable to read a valid public read capability.");
    }
  );

  it("refuses terminal input rather than allowing an echoed credential", async () => {
    const input = Readable.from([token]) as Readable & { isTTY?: boolean };
    input.isTTY = true;
    await expect(readPublicReadToken(input)).rejects.toThrow("nonterminal stream");
  });

  it("sanitizes stream errors and enforces a bounded wait", async () => {
    const failing = new Readable({ read() { this.destroy(new Error(`private stream error ${token}`)); } });
    await expect(readPublicReadToken(failing)).rejects.toThrow("Unable to read a valid public read capability.");
    vi.useFakeTimers();
    const hanging = new Readable({ read() {} });
    const result = readPublicReadToken(hanging).catch((error: Error) => error.message);
    await vi.advanceTimersByTimeAsync(15_000);
    await expect(result).resolves.toBe("Unable to read a valid public read capability.");
  });

  it("does not read stdin in anonymous mode and reports that eligibility is unverified", async () => {
    const input = new Readable({ read() { throw new Error("stdin should not be read"); } });
    const discover = vi.fn(async () => report("complete"));
    const result = await runPublicDiscovery("acme", {}, input, discover);
    expect(discover).toHaveBeenCalledWith("acme", {});
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('"acme/service": managed');
    expect(result.output).toContain("eligibility are not verified");
  });

  it("rejects an invalid organization before reading a capability or starting discovery", async () => {
    const input = new Readable({ read() { throw new Error("stdin should not be read"); } });
    const discover = vi.fn(async () => report("complete"));
    await expect(runPublicDiscovery("../other", { readTokenStdin: true }, input, discover)).rejects.toThrow("Invalid public organization.");
    expect(discover).not.toHaveBeenCalled();
  });

  it("passes the piped capability only to discovery, does not include it in JSON, and fails closed on partial results", async () => {
    const discover = vi.fn(async () => report("incomplete"));
    const result = await runPublicDiscovery("acme", { json: true, readTokenStdin: true }, Readable.from([`${token}\n`]), discover);
    expect(discover).toHaveBeenCalledWith("acme", { publicReadToken: token });
    expect(result.exitCode).toBe(1);
    expect(JSON.parse(result.output)).toMatchObject({ status: "incomplete", failure: { code: "rate-limit" } });
    expect(result.output).not.toContain(token);
  });

  it("escapes terminal control characters in displayed repository names", () => {
    const unsafe = { ...report("complete"), repositories: [{ ...report("complete").repositories[0]!, repository: "acme/\u001b[31m" }] };
    expect(formatPublicDiscovery(unsafe)).not.toContain("\u001b");
    expect(formatPublicDiscovery(unsafe)).toContain("\\u001b");
  });

  it("exposes the read-only command and fails closed on an invalid piped capability", () => {
    const cli = path.resolve("src/cli.ts");
    const env = { PATH: process.env.PATH ?? "" };
    const help = spawnSync(process.execPath, ["--import", "tsx", cli, "discover-public-fleet", "--help"], { encoding: "utf8", env });
    expect(help.status, help.stderr).toBe(0);
    expect(help.stdout).toContain("--read-token-stdin");
    const badInput = "bad credential input canary";
    const bad = spawnSync(process.execPath, ["--import", "tsx", cli, "discover-public-fleet", "--org", "acme", "--read-token-stdin"], { encoding: "utf8", input: badInput, env });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain("Unable to read a valid public read capability.");
    expect(`${bad.stdout}${bad.stderr}`).not.toContain(badInput);
  });

  it("runs the real CLI end to end against a fabricated GitHub provider without exposing its piped capability", () => {
    const fixture = path.resolve("tests/fixtures/public-discovery-cli-fixture.mjs");
    const args = ["--import", "tsx", fixture, "discover-public-fleet", "--org", "acme", "--json", "--read-token-stdin"];
    const env = { PATH: process.env.PATH ?? "" };
    const result = spawnSync(process.execPath, args, { encoding: "utf8", input: `${token}\n`, timeout: 15_000, env });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ status: "complete", scope: "public-manifest-discovery", verification: { policy: "unverified" }, repositories: [{ repository: "acme/service", outcome: "managed", manifest: { summary: { normalizedClass: "cli" } } }] });
    expect(`${result.stdout}${result.stderr}`).not.toContain(token);
    const failed = spawnSync(process.execPath, args, { encoding: "utf8", input: `${token}\n`, timeout: 15_000, env: { ...env, DISCOVERY_FIXTURE_MODE: "object-404" } });
    expect(failed.status, failed.stderr).toBe(1);
    expect(JSON.parse(failed.stdout)).toMatchObject({ status: "incomplete", failure: { code: "http-error", httpStatus: 404 } });
    expect(`${failed.stdout}${failed.stderr}`).not.toContain(token);
  });
});
