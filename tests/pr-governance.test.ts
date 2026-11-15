import { execFile, spawn } from "node:child_process";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect, type Server, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

type Fixture = { files: unknown[]; commits: unknown[]; reviews: unknown[] };
const execFileAsync = promisify(execFile);
const networkDirectories: string[] = [];
const fabricatedToken = "fabricated-governance-transport-token";

afterEach(async () => {
  await Promise.all(networkDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function networkDirectory() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-governance-transport-"));
  networkDirectories.push(directory);
  // Curl reads only this fabricated configuration, never the operator's curlrc.
  await writeFile(path.join(directory, ".curlrc"), "");
  return directory;
}

async function runNetworkGovernance(directory: string, base: string, overrides: Record<string, string> = {}) {
  return await new Promise<{ code: number; output: string }>((resolve, reject) => {
    const child = spawn("bash", [path.resolve("scripts/ci/check-pr-governance.sh")], {
      cwd: directory,
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        CURL_HOME: directory,
        PR_TITLE: "fix: exercise fabricated transport",
        PR_BODY: "Material change: no",
        PR_AUTHOR: "fixture-author",
        PR_FILES_URL: `${base}/files`,
        PR_COMMITS_URL: `${base}/commits`,
        PR_REVIEWS_URL: `${base}/reviews`,
        GITHUB_TOKEN: fabricatedToken,
        ...overrides
      }
    });
    child.stdin.end();
    let output = "";
    const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("error", (error) => { clearTimeout(timeout); reject(error); });
    child.on("close", (code) => { clearTimeout(timeout); resolve({ code: code ?? 1, output }); });
  });
}

async function installCurlProbe(directory: string) {
  const probe = path.join(directory, "curl");
  const log = path.join(directory, "curl-requests.jsonl");
  await writeFile(probe, `#!${process.execPath}
const fs = require("node:fs");
fs.appendFileSync(process.env.CURL_PROBE_LOG, JSON.stringify({argv: process.argv.slice(2), stdin: fs.readFileSync(0, "utf8")}) + "\\n");
process.stdout.write("[]");
process.exit(Number(process.env.CURL_PROBE_EXIT || "0"));
`);
  await chmod(probe, 0o755);
  return { log, env: { PATH: `${directory}:${process.env.PATH ?? "/usr/bin:/bin"}`, CURL_PROBE_LOG: log } };
}

async function readProbe(log: string): Promise<Array<{ argv: string[]; stdin: string }>> {
  return (await readFile(log, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture did not receive a TCP port");
  return address.port;
}

async function closeServer(server: Server) {
  if (server.listening) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

async function runGovernance(fixture: Fixture, overrides: Record<string, string> = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-pr-governance-"));
  const paths = {
    files: path.join(directory, "files.json"),
    commits: path.join(directory, "commits.json"),
    reviews: path.join(directory, "reviews.json")
  };
  await Promise.all([
    writeFile(paths.files, JSON.stringify(fixture.files)),
    writeFile(paths.commits, JSON.stringify(fixture.commits)),
    writeFile(paths.reviews, JSON.stringify(fixture.reviews))
  ]);
  const result = await new Promise<{ code: number; output: string }>((resolve, reject) => {
    const child = spawn("bash", [path.resolve("scripts/ci/check-pr-governance.sh")], {
      cwd: directory,
      env: {
        ...process.env,
        PR_TITLE: "feat: validate fixtures",
        PR_BODY: "Material change: no",
        PR_AUTHOR: "author",
        PR_FILES_FILE: paths.files,
        PR_COMMITS_FILE: paths.commits,
        PR_REVIEWS_FILE: paths.reviews,
        ...overrides
      }
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, output }));
  });
  return { ...result, directory };
}

describe("check-pr-governance", () => {
  it("reports synthetic title, DCO, and changed-line failures with its exclusions", async () => {
    const result = await runGovernance({
      files: [{ filename: "src/large.ts", additions: 801, deletions: 0 }, { filename: "docs/guide.md", additions: 50, deletions: 0 }],
      commits: [{ sha: "1234567890abcdef", author: { login: "human", type: "User" }, commit: { message: "feat: no signoff" } }],
      reviews: []
    }, { PR_TITLE: "missing conventional title" });

    expect(result.code).toBe(1);
    expect(result.output).toContain("PRS-PR-TITLE-001");
    expect(result.output).toContain("PRS-DCO-001");
    expect(result.output).toContain("PRS-PR-SIZE-001");
    expect(result.output).toContain("docs/guide.md");
  });

  it("exempts only pull requests opened before configured governance enforcement", async () => {
    const fixture = {
      files: [{ filename: "src/large.ts", additions: 801, deletions: 0 }],
      commits: [{ sha: "1234567890abcdef", author: { login: "human", type: "User" }, commit: { message: "feat: no signoff" } }],
      reviews: []
    };
    const legacy = await runGovernance(fixture, {
      PR_TITLE: "missing conventional title",
      PR_CREATED_AT: "2026-07-13T16:07:09Z",
      PR_GOVERNANCE_ENFORCE_AFTER: "2026-07-13T23:00:00Z"
    });
    const current = await runGovernance(fixture, {
      PR_TITLE: "missing conventional title",
      PR_CREATED_AT: "2026-07-14T00:00:00Z",
      PR_GOVERNANCE_ENFORCE_AFTER: "2026-07-13T23:00:00Z"
    });
    const malformed = await runGovernance(fixture, {
      PR_TITLE: "missing conventional title",
      PR_CREATED_AT: "not-a-timestamp",
      PR_GOVERNANCE_ENFORCE_AFTER: "2026-07-13T23:00:00Z"
    });

    expect(legacy.code).toBe(0);
    expect(legacy.output).toContain("PRS-PR-GOVERNANCE-LEGACY-001");
    expect(current.code).toBe(1);
    expect(current.output).toContain("PRS-PR-TITLE-001");
    expect(current.output).toContain("PRS-DCO-001");
    expect(malformed.code).toBe(1);
    expect(malformed.output).toContain("PRS-ENFORCEMENT-INPUT-001");
  });

  it("accepts a material change with an accepted ADR and independent reviewer", async () => {
    const result = await runGovernance({
      files: [{ filename: "src/policy.ts", additions: 10, deletions: 2 }],
      commits: [{ sha: "abcdef1234567890", author: { login: "human", type: "User" }, commit: { message: "feat: policy\n\nSigned-off-by: Human <human@example.com>" } }],
      reviews: [{ state: "APPROVED", user: { login: "reviewer", type: "User" } }]
    }, { PR_BODY: "Material change: yes\nADR: docs/decisions/ADR-0001-test.md" });
    await mkdir(path.join(result.directory, "docs", "decisions"), { recursive: true });
    await writeFile(path.join(result.directory, "docs", "decisions", "ADR-0001-test.md"), "# Decision\n\nStatus: Accepted\n");

    const rerun = await new Promise<{ code: number; output: string }>((resolve, reject) => {
      const child = spawn("bash", [path.resolve("scripts/ci/check-pr-governance.sh")], {
        cwd: result.directory,
        env: {
          ...process.env,
          PR_TITLE: "feat: apply policy",
          PR_BODY: "Material change: yes\nADR: docs/decisions/ADR-0001-test.md",
          PR_AUTHOR: "author",
          PR_FILES_FILE: path.join(result.directory, "files.json"),
          PR_COMMITS_FILE: path.join(result.directory, "commits.json"),
          PR_REVIEWS_FILE: path.join(result.directory, "reviews.json")
        }
      });
      let output = "";
      child.stdout.on("data", (chunk) => (output += chunk));
      child.stderr.on("data", (chunk) => (output += chunk));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code: code ?? 1, output }));
    });

    expect(rerun.code).toBe(0);
    expect(rerun.output).toContain("PASS PRS-PR-GOVERNANCE-001");
  });
});

describe("governance credential transport", () => {
  it("supplies the exact bearer header on stdin for every API request without a credential argument", async () => {
    const directory = await networkDirectory();
    const probe = await installCurlProbe(directory);
    const result = await runNetworkGovernance(directory, "https://fixture.invalid", probe.env);
    const calls = await readProbe(probe.log);

    expect(result.code, result.output).toBe(0);
    expect(calls).toHaveLength(3);
    expect(calls.map((call) => call.argv.at(-1))).toEqual([
      "https://fixture.invalid/files?per_page=100",
      "https://fixture.invalid/commits?per_page=250",
      "https://fixture.invalid/reviews?per_page=100"
    ]);
    for (const call of calls) {
      expect(call.argv.join(" ")).not.toContain(fabricatedToken);
      expect(call.stdin).toBe(`Authorization: Bearer ${fabricatedToken}\n`);
      expect(call.argv).toContain("@-");
    }
    expect(result.output).not.toContain(fabricatedToken);
  });

  it("stops on a failed curl transport without evaluating incomplete governance input", async () => {
    const directory = await networkDirectory();
    const probe = await installCurlProbe(directory);
    const result = await runNetworkGovernance(directory, "https://fixture.invalid", { ...probe.env, CURL_PROBE_EXIT: "7" });
    const calls = await readProbe(probe.log);

    expect(result.code).toBe(7);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.argv.join(" ")).not.toContain(fabricatedToken);
    expect(calls[0]!.stdin).toBe(`Authorization: Bearer ${fabricatedToken}\n`);
    expect(result.output).not.toContain("PASS PRS-PR-GOVERNANCE-001");
    expect(result.output).not.toContain(fabricatedToken);
  });

  it("preserves curlrc proxy and CA configuration, same-origin redirects, and certificate verification", async () => {
    const directory = await networkDirectory();
    const certificate = path.join(directory, "fixture-cert.pem");
    const privateKey = path.join(directory, "fixture-key.pem");
    await execFileAsync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-subj", "/CN=governance-fixture.invalid", "-addext", "subjectAltName=DNS:governance-fixture.invalid",
      "-keyout", privateKey, "-out", certificate
    ], { env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } });
    const requests: Array<{ url: string; authorization: string | undefined }> = [];
    const tunnels: string[] = [];
    const sockets = new Set<Socket>();
    const track = (socket: Socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); };
    const target = createHttpsServer({ key: await readFile(privateKey), cert: await readFile(certificate) }, (request, response) => {
      requests.push({ url: request.url ?? "", authorization: request.headers.authorization });
      if (request.url?.startsWith("/redirect/")) {
        response.writeHead(302, { location: request.url.replace("/redirect", "") });
        response.end();
      } else {
        response.writeHead(200, { "content-type": "application/json" });
        response.end("[]");
      }
    });
    target.on("connection", track);
    const proxy = createHttpServer((_request, response) => { response.writeHead(502); response.end(); });
    proxy.on("connection", track);
    try {
      const targetPort = await listen(target);
      proxy.on("connect", (request, client, head) => {
        tunnels.push(request.url ?? "");
        if (request.url !== `governance-fixture.invalid:${targetPort}`) { client.destroy(); return; }
        const upstream = connect(targetPort, "127.0.0.1");
        track(upstream);
        upstream.on("error", () => client.destroy());
        client.on("error", () => upstream.destroy());
        upstream.on("connect", () => {
          client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          if (head.length) upstream.write(head);
          upstream.pipe(client); client.pipe(upstream);
        });
      });
      const proxyPort = await listen(proxy);
      const proxyConfig = `proxy = "http://127.0.0.1:${proxyPort}"\n`;
      await writeFile(path.join(directory, ".curlrc"), `${proxyConfig}cacert = "${certificate}"\n`);
      const base = `https://governance-fixture.invalid:${targetPort}/redirect`;
      const result = await runNetworkGovernance(directory, base);

      expect(result.code, result.output).toBe(0);
      expect(requests.map((request) => request.url)).toEqual([
        "/redirect/files?per_page=100", "/files?per_page=100",
        "/redirect/commits?per_page=250", "/commits?per_page=250",
        "/redirect/reviews?per_page=100", "/reviews?per_page=100"
      ]);
      expect(requests.every((request) => request.authorization === `Bearer ${fabricatedToken}`)).toBe(true);
      expect(tunnels.length).toBeGreaterThanOrEqual(3);
      expect(new Set(tunnels)).toEqual(new Set([`governance-fixture.invalid:${targetPort}`]));

      // Keep the proxy configured but remove the synthetic CA: TLS must fail.
      await writeFile(path.join(directory, ".curlrc"), proxyConfig);
      const untrusted = await runNetworkGovernance(directory, base);
      expect(untrusted.code, untrusted.output).toBe(60);
      expect(untrusted.output).not.toContain("PASS PRS-PR-GOVERNANCE-001");
      expect(requests).toHaveLength(6);
    } finally {
      for (const socket of sockets) socket.destroy();
      await Promise.all([closeServer(proxy), closeServer(target)]);
    }
  }, 20_000);
});
