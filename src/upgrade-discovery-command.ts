import { Readable } from "node:stream";

import { discoverPublicManifests, isValidPublicDiscoveryOrganization, type PublicManifestDiscovery } from "./upgrade-discovery.js";

const MAX_TOKEN_BYTES = 4098;
const TOKEN_WAIT_MILLISECONDS = 15_000;

/** Read a supplied capability only from a nonterminal stream; never echo its contents. */
export async function readPublicReadToken(input: Readable & { isTTY?: boolean }): Promise<string> {
  if (input.isTTY) throw new Error("A public read capability must be supplied by a nonterminal stream.");
  const chunks: Buffer[] = [];
  let total = 0;
  const timer = setTimeout(() => input.destroy(new Error("Public read capability input timed out.")), TOKEN_WAIT_MILLISECONDS);
  try {
    for await (const part of input) {
      if (!(typeof part === "string" || part instanceof Uint8Array)) throw new Error("Invalid input.");
      const length = typeof part === "string" ? Buffer.byteLength(part, "utf8") : part.byteLength;
      total += length;
      if (total > MAX_TOKEN_BYTES) throw new Error("Input limit exceeded.");
      chunks.push(Buffer.from(part));
    }
    const bytes = Buffer.concat(chunks, total);
    try {
      if (bytes.some((byte) => byte > 0x7f)) throw new Error("Invalid input.");
      let token = bytes.toString("utf8");
      if (token.endsWith("\n")) token = token.slice(0, -1).replace(/\r$/, "");
      if (token.length < 20 || token.length > 4096 || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(token)) throw new Error("Invalid input.");
      return token;
    } finally {
      bytes.fill(0);
    }
  } catch {
    input.destroy();
    throw new Error("Unable to read a valid public read capability.");
  } finally {
    clearTimeout(timer);
    for (const chunk of chunks) chunk.fill(0);
  }
}

export function formatPublicDiscovery(report: PublicManifestDiscovery): string {
  const lines = [
    `Public fleet discovery: ${report.status}.`,
    "Manifest observations only; policy versions, drift, exceptions and pilot eligibility are not verified.",
    ...report.repositories.map((repo) => {
      const flags = [repo.fork && "fork", repo.archived && "archived", repo.disabled && "disabled"].filter(Boolean);
      const summary = repo.manifest?.summary;
      const details = summary ? `; class=${summary.normalizedClass ? JSON.stringify(summary.normalizedClass) : "unspecified"}; flow-ref=${summary.flowPolicy?.ref ? JSON.stringify(summary.flowPolicy.ref) : summary.flowPolicy ? "unrenderable" : "absent"}; declared-exceptions=${summary.exceptionCount}` : "";
      return `- ${JSON.stringify(repo.repository)}: ${repo.outcome}${repo.reason ? ` (${repo.reason})` : ""}${flags.length ? ` [${flags.join(", ")}]` : ""}${details}`;
    })
  ];
  if (report.failure) lines.push(`Discovery incomplete: ${report.failure.code}.`);
  return lines.join("\n");
}

export async function runPublicDiscovery(
  organization: string,
  options: { json?: boolean; readTokenStdin?: boolean },
  input: Readable & { isTTY?: boolean },
  discover: typeof discoverPublicManifests = discoverPublicManifests
): Promise<{ output: string; exitCode: number }> {
  if (!isValidPublicDiscoveryOrganization(organization)) throw new Error("Invalid public organization.");
  const token = options.readTokenStdin ? await readPublicReadToken(input) : undefined;
  const report = await discover(organization, token ? { publicReadToken: token } : {});
  return {
    output: options.json ? JSON.stringify(report, null, 2) : formatPublicDiscovery(report),
    exitCode: report.status === "complete" ? 0 : 1
  };
}
