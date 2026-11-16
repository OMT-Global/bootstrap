import YAML from "yaml";

export function releaseObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
  return value as Record<string, unknown>;
}

export async function releaseJson(response: Response, url: string, status: number): Promise<unknown> {
  if (response.status !== status || response.redirected || response.url !== url || !response.body) throw new Error();
  const chunks: Uint8Array[] = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 1024 * 1024) throw new Error();
    chunks.push(chunk);
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  if (YAML.parseDocument(text, { uniqueKeys: true, schema: "json" }).errors.length) throw new Error();
  return JSON.parse(text) as unknown;
}

export function nextReleasePage(link: string | null, expectedUrl: string, page: number): boolean {
  if (link === null) return false;
  if (link.length > 8192) throw new Error();
  const seen = new Set<string>(); let next = false;
  for (const part of link.split(",")) {
    const match = /^\s*<([^>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(part);
    if (!match || !match[1] || !match[2] || seen.has(match[2])) throw new Error();
    seen.add(match[2]);
    const target = new URL(match[1]); const expected = new URL(expectedUrl);
    if (target.origin !== expected.origin || target.pathname !== expected.pathname || target.hash ||
        [...target.searchParams.keys()].sort().join(",") !== "page,per_page" || target.searchParams.get("per_page") !== "100" ||
        !/^[1-9][0-9]{0,8}$/.test(target.searchParams.get("page") ?? "")) throw new Error();
    if (match[2] === "next") {
      if (target.searchParams.get("page") !== String(page + 1)) throw new Error();
      next = true;
    }
  }
  return next;
}
