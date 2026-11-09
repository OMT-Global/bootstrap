import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import type { Node } from "commonmark";

const commonmark: typeof import("commonmark") = createRequire(import.meta.url)("commonmark");

export const MAX_POLICY_MARKDOWN_BYTES = 65_536;
export const MAX_POLICY_MARKDOWN_LINES = 2_048;
export const MAX_POLICY_MARKDOWN_LINE_BYTES = 4_096;
export const MAX_POLICY_MARKDOWN_NODES = 32_768;
export const MAX_POLICY_MARKDOWN_DEPTH = 128;
export const MAX_POLICY_MARKDOWN_CANDIDATES = 512;

type InputFailure = "unsupported-file" | "unsupported-reader" | "input-limit" | "invalid-utf8" | "unreadable";
export type PolicyMarkdownInput =
  | { kind: "supported"; text: string }
  | { kind: "missing" }
  | { kind: "unsupported"; reason: InputFailure };
export type PolicyStatements =
  | { kind: "supported"; statements: ReadonlyArray<{ text: string; startLine: number; endLine: number }> }
  | { kind: "unsupported"; reason: "raw-html" | "input-limit" | "tree-limit" | "parse-error" };

function withinInputLimits(text: string): boolean {
  if (Buffer.byteLength(text, "utf8") > MAX_POLICY_MARKDOWN_BYTES) return false;
  const lines = text.split(/\r\n|\r|\n/);
  if (lines.at(-1) === "" && /[\r\n]$/.test(text)) lines.pop();
  return lines.length <= MAX_POLICY_MARKDOWN_LINES &&
    lines.every((line) => Buffer.byteLength(line, "utf8") <= MAX_POLICY_MARKDOWN_LINE_BYTES);
}

export async function readPolicyMarkdown(targetDir: string): Promise<PolicyMarkdownInput> {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0 ||
      typeof constants.O_NONBLOCK !== "number" || constants.O_NONBLOCK === 0) {
    return { kind: "unsupported", reason: "unsupported-reader" };
  }
  let opened = false;
  try {
    const handle = await open(path.join(targetDir, "SECURITY.md"), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    opened = true;
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1) return { kind: "unsupported", reason: "unsupported-file" };
      const bytes = Buffer.alloc(MAX_POLICY_MARKDOWN_BYTES + 1);
      let used = 0;
      while (used < bytes.length) {
        const { bytesRead } = await handle.read(bytes, used, bytes.length - used, null);
        if (bytesRead === 0) break;
        used += bytesRead;
      }
      if (used > MAX_POLICY_MARKDOWN_BYTES) return { kind: "unsupported", reason: "input-limit" };
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, used));
      } catch {
        return { kind: "unsupported", reason: "invalid-utf8" };
      }
      return withinInputLimits(text) ? { kind: "supported", text } : { kind: "unsupported", reason: "input-limit" };
    } finally {
      await handle.close();
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (!opened && code === "ENOENT") return { kind: "missing" };
    if (!opened && code === "ELOOP") return { kind: "unsupported", reason: "unsupported-file" };
    return { kind: "unsupported", reason: "unreadable" };
  }
}

function plainParagraph(node: Node): string | undefined {
  for (let ancestor = node.parent; ancestor; ancestor = ancestor.parent) {
    if (!["document", "list", "item"].includes(ancestor.type)) return undefined;
  }
  let text = "";
  for (let child = node.firstChild; child; child = child.next) {
    if (child.type === "text") text += child.literal ?? "";
    else if (child.type === "softbreak" || child.type === "linebreak") text += " ";
    else return undefined;
  }
  return text.replace(/[ \t]+/g, " ").replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, "")
    .replace(/\.$/, "").replace(/[A-Z]/g, (letter) => String.fromCharCode(letter.charCodeAt(0) + 32));
}

export function extractPolicyStatements(text: string): PolicyStatements {
  if (!withinInputLimits(text)) return { kind: "unsupported", reason: "input-limit" };
  try {
    const root = new commonmark.Parser({ smart: false }).parse(text);
    const walker = root.walker();
    const statements: Array<{ text: string; startLine: number; endLine: number }> = [];
    let nodes = 0;
    for (let event = walker.next(); event; event = walker.next()) {
      if (!event.entering) continue;
      if (++nodes > MAX_POLICY_MARKDOWN_NODES) return { kind: "unsupported", reason: "tree-limit" };
      const node = event.node;
      let depth = 0;
      for (let ancestor = node.parent; ancestor; ancestor = ancestor.parent) {
        if (++depth > MAX_POLICY_MARKDOWN_DEPTH) return { kind: "unsupported", reason: "tree-limit" };
      }
      if (node.type === "html_inline" || node.type === "html_block") return { kind: "unsupported", reason: "raw-html" };
      if (node.type !== "paragraph") continue;
      const statement = plainParagraph(node);
      if (statement === undefined) continue;
      if (statements.length >= MAX_POLICY_MARKDOWN_CANDIDATES) return { kind: "unsupported", reason: "tree-limit" };
      const startLine = node.sourcepos?.[0]?.[0];
      const endLine = node.sourcepos?.[1]?.[0];
      if (!Number.isSafeInteger(startLine) || !Number.isSafeInteger(endLine) || startLine < 1 || endLine < startLine) {
        return { kind: "unsupported", reason: "parse-error" };
      }
      statements.push({ text: statement, startLine, endLine });
    }
    return { kind: "supported", statements };
  } catch {
    return { kind: "unsupported", reason: "parse-error" };
  }
}
