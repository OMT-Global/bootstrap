import { constants } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { link, mkdir, mkdtemp, open, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  extractPolicyStatements, readPolicyMarkdown,
  MAX_POLICY_MARKDOWN_BYTES, MAX_POLICY_MARKDOWN_LINES, MAX_POLICY_MARKDOWN_LINE_BYTES,
  MAX_POLICY_MARKDOWN_NODES, MAX_POLICY_MARKDOWN_DEPTH, MAX_POLICY_MARKDOWN_CANDIDATES
} from "../src/security-response-markdown.js";

const commonmark: typeof import("commonmark") = createRequire(import.meta.url)("commonmark");
const promise = "Acknowledge a complete private report within 2 business days.";
const normalized = "acknowledge a complete private report within 2 business days";
const directories: string[] = [];

async function directory() {
  const value = await mkdtemp(path.join(os.tmpdir(), "bootstrap-response-markdown-"));
  directories.push(value);
  return value;
}

function statements(input: string) {
  const result = extractPolicyStatements(input);
  expect(result.kind).toBe("supported");
  if (result.kind !== "supported") throw new Error("Expected a supported document");
  return result.statements;
}

function parseTree(root: InstanceType<typeof commonmark.Node>) {
  vi.spyOn(commonmark, "Parser").mockImplementationOnce(function () { return { parse: () => root }; } as never);
  return extractPolicyStatements("bounded input");
}

afterEach(async () => {
  vi.restoreAllMocks();
  vi.doUnmock("node:fs/promises");
  vi.doUnmock("node:fs");
  await Promise.all(directories.splice(0).map((value) => rm(value, { recursive: true, force: true })));
});

describe("CommonMark response statement grammar", () => {
  it("returns whole normalized paragraphs with their actual block source lines", () => {
    expect(statements("- ACKNOWLEDGE a complete\n  private report within 2 business days.\n\nSeparate paragraph.")).toEqual([
      { text: normalized, startLine: 1, endLine: 2 },
      { text: "separate paragraph", startLine: 4, endLine: 4 }
    ]);
  });

  it.each([
    promise, `- ${promise}`, `1. ${promise}`, `- Parent:\n  - ${promise}`,
    promise.replace(" complete ", " complete\n"), promise.replace(" complete ", " complete  \n"),
    promise.replace(" complete ", " complete\\\n")
  ])("accepts a plain statement paragraph: %j", (source) => {
    expect(statements(source).map((entry) => entry.text)).toContain(normalized);
  });

  it("does not manufacture an unquoted line by deleting inline code", () => {
    expect(statements("`Example`\n" + promise)).toEqual([]);
  });

  it("does not discard later promises after email and URI autolinks", () => {
    expect(statements(`<security@example.org>\n\n<https://example.org/security>\n\n${promise}`)).toEqual([
      { text: normalized, startLine: 5, endLine: 5 }
    ]);
  });

  it.each([
    `> ${promise}`, `> > ${promise}`, `> Example\n${promise}`, `> > Example\n${promise}`,
    `- > ${promise}`, `> - ${promise}`, `# ${promise}`, `## ${promise}`,
    `    ${promise}`, `\t${promise}`, ` \t${promise}`, `  \t${promise}`, `   \t${promise}`,
    `\`${promise}\``, `\`\`example\n${promise}\n\`\``, `\`example\n${promise}\n\``,
    `*${promise}*`, `**${promise}**`, `[${promise}](https://example.org/)`, `![${promise}](image.png)`,
    `${promise}\n\`example\``, `${promise}\n[example](https://example.org/)`
  ])("excludes quoted, code, heading, or non-plain paragraphs: %j", (source) => {
    expect(statements(source).some((entry) => entry.text === normalized)).toBe(false);
  });

  it.each(["`", "~"].flatMap((character) => {
    const fence = character.repeat(4);
    const info = character === "`" ? "text" : "text `sample`";
    return [
      `${fence}${info}\nInline ${fence} sample\n${promise}\n${fence}`,
      `${fence}${info}\n${character.repeat(3)}\n${promise}\n${fence}`,
      `${fence}${info}\n${(character === "`" ? "~" : "`").repeat(4)}\n${promise}\n${fence}`,
      `${fence}${info}\n    ${fence}\n${promise}\n${fence}`,
      `${fence}${info}\n${fence} trailing text\n${promise}\n${fence}`,
      `${fence}${info}\n${promise}`,
      `- ${fence}${info}\n  ${promise}\n  ${fence}`,
      `1. ${fence}${info}\n   Inline ${fence} sample\n   ${promise}\n   ${fence}`
    ];
  }))("keeps code-fence content out of statements: %j", (source) => {
    expect(statements(source)).toEqual([]);
  });

  it.each(["`", "~"])("retains promises after a correctly closed %s fence", (character) => {
    const fence = character.repeat(3);
    expect(statements(`${fence}text\n<pre>code only\n   ${fence}${character} \t\n\n${promise}`).map((entry) => entry.text)).toEqual([normalized]);
  });

  it("does not split a paragraph into multiple promises or erase source context", () => {
    const whole = statements(promise + "\nTriage a confirmed report within 7 calendar days.");
    expect(whole).toHaveLength(1);
    expect(whole[0]!.text).toBe(normalized + ". triage a confirmed report within 7 calendar days");
    expect(statements("Example: " + promise)[0]!.text).toBe("example: " + normalized);
    expect(statements("Do not " + promise)[0]!.text).toBe("do not " + normalized);
  });

  it("uses ASCII-only case folding and whitespace normalization", () => {
    expect(statements("AcKnowledge a complete private report within 2 business days.")[0]!.text).toBe("acKnowledge a complete private report within 2 business days");
    expect(statements(promise.replace(" a ", "\u00a0a "))[0]!.text).toContain("\u00a0");
    expect(statements(promise.replace("knowledge", "k\u200bnowledge"))[0]!.text).toContain("\u200b");
    expect(statements(promise.replace(" complete ", " complete\t"))[0]!.text).toBe(normalized);
  });

  it.each([
    `<span>Example</span>\n${promise}`, `> <span>Example</span>\n${promise}`,
    `<div>\n\n${promise}\n\n</div>`, `<pre><code>\n${promise}\n</code></pre>`,
    `<pre>\n<pre>nested</pre>\n${promise}\n</pre>`, `<PrE><CoDe>\n${promise}\n</cOdE></pRe>`,
    `<pre data-note="> </pre>">\n${promise}\n</pre>`, `<pre><code>\n</span>\n${promise}\n</code></pre>`,
    `<pre data-note="\n${promise}`, `<pre><code>\n${promise}`, `<pre\n${promise}`,
    `<![CDATA[\n${promise}\n]]>`, `<?example\n${promise}\n?>`, `<!DOCTYPE example\n${promise}\n>`,
    `<![CDATA[\n${promise}`, `<?example\n${promise}`, `<!DOCTYPE example\n${promise}`,
    `<!-- ${promise} -->`, `> <!-- comment -->\n\n${promise}`,
    `<br>\n\n${promise}`, `<hr/>\n\n${promise}`, `<custom />\n\n${promise}`,
    `<![CDATA[Example only]]>\n<?example?>\n<!DOCTYPE example>\n<div>example</div>\n<br><img src="sample.png"><input><wbr>\n<hr/><custom />\n\n${promise}`
  ])("intentionally rejects any raw HTML AST node anywhere: %j", (source) => {
    expect(extractPolicyStatements(source)).toEqual({ kind: "unsupported", reason: "raw-html" });
  });

  it("never returns partial statements before a later raw HTML node", () => {
    expect(extractPolicyStatements(promise + "\n\n<!-- later HTML -->")).toEqual({ kind: "unsupported", reason: "raw-html" });
  });

  it("accepts literal HTML inside code without inventing an HTML context", () => {
    expect(statements("```text\n<pre><code>\n```\n\n" + promise).map((entry) => entry.text)).toEqual([normalized]);
  });

  it("excludes unknown custom ancestors and inline children instead of flattening them", () => {
    const root = new commonmark.Node("document", [[1, 1], [1, 1]]);
    const custom = new commonmark.Node("custom_block", [[1, 1], [1, 1]]);
    const paragraph = new commonmark.Node("paragraph", [[1, 1], [1, 1]]);
    const text = new commonmark.Node("text"); text.literal = promise;
    root.appendChild(custom); custom.appendChild(paragraph); paragraph.appendChild(text);
    expect(parseTree(root)).toEqual({ kind: "supported", statements: [] });
    const plainRoot = new commonmark.Node("document", [[1, 1], [1, 1]]);
    const nonPlain = new commonmark.Node("paragraph", [[1, 1], [1, 1]]);
    plainRoot.appendChild(nonPlain); nonPlain.appendChild(new commonmark.Node("custom_inline"));
    expect(parseTree(plainRoot)).toEqual({ kind: "supported", statements: [] });
  });

  it("returns only fixed errors for parser failures and impossible paragraph positions", () => {
    vi.spyOn(commonmark, "Parser").mockImplementationOnce(function () { return { parse: () => { throw new Error("PRIVATE_PARSER_DETAIL"); } }; } as never);
    expect(extractPolicyStatements(promise)).toEqual({ kind: "unsupported", reason: "parse-error" });
    const root = new commonmark.Node("document");
    const paragraph = new commonmark.Node("paragraph");
    const text = new commonmark.Node("text"); text.literal = promise;
    root.appendChild(paragraph); paragraph.appendChild(text);
    expect(parseTree(root)).toEqual({ kind: "unsupported", reason: "parse-error" });
  });
});

describe("bounded Markdown input and tree", () => {
  it("accepts the exact UTF-8 byte limit and rejects one additional byte", () => {
    const exact = ("x".repeat(4_095) + "\n").repeat(16);
    expect(Buffer.byteLength(exact)).toBe(MAX_POLICY_MARKDOWN_BYTES);
    expect(extractPolicyStatements(exact).kind).toBe("supported");
    expect(extractPolicyStatements(exact + "x")).toEqual({ kind: "unsupported", reason: "input-limit" });
  });

  it.each(["\n", "\r", "\r\n"])("counts CommonMark line endings %j without double-counting CRLF", (ending) => {
    const exact = Array(MAX_POLICY_MARKDOWN_LINES).fill("x").join(ending);
    expect(extractPolicyStatements(exact).kind).toBe("supported");
    expect(extractPolicyStatements(exact + ending + "x")).toEqual({ kind: "unsupported", reason: "input-limit" });
  });

  it.each(["x", "é"])("limits UTF-8 bytes per line for %s", (character) => {
    const exact = character.repeat(MAX_POLICY_MARKDOWN_LINE_BYTES / Buffer.byteLength(character));
    expect(extractPolicyStatements(exact).kind).toBe("supported");
    expect(extractPolicyStatements(exact + character)).toEqual({ kind: "unsupported", reason: "input-limit" });
  });

  it("accepts 512 eligible paragraphs but never returns a partial set after candidate overflow", () => {
    const exact = Array(MAX_POLICY_MARKDOWN_CANDIDATES).fill("Ordinary statement.").join("\n\n");
    expect(statements(exact)).toHaveLength(MAX_POLICY_MARKDOWN_CANDIDATES);
    expect(extractPolicyStatements(exact + "\n\nOne more.")).toEqual({ kind: "unsupported", reason: "tree-limit" });
  });

  it("does not count excluded quote paragraphs against the candidate limit", () => {
    const source = Array(MAX_POLICY_MARKDOWN_CANDIDATES + 1).fill("> Excluded statement.\n>").join("\n") + "\n\n" + promise;
    expect(statements(source).map((entry) => entry.text)).toEqual([normalized]);
  });

  it("counts entered AST nodes including the root at the exact boundary", () => {
    const root = new commonmark.Node("document", [[1, 1], [1, 1]]);
    for (let index = 1; index < MAX_POLICY_MARKDOWN_NODES; index += 1) root.appendChild(new commonmark.Node("thematic_break"));
    expect(parseTree(root)).toEqual({ kind: "supported", statements: [] });
    root.appendChild(new commonmark.Node("thematic_break"));
    expect(parseTree(root)).toEqual({ kind: "unsupported", reason: "tree-limit" });
  });

  it("bounds parent-chain depth with the document at depth zero", () => {
    const root = new commonmark.Node("document", [[1, 1], [1, 1]]);
    let cursor = root;
    for (let depth = 1; depth <= MAX_POLICY_MARKDOWN_DEPTH; depth += 1) {
      const child = new commonmark.Node("block_quote", [[1, 1], [1, 1]]);
      cursor.appendChild(child); cursor = child;
    }
    expect(parseTree(root)).toEqual({ kind: "supported", statements: [] });
    cursor.appendChild(new commonmark.Node("thematic_break"));
    expect(parseTree(root)).toEqual({ kind: "unsupported", reason: "tree-limit" });
  });

  it("fails closed on real deeply nested and many-inline-node parser input", () => {
    expect(extractPolicyStatements("> ".repeat(MAX_POLICY_MARKDOWN_DEPTH) + "text")).toEqual({ kind: "unsupported", reason: "tree-limit" });
    expect(extractPolicyStatements(Array(11).fill("*x* ".repeat(1_000)).join("\n"))).toEqual({ kind: "unsupported", reason: "tree-limit" });
  });
});

async function withMockedOpen(handle: object, openError?: Error) {
  vi.resetModules();
  const mockedOpen = vi.fn(async () => { if (openError) throw openError; return handle; });
  vi.doMock("node:fs/promises", async (importOriginal) => ({ ...await importOriginal<typeof import("node:fs/promises")>(), open: mockedOpen }));
  const module = await import("../src/security-response-markdown.js");
  const result = await module.readPolicyMarkdown("/PRIVATE_READER_TARGET");
  return { result, mockedOpen };
}

describe("bounded product SECURITY reader", () => {
  it("reads an ordinary singly linked file and distinguishes a missing file", async () => {
    const target = await directory();
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "missing" });
    await writeFile(path.join(target, "SECURITY.md"), promise);
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "supported", text: promise });
  });

  it.each([false, true])("rejects final symlinks without reading the target (dangling=%s)", async (dangling) => {
    const target = await directory();
    const outside = path.join(await directory(), "private-target.txt");
    if (!dangling) await writeFile(outside, "PRIVATE_TARGET_CONTENT");
    await symlink(outside, path.join(target, "SECURITY.md"));
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "unsupported", reason: "unsupported-file" });
  });

  it("rejects a hard-linked input and a directory", async () => {
    const target = await directory();
    const original = path.join(target, "original.md");
    await writeFile(original, promise);
    await link(original, path.join(target, "SECURITY.md"));
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "unsupported", reason: "unsupported-file" });
    await rm(path.join(target, "SECURITY.md"));
    await mkdir(path.join(target, "SECURITY.md"));
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "unsupported", reason: "unsupported-file" });
  });

  it.skipIf(process.platform === "win32")("rejects a FIFO without a writer through the nonblocking open", async () => {
    const target = await directory();
    execFileSync("mkfifo", [path.join(target, "SECURITY.md")]);
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "unsupported", reason: "unsupported-file" });
  });

  it("rejects oversized regular and sparse inputs without reading the whole file", async () => {
    const target = await directory();
    const file = path.join(target, "SECURITY.md");
    await writeFile(file, Buffer.alloc(MAX_POLICY_MARKDOWN_BYTES + 1, 0x78));
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "unsupported", reason: "input-limit" });
    const handle = await open(file, "w");
    try { await handle.truncate(MAX_POLICY_MARKDOWN_BYTES * 1_024); } finally { await handle.close(); }
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "unsupported", reason: "input-limit" });
  });

  it("rejects invalid UTF-8 instead of decoding replacement characters", async () => {
    const target = await directory();
    await writeFile(path.join(target, "SECURITY.md"), Buffer.from([0x61, 0xc3, 0x28]));
    expect(await readPolicyMarkdown(target)).toEqual({ kind: "unsupported", reason: "invalid-utf8" });
  });

  it("validates the opened handle before reading, bounds the buffer, and always closes it", async () => {
    const content = Buffer.from(promise);
    let position = 0;
    const handle = {
      stat: vi.fn(async () => ({ isFile: () => true, nlink: 1, size: Number.MAX_SAFE_INTEGER })),
      read: vi.fn(async (buffer: Buffer, offset: number, length: number, filePosition: unknown) => {
        expect(buffer.length).toBe(MAX_POLICY_MARKDOWN_BYTES + 1);
        expect(offset + length).toBe(buffer.length);
        expect(filePosition).toBeNull();
        const count = Math.min(7, content.length - position, length);
        content.copy(buffer, offset, position, position + count); position += count;
        return { bytesRead: count, buffer };
      }),
      close: vi.fn(async () => undefined)
    };
    const { result, mockedOpen } = await withMockedOpen(handle);
    expect(result).toEqual({ kind: "supported", text: promise });
    expect(mockedOpen.mock.calls[0]![1]).toBe(constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    expect(handle.stat.mock.invocationCallOrder[0]).toBeLessThan(handle.read.mock.invocationCallOrder[0]!);
    expect(handle.close).toHaveBeenCalledOnce();
  });

  it.each([
    ["invalid UTF-8", Buffer.from([0xc3, 0x28]), "invalid-utf8"],
    ["input overflow", Buffer.alloc(MAX_POLICY_MARKDOWN_BYTES + 1, 0x78), "input-limit"]
  ])("closes the opened handle after %s rejection", async (_name, content, reason) => {
    let position = 0;
    const handle = {
      stat: vi.fn(async () => ({ isFile: () => true, nlink: 1 })),
      read: vi.fn(async (buffer: Buffer, offset: number, length: number) => {
        expect(buffer.length).toBe(MAX_POLICY_MARKDOWN_BYTES + 1);
        const count = Math.min(content.length - position, length);
        content.copy(buffer, offset, position, position + count); position += count;
        return { bytesRead: count, buffer };
      }),
      close: vi.fn(async () => undefined)
    };
    const { result } = await withMockedOpen(handle);
    expect(result).toEqual({ kind: "unsupported", reason });
    expect(handle.close).toHaveBeenCalledOnce();
    expect(position).toBeLessThanOrEqual(MAX_POLICY_MARKDOWN_BYTES + 1);
  });

  it.each(["special file", "multiple links", "stat error", "read error", "close error", "stat ENOENT", "read ELOOP", "close ENOENT"])("closes rejected handles with fixed diagnostics: %s", async (failure) => {
    const handle = {
      stat: vi.fn(async () => {
        if (failure.startsWith("stat")) throw Object.assign(new Error("PRIVATE_FSTAT_DETAIL"), { code: failure.split(" ")[1] });
        return { isFile: () => failure !== "special file", nlink: failure === "multiple links" ? 2 : 1 };
      }),
      read: vi.fn(async () => { if (failure.startsWith("read")) throw Object.assign(new Error("PRIVATE_READ_DETAIL"), { code: failure.split(" ")[1] }); return { bytesRead: 0 }; }),
      close: vi.fn(async () => { if (failure.startsWith("close")) throw Object.assign(new Error("PRIVATE_CLOSE_DETAIL"), { code: failure.split(" ")[1] }); })
    };
    const { result } = await withMockedOpen(handle);
    expect(result).toEqual({ kind: "unsupported", reason: ["special file", "multiple links"].includes(failure) ? "unsupported-file" : "unreadable" });
    expect(handle.close).toHaveBeenCalledOnce();
    if (["special file", "multiple links"].includes(failure) || failure.startsWith("stat")) expect(handle.read).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toMatch(/PRIVATE|Error|stack|errno/);
  });

  it("does not expose open errors or retry through another reader", async () => {
    const failure = Object.assign(new Error("PRIVATE_OPEN_DETAIL"), { code: "EACCES" });
    const { result, mockedOpen } = await withMockedOpen({}, failure);
    expect(result).toEqual({ kind: "unsupported", reason: "unreadable" });
    expect(mockedOpen).toHaveBeenCalledOnce();
  });

  it("fails closed before opening when required safety flags are unavailable", async () => {
    vi.resetModules();
    const mockedOpen = vi.fn();
    vi.doMock("node:fs", async (importOriginal) => ({ ...await importOriginal<typeof import("node:fs")>(), constants: { ...constants, O_NOFOLLOW: undefined } }));
    vi.doMock("node:fs/promises", async (importOriginal) => ({ ...await importOriginal<typeof import("node:fs/promises")>(), open: mockedOpen }));
    const module = await import("../src/security-response-markdown.js");
    expect(await module.readPolicyMarkdown("/PRIVATE_READER_TARGET")).toEqual({ kind: "unsupported", reason: "unsupported-reader" });
    expect(mockedOpen).not.toHaveBeenCalled();
  });
});
