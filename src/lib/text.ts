export function dedent(
  strings: TemplateStringsArray,
  ...values: Array<string | number | boolean>
): string {
  const raw = strings.reduce((result, chunk, index) => {
    const value = values[index] ?? "";
    return `${result}${chunk}${value}`;
  }, "");

  const lines = raw.replace(/^\n/, "").split("\n");
  const nonEmpty = lines.filter((line) => line.trim().length > 0);
  const indent = nonEmpty.reduce((minIndent, line) => {
    const match = line.match(/^(\s*)/);
    const currentIndent = match?.[1]?.length ?? 0;
    return Math.min(minIndent, currentIndent);
  }, Number.POSITIVE_INFINITY);

  return lines
    .map((line) => line.slice(Number.isFinite(indent) ? indent : 0))
    .join("\n")
    .trimEnd();
}

export function yamlList(items: string[], indent = 0): string {
  const prefix = " ".repeat(indent);
  return items.map((item) => `${prefix}- '${item}'`).join("\n");
}

export function indentBlock(value: string, spaces: number): string {
  if (value.trim().length === 0) {
    return "";
  }

  const prefix = " ".repeat(spaces);
  return value
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join("\n");
}
