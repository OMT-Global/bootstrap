import { lstat, readFile, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";
import spdxLicenseIdentifiers from "spdx-license-list/simple.js";

import { sha256 } from "./lib/hash.js";
import type { BootstrapManifest, LicenseMode, LicensePolicy, RenderedFile, RepoState, ThirdPartyNotice } from "./types.js";

export const LICENSE_PATH = "LICENSE";
export const THIRD_PARTY_NOTICES_PATH = "THIRD_PARTY_NOTICES.md";

async function rejectAlternateLicenseFiles(targetDir: string): Promise<void> {
  const alternatePattern = /^(?:unlicense|licen[cs]e|copying)(?:[-._][\s\S]+)?$/i;
  const alternates = (await readdir(targetDir, { withFileTypes: true }))
    .filter((entry) => entry.name !== LICENSE_PATH && alternatePattern.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  if (alternates.length > 0) {
    const displayNames = alternates.map((fileName) =>
      JSON.stringify(fileName).replace(
        /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
        (character) => `\\u{${character.codePointAt(0)!.toString(16).padStart(4, "0")}}`
      )
    );
    throw new Error(
      `PRS-LICENSE-TRANSITION-001: alternate license file(s) ${displayNames.join(", ")} must be reconciled into LICENSE before Bootstrap can manage licensing.`
    );
  }
}

export interface LicensePlanSummary {
  beforeMode: string;
  afterMode: string;
  transitionRequired: boolean;
  templateApproval: string;
}

export interface LicenseProjection {
  files: RenderedFile[];
  summary: LicensePlanSummary;
  state: NonNullable<RepoState["license"]>;
}

interface LegalTextFile {
  bytes: Buffer;
  contents: string;
}

function modeLabel(policy: LicensePolicy): string {
  return policy.mode === "spdx" ? `spdx:${policy.identifier}` : "proprietary";
}

function resolveTemplatePath(targetDir: string, templatePath: string, reservedOutputPaths: readonly string[]): string {
  if (path.isAbsolute(templatePath)) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: license template path must be relative to the repository root.");
  }
  const resolved = path.resolve(targetDir, templatePath);
  const relative = path.relative(targetDir, resolved);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: license template path must stay within the repository.");
  }
  const normalizedRelative = relative.replace(/\\/g, "/").toLowerCase();
  const reservedPaths = [LICENSE_PATH, THIRD_PARTY_NOTICES_PATH, ...reservedOutputPaths]
    .map((filePath) => filePath.replace(/\\/g, "/").toLowerCase());
  if (reservedPaths.includes(normalizedRelative)) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: license template must be separate from Bootstrap-managed output files.");
  }
  return resolved;
}

function isPathWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

async function readApprovedTemplate(
  targetDir: string,
  templatePath: string,
  reservedOutputPaths: readonly string[]
): Promise<Buffer> {
  const resolved = resolveTemplatePath(targetDir, templatePath, reservedOutputPaths);
  let fileStat;
  try {
    let currentPath = path.resolve(targetDir);
    const relativeComponents = path.relative(currentPath, resolved).split(path.sep).filter(Boolean);
    for (const component of relativeComponents) {
      currentPath = path.join(currentPath, component);
      fileStat = await lstat(currentPath);
      if (fileStat.isSymbolicLink()) {
        throw new Error("PRS-LICENSE-TEMPLATE-001: license template path components cannot be symlinks.");
      }
    }
    fileStat ??= await lstat(resolved);
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      throw new Error(`PRS-LICENSE-TEMPLATE-001: approved license template was not found at ${templatePath}.`);
    }
    throw error;
  }
  if (!fileStat.isFile() || fileStat.nlink !== 1) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: license template must be a regular, singly linked file.");
  }

  for (const reservedPath of [LICENSE_PATH, THIRD_PARTY_NOTICES_PATH, ...reservedOutputPaths]) {
    try {
      const outputStat = await stat(path.resolve(targetDir, reservedPath));
      if (outputStat.dev === fileStat.dev && outputStat.ino === fileStat.ino) {
        throw new Error("PRS-LICENSE-TEMPLATE-001: license template cannot physically alias a Bootstrap-managed output file.");
      }
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        (error.code === "ENOENT" || error.code === "ENOTDIR")
      ) continue;
      throw error;
    }
  }

  const [repositoryRoot, physicalTemplatePath] = await Promise.all([realpath(targetDir), realpath(resolved)]);
  if (!isPathWithin(repositoryRoot, physicalTemplatePath)) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: license template must physically stay within the repository.");
  }
  return readFile(physicalTemplatePath);
}

function decodeLegalText(bytes: Buffer, description: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error(`PRS-LICENSE-ENCODING-001: ${description} must be valid UTF-8.`);
  }
}

async function readLegalTextIfExists(filePath: string, description: string): Promise<LegalTextFile | undefined> {
  let bytes;
  try {
    bytes = await readFile(filePath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  return { bytes, contents: decodeLegalText(bytes, description) };
}

async function readManagedLegalOutputIfExists(
  targetDir: string,
  relativePath: string,
  description: string
): Promise<LegalTextFile | undefined> {
  const outputPath = path.join(targetDir, relativePath);
  let outputStat;
  try {
    outputStat = await lstat(outputPath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  if (outputStat.isSymbolicLink() || !outputStat.isFile() || outputStat.nlink !== 1) {
    throw new Error(`PRS-OWNERSHIP-001: ${relativePath} must be a regular, non-linked repository file.`);
  }

  const [repositoryRoot, physicalOutputPath] = await Promise.all([realpath(targetDir), realpath(outputPath)]);
  if (!isPathWithin(repositoryRoot, physicalOutputPath)) {
    throw new Error(`PRS-OWNERSHIP-001: ${relativePath} must physically stay within the repository.`);
  }
  return readLegalTextIfExists(physicalOutputPath, description);
}

export async function readManagedLegalOutputTextIfExists(
  targetDir: string,
  relativePath: typeof LICENSE_PATH | typeof THIRD_PARTY_NOTICES_PATH
): Promise<string | undefined> {
  return (await readManagedLegalOutputIfExists(targetDir, relativePath, `existing ${relativePath}`))?.contents;
}

function renderLicenseTemplate(policy: LicensePolicy, template: string): string {
  const supportedTokens = new Set(["{{copyright_holder}}", "{{copyright_years}}", "{{spdx_identifier}}"]);
  const templateTokens = template.match(/{{[^{}]+}}/g) ?? [];
  if (templateTokens.some((token) => !supportedTokens.has(token))) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: approved template contains unsupported substitution tokens.");
  }
  for (const token of ["{{copyright_holder}}", "{{copyright_years}}"] as const) {
    if (!template.includes(token)) {
      throw new Error(`PRS-LICENSE-TEMPLATE-001: approved template is missing required token ${token}.`);
    }
  }
  if (
    policy.mode === "proprietary" &&
    (template.includes("{{spdx_identifier}}") || /SPDX-License-Identifier\s*:/i.test(template))
  ) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: proprietary templates cannot declare an SPDX identifier.");
  }
  if (policy.mode === "spdx" && policy.template.spdxIdentifier !== policy.identifier) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: SPDX template approval does not match the selected identifier.");
  }

  const replacements: Record<string, string> = {
    "{{copyright_holder}}": policy.holder,
    "{{copyright_years}}": policy.years,
    "{{spdx_identifier}}": policy.mode === "spdx" ? policy.identifier : ""
  };
  const contents = template.replace(
    /{{copyright_holder}}|{{copyright_years}}|{{spdx_identifier}}/g,
    (token) => replacements[token] ?? token
  );
  if (policy.mode === "proprietary" && /SPDX-License-Identifier\s*:/i.test(contents)) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: proprietary templates cannot declare an SPDX identifier.");
  }
  if (policy.mode === "spdx") {
    const declarations = [...contents.matchAll(/SPDX-License-Identifier\s*:\s*([^\r\n]*)/gi)]
      .map((match) => match[1]?.trim() ?? "");
    if (declarations.some((identifier) => identifier !== policy.identifier)) {
      throw new Error("PRS-LICENSE-TEMPLATE-001: rendered SPDX declaration does not match the selected identifier.");
    }
  }
  return contents;
}

function noticeSortKey(notice: ThirdPartyNotice): string {
  return [notice.name, notice.kind, notice.source, notice.license].join("\u0000");
}

function renderThirdPartyNotices(notices: ThirdPartyNotice[]): string {
  const entries = [...notices].sort((left, right) => {
    const leftKey = noticeSortKey(left);
    const rightKey = noticeSortKey(right);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  const lines = [
    "# Third-Party Notices",
    "",
    "This inventory is separate from the repository's first-party license. Each listed component remains subject to its own terms.",
    ""
  ];
  if (entries.length === 0) {
    lines.push("No third-party notices are declared in the Bootstrap manifest.", "");
  } else {
    for (const entry of entries) {
      lines.push(
        `## ${entry.name}`,
        "",
        `- Kind: ${entry.kind}`,
        `- License: ${entry.license}`,
        `- Source: ${entry.source}`,
        ...(entry.notice ? ["", entry.notice] : []),
        ""
      );
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

function classifyExistingLicense(contents: string | undefined, state: RepoState | undefined): string {
  if (contents === undefined) return "none";
  if (state?.license) return modeLabelFromState(state.license);
  const marker = contents.match(/^SPDX-License-Identifier:\s*([^\s]+)\s*$/m)?.[1];
  return marker && spdxLicenseIdentifiers.has(marker) ? `spdx:${marker} (unmanaged)` : "existing-unclassified";
}

function modeLabelFromState(state: NonNullable<RepoState["license"]>): string {
  const identifier = state.identifier && spdxLicenseIdentifiers.has(state.identifier) ? state.identifier : "unknown";
  return state.mode === "spdx" ? `spdx:${identifier}` : "proprietary";
}

function requireTransitionEvidence(
  policy: LicensePolicy,
  beforeMode: string,
  beforeContentSha256: string,
  afterMode: string,
  afterContentSha256: string
): void {
  if (!policy.transition) {
    throw new Error(
      `PRS-LICENSE-TRANSITION-001: adopting or replacing ${beforeMode} as ${afterMode} is a legal hard stop; record approvedBy, issue, ownership, contributors, and distributionHistory evidence.`
    );
  }
  const transitionMatches =
    policy.transition.fromMode === beforeMode &&
    policy.transition.fromContentSha256.toLowerCase() === beforeContentSha256 &&
    policy.transition.toMode === afterMode &&
    policy.transition.toContentSha256.toLowerCase() === afterContentSha256;
  if (!transitionMatches) {
    throw new Error(
      `PRS-LICENSE-TRANSITION-001: transition evidence does not match ${beforeMode}@${beforeContentSha256} -> ${afterMode}@${afterContentSha256}.`
    );
  }
}

export async function projectLicensePolicy(
  manifest: BootstrapManifest,
  targetDir: string,
  state?: RepoState,
  reservedOutputPaths: readonly string[] = []
): Promise<LicenseProjection | undefined> {
  const policy = manifest.license;
  if (!policy) return undefined;

  await rejectAlternateLicenseFiles(targetDir);

  const templateBytes = await readApprovedTemplate(targetDir, policy.template.path, reservedOutputPaths);
  if (sha256(templateBytes) !== policy.template.sha256.toLowerCase()) {
    throw new Error("PRS-LICENSE-TEMPLATE-001: license template digest does not match its approved SHA-256 pin.");
  }

  const template = decodeLegalText(templateBytes, "approved license template");
  const licenseContents = renderLicenseTemplate(policy, template);
  const noticesContents = renderThirdPartyNotices(policy.thirdPartyNotices);
  const existingLicenseFile = await readManagedLegalOutputIfExists(targetDir, LICENSE_PATH, "existing LICENSE");
  const existingLicense = existingLicenseFile?.contents;
  const existingNoticesFile = await readManagedLegalOutputIfExists(
    targetDir,
    THIRD_PARTY_NOTICES_PATH,
    "existing THIRD_PARTY_NOTICES.md"
  );
  const existingNotices = existingNoticesFile?.contents;
  const afterMode = modeLabel(policy);
  const beforeMode = classifyExistingLicense(existingLicense, state);
  const afterContentSha256 = sha256(licenseContents);
  const renderedLicenseBytes = Buffer.from(licenseContents, "utf8");
  const transitionRequired =
    (existingLicenseFile !== undefined &&
      (state?.license === undefined || !existingLicenseFile.bytes.equals(renderedLicenseBytes))) ||
    (state?.license !== undefined && modeLabelFromState(state.license) !== afterMode);

  const managedLicenseHash = state?.managedFiles[LICENSE_PATH];
  const recordedLicenseHashes = [managedLicenseHash, state?.license?.contentSha256].filter(
    (value): value is string => value !== undefined
  );
  if (existingLicense === undefined && recordedLicenseHashes.length > 0) {
    throw new Error("PRS-OWNERSHIP-001: managed LICENSE was deleted; restore it before planning a legal transition.");
  }
  const existingLicenseSha256 = existingLicenseFile === undefined ? undefined : sha256(existingLicenseFile.bytes);
  if (
    existingLicenseSha256 !== undefined &&
    recordedLicenseHashes.some((recordedHash) => recordedHash !== existingLicenseSha256)
  ) {
    throw new Error("PRS-OWNERSHIP-001: managed LICENSE was directly modified; restore it before planning a legal transition.");
  }
  if (transitionRequired) {
    const beforeContentSha256 = existingLicenseSha256 ?? state?.license?.contentSha256;
    if (!beforeContentSha256) {
      throw new Error("PRS-LICENSE-TRANSITION-001: prior license content hash is unavailable; restore or classify the existing license before transition.");
    }
    requireTransitionEvidence(policy, beforeMode, beforeContentSha256, afterMode, afterContentSha256);
  }
  if (
    existingNotices !== undefined &&
    existingNotices !== noticesContents &&
    state?.managedFiles[THIRD_PARTY_NOTICES_PATH] === undefined
  ) {
    throw new Error(
      "PRS-LICENSE-NOTICES-001: existing third-party notices are unmanaged and would be replaced; incorporate every obligation into license.thirdPartyNotices before applying."
    );
  }

  return {
    files: [
      { path: LICENSE_PATH, contents: licenseContents, reason: `Approved ${afterMode} license projection` },
      { path: THIRD_PARTY_NOTICES_PATH, contents: noticesContents, reason: "Separate third-party license inventory" }
    ],
    summary: {
      beforeMode,
      afterMode,
      transitionRequired,
      templateApproval: policy.template.approval
    },
    state: {
      mode: policy.mode as LicenseMode,
      ...(policy.mode === "spdx" ? { identifier: policy.identifier } : {}),
      contentSha256: afterContentSha256
    }
  };
}
