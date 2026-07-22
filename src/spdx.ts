import spdxLicenseIdentifiers from "spdx-license-list/simple.js";

export const SUPPORTED_SPDX_IDENTIFIERS = [...spdxLicenseIdentifiers].sort();

export function isSupportedSpdxIdentifier(value: string): boolean {
  return spdxLicenseIdentifiers.has(value);
}
